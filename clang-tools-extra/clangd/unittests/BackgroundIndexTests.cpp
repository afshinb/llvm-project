#include "Headers.h"
#include "SyncAPI.h"
#include "TestFS.h"
#include "TestTU.h"
#include "index/Background.h"
#include "clang/Tooling/CompilationDatabase.h"
#include "llvm/Support/ScopedPrinter.h"
#include "llvm/Support/Threading.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <thread>

using ::testing::_;
using ::testing::AllOf;
using ::testing::Contains;
using ::testing::ElementsAre;
using ::testing::Not;
using ::testing::UnorderedElementsAre;

namespace clang {
namespace clangd {

MATCHER_P(Named, N, "") { return arg.Name == N; }
MATCHER(Declared, "") {
  return !StringRef(arg.CanonicalDeclaration.FileURI).empty();
}
MATCHER(Defined, "") { return !StringRef(arg.Definition.FileURI).empty(); }
MATCHER_P(FileURI, F, "") { return StringRef(arg.Location.FileURI) == F; }
::testing::Matcher<const RefSlab &>
RefsAre(std::vector<::testing::Matcher<Ref>> Matchers) {
  return ElementsAre(::testing::Pair(_, UnorderedElementsAreArray(Matchers)));
}
// URI cannot be empty since it references keys in the IncludeGraph.
MATCHER(EmptyIncludeNode, "") {
  return arg.Flags == IncludeGraphNode::SourceFlag::None && !arg.URI.empty() &&
         arg.Digest == FileDigest{{0}} && arg.DirectIncludes.empty();
}

MATCHER(HadErrors, "") {
  return arg.Flags & IncludeGraphNode::SourceFlag::HadErrors;
}

MATCHER_P(NumReferences, N, "") { return arg.References == N; }

class MemoryShardStorage : public BackgroundIndexStorage {
  mutable std::mutex StorageMu;
  llvm::StringMap<std::string> &Storage;
  size_t &CacheHits;

public:
  MemoryShardStorage(llvm::StringMap<std::string> &Storage, size_t &CacheHits)
      : Storage(Storage), CacheHits(CacheHits) {}
  llvm::Error storeShard(llvm::StringRef ShardIdentifier,
                         IndexFileOut Shard) const override {
    std::lock_guard<std::mutex> Lock(StorageMu);
    AccessedPaths.insert(ShardIdentifier);
    Storage[ShardIdentifier] = llvm::to_string(Shard);
    return llvm::Error::success();
  }
  std::unique_ptr<IndexFileIn>
  loadShard(llvm::StringRef ShardIdentifier) const override {
    std::lock_guard<std::mutex> Lock(StorageMu);
    AccessedPaths.insert(ShardIdentifier);
    if (Storage.find(ShardIdentifier) == Storage.end()) {
      return nullptr;
    }
    auto IndexFile = readIndexFile(Storage[ShardIdentifier]);
    if (!IndexFile) {
      ADD_FAILURE() << "Error while reading " << ShardIdentifier << ':'
                    << IndexFile.takeError();
      return nullptr;
    }
    CacheHits++;
    return llvm::make_unique<IndexFileIn>(std::move(*IndexFile));
  }

  mutable llvm::StringSet<> AccessedPaths;
};

class BackgroundIndexTest : public ::testing::Test {
protected:
  BackgroundIndexTest() { BackgroundIndex::preventThreadStarvationInTests(); }
};

TEST_F(BackgroundIndexTest, NoCrashOnErrorFile) {
  MockFSProvider FS;
  FS.Files[testPath("root/A.cc")] = "error file";
  llvm::StringMap<std::string> Storage;
  size_t CacheHits = 0;
  MemoryShardStorage MSS(Storage, CacheHits);
  OverlayCDB CDB(/*Base=*/nullptr);
  BackgroundIndex Idx(Context::empty(), FS, CDB,
                      [&](llvm::StringRef) { return &MSS; });

  tooling::CompileCommand Cmd;
  Cmd.Filename = testPath("root/A.cc");
  Cmd.Directory = testPath("root");
  Cmd.CommandLine = {"clang++", "-DA=1", testPath("root/A.cc")};
  CDB.setCompileCommand(testPath("root/A.cc"), Cmd);

  ASSERT_TRUE(Idx.blockUntilIdleForTest());
}

TEST_F(BackgroundIndexTest, IndexTwoFiles) {
  MockFSProvider FS;
  // a.h yields different symbols when included by A.cc vs B.cc.
  FS.Files[testPath("root/A.h")] = R"cpp(
      void common();
      void f_b();
      #if A
        class A_CC {};
      #else
        class B_CC{};
      #endif
      )cpp";
  FS.Files[testPath("root/A.cc")] =
      "#include \"A.h\"\nvoid g() { (void)common; }";
  FS.Files[testPath("root/B.cc")] =
      R"cpp(
      #define A 0
      #include "A.h"
      void f_b() {
        (void)common;
        (void)common;
        (void)common;
        (void)common;
      })cpp";
  llvm::StringMap<std::string> Storage;
  size_t CacheHits = 0;
  MemoryShardStorage MSS(Storage, CacheHits);
  OverlayCDB CDB(/*Base=*/nullptr);
  BackgroundIndex Idx(Context::empty(), FS, CDB,
                      [&](llvm::StringRef) { return &MSS; });

  tooling::CompileCommand Cmd;
  Cmd.Filename = testPath("root/A.cc");
  Cmd.Directory = testPath("root");
  Cmd.CommandLine = {"clang++", "-DA=1", testPath("root/A.cc")};
  CDB.setCompileCommand(testPath("root/A.cc"), Cmd);

  ASSERT_TRUE(Idx.blockUntilIdleForTest());
  EXPECT_THAT(runFuzzyFind(Idx, ""),
              UnorderedElementsAre(AllOf(Named("common"), NumReferences(1U)),
                                   AllOf(Named("A_CC"), NumReferences(0U)),
                                   AllOf(Named("g"), NumReferences(0U)),
                                   AllOf(Named("f_b"), Declared(),
                                         Not(Defined()), NumReferences(0U))));

  Cmd.Filename = testPath("root/B.cc");
  Cmd.CommandLine = {"clang++", Cmd.Filename};
  CDB.setCompileCommand(testPath("root/B.cc"), Cmd);

  ASSERT_TRUE(Idx.blockUntilIdleForTest());
  // B_CC is dropped as we don't collect symbols from A.h in this compilation.
  EXPECT_THAT(runFuzzyFind(Idx, ""),
              UnorderedElementsAre(AllOf(Named("common"), NumReferences(5U)),
                                   AllOf(Named("A_CC"), NumReferences(0U)),
                                   AllOf(Named("g"), NumReferences(0U)),
                                   AllOf(Named("f_b"), Declared(), Defined(),
                                         NumReferences(1U))));

  auto Syms = runFuzzyFind(Idx, "common");
  EXPECT_THAT(Syms, UnorderedElementsAre(Named("common")));
  auto Common = *Syms.begin();
  EXPECT_THAT(getRefs(Idx, Common.ID),
              RefsAre({FileURI("unittest:///root/A.h"),
                       FileURI("unittest:///root/A.cc"),
                       FileURI("unittest:///root/B.cc"),
                       FileURI("unittest:///root/B.cc"),
                       FileURI("unittest:///root/B.cc"),
                       FileURI("unittest:///root/B.cc")}));
}

TEST_F(BackgroundIndexTest, ShardStorageTest) {
  MockFSProvider FS;
  FS.Files[testPath("root/A.h")] = R"cpp(
      void common();
      void f_b();
      class A_CC {};
      )cpp";
  std::string A_CC = "";
  FS.Files[testPath("root/A.cc")] = R"cpp(
      #include "A.h"
      void g() { (void)common; }
      class B_CC : public A_CC {};
      )cpp";

  llvm::StringMap<std::string> Storage;
  size_t CacheHits = 0;
  MemoryShardStorage MSS(Storage, CacheHits);

  tooling::CompileCommand Cmd;
  Cmd.Filename = testPath("root/A.cc");
  Cmd.Directory = testPath("root");
  Cmd.CommandLine = {"clang++", testPath("root/A.cc")};
  // Check nothing is loaded from Storage, but A.cc and A.h has been stored.
  {
    OverlayCDB CDB(/*Base=*/nullptr);
    BackgroundIndex Idx(Context::empty(), FS, CDB,
                        [&](llvm::StringRef) { return &MSS; });
    CDB.setCompileCommand(testPath("root/A.cc"), Cmd);
    ASSERT_TRUE(Idx.blockUntilIdleForTest());
  }
  EXPECT_EQ(CacheHits, 0U);
  EXPECT_EQ(Storage.size(), 2U);

  {
    OverlayCDB CDB(/*Base=*/nullptr);
    BackgroundIndex Idx(Context::empty(), FS, CDB,
                        [&](llvm::StringRef) { return &MSS; });
    CDB.setCompileCommand(testPath("root"), Cmd);
    ASSERT_TRUE(Idx.blockUntilIdleForTest());
  }
  EXPECT_EQ(CacheHits, 2U); // Check both A.cc and A.h loaded from cache.
  EXPECT_EQ(Storage.size(), 2U);

  auto ShardHeader = MSS.loadShard(testPath("root/A.h"));
  EXPECT_NE(ShardHeader, nullptr);
  EXPECT_THAT(
      *ShardHeader->Symbols,
      UnorderedElementsAre(Named("common"), Named("A_CC"),
                           AllOf(Named("f_b"), Declared(), Not(Defined()))));
  for (const auto &Ref : *ShardHeader->Refs)
    EXPECT_THAT(Ref.second,
                UnorderedElementsAre(FileURI("unittest:///root/A.h")));

  auto ShardSource = MSS.loadShard(testPath("root/A.cc"));
  EXPECT_NE(ShardSource, nullptr);
  EXPECT_THAT(*ShardSource->Symbols,
              UnorderedElementsAre(Named("g"), Named("B_CC")));
  for (const auto &Ref : *ShardSource->Refs)
    EXPECT_THAT(Ref.second,
                UnorderedElementsAre(FileURI("unittest:///root/A.cc")));

  // The BaseOf relationship between A_CC and B_CC is stored in the file
  // containing the definition of the subject (A_CC)
  SymbolID A = findSymbol(*ShardHeader->Symbols, "A_CC").ID;
  SymbolID B = findSymbol(*ShardSource->Symbols, "B_CC").ID;
  EXPECT_THAT(
      *ShardHeader->Relations,
      UnorderedElementsAre(Relation{A, index::SymbolRole::RelationBaseOf, B}));
  // (and not in the file containing the definition of the object (B_CC)).
  EXPECT_EQ(ShardSource->Relations->size(), 0u);
}

TEST_F(BackgroundIndexTest, DirectIncludesTest) {
  MockFSProvider FS;
  FS.Files[testPath("root/B.h")] = "";
  FS.Files[testPath("root/A.h")] = R"cpp(
      #include "B.h"
      void common();
      void f_b();
      class A_CC {};
      )cpp";
  std::string A_CC = "#include \"A.h\"\nvoid g() { (void)common; }";
  FS.Files[testPath("root/A.cc")] = A_CC;

  llvm::StringMap<std::string> Storage;
  size_t CacheHits = 0;
  MemoryShardStorage MSS(Storage, CacheHits);

  tooling::CompileCommand Cmd;
  Cmd.Filename = testPath("root/A.cc");
  Cmd.Directory = testPath("root");
  Cmd.CommandLine = {"clang++", testPath("root/A.cc")};
  {
    OverlayCDB CDB(/*Base=*/nullptr);
    BackgroundIndex Idx(Context::empty(), FS, CDB,
                        [&](llvm::StringRef) { return &MSS; });
    CDB.setCompileCommand(testPath("root/A.cc"), Cmd);
    ASSERT_TRUE(Idx.blockUntilIdleForTest());
  }

  auto ShardSource = MSS.loadShard(testPath("root/A.cc"));
  EXPECT_TRUE(ShardSource->Sources);
  EXPECT_EQ(ShardSource->Sources->size(), 2U); // A.cc, A.h
  EXPECT_THAT(
      ShardSource->Sources->lookup("unittest:///root/A.cc").DirectIncludes,
      UnorderedElementsAre("unittest:///root/A.h"));
  EXPECT_NE(ShardSource->Sources->lookup("unittest:///root/A.cc").Digest,
            FileDigest{{0}});
  EXPECT_THAT(ShardSource->Sources->lookup("unittest:///root/A.h"),
              EmptyIncludeNode());

  auto ShardHeader = MSS.loadShard(testPath("root/A.h"));
  EXPECT_TRUE(ShardHeader->Sources);
  EXPECT_EQ(ShardHeader->Sources->size(), 2U); // A.h, B.h
  EXPECT_THAT(
      ShardHeader->Sources->lookup("unittest:///root/A.h").DirectIncludes,
      UnorderedElementsAre("unittest:///root/B.h"));
  EXPECT_NE(ShardHeader->Sources->lookup("unittest:///root/A.h").Digest,
            FileDigest{{0}});
  EXPECT_THAT(ShardHeader->Sources->lookup("unittest:///root/B.h"),
              EmptyIncludeNode());
}

// FIXME: figure out the right timeouts or rewrite to not use the timeouts and
// re-enable.
TEST_F(BackgroundIndexTest, DISABLED_PeriodicalIndex) {
  MockFSProvider FS;
  llvm::StringMap<std::string> Storage;
  size_t CacheHits = 0;
  MemoryShardStorage MSS(Storage, CacheHits);
  OverlayCDB CDB(/*Base=*/nullptr);
  BackgroundIndex Idx(
      Context::empty(), FS, CDB, [&](llvm::StringRef) { return &MSS; },
      /*BuildIndexPeriodMs=*/500);

  FS.Files[testPath("root/A.cc")] = "#include \"A.h\"";

  tooling::CompileCommand Cmd;
  FS.Files[testPath("root/A.h")] = "class X {};";
  Cmd.Filename = testPath("root/A.cc");
  Cmd.CommandLine = {"clang++", Cmd.Filename};
  CDB.setCompileCommand(testPath("root/A.cc"), Cmd);

  ASSERT_TRUE(Idx.blockUntilIdleForTest());
  EXPECT_THAT(runFuzzyFind(Idx, ""), ElementsAre());
  std::this_thread::sleep_for(std::chrono::milliseconds(1000));
  EXPECT_THAT(runFuzzyFind(Idx, ""), ElementsAre(Named("X")));

  FS.Files[testPath("root/A.h")] = "class Y {};";
  FS.Files[testPath("root/A.cc")] += " "; // Force reindex the file.
  Cmd.CommandLine = {"clang++", "-DA=1", testPath("root/A.cc")};
  CDB.setCompileCommand(testPath("root/A.cc"), Cmd);

  ASSERT_TRUE(Idx.blockUntilIdleForTest());
  EXPECT_THAT(runFuzzyFind(Idx, ""), ElementsAre(Named("X")));
  std::this_thread::sleep_for(std::chrono::milliseconds(1000));
  EXPECT_THAT(runFuzzyFind(Idx, ""), ElementsAre(Named("Y")));
}

TEST_F(BackgroundIndexTest, ShardStorageLoad) {
  MockFSProvider FS;
  FS.Files[testPath("root/A.h")] = R"cpp(
      void common();
      void f_b();
      class A_CC {};
      )cpp";
  FS.Files[testPath("root/A.cc")] =
      "#include \"A.h\"\nvoid g() { (void)common; }";

  llvm::StringMap<std::string> Storage;
  size_t CacheHits = 0;
  MemoryShardStorage MSS(Storage, CacheHits);

  tooling::CompileCommand Cmd;
  Cmd.Filename = testPath("root/A.cc");
  Cmd.Directory = testPath("root");
  Cmd.CommandLine = {"clang++", testPath("root/A.cc")};
  // Check nothing is loaded from Storage, but A.cc and A.h has been stored.
  {
    OverlayCDB CDB(/*Base=*/nullptr);
    BackgroundIndex Idx(Context::empty(), FS, CDB,
                        [&](llvm::StringRef) { return &MSS; });
    CDB.setCompileCommand(testPath("root/A.cc"), Cmd);
    ASSERT_TRUE(Idx.blockUntilIdleForTest());
  }

  // Change header.
  FS.Files[testPath("root/A.h")] = R"cpp(
      void common();
      void f_b();
      class A_CC {};
      class A_CCnew {};
      )cpp";
  {
    OverlayCDB CDB(/*Base=*/nullptr);
    BackgroundIndex Idx(Context::empty(), FS, CDB,
                        [&](llvm::StringRef) { return &MSS; });
    CDB.setCompileCommand(testPath("root"), Cmd);
    ASSERT_TRUE(Idx.blockUntilIdleForTest());
  }
  EXPECT_EQ(CacheHits, 2U); // Check both A.cc and A.h loaded from cache.

  // Check if the new symbol has arrived.
  auto ShardHeader = MSS.loadShard(testPath("root/A.h"));
  EXPECT_NE(ShardHeader, nullptr);
  EXPECT_THAT(*ShardHeader->Symbols, Contains(Named("A_CCnew")));

  // Change source.
  FS.Files[testPath("root/A.cc")] =
      "#include \"A.h\"\nvoid g() { (void)common; }\nvoid f_b() {}";
  {
    CacheHits = 0;
    OverlayCDB CDB(/*Base=*/nullptr);
    BackgroundIndex Idx(Context::empty(), FS, CDB,
                        [&](llvm::StringRef) { return &MSS; });
    CDB.setCompileCommand(testPath("root"), Cmd);
    ASSERT_TRUE(Idx.blockUntilIdleForTest());
  }
  EXPECT_EQ(CacheHits, 2U); // Check both A.cc and A.h loaded from cache.

  // Check if the new symbol has arrived.
  ShardHeader = MSS.loadShard(testPath("root/A.h"));
  EXPECT_NE(ShardHeader, nullptr);
  EXPECT_THAT(*ShardHeader->Symbols, Contains(Named("A_CCnew")));
  auto ShardSource = MSS.loadShard(testPath("root/A.cc"));
  EXPECT_NE(ShardSource, nullptr);
  EXPECT_THAT(*ShardSource->Symbols,
              Contains(AllOf(Named("f_b"), Declared(), Defined())));
}

TEST_F(BackgroundIndexTest, ShardStorageEmptyFile) {
  MockFSProvider FS;
  FS.Files[testPath("root/A.h")] = R"cpp(
      void common();
      void f_b();
      class A_CC {};
      )cpp";
  FS.Files[testPath("root/B.h")] = R"cpp(
      #include "A.h"
      )cpp";
  FS.Files[testPath("root/A.cc")] =
      "#include \"B.h\"\nvoid g() { (void)common; }";

  llvm::StringMap<std::string> Storage;
  size_t CacheHits = 0;
  MemoryShardStorage MSS(Storage, CacheHits);

  tooling::CompileCommand Cmd;
  Cmd.Filename = testPath("root/A.cc");
  Cmd.Directory = testPath("root");
  Cmd.CommandLine = {"clang++", testPath("root/A.cc")};
  // Check that A.cc, A.h and B.h has been stored.
  {
    OverlayCDB CDB(/*Base=*/nullptr);
    BackgroundIndex Idx(Context::empty(), FS, CDB,
                        [&](llvm::StringRef) { return &MSS; });
    CDB.setCompileCommand(testPath("root/A.cc"), Cmd);
    ASSERT_TRUE(Idx.blockUntilIdleForTest());
  }
  EXPECT_THAT(Storage.keys(),
              UnorderedElementsAre(testPath("root/A.cc"), testPath("root/A.h"),
                                   testPath("root/B.h")));
  auto ShardHeader = MSS.loadShard(testPath("root/B.h"));
  EXPECT_NE(ShardHeader, nullptr);
  EXPECT_TRUE(ShardHeader->Symbols->empty());

  // Check that A.cc, A.h and B.h has been loaded.
  {
    CacheHits = 0;
    OverlayCDB CDB(/*Base=*/nullptr);
    BackgroundIndex Idx(Context::empty(), FS, CDB,
                        [&](llvm::StringRef) { return &MSS; });
    CDB.setCompileCommand(testPath("root/A.cc"), Cmd);
    ASSERT_TRUE(Idx.blockUntilIdleForTest());
  }
  EXPECT_EQ(CacheHits, 3U);

  // Update B.h to contain some symbols.
  FS.Files[testPath("root/B.h")] = R"cpp(
      #include "A.h"
      void new_func();
      )cpp";
  // Check that B.h has been stored with new contents.
  {
    CacheHits = 0;
    OverlayCDB CDB(/*Base=*/nullptr);
    BackgroundIndex Idx(Context::empty(), FS, CDB,
                        [&](llvm::StringRef) { return &MSS; });
    CDB.setCompileCommand(testPath("root/A.cc"), Cmd);
    ASSERT_TRUE(Idx.blockUntilIdleForTest());
  }
  EXPECT_EQ(CacheHits, 3U);
  ShardHeader = MSS.loadShard(testPath("root/B.h"));
  EXPECT_NE(ShardHeader, nullptr);
  EXPECT_THAT(*ShardHeader->Symbols,
              Contains(AllOf(Named("new_func"), Declared(), Not(Defined()))));
}

TEST_F(BackgroundIndexTest, NoDotsInAbsPath) {
  MockFSProvider FS;
  llvm::StringMap<std::string> Storage;
  size_t CacheHits = 0;
  MemoryShardStorage MSS(Storage, CacheHits);
  OverlayCDB CDB(/*Base=*/nullptr);
  BackgroundIndex Idx(Context::empty(), FS, CDB,
                      [&](llvm::StringRef) { return &MSS; });

  tooling::CompileCommand Cmd;
  FS.Files[testPath("root/A.cc")] = "";
  Cmd.Filename = "../A.cc";
  Cmd.Directory = testPath("root/build");
  Cmd.CommandLine = {"clang++", "../A.cc"};
  CDB.setCompileCommand(testPath("root/build/../A.cc"), Cmd);

  FS.Files[testPath("root/B.cc")] = "";
  Cmd.Filename = "./B.cc";
  Cmd.Directory = testPath("root");
  Cmd.CommandLine = {"clang++", "./B.cc"};
  CDB.setCompileCommand(testPath("root/./B.cc"), Cmd);

  ASSERT_TRUE(Idx.blockUntilIdleForTest());
  for (llvm::StringRef AbsPath : MSS.AccessedPaths.keys()) {
    EXPECT_FALSE(AbsPath.contains("./")) << AbsPath;
    EXPECT_FALSE(AbsPath.contains("../")) << AbsPath;
  }
}

TEST_F(BackgroundIndexTest, UncompilableFiles) {
  MockFSProvider FS;
  llvm::StringMap<std::string> Storage;
  size_t CacheHits = 0;
  MemoryShardStorage MSS(Storage, CacheHits);
  OverlayCDB CDB(/*Base=*/nullptr);
  BackgroundIndex Idx(Context::empty(), FS, CDB,
                      [&](llvm::StringRef) { return &MSS; });

  tooling::CompileCommand Cmd;
  FS.Files[testPath("A.h")] = "void foo();";
  FS.Files[testPath("B.h")] = "#include \"C.h\"\nasdf;";
  FS.Files[testPath("C.h")] = "";
  FS.Files[testPath("A.cc")] = R"cpp(
  #include "A.h"
  #include "B.h"
  #include "not_found_header.h"

  void foo() {}
  )cpp";
  Cmd.Filename = "../A.cc";
  Cmd.Directory = testPath("build");
  Cmd.CommandLine = {"clang++", "../A.cc"};
  CDB.setCompileCommand(testPath("build/../A.cc"), Cmd);
  ASSERT_TRUE(Idx.blockUntilIdleForTest());

  EXPECT_THAT(Storage.keys(), ElementsAre(testPath("A.cc"), testPath("A.h"),
                                          testPath("B.h"), testPath("C.h")));

  {
    auto Shard = MSS.loadShard(testPath("A.cc"));
    EXPECT_THAT(*Shard->Symbols, UnorderedElementsAre(Named("foo")));
    EXPECT_THAT(Shard->Sources->keys(),
                UnorderedElementsAre("unittest:///A.cc", "unittest:///A.h",
                                     "unittest:///B.h"));
    EXPECT_THAT(Shard->Sources->lookup("unittest:///A.cc"), HadErrors());
  }

  {
    auto Shard = MSS.loadShard(testPath("A.h"));
    EXPECT_THAT(*Shard->Symbols, UnorderedElementsAre(Named("foo")));
    EXPECT_THAT(Shard->Sources->keys(),
                UnorderedElementsAre("unittest:///A.h"));
    EXPECT_THAT(Shard->Sources->lookup("unittest:///A.h"), HadErrors());
  }

  {
    auto Shard = MSS.loadShard(testPath("B.h"));
    EXPECT_THAT(*Shard->Symbols, UnorderedElementsAre(Named("asdf")));
    EXPECT_THAT(Shard->Sources->keys(),
                UnorderedElementsAre("unittest:///B.h", "unittest:///C.h"));
    EXPECT_THAT(Shard->Sources->lookup("unittest:///B.h"), HadErrors());
  }

  {
    auto Shard = MSS.loadShard(testPath("C.h"));
    EXPECT_THAT(*Shard->Symbols, UnorderedElementsAre());
    EXPECT_THAT(Shard->Sources->keys(),
                UnorderedElementsAre("unittest:///C.h"));
    EXPECT_THAT(Shard->Sources->lookup("unittest:///C.h"), HadErrors());
  }
}

TEST_F(BackgroundIndexTest, CmdLineHash) {
  MockFSProvider FS;
  llvm::StringMap<std::string> Storage;
  size_t CacheHits = 0;
  MemoryShardStorage MSS(Storage, CacheHits);
  OverlayCDB CDB(/*Base=*/nullptr, /*FallbackFlags=*/{},
                 /*ResourceDir=*/std::string(""));
  BackgroundIndex Idx(Context::empty(), FS, CDB,
                      [&](llvm::StringRef) { return &MSS; });

  tooling::CompileCommand Cmd;
  FS.Files[testPath("A.cc")] = "#include \"A.h\"";
  FS.Files[testPath("A.h")] = "";
  Cmd.Filename = "../A.cc";
  Cmd.Directory = testPath("build");
  Cmd.CommandLine = {"clang++", "../A.cc", "-fsyntax-only"};
  CDB.setCompileCommand(testPath("build/../A.cc"), Cmd);
  ASSERT_TRUE(Idx.blockUntilIdleForTest());

  EXPECT_THAT(Storage.keys(), ElementsAre(testPath("A.cc"), testPath("A.h")));
  // Make sure we only store the Cmd for main file.
  EXPECT_FALSE(MSS.loadShard(testPath("A.h"))->Cmd);

  {
    tooling::CompileCommand CmdStored = *MSS.loadShard(testPath("A.cc"))->Cmd;
    EXPECT_EQ(CmdStored.CommandLine, Cmd.CommandLine);
    EXPECT_EQ(CmdStored.Directory, Cmd.Directory);
  }

  // FIXME: Changing compile commands should be enough to invalidate the cache.
  FS.Files[testPath("A.cc")] = " ";
  Cmd.CommandLine = {"clang++", "../A.cc", "-Dfoo", "-fsyntax-only"};
  CDB.setCompileCommand(testPath("build/../A.cc"), Cmd);
  ASSERT_TRUE(Idx.blockUntilIdleForTest());

  EXPECT_FALSE(MSS.loadShard(testPath("A.h"))->Cmd);

  {
    tooling::CompileCommand CmdStored = *MSS.loadShard(testPath("A.cc"))->Cmd;
    EXPECT_EQ(CmdStored.CommandLine, Cmd.CommandLine);
    EXPECT_EQ(CmdStored.Directory, Cmd.Directory);
  }
}

} // namespace clangd
} // namespace clang
