//===--- Headers.cpp - Include headers ---------------------------*- C++-*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Headers.h"
#include "Compiler.h"
#include "Logger.h"
#include "SourceCode.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/CompilerInvocation.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Lex/HeaderSearch.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Path.h"

namespace clang {
namespace clangd {
namespace {

class RecordHeaders : public PPCallbacks {
public:
  RecordHeaders(const SourceManager &SM, IncludeStructure *Out)
      : SM(SM), Out(Out) {}

  // Record existing #includes - both written and resolved paths. Only #includes
  // in the main file are collected.
  void InclusionDirective(SourceLocation HashLoc, const Token & /*IncludeTok*/,
                          llvm::StringRef FileName, bool IsAngled,
                          CharSourceRange FilenameRange, const FileEntry *File,
                          llvm::StringRef /*SearchPath*/,
                          llvm::StringRef /*RelativePath*/,
                          const Module * /*Imported*/,
                          SrcMgr::CharacteristicKind FileKind) override {
    if (SM.isWrittenInMainFile(HashLoc)) {
      Out->MainFileIncludes.emplace_back();
      auto &Inc = Out->MainFileIncludes.back();
      Inc.R = halfOpenToRange(SM, FilenameRange);
      Inc.Written =
          (IsAngled ? "<" + FileName + ">" : "\"" + FileName + "\"").str();
      Inc.Resolved = File ? File->tryGetRealPathName() : "";
      Inc.HashOffset = SM.getFileOffset(HashLoc);
      Inc.FileKind = FileKind;
    }
    if (File) {
      auto *IncludingFileEntry = SM.getFileEntryForID(SM.getFileID(HashLoc));
      if (!IncludingFileEntry) {
        assert(SM.getBufferName(HashLoc).startswith("<") &&
               "Expected #include location to be a file or <built-in>");
        // Treat as if included from the main file.
        IncludingFileEntry = SM.getFileEntryForID(SM.getMainFileID());
      }
      Out->recordInclude(IncludingFileEntry->getName(), File->getName(),
                         File->tryGetRealPathName());
    }
  }

private:
  const SourceManager &SM;
  IncludeStructure *Out;
};

} // namespace

bool isLiteralInclude(llvm::StringRef Include) {
  return Include.startswith("<") || Include.startswith("\"");
}

bool HeaderFile::valid() const {
  return (Verbatim && isLiteralInclude(File)) ||
         (!Verbatim && llvm::sys::path::is_absolute(File));
}

llvm::Expected<HeaderFile> toHeaderFile(llvm::StringRef Header,
                                        llvm::StringRef HintPath) {
  if (isLiteralInclude(Header))
    return HeaderFile{Header.str(), /*Verbatim=*/true};
  auto U = URI::parse(Header);
  if (!U)
    return U.takeError();

  auto IncludePath = URI::includeSpelling(*U);
  if (!IncludePath)
    return IncludePath.takeError();
  if (!IncludePath->empty())
    return HeaderFile{std::move(*IncludePath), /*Verbatim=*/true};

  auto Resolved = URI::resolve(*U, HintPath);
  if (!Resolved)
    return Resolved.takeError();
  return HeaderFile{std::move(*Resolved), /*Verbatim=*/false};
}

llvm::SmallVector<llvm::StringRef, 1> getRankedIncludes(const Symbol &Sym) {
  auto Includes = Sym.IncludeHeaders;
  // Sort in descending order by reference count and header length.
  llvm::sort(Includes, [](const Symbol::IncludeHeaderWithReferences &LHS,
                          const Symbol::IncludeHeaderWithReferences &RHS) {
    if (LHS.References == RHS.References)
      return LHS.IncludeHeader.size() < RHS.IncludeHeader.size();
    return LHS.References > RHS.References;
  });
  llvm::SmallVector<llvm::StringRef, 1> Headers;
  for (const auto &Include : Includes)
    Headers.push_back(Include.IncludeHeader);
  return Headers;
}

std::unique_ptr<PPCallbacks>
collectIncludeStructureCallback(const SourceManager &SM,
                                IncludeStructure *Out) {
  return llvm::make_unique<RecordHeaders>(SM, Out);
}

void IncludeStructure::recordInclude(llvm::StringRef IncludingName,
                                     llvm::StringRef IncludedName,
                                     llvm::StringRef IncludedRealName) {
  auto Child = fileIndex(IncludedName);
  if (!IncludedRealName.empty() && RealPathNames[Child].empty())
    RealPathNames[Child] = IncludedRealName;
  auto Parent = fileIndex(IncludingName);
  IncludeChildren[Parent].push_back(Child);
}

unsigned IncludeStructure::fileIndex(llvm::StringRef Name) {
  auto R = NameToIndex.try_emplace(Name, RealPathNames.size());
  if (R.second)
    RealPathNames.emplace_back();
  return R.first->getValue();
}

llvm::StringMap<unsigned>
IncludeStructure::includeDepth(llvm::StringRef Root) const {
  // Include depth 0 is the main file only.
  llvm::StringMap<unsigned> Result;
  Result[Root] = 0;
  std::vector<unsigned> CurrentLevel;
  llvm::DenseSet<unsigned> Seen;
  auto It = NameToIndex.find(Root);
  if (It != NameToIndex.end()) {
    CurrentLevel.push_back(It->second);
    Seen.insert(It->second);
  }

  // Each round of BFS traversal finds the next depth level.
  std::vector<unsigned> PreviousLevel;
  for (unsigned Level = 1; !CurrentLevel.empty(); ++Level) {
    PreviousLevel.clear();
    PreviousLevel.swap(CurrentLevel);
    for (const auto &Parent : PreviousLevel) {
      for (const auto &Child : IncludeChildren.lookup(Parent)) {
        if (Seen.insert(Child).second) {
          CurrentLevel.push_back(Child);
          const auto &Name = RealPathNames[Child];
          // Can't include files if we don't have their real path.
          if (!Name.empty())
            Result[Name] = Level;
        }
      }
    }
  }
  return Result;
}

void IncludeInserter::addExisting(const Inclusion &Inc) {
  IncludedHeaders.insert(Inc.Written);
  if (!Inc.Resolved.empty())
    IncludedHeaders.insert(Inc.Resolved);
}

/// FIXME(ioeric): we might not want to insert an absolute include path if the
/// path is not shortened.
bool IncludeInserter::shouldInsertInclude(
    PathRef DeclaringHeader, const HeaderFile &InsertedHeader) const {
  assert(InsertedHeader.valid());
  if (!HeaderSearchInfo && !InsertedHeader.Verbatim)
    return false;
  if (FileName == DeclaringHeader || FileName == InsertedHeader.File)
    return false;
  auto Included = [&](llvm::StringRef Header) {
    return IncludedHeaders.find(Header) != IncludedHeaders.end();
  };
  return !Included(DeclaringHeader) && !Included(InsertedHeader.File);
}

std::string
IncludeInserter::calculateIncludePath(const HeaderFile &InsertedHeader,
                                      llvm::StringRef IncludingFile) const {
  assert(InsertedHeader.valid());
  if (InsertedHeader.Verbatim)
    return InsertedHeader.File;
  bool IsSystem = false;
  // FIXME(kadircet): Handle same directory includes even if there is no
  // HeaderSearchInfo.
  if (!HeaderSearchInfo)
    return "\"" + InsertedHeader.File + "\"";
  std::string Suggested = HeaderSearchInfo->suggestPathToFileForDiagnostics(
      InsertedHeader.File, BuildDir, IncludingFile, &IsSystem);
  if (IsSystem)
    Suggested = "<" + Suggested + ">";
  else
    Suggested = "\"" + Suggested + "\"";
  return Suggested;
}

llvm::Optional<TextEdit>
IncludeInserter::insert(llvm::StringRef VerbatimHeader) const {
  llvm::Optional<TextEdit> Edit = None;
  if (auto Insertion = Inserter.insert(VerbatimHeader.trim("\"<>"),
                                       VerbatimHeader.startswith("<")))
    Edit = replacementToEdit(Code, *Insertion);
  return Edit;
}

llvm::raw_ostream &operator<<(llvm::raw_ostream &OS, const Inclusion &Inc) {
  return OS << Inc.Written << " = "
            << (Inc.Resolved.empty() ? Inc.Resolved : "[unresolved]") << " at "
            << Inc.R;
}

} // namespace clangd
} // namespace clang
