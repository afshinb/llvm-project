//===- DWARF.cpp ----------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// The -gdb-index option instructs the linker to emit a .gdb_index section.
// The section contains information to make gdb startup faster.
// The format of the section is described at
// https://sourceware.org/gdb/onlinedocs/gdb/Index-Section-Format.html.
//
//===----------------------------------------------------------------------===//

#include "DWARF.h"
#include "Symbols.h"
#include "Target.h"
#include "lld/Common/Memory.h"
#include "llvm/DebugInfo/DWARF/DWARFDebugPubTable.h"
#include "llvm/Object/ELFObjectFile.h"

using namespace llvm;
using namespace llvm::object;
using namespace lld;
using namespace lld::elf;

template <class ELFT> LLDDwarfObj<ELFT>::LLDDwarfObj(ObjFile<ELFT> *Obj) {
  for (InputSectionBase *Sec : Obj->getSections()) {
    if (!Sec)
      continue;

    if (LLDDWARFSection *M =
            StringSwitch<LLDDWARFSection *>(Sec->Name)
                .Case(".debug_addr", &AddrSection)
                .Case(".debug_gnu_pubnames", &GnuPubNamesSection)
                .Case(".debug_gnu_pubtypes", &GnuPubTypesSection)
                .Case(".debug_info", &InfoSection)
                .Case(".debug_ranges", &RangeSection)
                .Case(".debug_rnglists", &RngListsSection)
                .Case(".debug_line", &LineSection)
                .Default(nullptr)) {
      M->Data = toStringRef(Sec->data());
      M->Sec = Sec;
      continue;
    }

    if (Sec->Name == ".debug_abbrev")
      AbbrevSection = toStringRef(Sec->data());
    else if (Sec->Name == ".debug_str")
      StrSection = toStringRef(Sec->data());
    else if (Sec->Name == ".debug_line_str")
      LineStringSection = toStringRef(Sec->data());
  }
}

namespace {
template <class RelTy> struct LLDRelocationResolver {
  // In the ELF ABIs, S sepresents the value of the symbol in the relocation
  // entry. For Rela, the addend is stored as part of the relocation entry.
  static uint64_t resolve(object::RelocationRef Ref, uint64_t S,
                          uint64_t /* A */) {
    return S + Ref.getRawDataRefImpl().p;
  }
};

template <class ELFT> struct LLDRelocationResolver<Elf_Rel_Impl<ELFT, false>> {
  // For Rel, the addend A is supplied by the caller.
  static uint64_t resolve(object::RelocationRef /*Ref*/, uint64_t S,
                          uint64_t A) {
    return S + A;
  }
};
} // namespace

// Find if there is a relocation at Pos in Sec.  The code is a bit
// more complicated than usual because we need to pass a section index
// to llvm since it has no idea about InputSection.
template <class ELFT>
template <class RelTy>
Optional<RelocAddrEntry>
LLDDwarfObj<ELFT>::findAux(const InputSectionBase &Sec, uint64_t Pos,
                           ArrayRef<RelTy> Rels) const {
  auto It =
      partition_point(Rels, [=](const RelTy &A) { return A.r_offset < Pos; });
  if (It == Rels.end() || It->r_offset != Pos)
    return None;
  const RelTy &Rel = *It;

  const ObjFile<ELFT> *File = Sec.getFile<ELFT>();
  uint32_t SymIndex = Rel.getSymbol(Config->IsMips64EL);
  const typename ELFT::Sym &Sym = File->template getELFSyms<ELFT>()[SymIndex];
  uint32_t SecIndex = File->getSectionIndex(Sym);

  // An undefined symbol may be a symbol defined in a discarded section. We
  // shall still resolve it. This is important for --gdb-index: the end address
  // offset of an entry in .debug_ranges is relocated. If it is not resolved,
  // its zero value will terminate the decoding of .debug_ranges prematurely.
  Symbol &S = File->getRelocTargetSym(Rel);
  uint64_t Val = 0;
  if (auto *DR = dyn_cast<Defined>(&S)) {
    Val = DR->Value;

    // FIXME: We should be consistent about always adding the file
    // offset or not.
    if (DR->Section->Flags & ELF::SHF_ALLOC)
      Val += cast<InputSection>(DR->Section)->getOffsetInFile();
  }

  DataRefImpl D;
  D.p = getAddend<ELFT>(Rel);
  return RelocAddrEntry{SecIndex, RelocationRef(D, nullptr),
                        LLDRelocationResolver<RelTy>::resolve, Val};
}

template <class ELFT>
Optional<RelocAddrEntry> LLDDwarfObj<ELFT>::find(const llvm::DWARFSection &S,
                                                 uint64_t Pos) const {
  auto &Sec = static_cast<const LLDDWARFSection &>(S);
  if (Sec.Sec->AreRelocsRela)
    return findAux(*Sec.Sec, Pos, Sec.Sec->template relas<ELFT>());
  return findAux(*Sec.Sec, Pos, Sec.Sec->template rels<ELFT>());
}

template class elf::LLDDwarfObj<ELF32LE>;
template class elf::LLDDwarfObj<ELF32BE>;
template class elf::LLDDwarfObj<ELF64LE>;
template class elf::LLDDwarfObj<ELF64BE>;
