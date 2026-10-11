"""Classification of sections and symbols from ELF metadata only.

Rules are intentionally conservative: a symbol is only called a function/data
object when its ELF symbol *type* says so. Untyped symbols are classified by
section only as a hint and labelled as such.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import (CAT_BSS, CAT_CODE, CAT_DATA, CAT_DEBUG, CAT_NON_ALLOC, CAT_OTHER_ALLOC,
                     CAT_RODATA, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SectionInfo, SymKind)

_DATA_LIKE_TYPES = {"SHT_PROGBITS", "SHT_INIT_ARRAY", "SHT_FINI_ARRAY", "SHT_PREINIT_ARRAY"}


def categorize_section(name: str, sh_type: str, flags: int) -> str:
    """Return the memory category of a section based on type/flags (not on its name)."""
    if not flags & SHF_ALLOC:
        if name.startswith((".debug", ".zdebug", ".stab", ".gnu_debug")):
            return CAT_DEBUG
        return CAT_NON_ALLOC
    if flags & SHF_EXECINSTR:
        return CAT_CODE
    if sh_type == "SHT_NOBITS":
        return CAT_BSS
    if sh_type in _DATA_LIKE_TYPES:
        return CAT_DATA if flags & SHF_WRITE else CAT_RODATA
    return CAT_OTHER_ALLOC


@dataclass
class Classification:
    kind: SymKind
    data_class: str = ""
    notes: list[str] = field(default_factory=list)


def classify_symbol(sym_type: str, size: int, shndx, section: SectionInfo | None) -> Classification:
    """Classify one non-file, non-section, defined ELF symbol."""
    notes: list[str] = []
    if shndx == "SHN_ABS":
        notes.append("absolute symbol (not tied to a section)")
    cat = section.category if section else ""
    if sym_type in ("FUNC", "GNU_IFUNC"):
        if section and cat != CAT_CODE:
            notes.append(f"function symbol in non-executable section {section.name}")
        if size == 0:
            notes.append("zero-sized function symbol (size unknown)")
        if sym_type == "GNU_IFUNC":
            notes.append("GNU indirect function resolver")
        return Classification(SymKind.FUNCTION, "", notes)
    if sym_type in ("OBJECT", "TLS", "COMMON"):
        if section and cat == CAT_CODE:
            notes.append(f"data object in executable section {section.name}")
        return Classification(SymKind.DATA, _data_class(sym_type, shndx, section), notes)
    # STT_NOTYPE and anything exotic: do not over-claim.
    if size > 0 and section and cat in (CAT_DATA, CAT_BSS, CAT_RODATA):
        notes.append("untyped symbol with size; classified as data by section only")
        return Classification(SymKind.DATA, _data_class(sym_type, shndx, section), notes)
    if sym_type == "NOTYPE":
        notes.append("untyped symbol (label / linker-script symbol / assembler symbol)")
    return Classification(SymKind.OTHER, "", notes)


def _data_class(sym_type: str, shndx, section: SectionInfo | None) -> str:
    if shndx == "SHN_COMMON":
        return "common (zero-initialized at link time)"
    if sym_type == "TLS":
        return "thread-local"
    if section is None:
        return "unknown"
    return {CAT_BSS: "zero-initialized", CAT_DATA: "initialized", CAT_RODATA: "read-only",
            CAT_CODE: "in code section"}.get(section.category, "other")
