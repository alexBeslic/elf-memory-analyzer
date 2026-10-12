"""Plain data model shared by all analysis modules (no Qt, no I/O)."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHF_TLS = 0x400

CAT_CODE = "code"
CAT_RODATA = "rodata"
CAT_DATA = "data"
CAT_BSS = "bss"
CAT_OTHER_ALLOC = "other_alloc"
CAT_DEBUG = "debug"
CAT_NON_ALLOC = "non_alloc"

CATEGORY_LABELS = {
    CAT_CODE: "Executable code (flag-based)",
    CAT_RODATA: "Read-only data (flag-based)",
    CAT_DATA: "Initialized writable data",
    CAT_BSS: "Zero-initialized (NOBITS)",
    CAT_OTHER_ALLOC: "Other allocated sections",
    CAT_DEBUG: "Debug information (not allocated)",
    CAT_NON_ALLOC: "Other non-allocated (symtab, strtab, ...)",
}


class SymKind(str, Enum):
    FUNCTION = "function"
    DATA = "data"
    OTHER = "other"


@dataclass
class SectionInfo:
    index: int
    name: str
    type: str
    flags: int
    addr: int
    offset: int
    size: int
    align: int = 0
    category: str = CAT_NON_ALLOC
    lma: Optional[int] = None
    region: Optional[str] = None
    lma_region: Optional[str] = None

    @property
    def alloc(self) -> bool:
        return bool(self.flags & SHF_ALLOC)

    @property
    def writable(self) -> bool:
        return bool(self.flags & SHF_WRITE)

    @property
    def executable(self) -> bool:
        return bool(self.flags & SHF_EXECINSTR)

    @property
    def tls(self) -> bool:
        return bool(self.flags & SHF_TLS)

    @property
    def nobits(self) -> bool:
        return self.type == "SHT_NOBITS"

    @property
    def end(self) -> int:
        return self.addr + self.size

    @property
    def flags_str(self) -> str:
        s = ""
        s += "W" if self.writable else ""
        s += "A" if self.alloc else ""
        s += "X" if self.executable else ""
        s += "T" if self.tls else ""
        return s


@dataclass
class SegmentInfo:
    index: int
    type: str
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    flags: int
    align: int = 0

    @property
    def flags_str(self) -> str:
        return ("R" if self.flags & 4 else "-") + ("W" if self.flags & 2 else "-") + ("X" if self.flags & 1 else "-")


@dataclass(slots=True)
class Symbol:
    """One ELF symbol with derived information.

    ``kind``/``category``/``data_class`` come from ELF metadata only (symbol type
    and containing-section flags). Source-level info (``source_file``) is only
    set when DWARF confirms it.
    """
    id: int
    name: str
    address: int
    size: int
    sym_type: str
    bind: str
    visibility: str
    section: Optional[str]
    kind: SymKind
    category: str = ""
    data_class: str = ""
    is_thumb: bool = False
    demangled: Optional[str] = None
    file_hint: Optional[str] = None  # from preceding STT_FILE (local symbols only)
    region: Optional[str] = None
    source_file: Optional[str] = None
    source_line: Optional[int] = None
    stack_bytes: Optional[int] = None
    stack_kind: Optional[str] = None  # static | dynamic | dynamic_bounded
    stack_confidence: str = "unavailable"  # exact | approximate | ambiguous | unavailable
    stack_source: Optional[str] = None
    stack_note: str = ""
    alias_of: Optional[int] = None
    shndx: int = -1
    notes: list[str] = field(default_factory=list)
    search_blob: str = ""

    @property
    def end(self) -> int:
        return self.address + self.size

    @property
    def display_name(self) -> str:
        return self.demangled or self.name


@dataclass
class ElfModel:
    path: str
    file_size: int
    elf_class: int
    endianness: str
    machine: str
    machine_desc: str
    elf_type: str
    entry: int
    os_abi: str
    flags: int
    sections: list[SectionInfo]
    segments: list[SegmentInfo]
    symbols: list[Symbol]
    has_symtab: bool = False
    has_dynsym: bool = False
    has_section_headers: bool = True
    debug_sections: list[str] = field(default_factory=list)
    undefined_symbol_count: int = 0
    warnings: list[str] = field(default_factory=list)

    @property
    def has_debug_info(self) -> bool:
        return ".debug_info" in self.debug_sections or ".zdebug_info" in self.debug_sections

    @property
    def has_debug_line(self) -> bool:
        return ".debug_line" in self.debug_sections or ".zdebug_line" in self.debug_sections

    @property
    def stripped(self) -> bool:
        return not self.has_symtab

    def section_by_name(self, name: str) -> Optional[SectionInfo]:
        for s in self.sections:
            if s.name == name:
                return s
        return None
