"""ELF metadata, section, segment and symbol extraction (built on pyelftools)."""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Callable, Optional

from elftools.common.exceptions import ELFError
from elftools.elf.descriptions import describe_e_machine, describe_e_type, describe_ei_osabi
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from .models import ElfModel, SectionInfo, SegmentInfo, Symbol, SymKind
from .symbol_classifier import categorize_section, classify_symbol

log = logging.getLogger(__name__)
Progress = Optional[Callable[[str], None]]


class ElfLoadError(Exception):
    """Raised when a file cannot be parsed as an ELF."""


def load_elf(path: str | os.PathLike, progress: Progress = None) -> ElfModel:
    """Parse ``path`` into an :class:`ElfModel`. The file is treated as untrusted data."""
    p = Path(path)
    try:
        file_size = p.stat().st_size
        fh = open(p, "rb")
    except OSError as exc:
        raise ElfLoadError(f"Cannot open {p}: {exc}") from exc
    with fh:
        if fh.read(4) != b"\x7fELF":
            raise ElfLoadError(f"{p.name} is not an ELF file (bad magic number).")
        fh.seek(0)
        try:
            return _parse(ELFFile(fh), str(p), file_size, progress)
        except ElfLoadError:
            raise
        except (ELFError, ValueError, KeyError, EOFError, OverflowError, MemoryError) as exc:
            raise ElfLoadError(f"Malformed ELF file: {exc}") from exc
        except Exception as exc:  # pyelftools/struct can raise assorted errors on bad input
            log.exception("Unexpected parser failure")
            raise ElfLoadError(f"Failed to parse ELF ({type(exc).__name__}: {exc})") from exc


def _parse(elf: ELFFile, path: str, file_size: int, progress: Progress) -> ElfModel:
    say = progress or (lambda _m: None)
    warnings: list[str] = []
    say("Reading headers and sections...")
    sections: list[SectionInfo] = []
    for i, s in enumerate(elf.iter_sections()):
        flags = int(s["sh_flags"])
        stype = str(s["sh_type"])
        sections.append(SectionInfo(i, s.name, stype, flags, int(s["sh_addr"]), int(s["sh_offset"]),
                                    int(s["sh_size"]), int(s["sh_addralign"]),
                                    categorize_section(s.name, stype, flags)))
    segments = [SegmentInfo(i, str(g["p_type"]), int(g["p_offset"]), int(g["p_vaddr"]), int(g["p_paddr"]),
                            int(g["p_filesz"]), int(g["p_memsz"]), int(g["p_flags"]), int(g["p_align"]))
                for i, g in enumerate(elf.iter_segments())]
    has_sh = len(sections) > 1
    if not has_sh:
        warnings.append("No section headers: section-level analysis, symbols and debug info are unavailable.")
    _compute_lma(sections, segments)

    debug_sections = [s.name for s in sections if s.category == "debug"]
    model = ElfModel(
        path=path, file_size=file_size, elf_class=elf.elfclass,
        endianness="little" if elf.little_endian else "big",
        machine=str(elf["e_machine"]), machine_desc=describe_e_machine(elf["e_machine"]),
        elf_type=describe_e_type(elf["e_type"], elf), entry=int(elf["e_entry"]),
        os_abi=describe_ei_osabi(elf["e_ident"]["EI_OSABI"]), flags=int(elf["e_flags"]),
        sections=sections, segments=segments, symbols=[], has_section_headers=has_sh,
        debug_sections=debug_sections, warnings=warnings)
    if str(elf["e_type"]) == "ET_REL":
        warnings.append("Relocatable object (ET_REL): addresses are section-relative, not final run-time addresses.")

    say("Reading symbol table...")
    symtab = elf.get_section_by_name(".symtab")
    dynsym = elf.get_section_by_name(".dynsym")
    model.has_symtab = isinstance(symtab, SymbolTableSection)
    model.has_dynsym = isinstance(dynsym, SymbolTableSection)
    table = symtab if model.has_symtab else (dynsym if model.has_dynsym else None)
    if table is None:
        warnings.append("No symbol table (.symtab) found: the ELF appears stripped. "
                        "Function and variable analysis is unavailable.")
    else:
        if not model.has_symtab:
            warnings.append("No .symtab (ELF appears stripped); only .dynsym is present, so local (static) "
                            "symbols and most internal functions are missing.")
        _read_symbols(model, table)
    if has_sh and not model.has_debug_info:
        warnings.append("No DWARF debug information: source file/line and source-level variable info are unavailable.")
    if model.has_symtab and not model.symbols:
        warnings.append("Symbol table is present but contains no usable defined symbols.")
    return model


def _compute_lma(sections: list[SectionInfo], segments: list[SegmentInfo]) -> None:
    """Derive each allocated section's load address from PT_LOAD segments (file-offset based)."""
    loads = [g for g in segments if g.type == "PT_LOAD" and g.filesz > 0]
    for s in sections:
        if not s.alloc or s.nobits or s.size == 0:
            continue
        for g in loads:
            if g.offset <= s.offset and s.offset + s.size <= g.offset + g.filesz:
                s.lma = g.paddr + (s.offset - g.offset)
                break


def _read_symbols(model: ElfModel, table) -> None:
    secs = model.sections
    current_file: Optional[str] = None
    is_arm = model.machine == "EM_ARM"
    syms: list[Symbol] = []
    for idx, raw in enumerate(table.iter_symbols()):
        if idx == 0:
            continue
        info = raw["st_info"]
        stype = str(info["type"]).removeprefix("STT_")
        bind = str(info["bind"]).removeprefix("STB_")
        shndx = raw["st_shndx"]
        name = raw.name
        if stype == "FILE":
            current_file = name or None
            continue
        if stype == "SECTION":
            continue
        if shndx == "SHN_UNDEF":
            model.undefined_symbol_count += 1
            continue
        if not name:
            continue
        section = secs[shndx] if isinstance(shndx, int) and 0 <= shndx < len(secs) else None
        addr = int(raw["st_value"])
        size = int(raw["st_size"])
        thumb = False
        if is_arm and stype in ("FUNC", "GNU_IFUNC") and addr & 1:
            thumb, addr = True, addr & ~1
        cls = classify_symbol(stype, size, shndx, section)
        sym = Symbol(id=len(syms), name=name, address=addr, size=size, sym_type=stype, bind=bind,
                     visibility=str(raw["st_other"]["visibility"]).removeprefix("STV_"),
                     section=section.name if section else (str(shndx) if isinstance(shndx, str) else None),
                     kind=cls.kind, category=section.category if section else "",
                     data_class=cls.data_class, is_thumb=thumb,
                     file_hint=current_file if bind == "LOCAL" else None, notes=cls.notes)
        syms.append(sym)
    model.symbols = syms
    _mark_aliases(syms)


def _mark_aliases(syms: list[Symbol]) -> None:
    """Flag symbols that share address+kind with a preferred symbol (aliases)."""
    groups: dict[tuple[int, str], list[Symbol]] = {}
    for s in syms:
        if s.kind in (SymKind.FUNCTION, SymKind.DATA) and s.size > 0:
            groups.setdefault((s.address, s.kind.value), []).append(s)
    rank = {"GLOBAL": 0, "GNU_UNIQUE": 0, "WEAK": 2, "LOCAL": 1}
    for g in groups.values():
        if len(g) < 2:
            continue
        g.sort(key=lambda s: (rank.get(s.bind, 3), s.id))
        primary = g[0]
        for s in g[1:]:
            s.alias_of = primary.id
            s.notes.append(f"alias of {primary.name} (same address)")


def demangle_names(names: list[str], cxxfilt: Optional[str], timeout: float = 60.0) -> dict[str, str]:
    """Demangle Itanium-mangled names through ``c++filt`` (batched, no shell)."""
    todo = sorted({n for n in names if n.startswith("_Z")})
    if not todo or not cxxfilt:
        return {}
    exe = shutil.which(cxxfilt) or cxxfilt
    try:
        proc = subprocess.run([exe], input="\n".join(todo) + "\n", capture_output=True, text=True,
                              timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("Demangling failed: %s", exc)
        return {}
    out = proc.stdout.splitlines()
    if len(out) != len(todo):
        log.warning("Demangler output mismatch (%d != %d)", len(out), len(todo))
        return {}
    return {a: b for a, b in zip(todo, out) if a != b}


_SYM_SUFFIX = re.compile(r"\.(constprop|isra|part|cold|lto_priv|localalias|ltrans)\.?\d*$")


def strip_clone_suffix(name: str) -> str:
    """Remove GCC clone suffixes such as ``.constprop.0`` / ``.isra.1`` / ``.part.2``."""
    prev = None
    while prev != name:
        prev, name = name, _SYM_SUFFIX.sub("", name)
    return name
