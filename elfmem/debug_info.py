"""Optional DWARF analysis: function/variable declarations and address->line tables."""
from __future__ import annotations

import logging
import os
from bisect import bisect_left, bisect_right
from dataclasses import dataclass, field
from typing import Callable, Optional

from elftools.elf.elffile import ELFFile

log = logging.getLogger(__name__)


@dataclass
class DeclInfo:
    name: str
    linkage_name: Optional[str]
    file: Optional[str]
    line: Optional[int]
    low_pc: Optional[int] = None
    high_pc: Optional[int] = None


@dataclass
class DebugInfo:
    cu_count: int = 0
    dwarf_versions: set[int] = field(default_factory=set)
    producers: set[str] = field(default_factory=set)
    functions: dict[int, DeclInfo] = field(default_factory=dict)       # low_pc -> decl
    variables: dict[int, list[DeclInfo]] = field(default_factory=dict)  # address -> decls
    warnings: list[str] = field(default_factory=list)
    _rows: list[tuple[int, str, int, bool]] = field(default_factory=list)  # addr,file,line,end_seq
    _addrs: list[int] = field(default_factory=list)

    @property
    def has_lines(self) -> bool:
        return bool(self._rows)

    def finalize(self) -> None:
        self._rows.sort(key=lambda r: (r[0], not r[3]))
        self._addrs = [r[0] for r in self._rows]

    def line_at(self, addr: int) -> Optional[tuple[str, int]]:
        i = bisect_right(self._addrs, addr) - 1
        if i < 0 or self._rows[i][3]:
            return None
        return self._rows[i][1], self._rows[i][2]

    def lines_in_range(self, lo: int, hi: int) -> list[tuple[int, str, int]]:
        """Line-table rows with ``lo <= address < hi`` (statement boundaries only, end markers skipped)."""
        i, j = bisect_left(self._addrs, lo), bisect_left(self._addrs, hi)
        return [(a, f, l) for a, f, l, end in self._rows[i:j] if not end]


def _s(v) -> str:
    return v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v)


def _file_table(lp, comp_dir: str) -> Callable[[int], Optional[str]]:
    version = lp.header["version"]
    entries, dirs = lp["file_entry"], lp["include_directory"]
    cache: dict[int, Optional[str]] = {}

    def resolve(idx: int) -> Optional[str]:
        if idx in cache:
            return cache[idx]
        pos = idx if version >= 5 else idx - 1
        out = None
        if 0 <= pos < len(entries):
            e = entries[pos]
            name = _s(e.name)
            d = ""
            di = e.dir_index
            if version >= 5:
                d = _s(dirs[di]) if 0 <= di < len(dirs) else comp_dir
            elif di > 0 and di - 1 < len(dirs):
                d = _s(dirs[di - 1])
            else:
                d = comp_dir
            if not os.path.isabs(name) and d:
                if not os.path.isabs(d) and comp_dir:
                    d = os.path.join(comp_dir, d)
                name = os.path.join(d, name)
            out = os.path.normpath(name)
        cache[idx] = out
        return out
    return resolve


def _attr(die, name: str):
    a = die.attributes.get(name)
    return a.value if a is not None else None


def _origin_chain(die, depth: int = 4):
    yield die
    for _ in range(depth):
        for key in ("DW_AT_abstract_origin", "DW_AT_specification"):
            if key in die.attributes:
                try:
                    die = die.get_DIE_from_attribute(key)
                except Exception:  # broken reference in DWARF
                    return
                yield die
                break
        else:
            return


def _first(die, name: str):
    for d in _origin_chain(die):
        v = _attr(d, name)
        if v is not None:
            return v
    return None


def load_debug_info(path: str, progress: Optional[Callable[[str], None]] = None) -> DebugInfo:
    """Extract function/variable declaration locations and the line table (best effort)."""
    say = progress or (lambda _m: None)
    info = DebugInfo()
    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        if not elf.has_dwarf_info():
            info.warnings.append("ELF has no usable DWARF data.")
            return info
        dwarf = elf.get_dwarf_info()
        little = elf.little_endian
        for n, cu in enumerate(dwarf.iter_CUs()):
            info.cu_count += 1
            info.dwarf_versions.add(cu["version"])
            if n % 50 == 0:
                say(f"Reading DWARF: compilation unit {n}...")
            try:
                _read_cu(dwarf, cu, info, little)
            except Exception as exc:  # one broken CU must not abort the rest
                log.warning("DWARF CU %d skipped: %s", n, exc)
                info.warnings.append(f"Compilation unit #{n} skipped: {type(exc).__name__}: {exc}")
    info.finalize()
    return info


def _read_cu(dwarf, cu, info: DebugInfo, little: bool) -> None:
    top = cu.get_top_DIE()
    comp_dir = _s(_attr(top, "DW_AT_comp_dir") or b"")
    prod = _attr(top, "DW_AT_producer")
    if prod:
        info.producers.add(_s(prod))
    lp = dwarf.line_program_for_CU(cu)
    resolve = _file_table(lp, comp_dir) if lp else (lambda _i: None)
    if lp:
        for e in lp.get_entries():
            st = e.state
            if st is None:
                continue
            if st.end_sequence:
                info._rows.append((st.address, "", 0, True))
            elif st.is_stmt:
                f = resolve(st.file)
                if f:
                    info._rows.append((st.address, f, st.line, False))
    asz = cu["address_size"]
    for die in cu.iter_DIEs():
        tag = die.tag
        if tag == "DW_TAG_subprogram":
            low = _attr(die, "DW_AT_low_pc")
            if low is None:
                continue
            high = _attr(die, "DW_AT_high_pc")
            if high is not None and die.attributes["DW_AT_high_pc"].form != "DW_FORM_addr":
                high = low + high
            name = _first(die, "DW_AT_name")
            if name is None:
                continue
            link = _first(die, "DW_AT_linkage_name") or _first(die, "DW_AT_MIPS_linkage_name")
            fi, ln = _first(die, "DW_AT_decl_file"), _first(die, "DW_AT_decl_line")
            info.functions[low] = DeclInfo(_s(name), _s(link) if link else None,
                                           resolve(fi) if fi is not None else None, ln, low, high)
        elif tag == "DW_TAG_variable":
            loc = die.attributes.get("DW_AT_location")
            if loc is None or loc.form != "DW_FORM_exprloc":
                continue
            expr = list(loc.value)
            if len(expr) != 1 + asz or expr[0] != 0x03:  # DW_OP_addr only
                continue
            addr = int.from_bytes(bytes(expr[1:]), "little" if little else "big")
            name = _first(die, "DW_AT_name")
            if name is None:
                continue
            link = _first(die, "DW_AT_linkage_name") or _first(die, "DW_AT_MIPS_linkage_name")
            fi, ln = _first(die, "DW_AT_decl_file"), _first(die, "DW_AT_decl_line")
            info.variables.setdefault(addr, []).append(
                DeclInfo(_s(name), _s(link) if link else None, resolve(fi) if fi is not None else None, ln))
