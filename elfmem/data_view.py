"""Initial value of data objects, read from the ELF image (no execution, no external tools)."""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

from .models import ElfModel, Symbol

MAX_BYTES = 64 * 1024


@dataclass
class DataBytes:
    state: str  # "stored" | "zero" | "unavailable"
    data: bytes = b""
    message: str = ""
    truncated: bool = False
    file_offset: Optional[int] = None


def read_symbol_bytes(elf: ElfModel, sym: Symbol, limit: int = MAX_BYTES) -> DataBytes:
    """Bytes the ELF file stores for ``sym`` (its initial value), or an explanation why there are none."""
    if sym.size == 0:
        return DataBytes("unavailable", message="Symbol has size 0; its extent is unknown.")
    if not 0 < sym.shndx < len(elf.sections):
        return DataBytes("unavailable", message="Symbol is not tied to a section (absolute or COMMON symbol). "
                                                 "COMMON symbols are zero-initialized by the linker.")
    sec = elf.sections[sym.shndx]
    if sec.tls:
        return DataBytes("unavailable", message="Thread-local symbol: its value is an offset into the TLS template, "
                                                 "which is not decoded here.")
    rel = sym.address - sec.addr
    if rel < 0 or rel + sym.size > sec.size:
        return DataBytes("unavailable", message=f"Symbol extends outside its section {sec.name}.")
    if sec.nobits:
        return DataBytes("zero", message=f"{sec.name} is NOBITS: no value is stored in the file. The object starts as "
                                         "all zero if the start-up code clears this section (normal C runtime behaviour).")
    off = sec.offset + rel
    n = min(sym.size, limit)
    try:
        with open(elf.path, "rb") as fh:
            fh.seek(off)
            data = fh.read(n)
    except OSError as exc:
        return DataBytes("unavailable", message=f"Cannot read ELF file: {exc}")
    if len(data) < n:
        return DataBytes("unavailable", message="ELF file is truncated at this object.")
    msg = f"Stored in the ELF at file offset 0x{off:x} (section {sec.name})."
    if sec.lma is not None and sec.lma != sec.addr:
        msg += (f" Load address (LMA) 0x{sec.lma + rel:08x} - copied to run-time address (VMA) "
                f"0x{sym.address:08x} by start-up code.")
    return DataBytes("stored", data, msg, sym.size > limit, off)


def hexdump(data: bytes, base: int = 0, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hx = " ".join(f"{b:02x}" for b in chunk[:8])
        hy = " ".join(f"{b:02x}" for b in chunk[8:])
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + i:08x}  {hx:<23}  {hy:<23}  |{asc}|")
    return "\n".join(lines)


def values_text(data: bytes, base: int, width: int, kind: str, endian: str) -> str:
    """Render ``data`` as fixed-width elements. kind: uint | int | hex | float."""
    e = "<" if endian == "little" else ">"
    n = len(data) // width
    per_line = max(1, 16 // width)
    code = {1: "B", 2: "H", 4: "I", 8: "Q"}[width]
    if kind == "int":
        code = code.lower()
    if kind == "float":
        if width not in (4, 8):
            return "Float view needs 32- or 64-bit elements."
        code = "f" if width == 4 else "d"
    vals = struct.unpack(f"{e}{n}{code}", data[:n * width]) if n else ()
    out = []
    for i in range(0, n, per_line):
        cells = []
        for v in vals[i:i + per_line]:
            cells.append(f"0x{v:0{width * 2}x}" if kind == "hex" else (f"{v:.9g}" if kind == "float" else f"{v}"))
        out.append(f"{base + i * width:08x}:  " + "  ".join(f"{c:>{width * 2 + 2 if kind == 'hex' else 12}}" for c in cells))
    if len(data) % width:
        out.append(f"({len(data) % width} trailing byte(s) not shown in this view)")
    return "\n".join(out)


def c_string(data: bytes) -> Optional[str]:
    """If ``data`` is NUL-terminated printable text, return it (escaped); otherwise None."""
    end = data.find(b"\0")
    if end <= 0:
        return None
    text = data[:end]
    if any(b not in (9, 10, 13) and not 32 <= b < 127 for b in text):
        try:
            s = text.decode("utf-8")
        except UnicodeDecodeError:
            return None
        if not s.isprintable():
            return None
        return s.encode("unicode_escape").decode("ascii") if "\n" in s else s
    return text.decode("ascii").encode("unicode_escape").decode("ascii")


def summarize(data: bytes, endian: str) -> list[str]:
    """Short human-readable interpretations. These are hints: the ELF carries no type information here."""
    out: list[str] = []
    if not data:
        return out
    if all(b == 0 for b in data):
        out.append("All bytes are 0x00.")
    elif all(b == 0xFF for b in data):
        out.append("All bytes are 0xFF (erased-flash pattern).")
    e = "<" if endian == "little" else ">"
    if len(data) in (1, 2, 4, 8):
        w = len(data)
        u = int.from_bytes(data, "little" if endian == "little" else "big")
        s = u - (1 << (8 * w)) if u >> (8 * w - 1) else u
        out.append(f"As one {8 * w}-bit integer: unsigned {u}, signed {s}, hex 0x{u:0{2 * w}x}")
        if w in (4, 8):
            f = struct.unpack(f"{e}{'f' if w == 4 else 'd'}", data)[0]
            out.append(f"As IEEE-754 {'float' if w == 4 else 'double'}: {f:.9g}")
    s = c_string(data)
    if s is not None:
        out.append(f'Looks like a C string: "{s}"')
    return out
