"""Import memory regions from GNU ld map files, linker scripts (MEMORY {}) or JSON."""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

from .memory_analyzer import MemoryRegion

MAX_SCAN_BYTES = 200 * 1024 * 1024
_MAP_LINE = re.compile(r"^(?P<name>\S+)\s+0x(?P<origin>[0-9a-fA-F]+)\s+0x(?P<length>[0-9a-fA-F]+)(?:\s+(?P<attr>\S+))?\s*$")
_NUM = re.compile(r"^\s*(?P<num>0[xX][0-9a-fA-F]+|\d+)\s*(?P<suf>[KkMmGg])?\s*$")


class RegionImportError(Exception):
    pass


@dataclass
class ImportResult:
    regions: list[MemoryRegion] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    kind: str = ""


def parse_size(text: str) -> int:
    """``0x1000``, ``4096``, ``512K``, ``2M`` (K/M/G are powers of 1024, as in GNU ld)."""
    m = _NUM.match(text)
    if not m:
        raise ValueError(f"unsupported expression: {text.strip()!r}")
    v = int(m["num"], 0)
    return v * {"": 1, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30}[(m["suf"] or "").lower()]


def _finish(regions: list[MemoryRegion], warnings: list[str], kind: str) -> ImportResult:
    seen: dict[str, int] = {}
    out = []
    for r in regions:
        n = seen.get(r.name, 0)
        seen[r.name] = n + 1
        if n:
            warnings.append(f"Duplicate region name {r.name!r} renamed to {r.name}_{n + 1}.")
            r = MemoryRegion(f"{r.name}_{n + 1}", r.origin, r.length, r.description)
        out.append(r)
    spans = sorted(out, key=lambda r: r.origin)
    if any(a.end > b.origin for a, b in zip(spans, spans[1:])):
        warnings.append("Some regions overlap (e.g. cached/uncached aliases). Each address is assigned to the "
                        "smallest region containing it.")
    return ImportResult(out, warnings, kind)


def parse_map_lines(lines, ) -> ImportResult:
    """Parse the 'Memory Configuration' block of a GNU ld map file from an iterable of lines."""
    regions: list[MemoryRegion] = []
    warnings: list[str] = []
    state = 0  # 0 = before block, 1 = in block
    for raw in lines:
        line = raw.rstrip("\r\n")
        if state == 0:
            if line.strip() == "Memory Configuration":
                state = 1
            continue
        if line.startswith("Linker script and memory map"):
            break
        s = line.strip()
        if not s or s.startswith("Name "):
            continue
        m = _MAP_LINE.match(s)
        if not m:
            warnings.append(f"Ignored unparsable line in Memory Configuration: {s[:60]!r}")
            continue
        if m["name"] == "*default*":
            continue
        length = int(m["length"], 16)
        if length == 0:
            continue
        regions.append(MemoryRegion(m["name"], int(m["origin"], 16), length, m["attr"] or ""))
    if state == 0:
        raise RegionImportError("No 'Memory Configuration' section found (is this a GNU ld map file?).")
    if not regions:
        warnings.append("Memory Configuration contains no regions other than *default*.")
    return _finish(regions, warnings, "GNU ld map file")


def parse_linker_script(text: str) -> ImportResult:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)
    block = re.search(r"\bMEMORY\s*\{(.*?)\}", text, flags=re.S)
    if not block:
        raise RegionImportError("No MEMORY { } block found in the linker script.")
    rx = re.compile(r"(?P<name>[A-Za-z_.$][\w.$]*)\s*(?:\((?P<attr>[^)]*)\))?\s*:\s*"
                    r"(?:ORIGIN|origin|org|o)\s*=\s*(?P<o>[^,]+),\s*(?:LENGTH|length|len|l)\s*=\s*(?P<l>[^\n;,]+)")
    regions, warnings = [], []
    for m in rx.finditer(block.group(1)):
        try:
            regions.append(MemoryRegion(m["name"], parse_size(m["o"]), parse_size(m["l"]), (m["attr"] or "").strip()))
        except ValueError as exc:
            warnings.append(f"Region {m['name']}: {exc} (only numbers with optional K/M/G are supported)")
    if not regions and not warnings:
        warnings.append("MEMORY block is empty.")
    return _finish(regions, warnings, "linker script")


def parse_json_text(text: str) -> ImportResult:
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise RegionImportError(f"Invalid JSON: {exc}") from exc
    items = data.get("regions") if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise RegionImportError('JSON must be a list of regions or {"regions": [...]}.')
    regions, warnings = [], []
    for i, d in enumerate(items):
        try:
            o, l = d["origin"], d["length"]
            o = parse_size(o) if isinstance(o, str) else int(o)
            l = parse_size(l) if isinstance(l, str) else int(l)
            if l <= 0 or o < 0:
                raise ValueError("origin/length out of range")
            regions.append(MemoryRegion(str(d["name"]), o, l, str(d.get("description", d.get("attributes", "")))))
        except (KeyError, TypeError, ValueError) as exc:
            warnings.append(f"Region #{i + 1} skipped: {exc}")
    return _finish(regions, warnings, "JSON")


def regions_to_json(regions: list[MemoryRegion]) -> str:
    return json.dumps({"regions": [{"name": r.name, "origin": f"0x{r.origin:08x}", "length": f"0x{r.length:x}",
                                     "description": r.description} for r in regions]}, indent=2)


def import_regions(path: str) -> ImportResult:
    """Detect the file type and import regions. Raises :class:`RegionImportError` with a readable message."""
    try:
        size = os.path.getsize(path)
        ext = os.path.splitext(path)[1].lower()
        if ext == ".json":
            with open(path, encoding="utf-8", errors="replace") as fh:
                return parse_json_text(fh.read(5_000_000))
        if ext in (".ld", ".lds", ".x", ".icf"):
            with open(path, encoding="utf-8", errors="replace") as fh:
                return parse_linker_script(fh.read(5_000_000))
        if size > MAX_SCAN_BYTES:
            raise RegionImportError("File is too large to scan.")
        with open(path, encoding="utf-8", errors="replace") as fh:
            try:
                return parse_map_lines(fh)
            except RegionImportError:
                pass
        with open(path, encoding="utf-8", errors="replace") as fh:
            head = fh.read(5_000_000)
        if head.lstrip().startswith(("{", "[")):
            return parse_json_text(head)
        return parse_linker_script(head)
    except OSError as exc:
        raise RegionImportError(f"Cannot read {path}: {exc}") from exc
