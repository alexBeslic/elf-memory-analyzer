"""GCC-style ``.su`` discovery, tolerant parsing and conservative matching to ELF symbols."""
from __future__ import annotations

import logging
import os
import posixpath
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .elf_parser import strip_clone_suffix
from .models import Symbol, SymKind

log = logging.getLogger(__name__)

_LOC_RE = re.compile(r"^(?P<file>.*?):(?P<line>\d+):(?P<col>\d+):(?P<name>.+)$")
_WS_RE = re.compile(r"^(?P<name>.+?)\s+(?P<size>\d+)\s+(?P<qual>[A-Za-z_,]+)\s*$")
MAX_SU_BYTES = 64 * 1024 * 1024


@dataclass
class StackRecord:
    id: int
    name: str
    size: int
    qualifier: str
    kind: str  # static | dynamic | dynamic_bounded | unknown
    file: Optional[str]
    line: Optional[int]
    su_path: str
    su_line: int

    @property
    def source(self) -> str:
        return f"{self.su_path}:{self.su_line}"


@dataclass
class SuParseResult:
    root: str = ""
    files: list[str] = field(default_factory=list)
    records: list[StackRecord] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    malformed_lines: int = 0


def discover_su_files(root: str | os.PathLike) -> list[Path]:
    """Recursively find ``*.su`` files below ``root`` (symlinked dirs are not followed)."""
    found: list[Path] = []
    for dirpath, _dirs, names in os.walk(root, followlinks=False):
        for n in names:
            if n.lower().endswith(".su"):
                found.append(Path(dirpath) / n)
    return sorted(found)


def _classify(qual: str) -> str:
    q = {t.strip().lower() for t in qual.split(",") if t.strip()}
    if q == {"static"}:
        return "static"
    if "dynamic" in q and "bounded" in q:
        return "dynamic_bounded"
    if q == {"dynamic"}:
        return "dynamic"
    return "unknown"


def parse_su_text(text: str, su_path: str = "<memory>", first_id: int = 0) -> tuple[list[StackRecord], int]:
    """Parse one report. Returns (records, malformed_line_count). Never raises on bad input."""
    records: list[StackRecord] = []
    bad = 0
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.rstrip("\r\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        name_field = size = qual = None
        parts = line.split("\t")
        if len(parts) >= 3 and parts[-2].strip().isdigit():
            name_field, size, qual = "\t".join(parts[:-2]).strip(), int(parts[-2]), parts[-1].strip()
        else:
            m = _WS_RE.match(line.strip())
            if m:
                name_field, size, qual = m["name"].strip(), int(m["size"]), m["qual"]
        if not name_field or size is None or not qual:
            bad += 1
            continue
        file = lineno_src = None
        name = name_field
        m = _LOC_RE.match(name_field)
        if m:
            file, lineno_src, name = m["file"], int(m["line"]), m["name"].strip()
        records.append(StackRecord(first_id + len(records), name, size, qual, _classify(qual), file, lineno_src,
                                   su_path, lineno))
    return records, bad


def parse_su_directory(root: str, progress: Optional[Callable[[str], None]] = None) -> SuParseResult:
    """Discover and parse every .su file below ``root``."""
    say = progress or (lambda _m: None)
    res = SuParseResult(root=str(root))
    if not os.path.isdir(root):
        res.warnings.append(f"Not a directory: {root}")
        return res
    files = discover_su_files(root)
    if not files:
        res.warnings.append("No .su files found. Build with -fstack-usage (GCC) and select the build output directory.")
    for i, f in enumerate(files):
        if i % 50 == 0:
            say(f"Parsing stack usage reports ({i}/{len(files)})...")
        try:
            if f.stat().st_size > MAX_SU_BYTES:
                res.warnings.append(f"Skipped oversized file {f}")
                continue
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            res.warnings.append(f"Cannot read {f}: {exc}")
            continue
        recs, bad = parse_su_text(text, str(f), len(res.records))
        res.records.extend(recs)
        res.files.append(str(f))
        if bad:
            res.malformed_lines += bad
            res.warnings.append(f"{f.name}: {bad} malformed line(s) ignored")
    return res


# ---------------------------------------------------------------- matching

def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip())


def base_name(demangled: str) -> str:
    """``int ns::f(int) const`` -> ``ns::f`` (parameters and return type dropped)."""
    s = _norm(demangled)
    depth, cut = 0, None
    for i in range(len(s) - 1, -1, -1):  # find the '(' opening the trailing parameter list
        c = s[i]
        if c == ")":
            depth += 1
        elif c == "(":
            depth -= 1
            if depth == 0:
                cut = i
                break
    if cut is not None:
        s = s[:cut]
    depth = 0
    for i in range(len(s) - 1, -1, -1):  # drop a leading return type
        c = s[i]
        if c == ">":
            depth += 1
        elif c == "<":
            depth -= 1
        elif c == " " and depth == 0:
            return s[i + 1:]
    return s


def signature_key(name: str) -> str:
    """Name with the return type removed but parameters/qualifiers kept: ``int ns::f(int)`` -> ``ns::f(int)``.

    GCC prints C++ return types in .su files while c++filt omits them for ordinary functions, so
    this is the comparison form that still distinguishes overloads.
    """
    s = _norm(name)
    depth, cut = 0, None
    for i in range(len(s) - 1, -1, -1):
        if s[i] == ")":
            depth += 1
        elif s[i] == "(":
            depth -= 1
            if depth == 0:
                cut = i
                break
    if cut is None:
        return s
    head, tail = s[:cut], s[cut:]
    depth = 0
    for i in range(len(head) - 1, -1, -1):
        c = head[i]
        if c in ">)":
            depth += 1
        elif c in "<(":
            depth -= 1
        elif c == " " and depth == 0:
            head = head[i + 1:]
            break
    return head + tail


def _basename(p: Optional[str]) -> Optional[str]:
    return posixpath.basename(p.replace("\\", "/")) if p else None


@dataclass
class StackMatch:
    symbol_id: int
    confidence: str  # exact | approximate | ambiguous | unavailable
    record: Optional[StackRecord]
    candidates: list[StackRecord]
    note: str


@dataclass
class MatchResult:
    matches: dict[int, StackMatch] = field(default_factory=dict)
    unmatched_records: list[StackRecord] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        c = {"exact": 0, "approximate": 0, "ambiguous": 0, "unavailable": 0}
        for m in self.matches.values():
            c[m.confidence] += 1
        return c


def match_stack_usage(symbols: list[Symbol], records: list[StackRecord]) -> MatchResult:
    """Match .su records to function symbols without silently guessing.

    Evidence used, in order: exact name (raw or demangled), clone-suffix-stripped /
    parameter-less name (approximate), then source-file narrowing using the
    ELF STT_FILE hint or DWARF declaration file. Ambiguity is reported, never resolved by guessing.
    """
    funcs = [s for s in symbols if s.kind == SymKind.FUNCTION]
    by_name: dict[str, list[StackRecord]] = {}
    by_base: dict[str, list[StackRecord]] = {}
    for r in records:
        for key in {_norm(r.name), signature_key(r.name)}:
            by_name.setdefault(key, []).append(r)
        by_base.setdefault(strip_clone_suffix(base_name(r.name)), []).append(r)

    pending: dict[int, tuple[list[StackRecord], str, bool]] = {}
    claims: dict[int, set[int]] = {}  # record id -> distinct function addresses claiming it
    for s in funcs:
        exact_keys = {s.name} | ({_norm(s.demangled), signature_key(s.demangled)} if s.demangled else set())
        cands = _dedupe([r for k in exact_keys for r in by_name.get(k, [])])
        level = "exact"
        if not cands:
            keys = {strip_clone_suffix(s.name), strip_clone_suffix(_norm(s.demangled or s.name)),
                    strip_clone_suffix(base_name(s.demangled or s.name))}
            cands = _dedupe([r for k in keys for r in by_base.get(k, []) + by_name.get(k, [])])
            level = "approximate"
        narrowed = False
        want = _basename(s.file_hint) or _basename(s.source_file)
        if cands and want:
            same = [r for r in cands if _basename(r.file) == want]
            if same:
                narrowed = len(same) < len(cands) or len(cands) == 1
                cands = same
        pending[s.id] = (cands, level, narrowed)
        for r in cands:
            claims.setdefault(r.id, set()).add(s.address)

    result = MatchResult()
    for s in funcs:
        cands, level, narrowed = pending[s.id]
        if not cands:
            result.matches[s.id] = StackMatch(s.id, "unavailable", None, [], "no .su record with this name")
            continue
        uniq = _collapse_identical(cands)
        if len(uniq) > 1:
            where = "; ".join(f"{r.file or '?'}:{r.line or '?'}={r.size}" for r in uniq[:4])
            result.matches[s.id] = StackMatch(s.id, "ambiguous", None, uniq,
                                              f"{len(uniq)} candidate records ({where}); no source file evidence to choose")
            continue
        rec = uniq[0]
        rivals = claims.get(rec.id, set()) - {s.address}
        if rivals and not narrowed:
            result.matches[s.id] = StackMatch(s.id, "ambiguous", None, uniq,
                                              f"record {rec.source} also fits {len(rivals)} other function(s) at different addresses")
            continue
        note = "name matched" + (" and source file agrees" if narrowed else "")
        if level == "approximate":
            note = "matched after stripping clone suffix / parameters; verify manually"
        result.matches[s.id] = StackMatch(s.id, level, rec, uniq, note)

    # aliases inherit the primary's result (as approximate)
    for s in funcs:
        m = result.matches[s.id]
        if m.confidence == "unavailable" and s.alias_of is not None:
            src = result.matches.get(s.alias_of)
            if src and src.record is not None:
                result.matches[s.id] = StackMatch(s.id, "approximate", src.record, src.candidates,
                                                  f"alias of {symbols[s.alias_of].name}")
    used = {m.record.id for m in result.matches.values() if m.record}
    cand_ids = {r.id for m in result.matches.values() for r in m.candidates}
    result.unmatched_records = [r for r in records if r.id not in used and r.id not in cand_ids]
    return result


def _dedupe(recs: list[StackRecord]) -> list[StackRecord]:
    seen, out = set(), []
    for r in recs:
        if r.id not in seen:
            seen.add(r.id)
            out.append(r)
    return out


def _collapse_identical(recs: list[StackRecord]) -> list[StackRecord]:
    """Records that agree on name, file, line and size (e.g. duplicated reports) count once."""
    seen, out = set(), []
    for r in recs:
        key = (r.name, _basename(r.file), r.line, r.size, r.kind)
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out


def apply_matches(symbols: list[Symbol], result: MatchResult) -> None:
    """Write match results into the symbols (call from the thread that owns them)."""
    for sym in symbols:
        m = result.matches.get(sym.id)
        if not m:
            continue
        sym.stack_confidence, sym.stack_note = m.confidence, m.note
        if m.record is not None:
            sym.stack_bytes, sym.stack_kind, sym.stack_source = m.record.size, m.record.kind, m.record.source
        else:
            sym.stack_bytes = sym.stack_kind = sym.stack_source = None
