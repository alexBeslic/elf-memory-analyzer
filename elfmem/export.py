"""CSV, JSON and HTML export plus the overview/report HTML renderer."""
from __future__ import annotations

import csv
import json
import os
from html import escape
from typing import Iterable

from . import __version__
from .analysis import AnalysisResult
from .memory_analyzer import top_stack, top_symbols
from .models import CATEGORY_LABELS, Symbol, SymKind

FUNCTION_FIELDS = ["name", "demangled", "address", "size", "section", "region", "stack_bytes", "stack_kind",
                   "stack_confidence", "stack_source", "source_file", "source_line", "bind", "visibility",
                   "sym_type", "is_thumb", "alias_of", "notes"]
DATA_FIELDS = ["name", "demangled", "address", "size", "section", "region", "category", "data_class", "sym_type",
               "bind", "visibility", "source_file", "source_line", "alias_of", "notes"]
_FORMULA_PREFIX = ("=", "+", "-", "@", "\t", "\r")


def symbol_row(s: Symbol, fields: list[str]) -> dict:
    row = {}
    for f in fields:
        v = getattr(s, f)
        if f == "address" and v is not None:
            v = f"0x{v:08x}"
        elif f == "notes":
            v = "; ".join(v)
        row[f] = v
    return row


def _safe_cell(v):
    """Neutralise spreadsheet formula injection in text cells coming from untrusted symbol names."""
    if isinstance(v, str) and v.startswith(_FORMULA_PREFIX):
        return "'" + v
    return v


def export_symbols_csv(path: str, symbols: Iterable[Symbol], fields: list[str]) -> int:
    """Write ``symbols`` to CSV (in the given order). Returns the number of rows."""
    n = 0
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(fields)
        for s in symbols:
            r = symbol_row(s, fields)
            w.writerow(["" if r[f] is None else _safe_cell(r[f]) for f in fields])
            n += 1
    return n


def result_to_dict(res: AnalysisResult) -> dict:
    elf, mem = res.elf, res.memory
    return {
        "tool": {"name": "elfmem", "version": __version__},
        "elf": {k: getattr(elf, k) for k in ("path", "file_size", "elf_class", "endianness", "machine",
                                              "machine_desc", "elf_type", "entry", "os_abi", "flags",
                                              "has_symtab", "has_dynsym", "has_section_headers",
                                              "debug_sections", "undefined_symbol_count")},
        "sections": [dict(vars(s), flags_str=s.flags_str) for s in elf.sections],
        "segments": [dict(vars(g), flags_str=g.flags_str) for g in elf.segments],
        "memory": {
            "category_bytes": mem.category_bytes, "berkeley": {"text": mem.berkeley_text, "data": mem.berkeley_data,
                                                               "bss": mem.berkeley_bss},
            "load_filesz": mem.load_filesz, "load_memsz": mem.load_memsz,
            "regions": [{"name": u.region.name, "origin": u.region.origin, "length": u.region.length,
                         "used_bytes": u.used_bytes, "load_image_bytes": u.load_image_bytes, "percent": u.percent}
                        for u in mem.region_usage]} if mem else None,
        "functions": [symbol_row(s, FUNCTION_FIELDS) for s in res.functions],
        "data": [symbol_row(s, DATA_FIELDS) for s in res.data_symbols],
        "stack": ({"su_files": len(res.su.files), "records": len(res.su.records),
                   "match_counts": res.stack_match.counts() if res.stack_match else {},
                   "note": "Per-function values only; they are NOT a worst-case call-chain total."}
                  if res.su else None),
        "warnings": res.all_warnings(),
        "assumptions": ["Section sizes are not run-time usage; stack and heap are not included in .data/.bss.",
                        "Symbol sizes come from the ELF symbol table (st_size) and may be 0 or inaccurate for assembly."],
    }


def export_json(path: str, res: AnalysisResult) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result_to_dict(res), fh, indent=2, default=str)


def _table(headers: list[str], rows: list[list[str]], cls: str = "") -> str:
    h = "".join(f"<th>{escape(x)}</th>" for x in headers)
    b = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table class='{cls}'><tr>{h}</tr>{b}</table>"


def render_report(res: AnalysisResult, top_n: int = 25, embedded: bool = False) -> str:
    """Human-readable report. ``embedded`` returns only the body (for the Overview page)."""
    e, mem = res.elf, res.memory
    esc = escape
    yn = lambda b: "yes" if b else "no"  # noqa: E731
    out = [f"<h2>{esc(os.path.basename(e.path))}</h2>"]
    warns = res.all_warnings()
    if warns:
        out.append("<div class='warn'><b>Warnings</b><ul>" + "".join(f"<li>{esc(w)}</li>" for w in warns) + "</ul></div>")
    info = [("Path", esc(e.path)), ("File size on disk", f"{e.file_size:,} bytes"),
            ("ELF class / endianness", f"{e.elf_class}-bit / {e.endianness}"),
            ("Machine", f"{esc(e.machine_desc)} ({e.machine})"), ("Type", esc(e.elf_type)),
            ("Entry point", f"0x{e.entry:08x}"), ("OS/ABI", esc(e.os_abi)),
            ("Sections / segments", f"{len(e.sections)} / {len(e.segments)}"),
            ("Symbol table (.symtab)", yn(e.has_symtab) + ("" if e.has_symtab else " - ELF appears stripped")),
            ("Symbols (defined)", f"{len(e.symbols):,} ({len(res.functions):,} functions, "
                                  f"{len(res.data_symbols):,} data, {len(res.other_symbols):,} other)"),
            ("Debug info (.debug_info)", yn(e.has_debug_info)),
            ("Debug sections", esc(", ".join(e.debug_sections) or "none"))]
    if res.debug:
        info.append(("DWARF", f"{res.debug.cu_count} CUs, versions {sorted(res.debug.dwarf_versions)}"))
    out.append("<h3>General information</h3>" + _table(["Property", "Value"], [[k, v] for k, v in info]))
    if mem:
        out.append("<h3>Memory summary</h3><p class='note'>File size, section sizes, loadable sizes and run-time memory "
                   "are different quantities. Static RAM below excludes stack and heap.</p>")
        tot = mem.section_alloc_total or 1
        rows = [[esc(CATEGORY_LABELS[c]), f"{b:,}", f"{100 * b / tot:.1f}%" if c in
                 ("code", "rodata", "data", "bss", "other_alloc") else "n/a"]
                for c, b in mem.category_bytes.items()]
        out.append(_table(["Category", "Bytes", "% of allocated"], rows))
        out.append(f"<p>Berkeley-style: text={mem.berkeley_text:,} data={mem.berkeley_data:,} bss={mem.berkeley_bss:,} "
                   f"&nbsp;|&nbsp; PT_LOAD file size={mem.load_filesz:,} mem size={mem.load_memsz:,}</p>")
        if mem.region_usage:
            rows = [[esc(u.region.name), f"0x{u.region.origin:08x}", f"{u.region.length:,}", f"{u.used_bytes:,}",
                     f"{u.load_image_bytes:,}", f"{u.percent:.1f}%" if u.percent is not None else "n/a"]
                    for u in mem.region_usage]
            out.append(_table(["Region", "Origin", "Length", "Used (by VMA)", "Load image (LMA)", "Used %"], rows))
        rows = [[esc(s.name), esc(s.type.removeprefix("SHT_")), f"0x{s.addr:08x}", f"{s.size:,}", s.flags_str,
                 esc(s.category), esc(s.region or "")] for s in e.sections if s.alloc and s.size]
        out.append("<h3>Allocated sections</h3>" + _table(["Section", "Type", "Address", "Size", "Flags", "Category", "Region"], rows))
    def sym_rows(syms, extra=None):
        return [[esc(s.display_name), f"0x{s.address:08x}", f"{s.size:,}", esc(s.section or "")] +
                ([extra(s)] if extra else []) for s in syms]
    out.append(f"<h3>Largest functions</h3>" + _table(["Function", "Address", "Size", "Section"],
                                                      sym_rows(top_symbols(e.symbols, SymKind.FUNCTION, top_n))))
    out.append(f"<h3>Largest data objects</h3>" + _table(["Symbol", "Address", "Size", "Section", "Class"],
                                                         sym_rows(top_symbols(e.symbols, SymKind.DATA, top_n),
                                                                  lambda s: esc(s.data_class))))
    if res.su:
        c = res.stack_match.counts() if res.stack_match else {}
        out.append(f"<h3>Stack usage</h3><p>{len(res.su.files)} .su files, {len(res.su.records)} records. "
                   f"Matches: {c}. <b>Values are per-function frames, not a worst-case stack requirement.</b></p>")
        out.append(_table(["Function", "Stack bytes", "Kind", "Match", "Source"],
                          [[esc(s.display_name), str(s.stack_bytes), esc(s.stack_kind or ""),
                            esc(s.stack_confidence), esc(s.stack_source or "")] for s in top_stack(e.symbols, top_n)]))
    else:
        out.append("<h3>Stack usage</h3><p>Not loaded (select a build directory containing .su files).</p>")
    out.append("<h3>Assumptions</h3><ul>" + "".join(f"<li>{esc(a)}</li>" for a in result_to_dict(res)["assumptions"]) + "</ul>")
    body = "\n".join(out)
    if embedded:
        return _CSS + body
    return f"<!doctype html><html><head><meta charset='utf-8'><title>ELF report</title>{_CSS}</head><body>{body}" \
           f"<p class='note'>Generated by elfmem {__version__}</p></body></html>"


_CSS = ("<style>body{font-family:sans-serif;margin:16px} table{border-collapse:collapse;margin:6px 0}"
        "td,th{border:1px solid #bbb;padding:3px 8px;text-align:left;font-size:13px}th{background:#eee}"
        ".warn{background:#fff4d6;border:1px solid #e0b84a;padding:6px 12px}.note{color:#555;font-size:12px}</style>")


def export_html(path: str, res: AnalysisResult) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_report(res))
