"""HTML detail text for a selected symbol (used by the inspector and reports)."""
from __future__ import annotations

from html import escape

from .analysis import AnalysisResult
from .disassembler import function_bounds
from .models import CATEGORY_LABELS, Symbol, SymKind


def fmt_addr(a: int | None, width: int = 8) -> str:
    return "" if a is None else f"0x{a:0{width}x}"


def related_symbols(res: AnalysisResult, sym: Symbol, limit: int = 12) -> list[Symbol]:
    """Aliases at the same address plus the nearest neighbours in the same section."""
    same = [s for s in res.elf.symbols if s.address == sym.address and s.id != sym.id and s.kind == sym.kind]
    return same[:limit]


def symbol_details_html(res: AnalysisResult, sym: Symbol) -> str:
    esc = escape
    rows: list[tuple[str, str]] = [("Name", esc(sym.name))]
    if sym.demangled:
        rows.append(("Demangled", esc(sym.demangled)))
    rows.append(("Kind", f"{sym.kind.value} (ELF type STT_{sym.sym_type})"))
    rows.append(("Address", fmt_addr(sym.address)))
    if sym.kind == SymKind.FUNCTION:
        start, end, est = function_bounds(sym, res.elf)
        rows.append(("Address range", f"{fmt_addr(start)} - {fmt_addr(end)}" + (" (estimated end)" if est else "")))
        if sym.is_thumb:
            rows.append(("Instruction set", "Thumb (low address bit set in symbol)"))
    else:
        rows.append(("Address range", f"{fmt_addr(sym.address)} - {fmt_addr(sym.end)}"))
    rows.append(("Size", f"{sym.size:,} bytes"))
    rows.append(("Section", esc(sym.section or "-")))
    if sym.category:
        rows.append(("Section category", CATEGORY_LABELS.get(sym.category, sym.category)))
    if sym.data_class:
        rows.append(("Data class", esc(sym.data_class)))
    rows.append(("Region", esc(sym.region or "- (no matching configured region)")))
    rows.append(("Binding / visibility", f"{sym.bind} / {sym.visibility}"))
    if sym.file_hint:
        rows.append(("Translation unit (ELF STT_FILE)", esc(sym.file_hint)))
    if sym.source_file:
        rows.append(("Source (DWARF)", esc(f"{sym.source_file}:{sym.source_line or '?'}")))
    elif res.debug is None and res.elf.has_debug_info:
        rows.append(("Source (DWARF)", "not loaded yet"))
    else:
        rows.append(("Source (DWARF)", "unavailable"))
    if sym.kind == SymKind.FUNCTION:
        if sym.stack_bytes is not None:
            rows.append(("Stack usage", f"{sym.stack_bytes} bytes ({sym.stack_kind}) - match: {sym.stack_confidence}"))
            rows.append(("Stack source", esc(f"{sym.stack_source}  [{sym.stack_note}]")))
        else:
            rows.append(("Stack usage", f"unavailable - match: {sym.stack_confidence}" +
                         (f" ({esc(sym.stack_note)})" if sym.stack_note else "")))
    if sym.notes:
        rows.append(("Notes", "<br>".join(esc(n) for n in sym.notes)))
    rel = related_symbols(res, sym)
    if rel:
        rows.append(("Related (same address)", "<br>".join(esc(r.name) for r in rel)))
    body = "".join(f"<tr><td style='padding-right:12px'><b>{k}</b></td><td>{v}</td></tr>" for k, v in rows)
    return f"<table>{body}</table>"
