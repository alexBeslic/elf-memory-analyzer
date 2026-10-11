"""Headless command line interface (useful for CI and for validating results)."""
from __future__ import annotations

import argparse
import sys

from . import analysis as an
from .export import DATA_FIELDS, FUNCTION_FIELDS, export_html, export_json, export_symbols_csv
from .memory_analyzer import top_symbols
from .models import SymKind
from .toolchain import load_config


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="elfmem-cli", description="Analyse ELF memory usage without the GUI")
    ap.add_argument("elf")
    ap.add_argument("--build-dir", help="directory searched recursively for .su files")
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--no-dwarf", action="store_true")
    ap.add_argument("--csv-functions"), ap.add_argument("--csv-data")
    ap.add_argument("--json"), ap.add_argument("--html")
    a = ap.parse_args(argv)
    cfg = load_config()
    res = an.analyze_elf(a.elf, cfg)
    if res.elf.has_debug_info and not a.no_dwarf:
        an.apply_debug(res, an.load_debug(a.elf))
    if a.build_dir:
        an.apply_stack(res, an.load_stack_reports(a.build_dir))
    m = res.memory
    print(f"{res.elf.path}: {res.elf.machine_desc}, {res.elf.elf_class}-bit {res.elf.endianness}-endian")
    print(f"text={m.berkeley_text} data={m.berkeley_data} bss={m.berkeley_bss}  "
          f"({len(res.functions)} functions, {len(res.data_symbols)} data symbols)")
    for kind, title in ((SymKind.FUNCTION, "Largest functions"), (SymKind.DATA, "Largest data objects")):
        print(f"\n{title}:")
        for s in top_symbols(res.elf.symbols, kind, a.top):
            extra = f"  stack={s.stack_bytes} ({s.stack_confidence})" if kind == SymKind.FUNCTION and s.stack_bytes is not None else ""
            print(f"  {s.size:8d}  0x{s.address:08x}  {s.section or '-':<12} {s.display_name}{extra}")
    for w in res.all_warnings():
        print("warning:", w, file=sys.stderr)
    if a.csv_functions:
        export_symbols_csv(a.csv_functions, res.functions, FUNCTION_FIELDS)
    if a.csv_data:
        export_symbols_csv(a.csv_data, res.data_symbols, DATA_FIELDS)
    if a.json:
        export_json(a.json, res)
    if a.html:
        export_html(a.html, res)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
