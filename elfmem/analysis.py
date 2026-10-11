"""Orchestration: ties parsing, enrichment, stack matching and memory accounting together."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Callable, Optional

from .debug_info import DebugInfo, load_debug_info
from .elf_parser import demangle_names, load_elf
from .memory_analyzer import MemoryRegion, MemorySummary, summarize
from .models import ElfModel, Symbol, SymKind
from .stack_usage import MatchResult, SuParseResult, apply_matches, match_stack_usage, parse_su_directory
from .toolchain import ToolchainConfig, resolve_tool

Progress = Optional[Callable[[str], None]]


@dataclass
class AnalysisResult:
    elf: ElfModel
    config: ToolchainConfig
    regions: list[MemoryRegion] = field(default_factory=list)
    memory: Optional[MemorySummary] = None
    debug: Optional[DebugInfo] = None
    su: Optional[SuParseResult] = None
    stack_match: Optional[MatchResult] = None
    warnings: list[str] = field(default_factory=list)

    @property
    def functions(self) -> list[Symbol]:
        return [s for s in self.elf.symbols if s.kind == SymKind.FUNCTION]

    @property
    def data_symbols(self) -> list[Symbol]:
        return [s for s in self.elf.symbols if s.kind == SymKind.DATA]

    @property
    def other_symbols(self) -> list[Symbol]:
        return [s for s in self.elf.symbols if s.kind == SymKind.OTHER]

    def all_warnings(self) -> list[str]:
        out = list(self.elf.warnings) + self.warnings
        if self.memory:
            out += self.memory.warnings
        if self.su:
            out += self.su.warnings
        if self.debug:
            out += self.debug.warnings
        return out


def update_search_blob(s: Symbol) -> None:
    parts = [s.name, s.demangled or "", s.section or "", s.source_file or "", s.file_hint or "",
             f"0x{s.address:08x}", f"{s.address:x}", s.region or ""]
    s.search_blob = "\n".join(parts).lower()


def analyze_elf(path: str, config: Optional[ToolchainConfig] = None, regions: Optional[list[MemoryRegion]] = None,
                progress: Progress = None) -> AnalysisResult:
    """Phase 1: ELF-only analysis (+ demangling if a demangler is available)."""
    cfg = config or ToolchainConfig()
    elf = load_elf(path, progress)
    res = AnalysisResult(elf=elf, config=cfg, regions=list(regions or []))
    if cfg.demangle:
        (progress or (lambda _m: None))("Demangling C++ names...")
        tool = resolve_tool(cfg, "cxxfilt", elf.machine)
        names = demangle_names([s.name for s in elf.symbols], tool)
        if not names and any(s.name.startswith("_Z") for s in elf.symbols):
            res.warnings.append("C++ symbols found but no demangler (c++filt) available; names are shown mangled.")
        for s in elf.symbols:
            s.demangled = names.get(s.name)
    res.memory = summarize(elf, res.regions)
    for s in elf.symbols:
        update_search_blob(s)
    return res


def recompute_memory(res: AnalysisResult, regions: list[MemoryRegion]) -> None:
    res.regions = list(regions)
    res.memory = summarize(res.elf, res.regions)
    for s in res.elf.symbols:
        update_search_blob(s)


def load_debug(path: str, progress: Progress = None) -> DebugInfo:
    """Phase 2 (slow, run in background): parse DWARF without touching shared symbols."""
    return load_debug_info(path, progress)


def apply_debug(res: AnalysisResult, dbg: DebugInfo) -> None:
    """Attach DWARF-confirmed source locations. Only address-exact matches are applied."""
    res.debug = dbg
    for s in res.elf.symbols:
        if s.kind == SymKind.FUNCTION:
            d = dbg.functions.get(s.address)
            if d and (d.name in (s.name, s.demangled or "") or d.linkage_name == s.name or d.name in s.name):
                s.source_file, s.source_line = d.file, d.line
            elif d is None and dbg.has_lines:
                loc = dbg.line_at(s.address)
                if loc:
                    s.source_file, s.source_line = loc
                    s.notes.append("source location from line table only (no matching DWARF subprogram)")
        elif s.kind == SymKind.DATA:
            for d in dbg.variables.get(s.address, []):
                if d.name == s.name or d.linkage_name == s.name or d.name == s.demangled:
                    s.source_file, s.source_line = d.file, d.line
                    break
        update_search_blob(s)


def load_stack_reports(build_dir: str, progress: Progress = None) -> SuParseResult:
    return parse_su_directory(build_dir, progress)


def apply_stack(res: AnalysisResult, parsed: SuParseResult) -> MatchResult:
    res.su = parsed
    res.stack_match = match_stack_usage(res.elf.symbols, parsed.records)
    apply_matches(res.elf.symbols, res.stack_match)
    return res.stack_match
