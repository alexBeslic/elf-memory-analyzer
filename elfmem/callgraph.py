"""Optional call-graph and worst-case stack estimation derived from disassembly.

Limitations (reported to the user, never hidden): indirect calls, recursion, interrupts,
dynamic stack allocation, tail-call detection heuristics and missing .su data all make
the result a *lower bound* rather than a guaranteed worst case.
"""
from __future__ import annotations

import re
import subprocess
import os
import sys
from dataclasses import dataclass, field
from typing import Callable, Optional

from .disassembler import FUNC_HDR_RE, INSN_RE
from .models import ElfModel, Symbol, SymKind
from .toolchain import ToolchainConfig, resolve_tool

CALL_MNEMONICS = {"call", "callq", "calll", "bl", "blx", "blr", "jal", "jalr", "bl.w", "blx.w", "jsr", "rcall",
                  "call.l", "callx0", "callx4", "callx8", "callx12", "call0", "call4", "call8", "call12",
                  "bsr", "lcall"}
JUMP_MNEMONICS = {"jmp", "jmpq", "b", "b.w", "j", "bra", "tail", "jump", "rjmp"}
_TARGET_RE = re.compile(r"^(?:0x)?(?P<addr>[0-9a-f]+)\s+<")


@dataclass
class CallGraph:
    edges: dict[int, set[int]] = field(default_factory=dict)       # caller addr -> callee addrs
    indirect: set[int] = field(default_factory=set)                # callers with indirect calls
    names: dict[int, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


@dataclass
class StackEstimate:
    bound: int
    reliable: bool
    path: list[int]
    issues: list[str]


def build_call_graph(elf: ElfModel, cfg: ToolchainConfig, timeout: float = 300.0,
                     progress: Optional[Callable[[str], None]] = None) -> CallGraph:
    """Disassemble the whole image once and collect direct call/tail-call edges."""
    g = CallGraph()
    exe = resolve_tool(cfg, "objdump", elf.machine)
    if not exe:
        g.warnings.append("objdump not found; cannot build a call graph.")
        return g
    (progress or (lambda _m: None))("Disassembling image for call graph...")
    proc = subprocess.run([exe, "-d", "-z", "--wide", os.path.abspath(elf.path)], capture_output=True, text=True,
                          timeout=timeout, check=False, errors="replace")
    if proc.returncode != 0:
        g.warnings.append(f"objdump failed: {proc.stderr.strip()[:300]}")
        return g
    func_starts = {s.address for s in elf.symbols if s.kind == SymKind.FUNCTION}
    for s in elf.symbols:
        if s.kind == SymKind.FUNCTION:
            g.names.setdefault(s.address, s.display_name)
    current: Optional[int] = None
    for line in proc.stdout.splitlines():
        h = FUNC_HDR_RE.match(line)
        if h:
            current = int(h["addr"], 16)
            continue
        m = INSN_RE.match(line)
        if not m or current is None or not m["text"]:
            continue
        parts = m["text"].split(None, 1)
        mn, ops = parts[0].lower(), (parts[1] if len(parts) > 1 else "")
        if mn in CALL_MNEMONICS:
            t = _TARGET_RE.match(ops.strip())
            if t:
                g.edges.setdefault(current, set()).add(int(t["addr"], 16))
            else:
                g.indirect.add(current)
        elif mn in JUMP_MNEMONICS:
            t = _TARGET_RE.match(ops.strip())
            if t:
                tgt = int(t["addr"], 16)
                if tgt != current and tgt in func_starts:  # jump to another function's entry = tail call
                    g.edges.setdefault(current, set()).add(tgt)
    g.warnings.append("Call graph is derived from disassembly: calls through function pointers and "
                      "vtables are not resolved; interrupt handlers are not connected to their callers.")
    return g


def estimate_worst_case(graph: CallGraph, symbols: list[Symbol], root_addr: int) -> StackEstimate:
    """Longest-path stack estimate from ``root_addr`` using matched .su values."""
    stack: dict[int, tuple[int, str]] = {}
    for s in symbols:
        if s.kind == SymKind.FUNCTION and s.stack_bytes is not None and s.stack_confidence in ("exact", "approximate"):
            stack.setdefault(s.address, (s.stack_bytes, s.stack_kind or "unknown"))
    issues: list[str] = []
    memo: dict[int, tuple[int, list[int]]] = {}
    visiting: set[int] = set()
    approx = {s.address for s in symbols if s.stack_confidence == "approximate" and s.kind == SymKind.FUNCTION}
    seen_issue: set[str] = set()

    def note(msg: str) -> None:
        if msg not in seen_issue:
            seen_issue.add(msg)
            issues.append(msg)

    def nm(a: int) -> str:
        return graph.names.get(a, f"0x{a:x}")

    def visit(a: int) -> tuple[int, list[int]]:
        if a in memo:
            return memo[a]
        if a in visiting:
            note(f"recursion through {nm(a)}: depth unbounded")
            return 0, []
        visiting.add(a)
        own, kind = stack.get(a, (0, ""))
        if a not in stack:
            note(f"no stack data for {nm(a)}")
        elif kind == "dynamic":
            note(f"{nm(a)} uses dynamic stack (unbounded)")
        elif kind == "dynamic_bounded":
            note(f"{nm(a)} uses dynamic stack (bounded value used)")
        elif a in approx:
            note(f"stack value of {nm(a)} was matched approximately")
        if a in graph.indirect:
            note(f"{nm(a)} makes indirect calls (targets unknown)")
        best: tuple[int, list[int]] = (0, [])
        for c in sorted(graph.edges.get(a, ())):
            r = visit(c)
            if r[0] > best[0] or not best[1]:
                best = r
        visiting.discard(a)
        memo[a] = (own + best[0], [a] + best[1])
        return memo[a]

    old = sys.getrecursionlimit()
    sys.setrecursionlimit(max(old, 20000))
    try:
        total, path = visit(root_addr)
    except RecursionError:
        note("call chain too deep to analyse")
        total, path = 0, [root_addr]
    finally:
        sys.setrecursionlimit(old)
    hard = [i for i in issues if not i.endswith("(bounded value used)") and "approximately" not in i]
    return StackEstimate(total, reliable=not hard, path=path, issues=issues)
