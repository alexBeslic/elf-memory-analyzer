"""Call graph + worst-case stack estimation.

Two sources, best first:
  1. GCC ``-fcallgraph-info[=su,da]`` ``.ci`` files (compiler metadata, exact static-function identity,
     per-function stack and indirect-call markers);
  2. objdump disassembly (direct calls and tail-call jumps only; architecture-mnemonic based heuristic).

Limitations are reported, never hidden: indirect calls, recursion, interrupts, dynamic stack allocation and
missing stack data make the estimate a *lower bound*.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .disassembler import FUNC_HDR_RE, INSN_RE
from .elf_parser import strip_clone_suffix
from .models import ElfModel, Symbol, SymKind
from .toolchain import ToolchainConfig, resolve_tool

Progress = Optional[Callable[[str], None]]
CALL_MNEMONICS = {"call", "callq", "calll", "bl", "blx", "blr", "jal", "jalr", "bl.w", "blx.w", "jsr", "rcall",
                  "call.l", "callx0", "callx4", "callx8", "callx12", "call0", "call4", "call8", "call12",
                  "bsr", "lcall", "calla", "calli", "fcall", "fcalla", "fcalli"}
JUMP_MNEMONICS = {"jmp", "jmpq", "b", "b.w", "j", "bra", "tail", "jump", "rjmp", "ja", "jla"}
_TARGET_RE = re.compile(r"^(?:0x)?(?P<addr>[0-9a-f]+)\s+<")


@dataclass
class CallGraph:
    edges: dict[int, set[int]] = field(default_factory=dict)       # caller key -> callee keys
    indirect: set[int] = field(default_factory=set)                # callers that make indirect calls
    names: dict[int, str] = field(default_factory=dict)
    stack_hint: dict[int, tuple[int, str]] = field(default_factory=dict)  # from .ci: key -> (bytes, kind)
    origin: str = ""
    warnings: list[str] = field(default_factory=list)
    unresolved: int = 0
    # keys are ELF function addresses (>= 0); nodes with no ELF symbol get negative keys.

    def callers(self) -> dict[int, set[int]]:
        rev: dict[int, set[int]] = {}
        for a, bs in self.edges.items():
            for b in bs:
                rev.setdefault(b, set()).add(a)
        return rev

    def reachable(self, root: int) -> set[int]:
        seen, todo = {root}, [root]
        while todo:
            for c in self.edges.get(todo.pop(), ()):
                if c not in seen:
                    seen.add(c)
                    todo.append(c)
        return seen

    def node_name(self, key: int) -> str:
        return self.names.get(key, f"0x{key:x}" if key >= 0 else f"<node {key}>")


@dataclass
class StackEstimate:
    bound: int
    reliable: bool
    path: list[int]
    issues: list[str]


# ------------------------------------------------------------------ .ci (compiler metadata)

_STR = r'"((?:[^"\\]|\\.)*)"'
_TITLE = re.compile(r"title:\s*" + _STR)
_LABEL = re.compile(r"label:\s*" + _STR)
_SRC = re.compile(r"sourcename:\s*" + _STR)
_DST = re.compile(r"targetname:\s*" + _STR)
_BYTES = re.compile(r"(\d+)\s+bytes\s+\(([\w, ]+)\)")
_DYN = re.compile(r"(\d+)\s+dynamic objects?")


def _unescape(s: str) -> str:
    return re.sub(r"\\(.)", lambda m: "\n" if m[1] == "n" else m[1], s)


@dataclass
class CiNode:
    title: str
    name: str
    location: str = ""
    stack: Optional[int] = None
    stack_kind: str = ""
    dyn_objects: int = 0
    defined: bool = False


def discover_ci_files(root: str | os.PathLike) -> list[Path]:
    found = []
    for d, _dirs, names in os.walk(root, followlinks=False):
        found += [Path(d) / n for n in names if n.lower().endswith(".ci")]
    return sorted(found)


def parse_ci_text(text: str, nodes: dict[str, CiNode], edges: set[tuple[str, str]]) -> int:
    """Parse one VCG ``.ci`` file into ``nodes``/``edges``. Returns the number of lines ignored."""
    bad = 0
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("node:"):
            t, lab = _TITLE.search(s), _LABEL.search(s)
            if not t:
                bad += 1
                continue
            title = _unescape(t[1])
            parts = _unescape(lab[1]).split("\n") if lab else [title]
            is_stub = bool(re.search(r"shape\s*:\s*ellipse", s))
            node = CiNode(title, parts[0], parts[1] if len(parts) > 1 else "", defined=not is_stub)
            for p in parts[2:]:
                b, d = _BYTES.search(p), _DYN.search(p)
                if b:
                    node.stack, node.stack_kind = int(b[1]), b[2].replace(" ", "").lower()
                if d:
                    node.dyn_objects = int(d[1])
            old = nodes.get(title)
            if old is None or (node.defined and not old.defined) or (node.stack is not None and old.stack is None):
                nodes[title] = node
        elif s.startswith("edge:"):
            a, b = _SRC.search(s), _DST.search(s)
            if a and b:
                edges.add((_unescape(a[1]), _unescape(b[1])))
            else:
                bad += 1
    return bad


def _pick(cands: list[Symbol]) -> Optional[Symbol]:
    addrs = {c.address for c in cands}
    if len(addrs) == 1:
        return sorted(cands, key=lambda c: (c.alias_of is not None, c.id))[0]
    non_local = [c for c in cands if c.bind != "LOCAL"]
    if len({c.address for c in non_local}) == 1 and non_local:
        return non_local[0]
    return None


def build_call_graph_from_ci(elf: ElfModel, ci_files: list[Path], progress: Progress = None) -> CallGraph:
    """Build the graph from compiler ``.ci`` files and map node titles to ELF function symbols."""
    g = CallGraph(origin="compiler call-graph info (.ci)")
    nodes: dict[str, CiNode] = {}
    edges: set[tuple[str, str]] = set()
    bad = 0
    for i, p in enumerate(ci_files):
        if i % 50 == 0 and progress:
            progress(f"Reading call-graph info ({i}/{len(ci_files)})...")
        try:
            bad += parse_ci_text(p.read_text(encoding="utf-8", errors="replace"), nodes, edges)
        except OSError as exc:
            g.warnings.append(f"Cannot read {p}: {exc}")
    if bad:
        g.warnings.append(f"{bad} unparsable line(s) in .ci files were ignored.")
    if elf.elf_type and "REL" in elf.elf_type:
        g.warnings.append("Relocatable object: addresses overlap, call graph mapping is unreliable.")
    funcs = [s for s in elf.symbols if s.kind == SymKind.FUNCTION]
    by_name: dict[str, list[Symbol]] = {}
    by_dem: dict[str, list[Symbol]] = {}
    by_stripped: dict[str, list[Symbol]] = {}
    for s in funcs:
        by_name.setdefault(s.name, []).append(s)
        if s.demangled:
            by_dem.setdefault(s.demangled, []).append(s)
        st = strip_clone_suffix(s.name)
        if st != s.name:
            by_stripped.setdefault(st, []).append(s)

    key_of: dict[str, int] = {}
    neg = [0]
    ambiguous = []

    def resolve(title: str) -> int:
        if title in key_of:
            return key_of[title]
        node = nodes.get(title)
        name = node.name if node else title
        sym: Optional[Symbol] = None
        c = by_name.get(title)
        if c:
            sym = _pick(c)
            if sym is None:
                ambiguous.append(title)
        elif ":" in title:  # static function: "<source path>:<name>"
            path, _, nm = title.rpartition(":")
            loc = by_name.get(nm, [])
            local = [s for s in loc if s.bind == "LOCAL"]
            base = os.path.basename(path.replace("\\", "/"))
            same = [s for s in local if os.path.basename((s.file_hint or s.source_file or "").replace("\\", "/")) == base]
            sym = _pick(same) if same else (_pick(local) if len(local) == 1 else None)
            if sym is None and local:
                ambiguous.append(title)
        if sym is None:
            for table, key in ((by_dem, name), (by_stripped, title)):
                c = table.get(key)
                if c and _pick(c):
                    sym = _pick(c)
                    break
        if sym is not None:
            k = sym.address
            g.names.setdefault(k, sym.display_name)
        else:
            neg[0] -= 1
            k = neg[0]
            g.names[k] = name
            g.unresolved += 1
        key_of[title] = k
        return k

    for title, node in nodes.items():
        if title == "__indirect_call":
            continue
        k = resolve(title)
        if node.stack is not None and node.defined:
            kind = "dynamic_bounded" if "bounded" in node.stack_kind else ("dynamic" if "dynamic" in node.stack_kind else "static")
            if node.dyn_objects and kind == "static":
                kind = "dynamic"
            g.stack_hint[k] = (node.stack, kind)
    for a, b in edges:
        if a == "__indirect_call":
            continue
        ka = resolve(a)
        if b == "__indirect_call":
            g.indirect.add(ka)
            continue
        g.edges.setdefault(ka, set()).add(resolve(b))
    if ambiguous:
        g.warnings.append(f"{len(set(ambiguous))} node(s) could not be uniquely mapped to an ELF symbol "
                          f"(e.g. {sorted(set(ambiguous))[0]}) and are shown as unresolved.")
    if g.unresolved:
        g.warnings.append(f"{g.unresolved} node(s) have no ELF symbol (external, inlined away or removed by the linker).")
    g.warnings.append("Compiler call graph covers calls visible at compile time; interrupts and calls made from "
                      "assembly or other tools' code are not included.")
    return g


# ------------------------------------------------------------------ disassembly fallback

def build_call_graph(elf: ElfModel, cfg: ToolchainConfig, timeout: float = 300.0, progress: Progress = None) -> CallGraph:
    """Disassemble the whole image once and collect direct call/tail-call edges."""
    g = CallGraph(origin="disassembly (objdump heuristic)")
    exe = resolve_tool(cfg, "objdump", elf.machine)
    if not exe:
        g.warnings.append("objdump not found; cannot build a call graph from disassembly.")
        return g
    if progress:
        progress("Disassembling image for call graph...")
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
        t = _TARGET_RE.match(ops.strip().split(",")[-1].strip()) or _TARGET_RE.match(ops.strip())
        if mn in CALL_MNEMONICS:
            if t:
                g.edges.setdefault(current, set()).add(int(t["addr"], 16))
            else:
                g.indirect.add(current)
        elif mn in JUMP_MNEMONICS and t:
            tgt = int(t["addr"], 16)
            if tgt != current and tgt in func_starts:  # jump to another function's entry = tail call
                g.edges.setdefault(current, set()).add(tgt)
    g.warnings.append("Call graph is derived from disassembly: calls through function pointers and vtables are "
                      "not resolved; interrupt handlers are not connected to their callers. Compile with "
                      "-fcallgraph-info=su,da (GCC 10+) for compiler-accurate data.")
    return g


# ------------------------------------------------------------------ stack estimation

def stack_lookup(graph: CallGraph, symbols: list[Symbol]) -> dict[int, tuple[int, str, str]]:
    """key -> (bytes, kind, source). .su-matched values win; .ci values fill the gaps."""
    out: dict[int, tuple[int, str, str]] = {}
    for s in symbols:
        if s.kind == SymKind.FUNCTION and s.stack_bytes is not None and s.stack_confidence in ("exact", "approximate"):
            out.setdefault(s.address, (s.stack_bytes, s.stack_kind or "unknown",
                                       ".su" if s.stack_confidence == "exact" else ".su (approximate match)"))
    for k, (b, kind) in graph.stack_hint.items():
        out.setdefault(k, (b, kind, ".ci"))
    return out


def estimate_worst_case(graph: CallGraph, symbols: list[Symbol], root: int,
                        lookup: Optional[dict] = None) -> StackEstimate:
    """Longest-path stack estimate from ``root``. ``reliable`` is False when any limitation applies."""
    stack = lookup if lookup is not None else stack_lookup(graph, symbols)
    issues: list[str] = []
    seen_issue: set[str] = set()
    memo: dict[int, tuple[int, list[int]]] = {}
    visiting: set[int] = set()

    def note(msg: str) -> None:
        if msg not in seen_issue:
            seen_issue.add(msg)
            issues.append(msg)

    def visit(a: int) -> tuple[int, list[int]]:
        if a in memo:
            return memo[a]
        nm = graph.node_name(a)
        if a in visiting:
            note(f"recursion through {nm}: depth unbounded")
            return 0, []
        visiting.add(a)
        info = stack.get(a)
        own = 0
        if info is None:
            note(f"no stack data for {nm}")
        else:
            own, kind, src = info[0], info[1], info[2]
            if kind == "dynamic":
                note(f"{nm} uses dynamic stack (unbounded)")
            elif kind == "dynamic_bounded":
                note(f"{nm} uses dynamic stack (bounded value used)")
            elif "approximate" in src:
                note(f"stack value of {nm} was matched approximately")
        if a in graph.indirect:
            note(f"{nm} makes indirect calls (targets unknown)")
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
        total, path = visit(root)
    except RecursionError:
        note("call chain too deep to analyse")
        total, path = 0, [root]
    finally:
        sys.setrecursionlimit(old)
    hard = [i for i in issues if not i.endswith("(bounded value used)") and "approximately" not in i]
    return StackEstimate(total, reliable=not hard, path=path, issues=issues)


def apply_ci_stack(symbols: list[Symbol], graph: CallGraph) -> int:
    """Fill stack usage for functions that have no .su match, using exact compiler .ci data. Returns count."""
    n = 0
    for s in symbols:
        if s.kind == SymKind.FUNCTION and s.stack_confidence in ("unavailable", "ambiguous") and s.address in graph.stack_hint:
            b, kind = graph.stack_hint[s.address]
            s.stack_bytes, s.stack_kind, s.stack_confidence = b, kind, "exact"
            s.stack_source, s.stack_note = ".ci (compiler call-graph info)", "from -fcallgraph-info node"
            n += 1
    return n


def to_dot(graph: CallGraph, symbols: list[Symbol], root: Optional[int] = None, max_nodes: int = 3000) -> str:
    """Graphviz DOT text (whole graph, or everything reachable from ``root``)."""
    look = stack_lookup(graph, symbols)
    keys = graph.reachable(root) if root is not None else set(graph.edges) | {b for bs in graph.edges.values() for b in bs}
    keys = set(sorted(keys)[:max_nodes])

    def q(s: str) -> str:
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    lines = ["digraph callgraph {", "  rankdir=LR; node [shape=box, fontname=monospace];"]
    for k in sorted(keys):
        st = look.get(k)
        label = graph.node_name(k) + (f"\\n{st[0]} B ({st[1]})" if st else "")
        extra = " style=dashed" if k < 0 else (" color=red" if k in graph.indirect else "")
        lines.append(f"  n{k + 10**12} [label={q(label).replace('\\\\n', '\\n')}{extra}];")
    for a in sorted(keys):
        for b in sorted(graph.edges.get(a, ())):
            if b in keys:
                lines.append(f"  n{a + 10**12} -> n{b + 10**12};")
    lines.append("}")
    return "\n".join(lines)
