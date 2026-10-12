import subprocess

from elfmem import analysis as an
from elfmem.callgraph import build_call_graph, estimate_worst_case
from elfmem.disassembler import disassemble, format_disassembly, function_bounds, parse_objdump
from elfmem.toolchain import ToolchainConfig

SAMPLE = """
Disassembly of section .text:

0000000008000000 <thumb_fn>:
 8000000:\tb580      \tpush\t{r7, lr}
 8000002:\tf000 f804 \tbl\t800000e <other>\t; call
 8000006:\t00 00 00 00 00 00 00 00
 800000a:\t00 00
"""


def test_parse_objdump_text():
    ins = parse_objdump(SAMPLE)
    assert [i.mnemonic for i in ins] == ["push", "bl"]
    assert ins[0].operands == "{r7, lr}" and ins[1].operands.startswith("800000e <other>")
    assert ins[1].comment == "call" and "00 00" in ins[1].raw


def test_disassembly_matches_objdump(build):
    res = an.analyze_elf(str(build.elf))
    sym = next(s for s in res.functions if s.name == "big_function")
    start, end, est = function_bounds(sym, res.elf)
    assert not est and end - start == sym.size
    d = disassemble(str(build.elf), start, end, ToolchainConfig(), res.elf.machine)
    assert d.ok and d.instructions[0].address == sym.address
    assert d.instructions[-1].address < end
    ref = subprocess.run(["objdump", "-d", f"--disassemble=big_function", str(build.elf)], capture_output=True,
                         text=True).stdout
    ref_addrs = [i.address for i in parse_objdump(ref)]
    assert [i.address for i in d.instructions] == ref_addrs
    text, addr_line = format_disassembly(d.instructions)
    assert text.count("\n") + 1 == len(d.instructions) and f"{sym.address:08x}:" in text


def test_source_interleaving_with_dwarf(build):
    res = an.analyze_elf(str(build.elf))
    dbg = an.load_debug(str(build.elf))
    an.apply_debug(res, dbg)
    sym = next(s for s in res.functions if s.name == "big_function")
    assert sym.source_file.endswith("main.c") and sym.source_line == 9
    d = disassemble(str(build.elf), sym.address, sym.end, ToolchainConfig(), res.elf.machine)
    lines = dbg.lines_in_range(sym.address, sym.end)
    assert lines
    text, _ = format_disassembly(d.instructions, lines, lambda f, l: "SRC")
    assert "; main.c:" in text
    var = next(s for s in res.data_symbols if s.name == "counter")
    assert var.source_file.endswith("main.c") and var.source_line == 2   # DWARF-confirmed variable


def test_missing_objdump_gives_troubleshooting(build):
    res = an.analyze_elf(str(build.elf))
    cfg = ToolchainConfig(objdump="/nonexistent/objdump")
    d = disassemble(str(build.elf), 0x1000, 0x1010, cfg, "EM_ARM")
    assert not d.ok and d.error and d.troubleshooting
    assert any("arm-none-eabi-objdump" in t for t in d.troubleshooting)


def test_wrong_arch_objdump_explained(arm_elf):
    res = an.analyze_elf(str(arm_elf))
    d = disassemble(str(arm_elf), 0x08000000, 0x08000008, ToolchainConfig(), "EM_ARM")
    # host objdump usually cannot decode ARM: must fail with actionable text, never crash
    assert d.ok or (d.error and d.troubleshooting)


def test_zero_size_bounds_are_flagged(arm_elf):
    res = an.analyze_elf(str(arm_elf))
    sym = next(s for s in res.functions if s.name == "zero_size_fn")
    start, end, est = function_bounds(sym, res.elf)
    assert est and end == 0x08000010


def test_call_graph_and_recursion_is_not_invented(build):
    res = an.analyze_elf(str(build.elf))
    an.apply_stack(res, an.load_stack_reports(str(build.root)))
    g = build_call_graph(res.elf, ToolchainConfig())
    addr = {s.name: s.address for s in res.functions if s.bind != "LOCAL"}
    assert addr["big_function"] in g.edges[addr["main"]]
    assert addr["helper_a"] in g.edges[addr["big_function"]]
    est = estimate_worst_case(g, res.elf.symbols, addr["big_function"])
    assert est.bound > 0 and est.path[0] == addr["big_function"]
    rec = estimate_worst_case(g, res.elf.symbols, addr["fact"])
    assert not rec.reliable and any("recursion" in i for i in rec.issues)
    top = estimate_worst_case(g, res.elf.symbols, addr["main"])
    assert not top.reliable  # libc callees have no stack data: reported, not hidden


# ---------------------------------------------------------------- compiler call-graph info (.ci)
from elfmem.callgraph import (apply_ci_stack, build_call_graph_from_ci, discover_ci_files, parse_ci_text, stack_lookup,
                              to_dot)


def _ci_graph(build, apply_su=True):
    res = an.analyze_elf(str(build.elf))
    if apply_su:
        an.apply_stack(res, an.load_stack_reports(str(build.root)))
    g = build_call_graph_from_ci(res.elf, discover_ci_files(build.root))
    return res, g


def test_ci_discovery_and_static_function_identity(build):
    assert {p.name for p in discover_ci_files(build.root)} == {"main.ci", "other.ci", "cxx.ci"}
    res, g = _ci_graph(build)
    f = {s.name: s for s in res.functions if s.bind != "LOCAL"}
    dups = {s.file_hint: s for s in res.functions if s.name == "dup_name"}
    assert g.origin.startswith("compiler")
    # two same-named statics are told apart by the .ci title "<path>:<name>"
    assert dups["main.c"].address in g.edges[f["big_function"].address]
    assert dups["other.c"].address in g.edges[f["helper_a"].address]
    assert dups["other.c"].address not in g.edges[f["big_function"].address]
    assert f["fact"].address in g.edges[f["fact"].address]               # self recursion
    assert f["call_ptr"].address in g.indirect and f["main"].address not in g.indirect
    assert g.stack_hint[f["big_function"].address][0] == f["big_function"].stack_bytes   # agrees with .su


def test_ci_estimate_flags_recursion_indirect_and_external(build):
    res, g = _ci_graph(build)
    f = {s.name: s for s in res.functions if s.bind != "LOCAL"}
    est = estimate_worst_case(g, res.elf.symbols, f["fact"].address)
    assert not est.reliable and any("recursion" in i for i in est.issues)
    est = estimate_worst_case(g, res.elf.symbols, f["call_ptr"].address)
    assert not est.reliable and any("indirect" in i for i in est.issues)
    est = estimate_worst_case(g, res.elf.symbols, f["helper_b"].address)
    assert est.bound == f["helper_b"].stack_bytes and est.reliable


def test_ci_stack_without_su_and_dot_export(build):
    res, g = _ci_graph(build, apply_su=False)
    assert all(s.stack_bytes is None for s in res.functions)
    n = apply_ci_stack(res.elf.symbols, g)
    assert n >= 8
    big = next(s for s in res.functions if s.name == "big_function")
    assert big.stack_confidence == "exact" and big.stack_source.startswith(".ci") and big.stack_bytes >= 256
    dot = to_dot(g, res.elf.symbols, big.address)
    assert dot.startswith("digraph") and "->" in dot and "big_function" in dot and "304 B" in dot.replace(str(big.stack_bytes), "304")


def test_ci_parser_tolerates_garbage():
    nodes, edges = {}, set()
    bad = parse_ci_text('graph: { title: "x"\nnode: { oops }\nedge: { sourcename: "a" }\nnode: { title: "a" label: "a\\nf.c:1:1\\n8 bytes (static)\\n0 dynamic objects" }\n}', nodes, edges)
    assert bad == 2 and nodes["a"].stack == 8 and nodes["a"].defined


def test_disassembly_and_ci_graphs_agree_on_direct_calls(build):
    res, ci = _ci_graph(build)
    dis = build_call_graph(res.elf, ToolchainConfig())
    f = {s.name: s for s in res.functions if s.bind != "LOCAL"}
    for a, b in (("main", "big_function"), ("main", "fact"), ("big_function", "helper_a")):
        assert f[b].address in ci.edges[f[a].address] and f[b].address in dis.edges[f[a].address]
