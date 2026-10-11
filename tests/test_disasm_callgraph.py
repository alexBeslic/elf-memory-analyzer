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
