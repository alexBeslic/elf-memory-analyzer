import json
import os
import stat

import pytest

from elfmem import analysis as an
from elfmem.data_view import c_string, hexdump, read_symbol_bytes, summarize, values_text
from elfmem.memory_analyzer import MemoryRegion, region_for
from elfmem.region_import import (RegionImportError, import_regions, parse_json_text, parse_linker_script,
                                  parse_map_lines, parse_size, regions_to_json)
from elfmem.toolchain import ToolchainConfig, resolve_tool, scan_toolchain_dir


def sym(res, name):
    return next(s for s in res.elf.symbols if s.name == name)


def test_initial_values_from_real_elf(build):
    res = an.analyze_elf(str(build.elf))
    c = read_symbol_bytes(res.elf, sym(res, "counter"))
    assert c.state == "stored" and c.data == (5).to_bytes(4, "little")
    assert "file offset" in c.message
    m = read_symbol_bytes(res.elf, sym(res, "message"))
    assert m.data == b"hello embedded\0" and c_string(m.data) == "hello embedded"
    z = read_symbol_bytes(res.elf, sym(res, "zeroed_buffer"))
    assert z.state == "zero" and "NOBITS" in z.message and z.data == b""
    assert any("unsigned 5" in l for l in summarize(c.data, "little"))
    # cross-check against objdump -s
    import subprocess
    out = subprocess.run(["objdump", "-s", "-j", ".rodata", str(build.elf)], capture_output=True, text=True).stdout
    assert "68656c6c" in out.replace(" ", "")


def test_load_address_reported_for_data(arm_elf):
    res = an.analyze_elf(str(arm_elf))
    d = read_symbol_bytes(res.elf, sym(res, "g_data"))
    assert d.data == b"\x01\0\0\0" and "0x08000100" in d.message and "0x20000000" in d.message
    assert read_symbol_bytes(res.elf, sym(res, "g_bss")).state == "zero"
    assert read_symbol_bytes(res.elf, sym(res, "zero_size_fn")).state == "unavailable"


def test_formatting_helpers():
    data = bytes(range(32))
    assert hexdump(data, 0x1000).splitlines()[1].startswith("00001010")
    assert "0x03020100" in values_text(data, 0, 4, "hex", "little")
    assert "0x00010203" in values_text(data, 0, 4, "hex", "big")
    assert "-" in values_text(b"\xff\xff\xff\xff", 0, 4, "int", "little") and "1.5" in values_text(b"\x00\x00\xc0\x3f", 0, 4, "float", "little")
    assert c_string(b"abc\0") == "abc" and c_string(b"\x01\x02\0") is None and c_string(b"abc") is None
    assert any("All bytes are 0x00" in l for l in summarize(bytes(8), "little"))


MAP = """Archive member included...
foo.a(x.o)

Discarded input sections

Memory Configuration

Name             Origin             Length             Attributes
int_flash        0x80000000         0x00200000         xr
dsram            0x70000000         0x00030000         xrw
cached_flash     0x80000000         0x00100000         xr
*default*        0x00000000         0xffffffff

Linker script and memory map

.text  0x80000000 0x100
"""


def test_map_file_memory_configuration():
    r = parse_map_lines(MAP.splitlines(True))
    assert [(x.name, x.origin, x.length) for x in r.regions] == [
        ("int_flash", 0x80000000, 0x200000), ("dsram", 0x70000000, 0x30000), ("cached_flash", 0x80000000, 0x100000)]
    assert any("overlap" in w for w in r.warnings)
    assert region_for(0x80000010, r.regions) == "cached_flash"   # smallest containing region wins
    assert region_for(0x80150000, r.regions) == "int_flash"
    with pytest.raises(RegionImportError):
        parse_map_lines(["nothing here\n"])


def test_linker_script_and_json_and_files(tmp_path):
    ld = """/* c */ MEMORY { FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 512K
        RAM (rwx) : org = 0x20000000, len = 128K
        BAD : ORIGIN = _x + 1, LENGTH = 4 }"""
    r = parse_linker_script(ld)
    assert [(x.name, x.length) for x in r.regions] == [("FLASH", 512 * 1024), ("RAM", 128 * 1024)]
    assert r.warnings and "BAD" in r.warnings[0]
    j = regions_to_json(r.regions)
    again = parse_json_text(j)
    assert [x.to_dict() for x in again.regions] == [x.to_dict() for x in r.regions]
    assert parse_json_text('[{"name":"A","origin":"0x10","length":"2K"},{"name":"B"}]').regions[0].length == 2048
    for name, text in (("a.map", MAP), ("b.ld", ld), ("c.json", j), ("noext", MAP)):
        p = tmp_path / name
        p.write_text(text)
        assert import_regions(str(p)).regions, name
    (tmp_path / "junk.txt").write_text("hello")
    with pytest.raises(RegionImportError):
        import_regions(str(tmp_path / "junk.txt"))
    with pytest.raises(RegionImportError):
        import_regions(str(tmp_path / "missing.map"))
    assert parse_size("1M") == 1 << 20


def _fake_tool(path):
    path.write_text("#!/bin/sh\necho fake\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def test_toolchain_folder_scan_and_prefix_resolution(tmp_path):
    root = tmp_path / "tricore-gcc"
    (root / "bin").mkdir(parents=True)
    (root / "tricore-elf" / "bin").mkdir(parents=True)
    for t in ("objdump", "nm", "readelf", "c++filt", "gcc", "size", "gcc-nm", "gcc-ar"):
        _fake_tool(root / "bin" / f"tricore-elf-{t}")
    for t in ("objdump", "nm"):   # unprefixed duplicates in <target>/bin
        _fake_tool(root / "tricore-elf" / "bin" / t)
    (root / "bin" / "tricore-elf-objdump.txt").write_text("not a tool")
    cands = scan_toolchain_dir(str(root))
    assert cands[0].prefix == "tricore-elf-" and set(cands[0].tools) == {"objdump", "nm", "readelf", "cxxfilt", "compiler"}
    assert os.path.basename(cands[0].tools["compiler"]) == "tricore-elf-gcc"
    assert "" in [c.prefix for c in cands] and "tricore-elf-gcc-" not in [c.prefix for c in cands]
    cfg = ToolchainConfig(toolchain_dir=str(root))
    assert resolve_tool(cfg, "objdump").endswith("tricore-elf-objdump")
    cfg.tool_prefix = ""
    assert resolve_tool(cfg, "readelf").endswith("tricore-elf-readelf")
    cfg2 = ToolchainConfig(toolchain_dir=str(root), objdump="/explicit/objdump")
    assert resolve_tool(cfg2, "objdump") == "/explicit/objdump"
    assert scan_toolchain_dir(str(tmp_path / "nope")) == []
    assert scan_toolchain_dir(str(root / "bin" / "tricore-elf-nm"))[0].prefix == "tricore-elf-"  # file path accepted
