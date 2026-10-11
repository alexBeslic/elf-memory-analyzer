import subprocess

import pytest

from elfmem.elf_parser import ElfLoadError, load_elf
from elfmem.models import SymKind


def nm_sizes(path):
    out = subprocess.run(["nm", "-S", "--defined-only", str(path)], capture_output=True, text=True, check=True).stdout
    res = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 4:
            res[parts[3]] = (int(parts[0], 16), int(parts[1], 16), parts[2])
    return res


def test_metadata_matches_readelf(build):
    elf = load_elf(build.elf)
    hdr = subprocess.run(["readelf", "-h", str(build.elf)], capture_output=True, text=True).stdout
    assert elf.elf_class == 64 and elf.endianness == "little"
    assert elf.machine == "EM_X86_64"
    assert f"0x{elf.entry:x}" in hdr
    assert elf.has_symtab and elf.has_debug_info and elf.has_debug_line
    assert elf.file_size == build.elf.stat().st_size
    assert len(elf.sections) > 10 and elf.segments


def test_symbol_addresses_and_sizes_match_nm(build):
    elf = load_elf(build.elf)
    ref = nm_sizes(build.elf)
    checked = 0
    for s in elf.symbols:
        if s.sym_type in ("FUNC", "OBJECT") and s.name in ref and s.bind != "LOCAL":
            addr, size, _t = ref[s.name]
            assert (s.address, s.size) == (addr, size), s.name
            checked += 1
    assert checked >= 8


def test_function_and_data_extraction(build):
    elf = load_elf(build.elf)
    by = {s.name: s for s in elf.symbols}
    assert by["main"].kind == SymKind.FUNCTION and by["main"].size > 0
    assert by["big_function"].kind == SymKind.FUNCTION
    assert by["counter"].kind == SymKind.DATA and by["counter"].data_class == "initialized"
    assert by["counter"].size == 4
    assert by["zeroed_buffer"].data_class == "zero-initialized" and by["zeroed_buffer"].size == 1024
    assert by["message"].data_class == "read-only"
    assert by["weak_fn"].bind == "WEAK"


def test_static_duplicates_keep_translation_unit_hint(build):
    elf = load_elf(build.elf)
    dups = [s for s in elf.symbols if s.name == "dup_name"]
    assert len(dups) == 2
    assert {d.file_hint for d in dups} == {"main.c", "other.c"}
    assert all(d.bind == "LOCAL" for d in dups)


def test_section_categories(build):
    elf = load_elf(build.elf)
    cat = {s.name: s.category for s in elf.sections}
    assert cat[".text"] == "code" and cat[".data"] == "data" and cat[".bss"] == "bss"
    assert cat[".rodata"] == "rodata" and cat[".debug_info"] == "debug" and cat[".symtab"] == "non_alloc"


def test_stripped_elf_is_reported(build):
    elf = load_elf(build.stripped)
    assert elf.stripped and not elf.symbols
    assert any("stripped" in w.lower() for w in elf.warnings)
    assert any("DWARF" in w for w in elf.warnings)


def test_arm_thumb_zero_size_and_lma(arm_elf):
    elf = load_elf(arm_elf)
    by = {s.name: s for s in elf.symbols}
    assert elf.machine == "EM_ARM" and elf.elf_class == 32
    assert by["thumb_fn"].is_thumb and by["thumb_fn"].address == 0x08000000 and by["thumb_fn"].size == 8
    assert by["zero_size_fn"].size == 0 and any("zero-sized" in n for n in by["zero_size_fn"].notes)
    assert by["g_bss"].data_class == "zero-initialized"
    assert by["_estack"].kind == SymKind.OTHER
    data = elf.section_by_name(".data")
    assert data.addr == 0x20000000 and data.lma == 0x08000100  # runs in RAM, loaded from flash


def test_malformed_inputs(tmp_path, build):
    for name, content in (("empty", b""), ("text", b"hello world"), ("magic", b"\x7fELF"),
                          ("trunc", build.elf.read_bytes()[:200])):
        p = tmp_path / name
        p.write_bytes(content)
        with pytest.raises(ElfLoadError):
            load_elf(p)
    with pytest.raises(ElfLoadError):
        load_elf(tmp_path / "missing.elf")


def test_corrupted_header_does_not_crash(tmp_path, build):
    data = bytearray(build.elf.read_bytes())
    data[40:48] = b"\xff" * 8  # e_shoff garbage
    p = tmp_path / "bad.elf"
    p.write_bytes(bytes(data))
    try:
        load_elf(p)
    except ElfLoadError:
        pass
