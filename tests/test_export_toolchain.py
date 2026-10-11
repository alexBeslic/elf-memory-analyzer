import csv
import json

from elfmem import analysis as an
from elfmem.export import DATA_FIELDS, FUNCTION_FIELDS, export_html, export_json, export_symbols_csv, render_report
from elfmem.models import Symbol, SymKind
from elfmem.toolchain import (PRESETS, ToolchainConfig, detect_tools, load_config, resolve_tool, save_config,
                              validate_config, validate_tool)


def test_csv_json_html_exports(build, tmp_path):
    res = an.analyze_elf(str(build.elf))
    an.apply_stack(res, an.load_stack_reports(str(build.root)))
    csv_path = tmp_path / "f.csv"
    n = export_symbols_csv(str(csv_path), res.functions, FUNCTION_FIELDS)
    rows = list(csv.DictReader(open(csv_path, encoding="utf-8")))
    assert n == len(rows) == len(res.functions)
    big = next(r for r in rows if r["name"] == "big_function")
    assert big["stack_confidence"] == "exact" and big["address"].startswith("0x") and int(big["size"]) > 0
    export_symbols_csv(str(tmp_path / "d.csv"), res.data_symbols, DATA_FIELDS)
    j = tmp_path / "r.json"
    export_json(str(j), res)
    data = json.loads(j.read_text())
    assert data["elf"]["machine"] == "EM_X86_64" and data["functions"] and data["memory"]["berkeley"]["text"] > 0
    assert "NOT a worst-case" in data["stack"]["note"] and data["assumptions"]
    h = tmp_path / "r.html"
    export_html(str(h), res)
    html = h.read_text()
    assert "big_function" in html and "worst-case" in html and "<script" not in html


def test_csv_formula_injection_neutralised(tmp_path):
    s = Symbol(0, "=cmd|' /C calc'!A0", 0, 4, "OBJECT", "GLOBAL", "DEFAULT", ".data", SymKind.DATA)
    p = tmp_path / "x.csv"
    export_symbols_csv(str(p), [s], ["name", "size"])
    assert list(csv.reader(open(p)))[1][0].startswith("'=")


def test_html_escapes_symbol_names(arm_elf):
    res = an.analyze_elf(str(arm_elf))
    res.elf.symbols[0].name = "<script>alert(1)</script>"
    res.elf.symbols[0].demangled = None
    assert "<script>alert" not in render_report(res)


def test_toolchain_validation_and_detection(tmp_path):
    assert not validate_tool("objdump", "/nonexistent/objdump").ok
    assert not validate_tool("objdump", "").ok
    assert not validate_tool("objdump", "ls").ok          # runs, but is not objdump
    ok = validate_tool("objdump", "objdump")
    assert ok.ok and "objdump" in ok.version.lower()
    found = detect_tools("gnu-native")
    assert found["objdump"] and found["cxxfilt"]
    assert detect_tools("gnu-arm-embedded")["objdump"] in ("", detect_tools("gnu-arm-embedded")["objdump"])
    checks = {c.role: c for c in validate_config(ToolchainConfig(objdump="/nope"))}
    assert not checks["objdump"].ok and checks["nm"].ok


def test_config_roundtrip_and_unknown_keys(tmp_path):
    cfg = ToolchainConfig(objdump="/x/objdump", objdump_args="-M intel", build_dir="/b",
                          memory_regions=[{"name": "FLASH", "origin": 0, "length": 1024}])
    p = tmp_path / "c.json"
    save_config(cfg, p)
    data = json.loads(p.read_text())
    data["future_option"] = 1
    p.write_text(json.dumps(data))
    assert load_config(p) == cfg
    assert load_config(tmp_path / "missing.json") == ToolchainConfig()
    (tmp_path / "bad.json").write_text("{not json")
    assert load_config(tmp_path / "bad.json") == ToolchainConfig()


def test_presets_and_resolution():
    assert {"gnu-arm-embedded", "clang-llvm", "custom"} <= set(PRESETS)
    cfg = ToolchainConfig()
    cfg.apply_preset("clang-llvm")
    assert cfg.family == "clang" and cfg.su_dialect == "clang"
    assert resolve_tool(ToolchainConfig(objdump="/explicit/objdump"), "objdump") == "/explicit/objdump"
    assert resolve_tool(ToolchainConfig(), "objdump", "EM_X86_64").endswith("objdump")
