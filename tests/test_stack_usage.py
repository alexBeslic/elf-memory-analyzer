from elfmem import analysis as an
from elfmem.models import SymKind, Symbol
from elfmem.stack_usage import (base_name, discover_su_files, match_stack_usage, parse_su_directory,
                                parse_su_text)


def test_parse_gcc_tab_format():
    recs, bad = parse_su_text("main.c:12:5:foo\t32\tstatic\nmain.c:20:5:bar\t48\tdynamic,bounded\n"
                              "a.c:1:1:baz\t8\tdynamic\n")
    assert bad == 0
    assert [(r.name, r.size, r.kind, r.file, r.line) for r in recs] == [
        ("foo", 32, "static", "main.c", 12), ("bar", 48, "dynamic_bounded", "main.c", 20),
        ("baz", 8, "dynamic", "a.c", 1)]


def test_parse_whitespace_and_cxx_names():
    recs, bad = parse_su_text("function_name 32 static\nsrc/x.cpp:7:5:int ns::f(int) const\t16\tstatic\n"
                              "C:\\proj\\a.c:3:1:win_fn\t4\tstatic\n")
    assert bad == 0 and len(recs) == 3
    assert recs[0].name == "function_name" and recs[0].file is None
    assert recs[1].name == "int ns::f(int) const" and recs[1].file == "src/x.cpp"
    assert recs[2].file == "C:\\proj\\a.c" and recs[2].name == "win_fn"


def test_malformed_input_never_crashes():
    text = "garbage\n\n# comment\nfoo\tabc\tstatic\n\x00\x01\x02\nfoo 12\nonly:12:3:x\t5\n"
    recs, bad = parse_su_text(text)
    assert bad >= 3 and all(r.size >= 0 for r in recs)


def test_recursive_discovery_and_real_gcc_reports(build):
    files = discover_su_files(build.root)
    assert {f.name for f in files} == {"main.su", "other.su", "cxx.su"}
    parsed = parse_su_directory(str(build.root))
    assert len(parsed.files) == 3 and parsed.records
    names = {r.name for r in parsed.records}
    assert {"main", "big_function", "dup_name"} <= names
    assert any("scale" in n for n in names)  # C++ record carries demangled signature


def test_missing_dir_and_empty_dir(tmp_path):
    assert parse_su_directory(str(tmp_path / "nope")).warnings
    r = parse_su_directory(str(tmp_path))
    assert not r.records and r.warnings


def _fn(i, name, addr, file=None, demangled=None, bind="GLOBAL", alias_of=None):
    return Symbol(id=i, name=name, address=addr, size=16, sym_type="FUNC", bind=bind, visibility="DEFAULT",
                  section=".text", kind=SymKind.FUNCTION, demangled=demangled, file_hint=file, alias_of=alias_of)


def test_ambiguous_static_duplicates_not_guessed():
    recs, _ = parse_su_text("a.c:1:1:helper\t10\tstatic\nb.c:1:1:helper\t99\tstatic\n")
    syms = [_fn(0, "helper", 0x100, None, bind="LOCAL"), _fn(1, "helper", 0x200, None, bind="LOCAL")]
    res = match_stack_usage(syms, recs)
    assert res.matches[0].confidence == "ambiguous" and res.matches[0].record is None
    apply = res.matches
    assert apply[1].confidence == "ambiguous"


def test_file_hint_disambiguates():
    recs, _ = parse_su_text("src/a.c:1:1:helper\t10\tstatic\nother/b.c:1:1:helper\t99\tstatic\n")
    syms = [_fn(0, "helper", 0x100, "a.c", bind="LOCAL"), _fn(1, "helper", 0x200, "b.c", bind="LOCAL")]
    res = match_stack_usage(syms, recs)
    assert (res.matches[0].confidence, res.matches[0].record.size) == ("exact", 10)
    assert (res.matches[1].confidence, res.matches[1].record.size) == ("exact", 99)


def test_two_symbols_one_record_is_ambiguous_without_file_evidence():
    recs, _ = parse_su_text("a.c:1:1:helper\t10\tstatic\n")
    syms = [_fn(0, "helper", 0x100, None, bind="LOCAL"), _fn(1, "helper", 0x200, None, bind="LOCAL")]
    res = match_stack_usage(syms, recs)
    assert {m.confidence for m in res.matches.values()} == {"ambiguous"}


def test_clone_suffix_is_approximate_and_missing_is_unavailable():
    recs, _ = parse_su_text("a.c:1:1:work\t24\tstatic\na.c:9:1:never_linked\t8\tstatic\n")
    syms = [_fn(0, "work.constprop.0", 0x100), _fn(1, "no_record", 0x200)]
    res = match_stack_usage(syms, recs)
    assert res.matches[0].confidence == "approximate" and res.matches[0].record.size == 24
    assert res.matches[1].confidence == "unavailable"
    assert [r.name for r in res.unmatched_records] == ["never_linked"]


def test_cxx_overloads_exact_by_signature_and_alias_inherit():
    recs, _ = parse_su_text("c.cpp:2:5:app::scale(int)\t48\tstatic\nc.cpp:3:8:app::scale(double)\t16\tstatic\n")
    syms = [_fn(0, "_ZN3app5scaleEi", 0x100, demangled="app::scale(int)"),
            _fn(1, "_ZN3app5scaleEd", 0x200, demangled="app::scale(double)"),
            _fn(2, "scale_alias", 0x100, alias_of=0)]
    res = match_stack_usage(syms, recs)
    assert res.matches[0].record.size == 48 and res.matches[0].confidence == "exact"
    assert res.matches[1].record.size == 16 and res.matches[1].confidence == "exact"
    assert res.matches[2].confidence == "approximate" and res.matches[2].record.size == 48


def test_base_name():
    assert base_name("int ns::f<int>(int) const") == "ns::f<int>"
    assert base_name("ns::A::A()") == "ns::A::A"


def test_end_to_end_with_real_build(build):
    res = an.analyze_elf(str(build.elf))
    an.apply_debug(res, an.load_debug(str(build.elf)))
    an.apply_stack(res, an.load_stack_reports(str(build.root)))
    by = {}
    for s in res.functions:
        by.setdefault(s.name, []).append(s)
    big = by["big_function"][0]
    assert big.stack_confidence == "exact" and big.stack_bytes >= 256 and big.stack_kind == "static"
    dups = sorted(by["dup_name"], key=lambda s: s.file_hint)
    assert [d.file_hint for d in dups] == ["main.c", "other.c"]
    assert all(d.stack_confidence == "exact" for d in dups)
    assert dups[0].stack_bytes != dups[1].stack_bytes  # each got its own translation unit's record
    assert dups[1].stack_bytes >= 200
    scale = [s for s in res.functions if s.demangled and s.demangled.startswith("app::scale")]
    assert len(scale) == 2 and {s.stack_confidence for s in scale} <= {"exact", "approximate"}
    int_v = next(s for s in scale if s.demangled == "app::scale(int)")
    assert int_v.stack_bytes is not None and int_v.stack_bytes >= 32


def test_signature_key_drops_return_type_but_keeps_overload_params():
    from elfmem.stack_usage import signature_key
    assert signature_key("int app::scale(int)") == "app::scale(int)"
    assert signature_key("double app::scale(double)") == "app::scale(double)"
    assert signature_key("app::scale(int)") == "app::scale(int)"
    assert signature_key("int app::Widget::get() const") == "app::Widget::get() const"
    assert signature_key("plain_c_name") == "plain_c_name"
    assert signature_key("void (anonymous namespace)::f(int)") == "(anonymous namespace)::f(int)"
