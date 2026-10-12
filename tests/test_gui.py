import os
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")
from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import QApplication

from elfmem.gui.main_window import MainWindow
from elfmem.gui.tables import FUNCTION_COLUMNS, SymbolFilter, SymbolTableModel
from elfmem.models import Symbol, SymKind


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def wait_for(app, cond, timeout=20.0):
    end = time.time() + timeout
    while time.time() < end:
        app.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return False


@pytest.fixture()
def win(app, tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    QSettings.setPath(QSettings.Format.NativeFormat, QSettings.Scope.UserScope, str(tmp_path))
    w = MainWindow()
    w.show()
    yield w
    w._tasks.clear()
    w.close()


def test_open_inspect_disassemble_and_stack(app, win, build):
    win.open_elf(str(build.elf))
    assert wait_for(app, lambda: win.res is not None and win.res.debug is not None)
    assert win.fn_panel.model.rowCount() == len(win.res.functions) > 10
    assert win.data_panel.model.rowCount() == len(win.res.data_symbols)
    # search + sort
    win.fn_panel.search.setText("big_function")
    win.fn_panel._apply()
    assert win.fn_panel.model.rowCount() == 1
    win.fn_panel.select_symbol(win.fn_panel.model.symbol_at(0).id)
    assert win.inspector.current.name == "big_function"
    # disassembly arrives asynchronously
    assert wait_for(app, lambda: "push" in win.inspector.asm.edit.toPlainText() or "sub" in win.inspector.asm.edit.toPlainText())
    txt = win.inspector.asm.edit.toPlainText()
    assert "; ---- big_function" in txt and "main.c:" in txt
    win.inspector.asm.search.setText("ret")
    win.inspector.asm.find(True)
    assert win.inspector.asm.edit.textCursor().hasSelection()
    # stack usage via build dir
    win.load_build_dir(str(build.root))
    assert wait_for(app, lambda: win.res.su is not None)
    win.fn_panel.reset_filters()
    win.fn_panel.search.setText("big_function")
    win.fn_panel._apply()
    assert win.fn_panel.model.symbol_at(0).stack_confidence == "exact"
    assert win.stack_page.model.rowCount() == len(win.res.su.records)
    # treemap + navigation from chart to function
    win.viz.rebuild()
    assert win.viz.treemap.tile_count() > 5
    win.viz.treemap.resize(900, 600)
    win.viz.treemap._relayout()
    sid = next(s.id for s in win.res.functions if s.name == "main")
    win.show_symbol(sid)
    assert win.nav.currentRow() == 1 and win.inspector.current.name == "main"
    # regions via the memory map page
    win.mem_page.regions.setRowCount(0)
    win.mem_page._add_row("ROM", "0x0", "0x100000")
    win.mem_page._apply()
    assert any(u.region.name == "ROM" for u in win.res.memory.region_usage)
    win.grab().save(str(build.root / "shot_main.png"))


def test_bad_file_does_not_crash(app, win, tmp_path, monkeypatch):
    from PySide6.QtWidgets import QMessageBox
    shown = []
    monkeypatch.setattr(QMessageBox, "critical", lambda *a, **k: shown.append(a[2]))
    bad = tmp_path / "x.elf"
    bad.write_bytes(b"not an elf")
    win.open_elf(str(bad))
    assert wait_for(app, lambda: bool(shown))
    assert "not an ELF" in shown[0]


def _synthetic(n):
    return [Symbol(i, f"sym_{i}", 0x08000000 + i * 4, (i * 7919) % 5000 + 1, "FUNC", "GLOBAL", "DEFAULT", ".text",
                   SymKind.FUNCTION, search_blob=f"sym_{i}\n.text\n0x{0x08000000 + i * 4:08x}")
            for i in range(n)]


def test_large_symbol_list_filter_and_sort_stay_fast(app):
    syms = _synthetic(100_000)
    m = SymbolTableModel(FUNCTION_COLUMNS)
    t0 = time.perf_counter()
    m.set_symbols(syms)
    m.sort(0, Qt.SortOrder.AscendingOrder)
    m.set_filter(SymbolFilter(text="sym_99 text", min_size=100))
    elapsed = time.perf_counter() - t0
    assert elapsed < 3.0, f"too slow: {elapsed:.2f}s"
    assert 0 < m.rowCount() < 100_000


def test_treemap_with_thousands_of_items(app):
    from elfmem.gui.charts import TreemapWidget
    from elfmem.visualization import TreeItem
    items = [TreeItem(f"f{i}", (i * 31) % 900 + 1, f".s{i % 4}", i) for i in range(30_000)]
    w = TreemapWidget()
    w.resize(1000, 700)
    t0 = time.perf_counter()
    w.set_items(items, True)
    w.grab()
    assert time.perf_counter() - t0 < 6.0
    assert w.tile_at(5, 20) is not None or w.tile_count() > 0


# ---------------------------------------------------------------- regressions from user feedback
def _load(app, win, build, with_stack=False):
    win.open_elf(str(build.elf))
    assert wait_for(app, lambda: win.res is not None and win.res.debug is not None)
    if with_stack:
        win.load_build_dir(str(build.root))
        assert wait_for(app, lambda: win.res.su is not None and win._graph is not None)


def test_window_stays_resizable_after_selecting_function(app, win, build):
    from PySide6.QtCore import Qt
    _load(app, win, build)
    win.nav.setCurrentRow(1)
    win.show_symbol(next(s.id for s in win.res.functions if s.name == "main"))
    wait_for(app, lambda: False, 0.3)
    for page in range(len(win.pages)):
        win.nav.setCurrentRow(page)
        app.processEvents()
        # every page together with the dock must fit on a 1366px laptop screen
        assert win.minimumSizeHint().width() <= 1300, (page, win.minimumSizeHint().width())
    win.nav.setCurrentRow(1)
    win.resize(1500, 900)
    win.resizeDocks([win.dock], [650], Qt.Orientation.Horizontal)
    app.processEvents()
    assert win.dock.width() >= 600
    win.resizeDocks([win.dock], [300], Qt.Orientation.Horizontal)
    app.processEvents()
    assert win.dock.width() <= 340


def test_dock_can_float_and_be_pinned_back_and_reset(app, win, build):
    from PySide6.QtCore import Qt
    _load(app, win, build)
    win.dock.setFloating(True)
    app.processEvents()
    assert win.dock.isFloating()
    win.dock.setFloating(False)
    app.processEvents()
    assert not win.dock.isFloating() and win.dockWidgetArea(win.dock) == Qt.DockWidgetArea.RightDockWidgetArea
    win.dock.setFloating(True)
    win.reset_layout()
    app.processEvents()
    assert not win.dock.isFloating() and win.dock.isVisible()


def test_initial_value_view_for_data_symbols(app, win, build):
    _load(app, win, build)
    ids = {s.name: s.id for s in win.res.data_symbols}
    win.show_symbol(ids["counter"])
    app.processEvents()
    assert win.inspector.tabs.tabText(1) == "Initial value"
    dv = win.inspector.data_view
    assert win.inspector.view_stack.currentWidget() is dv
    assert "05 00 00 00" in dv.edit.toPlainText() and "unsigned 5" in dv.hints.text()
    win.show_symbol(ids["message"])
    assert "hello embedded" in dv.hints.text() and "68 65 6c 6c" in dv.edit.toPlainText()
    win.show_symbol(ids["zeroed_buffer"])
    assert "NOBITS" in dv.info.text() and "1,024 bytes" in dv.edit.toPlainText()
    win.show_symbol(next(s.id for s in win.res.functions if s.name == "main"))
    assert win.inspector.tabs.tabText(1) == "Assembly" and win.inspector.view_stack.currentWidget() is win.inspector.asm


def test_new_elf_resets_build_dir_stack_and_graph(app, win, build, arm_elf):
    _load(app, win, build, with_stack=True)
    assert win.stack_page.dir_edit.text() and win.stack_page.model.rowCount() > 0
    win.open_elf(str(arm_elf))
    assert wait_for(app, lambda: win.res is not None and win.res.elf.machine == "EM_ARM")
    assert win.stack_page.dir_edit.text() == "" and win.stack_page.model.rowCount() == 0
    assert win.res.su is None and win._graph is None and win.cg_page.graph is None
    assert all(s.stack_bytes is None for s in win.res.functions)


def test_map_file_next_to_elf_is_imported_and_remembered_per_elf(app, win, build, tmp_path, arm_elf):
    import shutil
    elf = tmp_path / "fw2.elf"
    shutil.copy(build.elf, elf)
    (tmp_path / "fw2.map").write_text("Memory Configuration\n\nName Origin Length Attributes\nALL 0x0 0x100000 xrw\n"
                                      "*default* 0x0 0xffffffff\n\nLinker script and memory map\n")
    win.open_elf(str(elf))
    assert wait_for(app, lambda: win.res is not None and win.res.elf.path == str(elf))
    assert [u.region.name for u in win.res.memory.region_usage] == ["ALL"]
    assert win.mem_page.regions.rowCount() == 1 and "imported from fw2.map" in win.mem_page.msg.text()
    win.open_elf(str(arm_elf))      # a different firmware must not inherit these regions
    assert wait_for(app, lambda: win.res is not None and win.res.elf.machine == "EM_ARM")
    assert win.res.memory.region_usage == [] and win.mem_page.regions.rowCount() == 0


def test_call_graph_page_from_ci(app, win, build):
    _load(app, win, build, with_stack=True)
    assert win._graph.origin.startswith("compiler")
    sid = next(s.id for s in win.res.functions if s.name == "main")
    win.show_symbol(sid)
    win.show_callgraph_for_selected()
    app.processEvents()
    top = win.cg_page.tree.topLevelItem(0)
    assert top.text(0) == "main"
    win.cg_page.tree.expandItem(top)
    names = [top.child(i).text(0) for i in range(top.childCount())]
    assert "big_function" in names and "fact" in names
    fact = next(top.child(i) for i in range(top.childCount()) if top.child(i).text(0) == "fact")
    win.cg_page.tree.expandItem(fact)
    assert "recursion" in fact.child(0).text(3)
    assert "Issues" in win.cg_page.summary.toHtml()


def test_toolchain_folder_scan_fills_fields(app, win, tmp_path):
    import stat
    root = tmp_path / "tc" / "bin"
    root.mkdir(parents=True)
    for t in ("objdump", "nm", "readelf", "c++filt", "gcc"):
        f = root / f"tricore-elf-{t}"
        f.write_text("#!/bin/sh\n")
        f.chmod(f.stat().st_mode | stat.S_IXUSR)
    tp = win.tool_page
    tp.tc_dir.setText(str(tmp_path / "tc"))
    tp._scan()
    assert tp.edits["objdump"].text().endswith("tricore-elf-objdump") and tp.edits["compiler"].text().endswith("tricore-elf-gcc")
    cfg = tp.config()
    assert cfg.toolchain_dir == str(tmp_path / "tc") and cfg.tool_prefix == "tricore-elf-"
