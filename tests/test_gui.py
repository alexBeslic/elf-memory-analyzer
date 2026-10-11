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
