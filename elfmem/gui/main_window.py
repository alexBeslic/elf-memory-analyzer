"""Main application window: navigation, menus, background analysis orchestration."""
from __future__ import annotations

import hashlib
import linecache
import logging
import os
from typing import Callable, Optional

from PySide6.QtCore import QSettings, Qt
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import (QApplication, QDockWidget, QFileDialog, QLabel, QListWidget, QMainWindow, QMessageBox,
                               QProgressBar, QSizePolicy, QStackedWidget, QToolBar)

from .. import __version__
from .. import analysis as an
from ..callgraph import CallGraph, apply_ci_stack, build_call_graph, build_call_graph_from_ci, discover_ci_files
from ..disassembler import DisasmResult, disassemble, function_bounds
from ..export import DATA_FIELDS, FUNCTION_FIELDS, export_html, export_json
from ..memory_analyzer import MemoryRegion
from ..models import SymKind
from ..region_import import RegionImportError, import_regions
from ..toolchain import ToolchainConfig, config_dir, load_config, save_config
from .callgraph_page import CallGraphPage
from .inspector import Inspector
from .pages import LIMITATIONS, MemoryMapPage, OverviewPage, StackPage, ToolchainPage, VisualizationPage
from .symbol_panel import SymbolPanel
from .tables import DATA_COLUMNS, FUNCTION_COLUMNS
from .workers import Task

log = logging.getLogger(__name__)
PAGES = ["Overview", "Functions", "Global Data", "Memory Map", "Visualization", "Stack Analysis", "Call Graph", "Toolchain Settings"]


def _disasm_job(path: str, start: int, end: int, estimated: bool, cfg: ToolchainConfig, machine: str,
                progress=None) -> DisasmResult:
    d = disassemble(path, start, end, cfg, machine)
    d.end_estimated = estimated
    return d


def _build_dir_job(directory: str, progress=None):
    """Scan a build directory for .su stack reports and .ci call-graph files."""
    parsed = an.load_stack_reports(directory, progress)
    return parsed, discover_ci_files(directory)


def _ci_job(elf, ci_files, progress=None) -> CallGraph:
    return build_call_graph_from_ci(elf, ci_files, progress)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("ELF Memory Analyzer")
        self.resize(1500, 920)
        self.setAcceptDrops(True)
        self.settings = QSettings("elfmem", "elfmem")
        self.cfg = load_config()
        self.res: Optional[an.AnalysisResult] = None
        self._gen = 0
        self._tasks: set[Task] = set()
        self._busy = 0
        self._graph: Optional[CallGraph] = None
        self._ci_files: list = []
        self._addr_sym: dict[int, int] = {}

        self.overview = OverviewPage()
        self.fn_panel = SymbolPanel("Functions", FUNCTION_COLUMNS, FUNCTION_FIELDS, True, "functions")
        self.data_panel = SymbolPanel("Global data", DATA_COLUMNS, DATA_FIELDS, False, "data")
        self.mem_page = MemoryMapPage()
        self.viz = VisualizationPage()
        self.stack_page = StackPage()
        self.cg_page = CallGraphPage()
        self.tool_page = ToolchainPage(self.cfg)
        self.pages = [self.overview, self.fn_panel, self.data_panel, self.mem_page, self.viz, self.stack_page, self.cg_page,
                      self.tool_page]
        self.stack = QStackedWidget()
        for p in self.pages:
            self.stack.addWidget(p)
        self.nav = QListWidget()
        self.nav.addItems(PAGES)
        self.nav.setMinimumWidth(150)
        self.nav.setMaximumWidth(190)
        self.nav.currentRowChanged.connect(self._page_changed)
        self.nav.setCurrentRow(0)
        from PySide6.QtWidgets import QSplitter
        split = QSplitter()
        split.addWidget(self.nav)
        split.addWidget(self.stack)
        split.setStretchFactor(0, 0)
        split.setStretchFactor(1, 1)
        split.setSizes([165, 1100])
        self.setCentralWidget(split)

        self.inspector = Inspector()
        self.dock = QDockWidget("Inspector", self)
        self.dock.setObjectName("inspector")
        self.dock.setWidget(self.inspector)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.dock)
        self.dock.setMinimumWidth(260)

        self.state_label = QLabel("No ELF loaded")
        self.state_label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)  # long text must not widen the window
        self.state_label.setMinimumWidth(0)
        self.progress = QProgressBar(maximumWidth=160, maximum=0, visible=False)
        self.statusBar().addWidget(self.state_label, 1)
        self.statusBar().addPermanentWidget(self.progress)

        self._build_menus()
        self._wire()
        geo, st = self.settings.value("window/geometry"), self.settings.value("window/state")
        if geo:
            self.restoreGeometry(geo)
        if st:
            self.restoreState(st)
        # A floating/odd dock layout from an earlier session must never lock the window: always start docked.
        self.dock.setFloating(False)
        self.dock.show()

    # ------------------------------------------------------------------ setup
    def _act(self, text: str, slot: Callable, shortcut: str = "", tip: str = "") -> QAction:
        a = QAction(text, self)
        a.triggered.connect(lambda _c=False: slot())
        if shortcut:
            a.setShortcut(QKeySequence(shortcut))
        if tip:
            a.setStatusTip(tip)
        return a

    def _build_menus(self) -> None:
        self.act_open = self._act("Open ELF…", self.open_elf_dialog, "Ctrl+O", "Load an ELF file")
        self.act_build = self._act("Open build directory…", self.open_build_dialog, "Ctrl+Shift+O", "Load .su stack reports")
        self.act_reload = self._act("Reload", self.reload, "F5")
        self.act_csv_f = self._act("Export functions (CSV)…", self.fn_panel.export_csv)
        self.act_csv_d = self._act("Export global data (CSV)…", self.data_panel.export_csv)
        self.act_json = self._act("Export analysis (JSON)…", self.export_json)
        self.act_html = self._act("Export report (HTML)…", self.export_html)
        fm = self.menuBar().addMenu("&File")
        for a in (self.act_open, self.act_build, self.act_reload):
            fm.addAction(a)
        fm.addSeparator()
        for a in (self.act_csv_f, self.act_csv_d, self.act_json, self.act_html):
            fm.addAction(a)
        fm.addSeparator()
        fm.addAction(self._act("Quit", self.close, "Ctrl+Q"))
        vm = self.menuBar().addMenu("&View")
        for i, name in enumerate(PAGES):
            vm.addAction(self._act(name, lambda i=i: self.nav.setCurrentRow(i), f"Ctrl+{i + 1}"))
        vm.addSeparator()
        vm.addAction(self._act("Search in current page", self.focus_search, "Ctrl+F"))
        vm.addAction(self.dock.toggleViewAction())
        vm.addSeparator()
        vm.addAction(self._act("Reset window layout", self.reset_layout, tip="Re-dock the inspector and restore default columns"))
        vm.addAction(self._act("Reset all saved settings…", self.reset_all_settings))
        hm = self.menuBar().addMenu("&Help")
        hm.addAction(self._act("Interpreting results / limitations", self.show_limitations))
        hm.addAction(self._act("About", self.show_about))
        tb = QToolBar("Main")
        tb.setObjectName("toolbar")
        tb.setMovable(False)
        for a in (self.act_open, self.act_build, self.act_reload, self.act_json, self.act_html):
            tb.addAction(a)
        self.addToolBar(tb)

    def _wire(self) -> None:
        for p in (self.fn_panel, self.data_panel):
            p.symbol_selected.connect(self.on_symbol_selected)
            p.symbol_activated.connect(self.on_symbol_activated)
        self.inspector.disassemble_requested.connect(self.start_disassembly)
        self.viz.symbol_requested.connect(self.show_symbol)
        self.viz.section_requested.connect(self.show_section)
        self.mem_page.regions_changed.connect(self.on_regions_changed)
        self.stack_page.load_requested.connect(self.load_build_dir)
        self.stack_page.estimate_requested.connect(self.show_callgraph_for_selected)
        self.cg_page.use_selected_requested.connect(self.show_callgraph_for_selected)
        self.cg_page.rebuild_disasm_requested.connect(self.build_graph_from_disassembly)
        self.cg_page.reload_ci_requested.connect(self.reload_ci)
        self.cg_page.symbol_requested.connect(self.show_symbol_at_address)
        self.tool_page.config_changed.connect(self.on_config_changed)

    # ------------------------------------------------------------------ tasks
    def run_task(self, fn, *args, on_done, on_fail=None, busy: bool = True, message: str = "", **kw) -> Task:
        if busy:
            self._busy += 1
            self.progress.setVisible(True)
        if message:
            self.state_label.setText(message)

        def done(r):
            on_done(r)

        def fail(msg):
            (on_fail or self._task_failed)(msg)

        t = Task(fn, *args, on_done=done, on_fail=fail,
                 on_progress=(lambda m: self.state_label.setText(m)) if busy else None, parent=self, **kw)
        self._tasks.add(t)

        def finish(task):
            self._tasks.discard(task)
            if busy:
                self._busy -= 1
                self.progress.setVisible(self._busy > 0)
            task.deleteLater()
        t.done.connect(finish)
        from PySide6.QtCore import QThreadPool
        QThreadPool.globalInstance().start(t.worker)
        return t

    def _task_failed(self, msg: str) -> None:
        self.state_label.setText(f"Error: {msg}")
        QMessageBox.warning(self, "Operation failed", msg)

    # ------------------------------------------------------------------ open / load
    def open_elf_dialog(self) -> None:
        start = self.settings.value("last_dir", "")
        path, _ = QFileDialog.getOpenFileName(self, "Open ELF file", start, "ELF files (*.elf *.axf *.out *.o *.so);;All files (*)")
        if path:
            self.open_elf(path)

    def open_build_dialog(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Select build output directory", self.stack_page.dir_edit.text())
        if d:
            self.stack_page.set_directory(d)
            self.load_build_dir(d)

    def reload(self) -> None:
        if self.res:
            self.open_elf(self.res.elf.path)

    # ---- per-ELF session state (regions are device specific; build dir/graph belong to one build)
    @staticmethod
    def _session_key(path: str) -> str:
        return "session/" + hashlib.sha1(os.path.abspath(path).encode()).hexdigest()[:16]

    def _load_session_regions(self, path: str) -> tuple[list[MemoryRegion], str]:
        """Regions saved for this ELF, else regions found in a .map file next to it, else none."""
        import json
        raw = self.settings.value(self._session_key(path) + "/regions")
        if raw:
            try:
                return [MemoryRegion.from_dict(d) for d in json.loads(raw)], "saved for this ELF"
            except (ValueError, KeyError, TypeError):
                pass
        stem = os.path.splitext(path)[0]
        for cand in (stem + ".map", path + ".map"):
            if os.path.isfile(cand) and os.path.getsize(cand) < 300 * 1024 * 1024:
                try:
                    r = import_regions(cand)
                    if r.regions:
                        return r.regions, f"imported from {os.path.basename(cand)}"
                except RegionImportError:
                    continue
        return [], ""

    def _save_session_regions(self, regions: list) -> None:
        import json
        if self.res:
            self.settings.setValue(self._session_key(self.res.elf.path) + "/regions",
                                   json.dumps([r.to_dict() for r in regions]))

    def open_elf(self, path: str) -> None:
        self._gen += 1
        gen = self._gen
        self.settings.setValue("last_dir", os.path.dirname(path))
        # New ELF = clean slate: nothing from the previous firmware may leak into this one.
        self._graph, self._ci_files, self._addr_sym = None, [], {}
        self.res = None
        self.stack_page.set_directory("")
        self.stack_page.clear()
        self.cg_page.set_graph(None, [])
        self.cg_page.root = None
        regions, how = self._load_session_regions(path)
        self._region_note = f"Regions {how}" if how else ""
        self.mem_page.set_regions(regions)
        self.mem_page.msg.setText(f"{len(regions)} region(s) {how}." if regions else
                                  "No memory regions defined for this ELF. Import a .map / linker script / JSON, or add regions.")
        self.run_task(an.analyze_elf, path, self.cfg, regions, message=f"Loading {os.path.basename(path)}…",
                      on_done=lambda r: self._elf_loaded(gen, r), on_fail=self._load_failed)

    def _load_failed(self, msg: str) -> None:
        self.state_label.setText("Failed to load ELF")
        QMessageBox.critical(self, "Cannot load ELF", msg)

    def _elf_loaded(self, gen: int, res: an.AnalysisResult) -> None:
        if gen != self._gen:
            return
        self.res = res
        e = res.elf
        self.setWindowTitle(f"{os.path.basename(e.path)} - ELF Memory Analyzer")
        self.overview.show_result(res)
        self.fn_panel.set_symbols(res.functions)
        self.data_panel.set_symbols(res.data_symbols)
        self.mem_page.set_result(res)
        self.viz.set_result(res)
        self.stack_page.clear()
        self.inspector.current = None
        self.inspector.title.setText("No symbol selected")
        self._addr_sym = {}
        for sym in res.functions:
            if sym.alias_of is None:
                self._addr_sym.setdefault(sym.address, sym.id)
        self.cg_page.set_graph(None, res.elf.symbols)
        self.inspector.view_stack.setCurrentWidget(self.inspector.placeholder)
        self.state_label.setText(f"{os.path.basename(e.path)} - {len(e.symbols):,} symbols; ELF analysis complete"
                                 + (f". {self._region_note}" if getattr(self, "_region_note", "") else ""))
        if self.cfg.load_dwarf and e.has_debug_info:
            self.run_task(an.load_debug, e.path, message="Reading DWARF debug info…",
                          on_done=lambda d: self._debug_loaded(gen, d), on_fail=lambda m: self._soft_fail("DWARF", m))

    def _soft_fail(self, what: str, msg: str) -> None:
        self.state_label.setText(f"{what} failed: {msg}")
        if self.res:
            self.res.warnings.append(f"{what} analysis failed: {msg}")
            self.overview.show_result(self.res)

    def _debug_loaded(self, gen: int, dbg) -> None:
        if gen != self._gen or not self.res:
            return
        an.apply_debug(self.res, dbg)
        self._refresh_all("DWARF loaded")

    def load_build_dir(self, d: str) -> None:
        if not self.res:
            QMessageBox.information(self, "Load an ELF first", "Open an ELF file before loading stack reports.")
            return
        if not d or not os.path.isdir(d):
            QMessageBox.warning(self, "Invalid directory", f"Not a directory: {d!r}")
            return
        gen = self._gen
        self.stack_page.set_directory(d)
        self.run_task(_build_dir_job, d, message="Scanning build directory for .su / .ci files…",
                      on_done=lambda r: self._stack_loaded(gen, r), on_fail=lambda m: self._soft_fail("Stack usage", m))

    def _stack_loaded(self, gen: int, result) -> None:
        if gen != self._gen or not self.res:
            return
        parsed, ci_files = result
        an.apply_stack(self.res, parsed)
        self._ci_files = ci_files
        self.stack_page.set_result(self.res)
        msg = f"Stack usage loaded: {len(parsed.records):,} records from {len(parsed.files)} .su files"
        if ci_files:
            msg += f"; reading {len(ci_files)} .ci call-graph files…"
            self.run_task(_ci_job, self.res.elf, ci_files, message="Reading compiler call-graph info…",
                          on_done=lambda g: self._graph_ready(gen, g), on_fail=lambda m: self._soft_fail("Call graph", m))
        else:
            msg += ". No .ci files found (compile with -fcallgraph-info=su,da for a compiler call graph)"
        self._refresh_all(msg)

    def _graph_ready(self, gen: int, graph: CallGraph) -> None:
        if gen != self._gen or not self.res:
            return
        self._graph = graph
        n = apply_ci_stack(self.res.elf.symbols, graph)
        self.cg_page.set_graph(graph, self.res.elf.symbols)
        self._refresh_all(f"Call graph ready ({graph.origin}); {n} function(s) got stack data from .ci")
        self.stack_page.set_result(self.res)

    def reload_ci(self) -> None:
        d = self.stack_page.dir_edit.text().strip()
        if d and os.path.isdir(d):
            self.load_build_dir(d)
        else:
            QMessageBox.information(self, "No build directory", "Choose a build directory on the Stack Analysis page first.")

    def build_graph_from_disassembly(self) -> None:
        if not self.res:
            return
        gen = self._gen
        self.run_task(build_call_graph, self.res.elf, self.cfg, message="Building call graph from disassembly…",
                      on_done=lambda g: self._disasm_graph_ready(gen, g), on_fail=lambda m: self._soft_fail("Call graph", m))

    def _disasm_graph_ready(self, gen: int, graph: CallGraph) -> None:
        if gen != self._gen or not self.res:
            return
        if not graph.edges and graph.warnings:
            QMessageBox.warning(self, "Call graph", "\n".join(graph.warnings))
        self._graph = graph
        self.cg_page.set_graph(graph, self.res.elf.symbols)
        self._show_selected_in_graph()
        self.state_label.setText(f"Call graph built from disassembly ({sum(len(v) for v in graph.edges.values()):,} edges)")

    def _refresh_all(self, msg: str) -> None:
        if not self.res:
            return
        self.fn_panel.refresh()
        self.data_panel.refresh()
        self.overview.show_result(self.res)
        self.viz.set_result(self.res)
        self.inspector.refresh_details(self.res)
        self.state_label.setText(f"{os.path.basename(self.res.elf.path)} - {msg}")

    # ------------------------------------------------------------------ navigation
    def focus_search(self) -> None:
        w = self.stack.currentWidget()
        if hasattr(w, "focus_search"):
            w.focus_search()

    def on_symbol_selected(self, sid: int) -> None:
        if self.res:
            self.inspector.show_symbol(self.res, self.res.elf.symbols[sid])
            if self.stack.currentWidget() is self.cg_page:
                self._show_selected_in_graph()

    def _page_changed(self, row: int) -> None:
        self.stack.setCurrentIndex(row)
        if self.stack.currentWidget() is self.cg_page:
            self._show_selected_in_graph()

    def _show_selected_in_graph(self) -> bool:
        sym = self.inspector.current
        if self._graph is not None and sym is not None and sym.kind == SymKind.FUNCTION:
            return self.cg_page.show_root(sym.address)
        return False

    def show_callgraph_for_selected(self) -> None:
        if not self.res:
            return
        sym = self.inspector.current
        if sym is None or sym.kind != SymKind.FUNCTION:
            QMessageBox.information(self, "Select a function", "Select a function on the Functions page first.")
            return
        self.nav.setCurrentRow(PAGES.index("Call Graph"))
        if self._graph is None:
            self.build_graph_from_disassembly()   # no .ci data loaded: fall back to disassembly
        else:
            self._show_selected_in_graph()

    def show_symbol_at_address(self, addr: int) -> None:
        sid = self._addr_sym.get(addr)
        if sid is not None:
            self.show_symbol(sid)

    def on_symbol_activated(self, sid: int) -> None:
        self.on_symbol_selected(sid)
        self.dock.show()
        sym = self.res.elf.symbols[sid] if self.res else None
        if sym and sym.kind in (SymKind.FUNCTION, SymKind.DATA):
            self.inspector.tabs.setCurrentWidget(self.inspector.view_stack)

    def show_symbol(self, sid: int) -> None:
        if not self.res:
            return
        sym = self.res.elf.symbols[sid]
        panel, row = (self.fn_panel, 1) if sym.kind == SymKind.FUNCTION else (self.data_panel, 2)
        self.nav.setCurrentRow(row)
        if not panel.select_symbol(sid):
            self.inspector.show_symbol(self.res, sym)
        self.dock.show()

    def show_section(self, name: str) -> None:
        self.nav.setCurrentRow(3)
        self.mem_page.select_section(name)

    # ------------------------------------------------------------------ disassembly
    def start_disassembly(self, sid: int) -> None:
        if not self.res:
            return
        sym = self.res.elf.symbols[sid]
        start, end, est = function_bounds(sym, self.res.elf)
        self.run_task(_disasm_job, self.res.elf.path, start, end, est, self.cfg, self.res.elf.machine, busy=False,
                      on_done=lambda d: self._disasm_done(sid, d), on_fail=lambda m: self._disasm_failed(sid, m))

    def _disasm_failed(self, sid: int, msg: str) -> None:
        if self.inspector.current and self.inspector.current.id == sid:
            self.inspector.asm.show_error("Disassembly failed", msg, [])

    def _disasm_done(self, sid: int, d: DisasmResult) -> None:
        cur = self.inspector.current
        if not cur or cur.id != sid or not self.res:
            return  # user already selected something else
        if not d.ok:
            from html import escape
            self.inspector.asm.show_error("Cannot disassemble", escape(d.error), [escape(t) for t in d.troubleshooting])
            return
        rows = self.res.debug.lines_in_range(d.start, d.end) if self.res.debug else None
        self.inspector.asm.show_result(cur.display_name, d, rows, lambda f, l: linecache.getline(f, l).strip() or None)

    # ------------------------------------------------------------------ regions / config
    def on_regions_changed(self, regions: list) -> None:
        self._save_session_regions(regions)
        if self.res:
            an.recompute_memory(self.res, regions)
            self.mem_page.set_result(self.res)
            self.fn_panel.refresh()
            self.data_panel.refresh()
            self.overview.show_result(self.res)
            self.viz.set_result(self.res)
            self.state_label.setText(f"{len(regions)} memory region(s) applied to this ELF")

    def on_config_changed(self, cfg: ToolchainConfig) -> None:
        self.cfg = cfg
        try:
            save_config(cfg)
        except OSError as exc:
            QMessageBox.warning(self, "Cannot save settings", str(exc))
        self.state_label.setText("Toolchain settings saved")
        if self.inspector.current:
            self.inspector.show_symbol(self.res, self.inspector.current)

    # ------------------------------------------------------------------ reset
    def reset_layout(self) -> None:
        """Re-dock the inspector, restore default window size and table columns."""
        for key in ("window/geometry", "window/state", "header/functions", "header/data"):
            self.settings.remove(key)
        self.dock.setFloating(False)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.dock)
        self.dock.show()
        self.resize(1500, 920)
        self.resizeDocks([self.dock], [460], Qt.Orientation.Horizontal)
        self.fn_panel.reset_header()
        self.data_panel.reset_header()
        self.state_label.setText("Window layout reset")

    def reset_all_settings(self) -> None:
        if QMessageBox.question(self, "Reset all saved settings", "Forget window layout, column layouts, per-firmware "
                                "memory regions and toolchain settings?") != QMessageBox.StandardButton.Yes:
            return
        self.settings.clear()
        try:
            (config_dir() / "toolchain.json").unlink(missing_ok=True)
        except OSError:
            pass
        self.cfg = ToolchainConfig()
        self.tool_page.set_config(self.cfg)
        self.mem_page.set_regions([])
        if self.res:
            an.recompute_memory(self.res, [])
            self.mem_page.set_result(self.res)
            self._refresh_all("settings reset")
        self.reset_layout()

    # ------------------------------------------------------------------ export / help
    def _export(self, title: str, default: str, filt: str, fn) -> None:
        if not self.res:
            QMessageBox.information(self, "Nothing to export", "Open an ELF file first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, title, default, filt)
        if path:
            try:
                fn(path, self.res)
            except OSError as exc:
                QMessageBox.critical(self, "Export failed", str(exc))
            else:
                self.state_label.setText(f"Exported {path}")

    def export_json(self) -> None:
        self._export("Export analysis", "analysis.json", "JSON (*.json)", export_json)

    def export_html(self) -> None:
        self._export("Export report", "report.html", "HTML (*.html)", export_html)

    def show_limitations(self) -> None:
        QMessageBox.information(self, "Interpreting results", (
            "<b>Sizes are not interchangeable.</b> File size, section sizes, loadable (PT_LOAD) sizes and run-time memory "
            "are different measurements. Stack and heap are not part of .data/.bss.<br><br>"
            "<b>Symbol sizes</b> come from the ELF symbol table; assembly routines may have size 0.<br>"
            "<b>Data classification</b> comes from symbol type + section flags, not from source-level analysis; DWARF is used "
            "only when it confirms a variable at the same address.<br><br>" + LIMITATIONS))

    def show_about(self) -> None:
        QMessageBox.about(self, "About", f"<b>ELF Memory Analyzer</b> {__version__}<br>ELF/DWARF parsing by pyelftools; "
                          "disassembly through your toolchain's objdump.")

    # ------------------------------------------------------------------ events
    def dragEnterEvent(self, e) -> None:
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e) -> None:
        urls = [u.toLocalFile() for u in e.mimeData().urls() if u.isLocalFile()]
        if not urls:
            return
        if os.path.isdir(urls[0]):
            self.stack_page.set_directory(urls[0])
            self.load_build_dir(urls[0])
        else:
            self.open_elf(urls[0])

    def closeEvent(self, e) -> None:
        self.settings.setValue("window/geometry", self.saveGeometry())
        self.settings.setValue("window/state", self.saveState())
        self.fn_panel.save_header()
        self.data_panel.save_header()
        super().closeEvent(e)
