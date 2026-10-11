"""Main application window: navigation, menus, background analysis orchestration."""
from __future__ import annotations

import linecache
import logging
import os
from typing import Callable, Optional

from PySide6.QtCore import QSettings, Qt
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import (QApplication, QDockWidget, QFileDialog, QLabel, QListWidget, QMainWindow, QMessageBox,
                               QProgressBar, QStackedWidget, QToolBar)

from .. import __version__
from .. import analysis as an
from ..callgraph import CallGraph, build_call_graph, estimate_worst_case
from ..disassembler import DisasmResult, disassemble, function_bounds
from ..export import DATA_FIELDS, FUNCTION_FIELDS, export_html, export_json
from ..memory_analyzer import MemoryRegion
from ..models import SymKind
from ..toolchain import ToolchainConfig, load_config, save_config
from .inspector import Inspector
from .pages import LIMITATIONS, MemoryMapPage, OverviewPage, StackPage, ToolchainPage, VisualizationPage
from .symbol_panel import SymbolPanel
from .tables import DATA_COLUMNS, FUNCTION_COLUMNS
from .workers import Task

log = logging.getLogger(__name__)
PAGES = ["Overview", "Functions", "Global Data", "Memory Map", "Visualization", "Stack Analysis", "Toolchain Settings"]


def _disasm_job(path: str, start: int, end: int, estimated: bool, cfg: ToolchainConfig, machine: str,
                progress=None) -> DisasmResult:
    d = disassemble(path, start, end, cfg, machine)
    d.end_estimated = estimated
    return d


def _estimate_job(elf, cfg, symbols, root_addr, graph: Optional[CallGraph], progress=None):
    g = graph or build_call_graph(elf, cfg, progress=progress)
    return g, estimate_worst_case(g, symbols, root_addr)


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

        self.overview = OverviewPage()
        self.fn_panel = SymbolPanel("Functions", FUNCTION_COLUMNS, FUNCTION_FIELDS, True, "functions")
        self.data_panel = SymbolPanel("Global data", DATA_COLUMNS, DATA_FIELDS, False, "data")
        self.mem_page = MemoryMapPage()
        self.viz = VisualizationPage()
        self.stack_page = StackPage()
        self.tool_page = ToolchainPage(self.cfg)
        self.pages = [self.overview, self.fn_panel, self.data_panel, self.mem_page, self.viz, self.stack_page, self.tool_page]
        self.stack = QStackedWidget()
        for p in self.pages:
            self.stack.addWidget(p)
        self.nav = QListWidget()
        self.nav.addItems(PAGES)
        self.nav.setMinimumWidth(150)
        self.nav.setMaximumWidth(190)
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.nav.setCurrentRow(0)
        from PySide6.QtWidgets import QSplitter
        split = QSplitter()
        split.addWidget(self.nav)
        split.addWidget(self.stack)
        split.setStretchFactor(1, 1)
        self.setCentralWidget(split)

        self.inspector = Inspector()
        self.dock = QDockWidget("Inspector", self)
        self.dock.setObjectName("inspector")
        self.dock.setWidget(self.inspector)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.dock)
        self.dock.setMinimumWidth(430)

        self.state_label = QLabel("No ELF loaded")
        self.progress = QProgressBar(maximumWidth=160, maximum=0, visible=False)
        self.statusBar().addWidget(self.state_label, 1)
        self.statusBar().addPermanentWidget(self.progress)

        self._build_menus()
        self._wire()
        self.mem_page.set_regions([MemoryRegion.from_dict(d) for d in self.cfg.memory_regions if _valid_region(d)])
        if self.cfg.build_dir:
            self.stack_page.set_directory(self.cfg.build_dir)
        geo, st = self.settings.value("window/geometry"), self.settings.value("window/state")
        if geo:
            self.restoreGeometry(geo)
        if st:
            self.restoreState(st)

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
        self.stack_page.estimate_requested.connect(self.estimate_stack)
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
        d = QFileDialog.getExistingDirectory(self, "Select build output directory", self.cfg.build_dir)
        if d:
            self.stack_page.set_directory(d)
            self.load_build_dir(d)

    def reload(self) -> None:
        if self.res:
            self.open_elf(self.res.elf.path)

    def open_elf(self, path: str) -> None:
        self._gen += 1
        gen = self._gen
        self.settings.setValue("last_dir", os.path.dirname(path))
        self._graph = None
        regions = [MemoryRegion.from_dict(d) for d in self.cfg.memory_regions if _valid_region(d)]
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
        self.state_label.setText(f"{os.path.basename(e.path)} - {len(e.symbols):,} symbols; ELF analysis complete")
        if self.cfg.load_dwarf and e.has_debug_info:
            self.run_task(an.load_debug, e.path, message="Reading DWARF debug info…",
                          on_done=lambda d: self._debug_loaded(gen, d), on_fail=lambda m: self._soft_fail("DWARF", m))
        if self.cfg.build_dir and os.path.isdir(self.cfg.build_dir):
            self.load_build_dir(self.cfg.build_dir)

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
        self.cfg.build_dir = d
        self.run_task(an.load_stack_reports, d, message="Scanning for .su files…",
                      on_done=lambda p: self._stack_loaded(gen, p), on_fail=lambda m: self._soft_fail("Stack usage", m))

    def _stack_loaded(self, gen: int, parsed) -> None:
        if gen != self._gen or not self.res:
            return
        an.apply_stack(self.res, parsed)
        self.stack_page.set_result(self.res)
        self._refresh_all(f"Stack usage loaded: {len(parsed.records):,} records from {len(parsed.files)} files")

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

    def on_symbol_activated(self, sid: int) -> None:
        self.on_symbol_selected(sid)
        self.dock.show()
        sym = self.res.elf.symbols[sid] if self.res else None
        if sym and sym.kind == SymKind.FUNCTION:
            self.inspector.tabs.setCurrentWidget(self.inspector.asm)

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
        self.cfg.memory_regions = [r.to_dict() for r in regions]
        save_config(self.cfg)
        if self.res:
            an.recompute_memory(self.res, regions)
            self.mem_page.set_result(self.res)
            self.fn_panel.refresh()
            self.data_panel.refresh()
            self.overview.show_result(self.res)
            self.viz.set_result(self.res)

    def on_config_changed(self, cfg: ToolchainConfig) -> None:
        cfg.memory_regions = self.cfg.memory_regions
        self.cfg = cfg
        try:
            save_config(cfg)
        except OSError as exc:
            QMessageBox.warning(self, "Cannot save settings", str(exc))
        self.state_label.setText("Toolchain settings saved")
        if self.inspector.current:
            self.inspector.show_symbol(self.res, self.inspector.current)

    # ------------------------------------------------------------------ stack estimate
    def estimate_stack(self) -> None:
        sym = self.inspector.current
        if not self.res or not sym or sym.kind != SymKind.FUNCTION:
            QMessageBox.information(self, "Select a function", "Select a function (Functions page) first.")
            return
        if not self.res.su:
            QMessageBox.information(self, "No stack data", "Load a build directory with .su files first.")
            return
        self.run_task(_estimate_job, self.res.elf, self.cfg, self.res.elf.symbols, sym.address, self._graph,
                      message=f"Estimating call-path stack for {sym.display_name}…",
                      on_done=lambda r: self._estimate_done(sym, r))

    def _estimate_done(self, sym, result) -> None:
        from html import escape
        graph, est = result
        self._graph = graph
        names = " → ".join(escape(graph.names.get(a, f"0x{a:x}")) for a in est.path[:25])
        verdict = ("<b>No limiting issues found along the analysed paths.</b> Interrupts and unseen callers are still not included."
                   if est.reliable else
                   f"<b>Lower bound only</b> - a reliable worst case cannot be established.")
        issues = "".join(f"<li>{escape(i)}</li>" for i in est.issues[:40]) or "<li>none</li>"
        warns = "".join(f"<li>{escape(w)}</li>" for w in graph.warnings)
        self.stack_page.show_estimate(
            f"<h4>{escape(sym.display_name)}: ≥ {est.bound:,} bytes along the deepest known path</h4><p>{verdict}</p>"
            f"<p>Path: {names}</p><p>Issues:</p><ul>{issues}</ul><ul>{warns}</ul>{LIMITATIONS}")
        self.nav.setCurrentRow(5)

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
        try:
            save_config(self.cfg)
        except OSError:
            pass
        super().closeEvent(e)


def _valid_region(d: dict) -> bool:
    try:
        MemoryRegion.from_dict(d)
        return True
    except (KeyError, ValueError, TypeError):
        return False
