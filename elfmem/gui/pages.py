"""Navigation pages: Overview, Memory Map, Visualization, Stack Analysis, Toolchain Settings."""
from __future__ import annotations

import os
from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QFileDialog, QFormLayout, QGroupBox, QHBoxLayout,
                               QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QSizePolicy, QSpinBox, QSplitter,
                               QTableView, QTableWidget, QTableWidgetItem, QTabWidget, QTextBrowser, QVBoxLayout,
                               QWidget)

from ..analysis import AnalysisResult
from ..export import render_report
from ..memory_analyzer import MemoryRegion, top_sections, top_stack, top_symbols
from ..region_import import RegionImportError, import_regions, regions_to_json
from ..models import SymKind
from ..toolchain import PRESETS, ROLES, ToolchainConfig, detect_tools, scan_toolchain_dir, validate_config, validate_tool
from ..visualization import items_from_regions, items_from_sections, items_from_symbols
from .charts import BarChartWidget, TreemapWidget
from .tables import RowsModel

LIMITATIONS = (
    "<b>How to read stack numbers</b><ul>"
    "<li>.su values are <i>per-function frame sizes</i>. They are not summed into a total, because the real "
    "requirement depends on the deepest call chain.</li>"
    "<li>Call-path estimates come from disassembly: calls through function pointers/vtables, interrupts, "
    "recursion, dynamic allocation (alloca/VLA) and functions without .su data make the result a "
    "<b>lower bound</b>; the tool says so instead of inventing a worst case.</li>"
    "<li>Matches are labelled exact / approximate / ambiguous. Ambiguous records are never assigned.</li></ul>")


def make_table(model: RowsModel, sortable: bool = True) -> QTableView:
    t = QTableView()
    t.setModel(model)
    t.setSortingEnabled(sortable)
    t.setAlternatingRowColors(True)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.verticalHeader().setVisible(False)
    t.verticalHeader().setDefaultSectionSize(22)
    t.horizontalHeader().setStretchLastSection(True)
    return t


def hexf(v) -> str:
    return f"0x{v:08x}"


def intf(v) -> str:
    return f"{v:,}"


class OverviewPage(QTextBrowser):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setOpenExternalLinks(False)
        self.show_empty()

    def show_empty(self) -> None:
        self.setHtml("<h2>ELF Memory Analyzer</h2><p>Open an ELF file (<b>Ctrl+O</b>) or drag and drop one onto this window.</p>"
                     "<ol><li>Review this overview and the warnings.</li><li>Find the largest functions/data in the "
                     "<b>Functions</b> and <b>Global Data</b> pages.</li><li>Select a function to see assembly in the "
                     "Inspector.</li><li>Load the build directory (<b>Ctrl+Shift+O</b>) to add stack usage from .su files.</li>"
                     "<li>Explore <b>Visualization</b> and export CSV/JSON/HTML.</li></ol>")

    def show_result(self, res: AnalysisResult) -> None:
        self.setHtml(render_report(res, top_n=15, embedded=True))


class MemoryMapPage(QWidget):
    regions_changed = Signal(list)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.sec_model = RowsModel(["#", "Section", "Type", "Address (VMA)", "Load addr (LMA)", "Size", "Flags", "Category",
                                    "Region", "Load region"], (0, 3, 4, 5), {3: hexf, 4: hexf, 5: intf})
        self.seg_model = RowsModel(["#", "Type", "Offset", "VirtAddr", "PhysAddr", "FileSz", "MemSz", "Flags"],
                                   (0, 2, 3, 4, 5, 6), {2: hexf, 3: hexf, 4: hexf, 5: intf, 6: intf})
        self.use_model = RowsModel(["Region", "Origin", "Length", "Used (by VMA)", "Load image (LMA)", "Used %"],
                                   (1, 2, 3, 4, 5), {1: hexf, 2: intf, 3: intf, 4: intf, 5: lambda v: f"{v:.1f}%"})
        self.sec_table, self.seg_table, self.use_table = (make_table(m) for m in (self.sec_model, self.seg_model, self.use_model))
        self.regions = QTableWidget(0, 3)
        self.regions.setHorizontalHeaderLabels(["Region name", "Origin (hex/dec)", "Length (bytes, hex/dec)"])
        self.regions.horizontalHeader().setStretchLastSection(True)
        add, rem, apply = QPushButton("Add region"), QPushButton("Remove selected"), QPushButton("Apply regions")
        imp, exp = QPushButton("Import (.map / .ld / .json)…"), QPushButton("Export JSON…")
        imp.setToolTip("Reads 'Memory Configuration' from a GNU ld map file, a MEMORY {} block from a linker script, or JSON")
        imp.clicked.connect(self._import)
        exp.clicked.connect(self._export)
        add.clicked.connect(lambda: self._add_row("", "", ""))
        rem.clicked.connect(lambda: [self.regions.removeRow(i) for i in sorted({x.row() for x in self.regions.selectedIndexes()}, reverse=True)])
        apply.clicked.connect(self._apply)
        self.msg = QLabel(wordWrap=True)
        hint = QLabel("A memory-region model is needed to compute usage percentages: the ELF does not say how much "
                      "flash/RAM the device has. Example: FLASH 0x08000000 / 0x100000, RAM 0x20000000 / 0x20000.", wordWrap=True)
        box = QGroupBox("Memory regions (user-defined)")
        bl = QVBoxLayout(box)
        bl.addWidget(hint)
        bl.addWidget(self.regions)
        row = QHBoxLayout()
        for b in (add, rem, apply, imp, exp):
            row.addWidget(b)
        row.addStretch(1)
        bl.addLayout(row)
        bl.addWidget(self.msg)
        tabs = QTabWidget()
        tabs.addTab(self.sec_table, "Sections")
        tabs.addTab(self.seg_table, "Segments (program headers)")
        tabs.addTab(self.use_table, "Region usage")
        lay = QVBoxLayout(self)
        lay.addWidget(box)
        lay.addWidget(tabs, 1)
        self.tabs = tabs

    def _add_row(self, name: str, origin: str, length: str) -> None:
        r = self.regions.rowCount()
        self.regions.insertRow(r)
        for c, v in enumerate((name, origin, length)):
            self.regions.setItem(r, c, QTableWidgetItem(v))

    def set_regions(self, regions: list[MemoryRegion]) -> None:
        self.regions.setRowCount(0)
        for r in regions:
            self._add_row(r.name, f"0x{r.origin:08x}", f"0x{r.length:x}")

    def _import(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Import memory regions", "",
                                              "Map / linker script / JSON (*.map *.ld *.lds *.json *.txt);;All files (*)")
        if path:
            self.import_file(path)

    def import_file(self, path: str) -> bool:
        try:
            r = import_regions(path)
        except RegionImportError as exc:
            self.msg.setText(f"Import failed: {exc}")
            return False
        self.set_regions(r.regions)
        extra = (" Notes: " + " | ".join(r.warnings)) if r.warnings else ""
        self.msg.setText(f"Imported {len(r.regions)} region(s) from {r.kind}: {os.path.basename(path)}.{extra}")
        self.regions_changed.emit(r.regions)
        return True

    def _export(self) -> None:
        regions = self._parse_table()
        if regions is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export memory regions", "memory_regions.json", "JSON (*.json)")
        if path:
            try:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(regions_to_json(regions))
            except OSError as exc:
                self.msg.setText(f"Export failed: {exc}")

    def _apply(self) -> None:
        out = self._parse_table()
        if out is not None:
            self.msg.setText(f"Applied {len(out)} region(s).")
            self.regions_changed.emit(out)

    def _parse_table(self):
        out: list[MemoryRegion] = []
        for r in range(self.regions.rowCount()):
            cells = [(self.regions.item(r, c).text().strip() if self.regions.item(r, c) else "") for c in range(3)]
            if not any(cells):
                continue
            try:
                name, origin, length = cells[0], int(cells[1], 0), int(cells[2], 0)
                if not name or length <= 0 or origin < 0:
                    raise ValueError
            except ValueError:
                self.msg.setText(f"Row {r + 1}: need a name, a numeric origin and a positive length.")
                return None
            out.append(MemoryRegion(name, origin, length))
        names = [m.name for m in out]
        if len(set(names)) != len(names):
            self.msg.setText("Region names must be unique.")
            return None
        return out

    def set_result(self, res: AnalysisResult) -> None:
        e, m = res.elf, res.memory
        self.sec_model.set_rows([[s.index, s.name, s.type.removeprefix("SHT_"), s.addr, s.lma, s.size, s.flags_str,
                                  s.category, s.region, s.lma_region] for s in e.sections if s.index],
                                [s.name for s in e.sections if s.index])
        self.seg_model.set_rows([[g.index, g.type.removeprefix("PT_"), g.offset, g.vaddr, g.paddr, g.filesz, g.memsz,
                                  g.flags_str] for g in e.segments])
        self.use_model.set_rows([[u.region.name, u.region.origin, u.region.length, u.used_bytes, u.load_image_bytes,
                                  u.percent] for u in (m.region_usage if m else [])])

    def select_section(self, name: str) -> None:
        row = self.sec_model.find_payload(lambda p: p == name)
        if row >= 0:
            self.tabs.setCurrentIndex(0)
            self.sec_table.selectRow(row)
            self.sec_table.scrollTo(self.sec_model.index(row, 0), QAbstractItemView.ScrollHint.PositionAtCenter)


class VisualizationPage(QWidget):
    symbol_requested = Signal(int)
    section_requested = Signal(str)

    MODES = ["Functions", "Global & static data", "Sections", "Memory regions"]

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.res: Optional[AnalysisResult] = None
        self.mode = QComboBox()
        self.mode.addItems(self.MODES)
        self.group = QComboBox()
        for label, v in (("Group by section", "section"), ("Group by category", "category"), ("Group by region", "region"), ("No grouping", "none")):
            self.group.addItem(label, v)
        self.min_size = QSpinBox(maximum=2_000_000_000, prefix="min ", suffix=" B", value=1, minimum=1)
        self.search = QLineEdit(placeholderText="Highlight objects by name…")
        self.info = QLabel(wordWrap=True)
        self.info.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.treemap = TreemapWidget()
        self.charts = {k: BarChartWidget() for k in ("Largest functions", "Largest data", "Largest sections", "Largest stack")}
        tabs = QTabWidget()
        from PySide6.QtWidgets import QScrollArea
        for name, ch in self.charts.items():
            sa = QScrollArea()
            sa.setWidgetResizable(True)
            sa.setWidget(ch)
            tabs.addTab(sa, name)
            ch.bar_activated.connect(self._bar_clicked)
        left = QWidget()
        ll = QVBoxLayout(left)
        row = QHBoxLayout()
        for w in (self.mode, self.group, self.min_size):
            row.addWidget(w)
        row.addWidget(self.search, 1)
        ll.addLayout(row)
        ll.addWidget(self.treemap, 1)
        ll.addWidget(self.info)
        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(left)
        split.addWidget(tabs)
        split.setSizes([900, 500])
        lay = QVBoxLayout(self)
        lay.addWidget(split)
        for sig in (self.mode.currentIndexChanged, self.group.currentIndexChanged, self.min_size.valueChanged):
            sig.connect(lambda *_: self.rebuild())
        self.search.textChanged.connect(self.treemap.set_highlight)
        self.treemap.item_activated.connect(self._tile_clicked)

    def set_result(self, res: Optional[AnalysisResult]) -> None:
        self.res = res
        self.rebuild()

    def rebuild(self) -> None:
        res = self.res
        if res is None:
            self.treemap.set_items([], True)
            return
        e, mode, group, mn = res.elf, self.mode.currentIndex(), self.group.currentData(), self.min_size.value()
        if mode == 0:
            items = items_from_symbols(e.symbols, SymKind.FUNCTION, group, mn)
        elif mode == 1:
            items = items_from_symbols(e.symbols, SymKind.DATA, group, mn)
        elif mode == 2:
            items = [i for i in items_from_sections(e.sections, "category" if group != "none" else "none") if i.size >= mn]
        else:
            items = [i for i in items_from_regions(e, res.regions) if i.size >= mn]
        total = sum(i.size for i in items)
        self.info.setText(f"{len(items):,} objects, {total:,} bytes. Rectangle area is proportional to ELF symbol/section size "
                          f"(not necessarily run-time usage). Click a rectangle to inspect it.")
        self.treemap.set_items(items, grouped=(group != "none") or mode == 3)
        self.charts["Largest functions"].set_rows([(s.display_name, s.size, ("sym", s.id)) for s in top_symbols(e.symbols, SymKind.FUNCTION, 25)])
        self.charts["Largest data"].set_rows([(s.display_name, s.size, ("sym", s.id)) for s in top_symbols(e.symbols, SymKind.DATA, 25)])
        self.charts["Largest sections"].set_rows([(s.name, s.size, ("sec", s.name)) for s in top_sections(e, 25)])
        self.charts["Largest stack"].set_rows([(s.display_name, s.stack_bytes or 0, ("sym", s.id)) for s in top_stack(e.symbols, 25)])

    def _bar_clicked(self, payload) -> None:
        kind, v = payload
        (self.symbol_requested if kind == "sym" else self.section_requested).emit(v)

    def _tile_clicked(self, item) -> None:
        if item.symbol_id is not None:
            self.symbol_requested.emit(item.symbol_id)
        elif item.section:
            self.section_requested.emit(item.section)


class StackPage(QWidget):
    load_requested = Signal(str)
    estimate_requested = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.dir_edit = QLineEdit(placeholderText="Build output directory (searched recursively for *.su)")
        browse, load = QPushButton("Browse…"), QPushButton("Load stack reports")
        browse.clicked.connect(self._browse)
        load.clicked.connect(lambda: self.load_requested.emit(self.dir_edit.text().strip()))
        self.summary = QLabel("No stack usage reports loaded.", wordWrap=True)
        self.model = RowsModel(["Name (as in .su)", "Stack (B)", "Class", "Source", ".su file", "Match", "Matched ELF symbol(s)"], (1,), {1: intf})
        self.table = make_table(self.model)
        self.estimate_btn = QPushButton("Show call graph / worst-case stack for the selected function")
        self.estimate_btn.clicked.connect(self.estimate_requested.emit)
        self.estimate_out = QTextBrowser()
        self.estimate_out.setMaximumHeight(190)
        self.estimate_out.setHtml(LIMITATIONS)
        top = QHBoxLayout()
        top.addWidget(self.dir_edit, 1)
        top.addWidget(browse)
        top.addWidget(load)
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(self.summary)
        lay.addWidget(self.table, 1)
        lay.addWidget(self.estimate_btn)
        lay.addWidget(self.estimate_out)

    def _browse(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Select build output directory", self.dir_edit.text())
        if d:
            self.dir_edit.setText(d)
            self.load_requested.emit(d)

    def set_directory(self, d: str) -> None:
        self.dir_edit.setText(d)

    def clear(self) -> None:
        self.model.set_rows([])
        self.summary.setText("No stack usage reports loaded.")

    def set_result(self, res: AnalysisResult) -> None:
        if not res.su:
            return self.clear()
        mr = res.stack_match
        counts = mr.counts() if mr else {}
        info: dict[int, list] = {}
        if mr:
            for sid, m in mr.matches.items():
                name = res.elf.symbols[sid].name
                if m.record is not None:
                    info.setdefault(m.record.id, [m.confidence, []])[1].append(name)
                elif m.confidence == "ambiguous":
                    for r in m.candidates:
                        info.setdefault(r.id, ["ambiguous (candidate)", []])[1].append(name)
        rows = []
        for r in res.su.records:
            status, names = info.get(r.id, ["unmatched (no ELF function; inlined/removed/other build?)", []])
            rows.append([r.name, r.size, r.kind, f"{os.path.basename(r.file)}:{r.line}" if r.file else "",
                         os.path.relpath(r.su_path, res.su.root) if res.su.root else r.su_path, status, ", ".join(names[:4])])
        self.model.set_rows(rows)
        self.table.sortByColumn(1, Qt.SortOrder.DescendingOrder)
        self.summary.setText(
            f"{len(res.su.files)} .su file(s), {len(res.su.records):,} record(s), {res.su.malformed_lines} malformed line(s). "
            f"ELF functions: {counts.get('exact', 0)} exact, {counts.get('approximate', 0)} approximate, "
            f"{counts.get('ambiguous', 0)} ambiguous, {counts.get('unavailable', 0)} without a record. "
            f"Unmatched records: {len(mr.unmatched_records) if mr else 0}.")

    def show_estimate(self, html: str) -> None:  # kept for compatibility; estimates live on the Call Graph page
        self.estimate_out.setHtml(html)


class ToolchainPage(QWidget):
    config_changed = Signal(object)

    def __init__(self, cfg: ToolchainConfig, parent=None) -> None:
        super().__init__(parent)
        self.preset = QComboBox()
        for k, p in PRESETS.items():
            self.preset.addItem(p.label, k)
        self.edits: dict[str, QLineEdit] = {}
        self.tc_dir = QLineEdit(placeholderText="Folder containing the compiler / binutils (e.g. .../tricore-gcc/bin) - tools are found automatically")
        tb, ts = QPushButton("Browse…"), QPushButton("Scan")
        tb.clicked.connect(self._browse_toolchain)
        ts.clicked.connect(self._scan)
        self.tc_prefix = QComboBox()
        self.tc_prefix.setEditable(True)
        self.tc_prefix.setToolTip("Tool name prefix, e.g. tricore-elf-  (tools are named <prefix>objdump, <prefix>nm, ...)")
        self.tc_prefix.activated.connect(self._apply_candidate)   # user picked another prefix from the list
        self._candidates = []
        folder = QHBoxLayout()
        for w in (self.tc_dir, tb, ts):
            folder.addWidget(w)
        form = QFormLayout()
        form.addRow("Toolchain folder", folder)
        form.addRow("Tool prefix", self.tc_prefix)
        form.addRow("Preset", self.preset)
        for role in ROLES:
            e = QLineEdit(placeholderText="auto-detect from PATH" if role != "compiler" else "optional")
            b = QPushButton("Browse…")
            b.clicked.connect(lambda _c=False, ed=e: self._browse(ed))
            v = QPushButton("Validate")
            v.clicked.connect(lambda _c=False, r=role, ed=e: self._validate_one(r, ed))
            row = QHBoxLayout()
            for w in (e, b, v):
                row.addWidget(w)
            form.addRow({"cxxfilt": "c++filt (demangler)"}.get(role, role), row)
            self.edits[role] = e
        self.args = QLineEdit(placeholderText="Extra objdump options, e.g. -M intel  or  -M force-thumb")
        self.su_dialect = QComboBox()
        self.su_dialect.addItems(["gcc", "clang"])
        self.demangle = QCheckBox("Demangle C++ names")
        self.dwarf = QCheckBox("Read DWARF debug info in the background (source file/line)")
        form.addRow("objdump options", self.args)
        form.addRow("Stack report dialect", self.su_dialect)
        form.addRow("", self.demangle)
        form.addRow("", self.dwarf)
        detect, validate, save = QPushButton("Detect tools"), QPushButton("Validate all"), QPushButton("Save && apply")
        detect.clicked.connect(self._detect)
        validate.clicked.connect(self._validate_all)
        save.clicked.connect(self._save)
        row = QHBoxLayout()
        for b in (detect, validate, save):
            row.addWidget(b)
        row.addStretch(1)
        self.diag = QPlainTextEdit(readOnly=True)
        note = QLabel("The ELF itself is analysed without any external tool. objdump is needed for assembly and call graphs, "
                      "c++filt for demangling.", wordWrap=True)
        lay = QVBoxLayout(self)
        lay.addWidget(note)
        lay.addLayout(form)
        lay.addLayout(row)
        lay.addWidget(QLabel("Diagnostics"))
        lay.addWidget(self.diag, 1)
        self.set_config(cfg)
        self.preset.currentIndexChanged.connect(self._preset_changed)

    def set_config(self, cfg: ToolchainConfig) -> None:
        self.preset.blockSignals(True)
        i = self.preset.findData(cfg.preset)
        self.preset.setCurrentIndex(max(i, 0))
        self.preset.blockSignals(False)
        for r, e in self.edits.items():
            e.setText(getattr(cfg, r))
        self.args.setText(cfg.objdump_args)
        self.su_dialect.setCurrentText(cfg.su_dialect)
        self.demangle.setChecked(cfg.demangle)
        self.dwarf.setChecked(cfg.load_dwarf)
        self.tc_dir.setText(cfg.toolchain_dir)
        self.tc_prefix.setCurrentText(cfg.tool_prefix)
        self._base = cfg

    def config(self) -> ToolchainConfig:
        c = ToolchainConfig.from_dict(self._base.to_dict())
        c.preset = self.preset.currentData()
        c.family = PRESETS[c.preset].family
        for r, e in self.edits.items():
            setattr(c, r, e.text().strip())
        c.objdump_args, c.su_dialect = self.args.text().strip(), self.su_dialect.currentText()
        c.demangle, c.load_dwarf = self.demangle.isChecked(), self.dwarf.isChecked()
        c.toolchain_dir = self.tc_dir.text().strip()
        c.tool_prefix = (self.tc_prefix.currentData() if self.tc_prefix.currentData() is not None else self.tc_prefix.currentText()).strip()
        return c

    def _browse(self, ed: QLineEdit) -> None:
        p, _ = QFileDialog.getOpenFileName(self, "Select executable", ed.text())
        if p:
            ed.setText(p)

    def _browse_toolchain(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Select toolchain folder (the folder with the compiler / bin)", self.tc_dir.text())
        if d:
            self.tc_dir.setText(d)
            self._scan()

    def _scan(self) -> None:
        """Find <prefix>objdump/nm/readelf/c++filt/gcc in the folder and fill all tool fields."""
        root = self.tc_dir.text().strip()
        self._candidates = scan_toolchain_dir(root) if root else []
        self.tc_prefix.blockSignals(True)
        self.tc_prefix.clear()
        for c in self._candidates:
            self.tc_prefix.addItem(f"{c.prefix or '(no prefix)'}   -  {len(c.tools)} tool(s) in {c.directory}", c.prefix)
        self.tc_prefix.blockSignals(False)
        if not self._candidates:
            self.diag.setPlainText(f"No binutils/compiler tools found in {root or '(empty)'} or its bin subfolders.\n"
                                   "Select the folder that contains files like <prefix>objdump and <prefix>gcc.")
            return
        self.tc_prefix.setCurrentIndex(0)
        self._apply_candidate(0)

    def _apply_candidate(self, index: int) -> None:
        if not 0 <= index < len(self._candidates):
            return
        c = self._candidates[index]
        for role, ed in self.edits.items():
            ed.setText(c.tools.get(role, ""))
        lines = [f"Prefix '{c.prefix}' in {c.directory}:"] + [f"  {r:9s} {c.tools.get(r, '- not found')}" for r in self.edits]
        if len(self._candidates) > 1:
            lines.append("Other prefixes found: " + ", ".join(repr(x.prefix) for x in self._candidates if x is not c)
                         + "  (pick another in 'Tool prefix' if this is the wrong target)")
        missing = [r for r in ("objdump",) if r not in c.tools]
        if missing:
            lines.append("WARNING: no objdump with this prefix - disassembly will not work.")
        self.diag.setPlainText("\n".join(lines))

    def _preset_changed(self) -> None:
        c = self.config()
        c.apply_preset(self.preset.currentData())
        self.args.setText(c.objdump_args)
        self.su_dialect.setCurrentText(c.su_dialect)
        for e in self.edits.values():
            e.clear()
        self._detect()

    def _detect(self) -> None:
        found = detect_tools(self.preset.currentData())
        lines = []
        for role, path in found.items():
            lines.append(f"{role:9s}: {path or 'not found on PATH'}")
            if path and not self.edits[role].text():
                self.edits[role].setPlaceholderText(path)
        self.diag.setPlainText("Detected tools for preset '%s':\n%s" % (self.preset.currentData(), "\n".join(lines)))

    def _validate_one(self, role: str, ed: QLineEdit) -> None:
        c = validate_tool(role, ed.text().strip() or ed.placeholderText())
        self.diag.setPlainText(f"{role}: {'OK' if c.ok else 'PROBLEM'} - {c.message}\n{c.version}")

    def _validate_all(self) -> None:
        lines = []
        for c in validate_config(self.config()):
            lines.append(f"[{'ok' if c.ok else '!!'}] {c.role:9s} {c.path or '-':40s} {c.message} {c.version}")
        self.diag.setPlainText("\n".join(lines))

    def _save(self) -> None:
        self.config_changed.emit(self.config())
        self.diag.appendPlainText("Settings saved.")
