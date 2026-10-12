"""Searchable/filterable/sortable symbol table with CSV export (used for functions and data)."""
from __future__ import annotations

from typing import Optional

from PySide6.QtCore import QSettings, Qt, QTimer, Signal
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QHeaderView,
                               QLabel, QLineEdit, QMessageBox, QPushButton, QSizePolicy, QSpinBox, QTableView,
                               QVBoxLayout, QWidget)

from ..export import export_symbols_csv
from ..models import Symbol
from .tables import Column, SymbolFilter, SymbolTableModel

MAX_SPIN = 2_000_000_000


class SymbolPanel(QWidget):
    symbol_selected = Signal(int)
    symbol_activated = Signal(int)

    def __init__(self, title: str, columns: list[Column], export_fields: list[str], is_function: bool,
                 settings_key: str, parent=None) -> None:
        super().__init__(parent)
        self.title, self.export_fields, self.is_function, self.settings_key = title, export_fields, is_function, settings_key
        self.model = SymbolTableModel(columns, self)
        self._timer = QTimer(self, singleShot=True, interval=200)
        self._timer.timeout.connect(self._apply)

        self.search = QLineEdit(placeholderText="Search name, demangled name, address (0x...), section, source file")
        self.search.setClearButtonEnabled(True)
        self.min_size = QSpinBox(maximum=MAX_SPIN, prefix="min ", suffix=" B")
        self.max_size = QSpinBox(maximum=MAX_SPIN, prefix="max ", suffix=" B", specialValueText="max: any")
        self.section = QComboBox()
        self.section.addItem("All sections", "")
        self.addr_min = QLineEdit(placeholderText="addr ≥ 0x...", maximumWidth=120, minimumWidth=70)
        self.addr_max = QLineEdit(placeholderText="addr ≤ 0x...", maximumWidth=120, minimumWidth=70)
        self.extra = QComboBox()
        if is_function:
            for label, val in (("Stack: any", "any"), ("Has stack value", "has"), ("No stack value", "none"),
                               ("Ambiguous stack match", "ambiguous")):
                self.extra.addItem(label, val)
        else:
            self.extra.addItem("All classes", "")
            for c in ("initialized", "zero-initialized", "read-only", "thread-local",
                      "common (zero-initialized at link time)", "in code section", "other", "unknown"):
                self.extra.addItem(c, c)
        self.hide_alias = QCheckBox("Hide aliases")
        self.count = QLabel()
        # Long, changing text must never force the window wider (this made the inspector dock unresizable).
        self.count.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.count.setMinimumWidth(0)
        for combo in (self.section, self.extra):
            combo.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
            combo.setMinimumContentsLength(12)
        self.search.setMinimumWidth(120)
        self.export_btn = QPushButton("Export CSV…")
        self.reset_btn = QPushButton("Reset filters")

        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(22)
        self.table.horizontalHeader().setSectionsMovable(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        for i, c in enumerate(columns):
            self.table.setColumnWidth(i, c.width)
        self.table.sortByColumn(3, Qt.SortOrder.DescendingOrder)
        self._restore_header()

        row1, row2, row3 = QHBoxLayout(), QHBoxLayout(), QHBoxLayout()
        row1.addWidget(self.search, 1)
        row1.addWidget(self.export_btn)
        for w in (self.min_size, self.max_size, self.section, self.extra):
            row2.addWidget(w)
        row2.addStretch(1)
        for w in (self.addr_min, self.addr_max, self.hide_alias, self.reset_btn):
            row3.addWidget(w)
        row3.addWidget(self.count, 1)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(6, 6, 6, 6)
        lay.addLayout(row1)
        lay.addLayout(row2)
        lay.addLayout(row3)
        lay.addWidget(self.table, 1)

        for sig in (self.search.textChanged, self.addr_min.textChanged, self.addr_max.textChanged):
            sig.connect(lambda *_: self._timer.start())
        for sig in (self.min_size.valueChanged, self.max_size.valueChanged, self.section.currentIndexChanged,
                    self.extra.currentIndexChanged, self.hide_alias.toggled):
            sig.connect(lambda *_: self._timer.start(0))
        self.reset_btn.clicked.connect(self.reset_filters)
        self.export_btn.clicked.connect(self.export_csv)
        self.table.selectionModel().currentRowChanged.connect(self._on_row)
        self.table.doubleClicked.connect(lambda idx: self._emit(idx.row(), self.symbol_activated))
        self.model.modelReset.connect(self._update_count)

    # -- public API
    def set_symbols(self, symbols: list[Symbol]) -> None:
        names = sorted({s.section for s in symbols if s.section})
        self.section.blockSignals(True)
        self.section.clear()
        self.section.addItem("All sections", "")
        for n in names:
            self.section.addItem(n, n)
        self.section.blockSignals(False)
        self.model.set_symbols(symbols)

    def refresh(self) -> None:
        self.model.refresh()

    def focus_search(self) -> None:
        self.search.setFocus()
        self.search.selectAll()

    def reset_filters(self) -> None:
        for w in (self.search, self.addr_min, self.addr_max):
            w.clear()
        self.min_size.setValue(0)
        self.max_size.setValue(0)
        self.section.setCurrentIndex(0)
        self.extra.setCurrentIndex(0)
        self.hide_alias.setChecked(False)
        self._apply()

    def select_symbol(self, symbol_id: int) -> bool:
        row = self.model.row_of(symbol_id)
        if row < 0:  # hidden by filters: clear them so navigation always works
            self.reset_filters()
            row = self.model.row_of(symbol_id)
        if row < 0:
            return False
        self.table.selectRow(row)
        self.table.scrollTo(self.model.index(row, 0), QAbstractItemView.ScrollHint.PositionAtCenter)
        return True

    def export_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, f"Export {self.title}", f"{self.title.lower().replace(' ', '_')}.csv",
                                              "CSV files (*.csv)")
        if not path:
            return
        try:
            n = export_symbols_csv(path, self.model.visible(), self.export_fields)
        except OSError as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
            return
        QMessageBox.information(self, "Export complete", f"Wrote {n:,} rows to {path}")

    def reset_header(self) -> None:
        """Restore default column order, visibility and widths."""
        h = self.table.horizontalHeader()
        for logical in range(len(self.model.columns)):
            h.moveSection(h.visualIndex(logical), logical)
            h.setSectionHidden(logical, False)
            self.table.setColumnWidth(logical, self.model.columns[logical].width)
        self.table.sortByColumn(3, Qt.SortOrder.DescendingOrder)

    def save_header(self) -> None:
        QSettings("elfmem", "elfmem").setValue(f"header/{self.settings_key}", self.table.horizontalHeader().saveState())

    # -- internals
    def _restore_header(self) -> None:
        state = QSettings("elfmem", "elfmem").value(f"header/{self.settings_key}")
        if state is not None:
            self.table.horizontalHeader().restoreState(state)

    @staticmethod
    def _parse_addr(text: str) -> Optional[int]:
        try:
            return int(text.strip(), 0) if text.strip() else None
        except ValueError:
            return None

    def _apply(self) -> None:
        flt = SymbolFilter(text=self.search.text(), min_size=self.min_size.value(),
                           max_size=self.max_size.value() or None, section=self.section.currentData() or "",
                           addr_min=self._parse_addr(self.addr_min.text()), addr_max=self._parse_addr(self.addr_max.text()),
                           hide_aliases=self.hide_alias.isChecked())
        if self.is_function:
            flt.stack = self.extra.currentData() or "any"
        else:
            flt.data_class = self.extra.currentData() or ""
        self.model.set_filter(flt)

    def _update_count(self) -> None:
        vis = self.model.visible()
        total = sum(s.size for s in vis if s.alias_of is None)
        self.count.setText(f"{len(vis):,} of {self.model.all_count:,} shown · {total:,} B (aliases not double-counted)")

    def _emit(self, row: int, sig) -> None:
        s = self.model.symbol_at(row)
        if s is not None:
            sig.emit(s.id)

    def _on_row(self, current, _prev) -> None:
        self._emit(current.row(), self.symbol_selected)
