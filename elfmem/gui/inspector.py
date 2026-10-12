"""Detail panel: symbol details + assembly viewer."""
from __future__ import annotations

from typing import Optional

from PySide6.QtCore import QTimer, Signal
from PySide6.QtWidgets import QLabel, QStackedWidget, QTabWidget, QTextBrowser, QVBoxLayout, QWidget

from ..analysis import AnalysisResult
from ..details import symbol_details_html
from ..models import Symbol, SymKind
from .assembly_view import AssemblyView
from .data_view import DataContentView


class Inspector(QWidget):
    disassemble_requested = Signal(int)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.title = QLabel("No symbol selected", wordWrap=True)
        self.title.setStyleSheet("font-weight: bold; padding: 4px;")
        self.details = QTextBrowser()
        self.asm = AssemblyView()
        self.data_view = DataContentView()
        self.placeholder = QLabel("No contents view for this kind of symbol.", wordWrap=True)
        self.view_stack = QStackedWidget()
        for w in (self.asm, self.data_view, self.placeholder):
            self.view_stack.addWidget(w)
        self.tabs = QTabWidget()
        self.tabs.addTab(self.details, "Details")
        self.tabs.addTab(self.view_stack, "Assembly")
        self.tabs.setMinimumWidth(200)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.addWidget(self.title)
        lay.addWidget(self.tabs, 1)
        self.current: Optional[Symbol] = None
        self._timer = QTimer(self, singleShot=True, interval=150)
        self._timer.timeout.connect(self._request)
        self.tabs.currentChanged.connect(lambda _i: self._request_if_needed())

    def show_symbol(self, res: AnalysisResult, sym: Symbol) -> None:
        self.current = sym
        self.title.setText(sym.display_name)
        self.details.setHtml(symbol_details_html(res, sym))
        if sym.kind == SymKind.FUNCTION:
            self.tabs.setTabText(1, "Assembly")
            self.view_stack.setCurrentWidget(self.asm)
            self.asm.clear("Disassembling...")
            self._timer.start()
        elif sym.kind == SymKind.DATA:
            stored = sym.category in ("data", "rodata")
            self.tabs.setTabText(1, "Initial value" if stored else "Contents")
            self.view_stack.setCurrentWidget(self.data_view)
            self.data_view.show_symbol(res.elf, sym)
        else:
            self.tabs.setTabText(1, "Contents")
            self.view_stack.setCurrentWidget(self.placeholder)

    def refresh_details(self, res: AnalysisResult) -> None:
        if self.current is not None:
            self.details.setHtml(symbol_details_html(res, self.current))

    def _request_if_needed(self) -> None:
        if self.current is not None and self.current.kind == SymKind.FUNCTION and self.tabs.currentWidget() is self.view_stack:
            self._request()

    def _request(self) -> None:
        if self.current is not None and self.current.kind == SymKind.FUNCTION:
            self.disassemble_requested.emit(self.current.id)
