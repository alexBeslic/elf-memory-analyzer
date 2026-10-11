"""Detail panel: symbol details + assembly viewer."""
from __future__ import annotations

from typing import Optional

from PySide6.QtCore import QTimer, Signal
from PySide6.QtWidgets import QLabel, QTabWidget, QTextBrowser, QVBoxLayout, QWidget

from ..analysis import AnalysisResult
from ..details import symbol_details_html
from ..models import Symbol, SymKind
from .assembly_view import AssemblyView


class Inspector(QWidget):
    disassemble_requested = Signal(int)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.title = QLabel("No symbol selected", wordWrap=True)
        self.title.setStyleSheet("font-weight: bold; padding: 4px;")
        self.details = QTextBrowser()
        self.asm = AssemblyView()
        self.tabs = QTabWidget()
        self.tabs.addTab(self.details, "Details")
        self.tabs.addTab(self.asm, "Assembly")
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
            self.asm.clear("Disassembling...")
            self._timer.start()
        else:
            self.asm.clear("Assembly is only available for functions.")

    def refresh_details(self, res: AnalysisResult) -> None:
        if self.current is not None:
            self.details.setHtml(symbol_details_html(res, self.current))

    def _request_if_needed(self) -> None:
        if self.current is not None and self.current.kind == SymKind.FUNCTION and self.tabs.currentWidget() is self.asm:
            self._request()

    def _request(self) -> None:
        if self.current is not None and self.current.kind == SymKind.FUNCTION:
            self.disassemble_requested.emit(self.current.id)
