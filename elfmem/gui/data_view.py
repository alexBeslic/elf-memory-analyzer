"""Initial value / contents viewer for data objects (replaces 'assembly only for functions')."""
from __future__ import annotations

from PySide6.QtGui import QFontDatabase, QGuiApplication
from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget

from ..data_view import DataBytes, hexdump, read_symbol_bytes, summarize, values_text
from ..models import ElfModel, Symbol

MODES = [("Hex dump", ("dump", 1)), ("Hex, 8-bit", ("hex", 1)), ("Hex, 16-bit", ("hex", 2)), ("Hex, 32-bit", ("hex", 4)),
         ("Hex, 64-bit", ("hex", 8)), ("Unsigned 8-bit", ("uint", 1)), ("Unsigned 16-bit", ("uint", 2)),
         ("Unsigned 32-bit", ("uint", 4)), ("Unsigned 64-bit", ("uint", 8)), ("Signed 8-bit", ("int", 1)),
         ("Signed 16-bit", ("int", 2)), ("Signed 32-bit", ("int", 4)), ("Signed 64-bit", ("int", 8)),
         ("Float 32", ("float", 4)), ("Float 64", ("float", 8))]


class DataContentView(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.info = QLabel(wordWrap=True)
        self.hints = QLabel(wordWrap=True)
        self.mode = QComboBox()
        for label, v in MODES:
            self.mode.addItem(label, v)
        self.copy_btn = QPushButton("Copy")
        self.edit = QPlainTextEdit(readOnly=True)
        self.edit.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.edit.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        bar = QHBoxLayout()
        bar.addWidget(QLabel("Show as:"))
        bar.addWidget(self.mode, 1)
        bar.addWidget(self.copy_btn)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        for w in (self.info, self.hints):
            lay.addWidget(w)
        lay.addLayout(bar)
        lay.addWidget(self.edit, 1)
        self._elf, self._sym, self._db = None, None, None
        self.mode.currentIndexChanged.connect(self._render)
        self.copy_btn.clicked.connect(lambda: QGuiApplication.clipboard().setText(self.edit.toPlainText()))

    def clear(self, text: str = "") -> None:
        self._sym = self._db = None
        self.info.setText(text)
        self.hints.clear()
        self.edit.clear()

    def show_symbol(self, elf: ElfModel, sym: Symbol) -> None:
        self._elf, self._sym = elf, sym
        self._db = read_symbol_bytes(elf, sym)
        self._render()

    def _render(self) -> None:
        db: DataBytes | None = self._db
        if db is None or self._elf is None:
            return
        self.info.setText(db.message)
        if db.state != "stored":
            self.hints.clear()
            self.edit.setPlainText("" if db.state != "zero" else f"{self._sym.size:,} bytes, all 0x00 at start-up")
            return
        kind, width = self.mode.currentData()
        endian = self._elf.endianness
        data = db.data
        self.hints.setText("\n".join(summarize(data, endian)) + ("\n" if summarize(data, endian) else "") +
                           f"(interpretations are hints; byte order: {endian}-endian)")
        body = hexdump(data, self._sym.address) if kind == "dump" else values_text(data, self._sym.address, width, kind, endian)
        if db.truncated:
            body += f"\n... showing the first {len(data):,} of {self._sym.size:,} bytes"
        self.edit.setPlainText(body)
