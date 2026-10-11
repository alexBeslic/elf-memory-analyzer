"""Disassembly viewer with highlighting, search, go-to-address, copy and export."""
from __future__ import annotations

import re
from bisect import bisect_right
from typing import Optional

from PySide6.QtCore import QRegularExpression, Qt
from PySide6.QtGui import (QColor, QFont, QFontDatabase, QGuiApplication, QSyntaxHighlighter, QTextCharFormat,
                           QTextCursor, QTextDocument)
from PySide6.QtWidgets import (QFileDialog, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton,
                               QTextEdit, QVBoxLayout, QWidget)

from ..disassembler import DisasmResult, format_disassembly

_BRANCH = re.compile(r"^(b|bl|bx|blx|bne|beq|bgt|blt|bge|ble|bcc|bcs|bhi|bls|bmi|bpl|cbz|cbnz|call\w*|jmp\w*|j[a-z]{1,3}|"
                     r"ret\w*|bra|rjmp|rcall|jal\w*|b\.\w+|bl\.\w+|svc|int)$")
_LINE = re.compile(r"^(?P<addr>[0-9a-f]+):(?P<sp1>\s{2})(?P<raw>[0-9a-f]+(?: [0-9a-f]+)*)\s{2,}(?P<mn>\S+)(?P<ops>.*)$")


def _fmt(color: str, bold: bool = False, italic: bool = False) -> QTextCharFormat:
    f = QTextCharFormat()
    f.setForeground(QColor(color))
    if bold:
        f.setFontWeight(QFont.Weight.Bold)
    f.setFontItalic(italic)
    return f


class AsmHighlighter(QSyntaxHighlighter):
    def __init__(self, doc: QTextDocument) -> None:
        super().__init__(doc)
        self.f_addr, self.f_raw = _fmt("#6a8fc9"), _fmt("#8a8a8a")
        self.f_mn, self.f_br = _fmt("#b5651d", bold=True), _fmt("#c0392b", bold=True)
        self.f_imm, self.f_reg = _fmt("#2e8b57"), _fmt("#8e44ad")
        self.f_sym, self.f_cm = _fmt("#2980b9", italic=True), _fmt("#7f8c8d", italic=True)
        self.f_src, self.f_hdr = _fmt("#3a9d5d", italic=True), _fmt("#d4a017", bold=True)
        self.op_rules = [(re.compile(r"<[^>]+>"), self.f_sym), (re.compile(r"(?:#|\$)?-?\b0x[0-9a-f]+\b|#-?\d+\b|\$-?\d+\b"), self.f_imm),
                         (re.compile(r"%[a-z0-9]+|\b(?:r\d{1,2}|sp|lr|pc|x\d{1,2}|w\d{1,2}|a\d|t\d|s\d{1,2}|ra|zero|[re]?[abcd]x|[re]?[sd]i|[re]?[sb]p)\b"), self.f_reg)]

    def highlightBlock(self, text: str) -> None:
        if text.startswith("; ----"):
            self.setFormat(0, len(text), self.f_hdr)
            return
        if text.startswith(";"):
            self.setFormat(0, len(text), self.f_src)
            return
        m = _LINE.match(text)
        if not m:
            return
        self.setFormat(m.start("addr"), len(m["addr"]), self.f_addr)
        self.setFormat(m.start("raw"), len(m["raw"]), self.f_raw)
        self.setFormat(m.start("mn"), len(m["mn"]), self.f_br if _BRANCH.match(m["mn"]) else self.f_mn)
        ops_start = m.start("ops")
        cm = text.find(" ; ", ops_start)
        end = cm if cm >= 0 else len(text)
        for rx, fmt in self.op_rules:
            for mm in rx.finditer(text, ops_start, end):
                self.setFormat(mm.start(), mm.end() - mm.start(), fmt)
        if cm >= 0:
            self.setFormat(cm, len(text) - cm, self.f_cm)


class AssemblyView(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.edit = QPlainTextEdit(readOnly=True)
        self.edit.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.edit.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.highlighter = AsmHighlighter(self.edit.document())
        self.message = QLabel(wordWrap=True, textInteractionFlags=Qt.TextInteractionFlag.TextSelectableByMouse)
        self.message.setVisible(False)
        self.search = QLineEdit(placeholderText="Find in assembly (Enter = next)")
        self.goto = QLineEdit(placeholderText="Go to address 0x...", maximumWidth=170)
        self.prev_btn, self.next_btn = QPushButton("◀"), QPushButton("▶")
        self.copy_btn, self.export_btn = QPushButton("Copy"), QPushButton("Export…")
        for b in (self.prev_btn, self.next_btn):
            b.setMaximumWidth(34)
        bar = QHBoxLayout()
        for w in (self.search, self.prev_btn, self.next_btn, self.goto, self.copy_btn, self.export_btn):
            bar.addWidget(w)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addLayout(bar)
        lay.addWidget(self.message)
        lay.addWidget(self.edit, 1)
        self._addrs: list[int] = []
        self._addr_line: dict[int, int] = {}
        self.search.returnPressed.connect(lambda: self.find(True))
        self.next_btn.clicked.connect(lambda: self.find(True))
        self.prev_btn.clicked.connect(lambda: self.find(False))
        self.goto.returnPressed.connect(self.go_to_address)
        self.copy_btn.clicked.connect(lambda: QGuiApplication.clipboard().setText(self.edit.toPlainText()))
        self.export_btn.clicked.connect(self.export_text)

    def clear(self, text: str = "") -> None:
        self.message.setVisible(False)
        self.edit.setPlainText(text)
        self._addrs, self._addr_line = [], {}

    def show_error(self, title: str, detail: str, tips: list[str]) -> None:
        self.edit.clear()
        body = "<b>%s</b><br>%s" % (title, detail)
        if tips:
            body += "<ul>" + "".join(f"<li>{t}</li>" for t in tips) + "</ul>"
        self.message.setText(body)
        self.message.setVisible(True)

    def show_result(self, name: str, res: DisasmResult, line_rows=None, read_source=None) -> None:
        self.message.setVisible(False)
        body, addr_line = format_disassembly(res.instructions, line_rows, read_source)
        est = " (end estimated from next symbol)" if res.end_estimated else ""
        header = f"; ---- {name}  [0x{res.start:08x} .. 0x{res.end:08x}){est} ----"
        footer = "; ---- end of function ----"
        self.edit.setPlainText(f"{header}\n{body}\n{footer}")
        self._addr_line = {a: n + 1 for a, n in addr_line.items()}
        self._addrs = sorted(self._addr_line)

    def find(self, forward: bool = True) -> None:
        text = self.search.text()
        if not text:
            return
        flags = QTextDocument.FindFlag(0) if forward else QTextDocument.FindFlag.FindBackward
        if not self.edit.find(text, flags):
            cur = self.edit.textCursor()
            cur.movePosition(QTextCursor.MoveOperation.Start if forward else QTextCursor.MoveOperation.End)
            self.edit.setTextCursor(cur)
            self.edit.find(text, flags)

    def go_to_address(self) -> None:
        try:
            target = int(self.goto.text().strip(), 16)
        except ValueError:
            return
        if not self._addrs:
            return
        i = bisect_right(self._addrs, target) - 1
        addr = self._addrs[max(i, 0)]
        block = self.edit.document().findBlockByNumber(self._addr_line[addr])
        cur = QTextCursor(block)
        self.edit.setTextCursor(cur)
        self.edit.centerCursor()
        sel = QTextEdit.ExtraSelection()
        sel.cursor = cur
        sel.cursor.select(QTextCursor.SelectionType.LineUnderCursor)
        sel.format.setBackground(QColor(255, 235, 59, 90))
        self.edit.setExtraSelections([sel])

    def export_text(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export disassembly", "disassembly.txt", "Text files (*.txt)")
        if path:
            try:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(self.edit.toPlainText() + "\n")
            except OSError as exc:
                QMessageBox.critical(self, "Export failed", str(exc))
