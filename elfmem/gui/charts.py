"""Custom-painted widgets: squarified treemap and clickable horizontal bar chart."""
from __future__ import annotations

import zlib
from typing import Any, Optional

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFontMetrics, QPainter, QPen
from PySide6.QtWidgets import QToolTip, QWidget

from ..visualization import Tile, TreeItem, layout_treemap


def group_color(group: str, dim: bool = False) -> QColor:
    hue = zlib.crc32(group.encode()) % 360
    return QColor.fromHsv(hue, 90 if dim else 140, 225 if dim else 205)


class TreemapWidget(QWidget):
    item_activated = Signal(object)  # TreeItem

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setMouseTracking(True)
        self.setMinimumSize(300, 200)
        self._items: list[TreeItem] = []
        self._grouped = True
        self._tiles: list[Tile] = []
        self._hover: Optional[Tile] = None
        self._highlight = ""
        self._timer = QTimer(self, singleShot=True, interval=100)
        self._timer.timeout.connect(self._relayout)

    def set_items(self, items: list[TreeItem], grouped: bool) -> None:
        self._items, self._grouped = items, grouped
        self._relayout()

    def set_highlight(self, text: str) -> None:
        self._highlight = text.strip().lower()
        self.update()

    def tile_count(self) -> int:
        return len(self._tiles)

    def _relayout(self) -> None:
        self._tiles = layout_treemap(self._items, max(self.width(), 1), max(self.height(), 1), self._grouped)
        self._hover = None
        self.update()

    def resizeEvent(self, _e) -> None:
        self._timer.start()

    def tile_at(self, x: float, y: float) -> Optional[Tile]:
        hit = None
        for t in self._tiles:
            if t.x <= x < t.x + t.w and t.y <= y < t.y + t.h and not t.is_group:
                hit = t
        return hit

    def paintEvent(self, _e) -> None:
        p = QPainter(self)
        p.fillRect(self.rect(), self.palette().window())
        if not self._tiles:
            p.setPen(self.palette().text().color())
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No items to display (check filters / minimum size)")
            return
        fm = QFontMetrics(self.font())
        hl = self._highlight
        border = QPen(QColor(0, 0, 0, 90))
        for t in self._tiles:
            if t.w < 0.6 or t.h < 0.6:
                continue
            r = QRectF(t.x, t.y, t.w, t.h)
            if t.is_group:
                p.fillRect(r, QColor(60, 60, 70))
                p.setPen(QColor(235, 235, 235))
                p.drawText(r.adjusted(4, 0, -2, 0), Qt.AlignmentFlag.AlignVCenter, fm.elidedText(t.item.label, Qt.TextElideMode.ElideRight, int(t.w) - 6))
                continue
            match = bool(hl) and hl in t.item.label.lower()
            p.fillRect(r, group_color(t.group, dim=bool(hl) and not match))
            p.setPen(border)
            p.drawRect(r)
            if match:
                p.setPen(QPen(QColor(220, 20, 60), 2))
                p.drawRect(r.adjusted(1, 1, -1, -1))
            if t.w > 48 and t.h > fm.height() + 2:
                p.setPen(QColor(20, 20, 20))
                p.drawText(r.adjusted(3, 1, -2, -1), Qt.AlignmentFlag.AlignTop, fm.elidedText(t.item.label, Qt.TextElideMode.ElideRight, int(t.w) - 6))
        if self._hover:
            p.setPen(QPen(QColor(255, 255, 255), 2))
            p.drawRect(QRectF(self._hover.x, self._hover.y, self._hover.w, self._hover.h))
            p.setPen(QPen(QColor(0, 0, 0), 1))
            p.drawRect(QRectF(self._hover.x + 1, self._hover.y + 1, self._hover.w - 2, self._hover.h - 2))

    def mouseMoveEvent(self, e) -> None:
        pos = e.position()
        t = self.tile_at(pos.x(), pos.y())
        if t is not self._hover:
            self._hover = t
            self.update()
        if t:
            it = t.item
            addr = f"\n0x{it.address:08x}" if it.address is not None else ""
            QToolTip.showText(e.globalPosition().toPoint(), f"{it.label}\n{it.size:,} bytes{addr}\nsection: {it.section or '-'}", self)
        else:
            QToolTip.hideText()

    def mousePressEvent(self, e) -> None:
        pos = e.position()
        t = self.tile_at(pos.x(), pos.y())
        if t and e.button() == Qt.MouseButton.LeftButton:
            self.item_activated.emit(t.item)


class BarChartWidget(QWidget):
    """Horizontal bars: list of (label, value, payload). Click a bar to emit its payload."""
    bar_activated = Signal(object)
    ROW = 24

    def __init__(self, unit: str = "B", parent=None) -> None:
        super().__init__(parent)
        self.unit = unit
        self.rows: list[tuple[str, int, Any]] = []
        self.setMouseTracking(True)
        self._hover = -1

    def set_rows(self, rows: list[tuple[str, int, Any]]) -> None:
        self.rows = rows
        self.setMinimumHeight(max(40, len(rows) * self.ROW + 8))
        self.update()

    def paintEvent(self, _e) -> None:
        p = QPainter(self)
        if not self.rows:
            p.setPen(self.palette().text().color())
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No data available")
            return
        fm = QFontMetrics(self.font())
        label_w = min(int(self.width() * 0.4), 320)
        vmax = max(v for _l, v, _p in self.rows) or 1
        for i, (label, val, _p) in enumerate(self.rows):
            y = 4 + i * self.ROW
            p.setPen(self.palette().text().color())
            p.drawText(QRectF(4, y, label_w - 8, self.ROW), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight,
                       fm.elidedText(label, Qt.TextElideMode.ElideMiddle, label_w - 10))
            avail = max(self.width() - label_w - 90, 10)
            w = max(2.0, avail * val / vmax)
            col = QColor(70, 130, 200) if i != self._hover else QColor(240, 150, 40)
            p.fillRect(QRectF(label_w, y + 3, w, self.ROW - 6), col)
            p.setPen(self.palette().text().color())
            p.drawText(QPointF(label_w + w + 6, y + self.ROW / 2 + fm.ascent() / 2 - 1), f"{val:,} {self.unit}")

    def _row_at(self, y: float) -> int:
        i = int((y - 4) // self.ROW)
        return i if 0 <= i < len(self.rows) else -1

    def mouseMoveEvent(self, e) -> None:
        i = self._row_at(e.position().y())
        if i != self._hover:
            self._hover = i
            self.update()

    def mousePressEvent(self, e) -> None:
        i = self._row_at(e.position().y())
        if i >= 0:
            self.bar_activated.emit(self.rows[i][2])
