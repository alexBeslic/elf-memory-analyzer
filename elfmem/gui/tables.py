"""Table models. Filtering and sorting are done in Python (faster than proxy models for 100k+ rows)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt

from ..models import Symbol

SortKey = Callable[[Symbol], Any]


@dataclass
class Column:
    title: str
    text: Callable[[Symbol], str]
    key: SortKey
    right: bool = False
    width: int = 110


def _src(s: Symbol) -> str:
    return f"{s.source_file}:{s.source_line}" if s.source_file else ""


FUNCTION_COLUMNS = [
    Column("Name", lambda s: s.name, lambda s: s.name.lower(), width=220),
    Column("Demangled", lambda s: s.demangled or "", lambda s: (s.demangled or "").lower(), width=220),
    Column("Address", lambda s: f"0x{s.address:08x}", lambda s: s.address, True, 100),
    Column("Size", lambda s: f"{s.size:,}", lambda s: s.size, True, 80),
    Column("Section", lambda s: s.section or "", lambda s: s.section or "", width=90),
    Column("Region", lambda s: s.region or "", lambda s: s.region or "", width=80),
    Column("Stack", lambda s: "" if s.stack_bytes is None else str(s.stack_bytes),
           lambda s: -1 if s.stack_bytes is None else s.stack_bytes, True, 70),
    Column("Stack class", lambda s: s.stack_kind or "", lambda s: s.stack_kind or "", width=100),
    Column("Stack match", lambda s: "" if s.stack_confidence == "unavailable" else s.stack_confidence,
           lambda s: s.stack_confidence, width=90),
    Column("Source", _src, lambda s: _src(s).lower(), width=200),
    Column("Binding", lambda s: s.bind, lambda s: s.bind, width=70),
    Column("Visibility", lambda s: s.visibility, lambda s: s.visibility, width=70),
    Column("Type", lambda s: s.sym_type + (" (thumb)" if s.is_thumb else "") + (" [alias]" if s.alias_of is not None else ""),
           lambda s: s.sym_type, width=100),
]

DATA_COLUMNS = [
    Column("Name", lambda s: s.name, lambda s: s.name.lower(), width=220),
    Column("Demangled", lambda s: s.demangled or "", lambda s: (s.demangled or "").lower(), width=200),
    Column("Address", lambda s: f"0x{s.address:08x}", lambda s: s.address, True, 100),
    Column("Size", lambda s: f"{s.size:,}", lambda s: s.size, True, 80),
    Column("Section", lambda s: s.section or "", lambda s: s.section or "", width=90),
    Column("Region", lambda s: s.region or "", lambda s: s.region or "", width=80),
    Column("Class (from section)", lambda s: s.data_class, lambda s: s.data_class, width=130),
    Column("Type", lambda s: s.sym_type + (" [alias]" if s.alias_of is not None else ""), lambda s: s.sym_type, width=90),
    Column("Binding", lambda s: s.bind, lambda s: s.bind, width=70),
    Column("Visibility", lambda s: s.visibility, lambda s: s.visibility, width=70),
    Column("Source (DWARF)", _src, lambda s: _src(s).lower(), width=200),
]


@dataclass
class SymbolFilter:
    text: str = ""
    min_size: int = 0
    max_size: Optional[int] = None
    section: str = ""
    addr_min: Optional[int] = None
    addr_max: Optional[int] = None
    stack: str = "any"       # any | has | none | ambiguous
    data_class: str = ""
    hide_aliases: bool = False

    def predicate(self) -> Callable[[Symbol], bool]:
        terms = [t for t in self.text.lower().split() if t]
        f = self

        def ok(s: Symbol) -> bool:
            if s.size < f.min_size:
                return False
            if f.max_size is not None and s.size > f.max_size:
                return False
            if f.section and s.section != f.section:
                return False
            if f.addr_min is not None and s.address < f.addr_min:
                return False
            if f.addr_max is not None and s.address > f.addr_max:
                return False
            if f.stack == "has" and s.stack_bytes is None:
                return False
            if f.stack == "none" and s.stack_bytes is not None:
                return False
            if f.stack == "ambiguous" and s.stack_confidence != "ambiguous":
                return False
            if f.data_class and s.data_class != f.data_class:
                return False
            if f.hide_aliases and s.alias_of is not None:
                return False
            blob = s.search_blob
            return all(t in blob for t in terms)
        return ok


class SymbolTableModel(QAbstractTableModel):
    """Holds all symbols of one kind, plus the filtered+sorted view shown by the table."""

    def __init__(self, columns: list[Column], parent=None) -> None:
        super().__init__(parent)
        self.columns = columns
        self._all: list[Symbol] = []
        self._rows: list[Symbol] = []
        self._filter = SymbolFilter()
        self._sort_col = 3
        self._descending = True

    # -- data
    def set_symbols(self, symbols: list[Symbol]) -> None:
        self._all = symbols
        self.refresh()

    def set_filter(self, flt: SymbolFilter) -> None:
        self._filter = flt
        self.refresh()

    def refresh(self) -> None:
        self.beginResetModel()
        pred = self._filter.predicate()
        rows = [s for s in self._all if pred(s)]
        rows.sort(key=self.columns[self._sort_col].key, reverse=self._descending)
        self._rows = rows
        self.endResetModel()

    def sort(self, column: int, order: Qt.SortOrder = Qt.SortOrder.AscendingOrder) -> None:
        if 0 <= column < len(self.columns):
            self._sort_col = column
            self._descending = order == Qt.SortOrder.DescendingOrder
            self.refresh()

    @property
    def all_count(self) -> int:
        return len(self._all)

    def visible(self) -> list[Symbol]:
        return self._rows

    def symbol_at(self, row: int) -> Optional[Symbol]:
        return self._rows[row] if 0 <= row < len(self._rows) else None

    def row_of(self, symbol_id: int) -> int:
        for i, s in enumerate(self._rows):
            if s.id == symbol_id:
                return i
        return -1

    # -- Qt model API
    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.columns)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        col = self.columns[index.column()]
        if role == Qt.ItemDataRole.DisplayRole:
            return col.text(self._rows[index.row()])
        if role == Qt.ItemDataRole.TextAlignmentRole and col.right:
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        if role == Qt.ItemDataRole.ToolTipRole:
            s = self._rows[index.row()]
            return "\n".join(s.notes) if s.notes and index.column() == 0 else None
        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.columns[section].title
        return None


class RowsModel(QAbstractTableModel):
    """Generic sortable table of pre-computed rows. ``rows`` are lists of raw values (+ optional payload)."""

    def __init__(self, headers: list[str], right_cols: tuple[int, ...] = (), formats: Optional[dict] = None,
                 parent=None) -> None:
        super().__init__(parent)
        self.headers, self.right_cols, self.formats = headers, set(right_cols), formats or {}
        self._rows: list[tuple[list, Any]] = []

    def set_rows(self, rows: list[list], payloads: Optional[list] = None) -> None:
        self.beginResetModel()
        self._rows = [(r, payloads[i] if payloads else None) for i, r in enumerate(rows)]
        self.endResetModel()

    def payload(self, row: int):
        return self._rows[row][1] if 0 <= row < len(self._rows) else None

    def find_payload(self, pred) -> int:
        for i, (_r, p) in enumerate(self._rows):
            if pred(p):
                return i
        return -1

    def sort(self, column: int, order=Qt.SortOrder.AscendingOrder) -> None:
        def key(item):
            v = item[0][column]
            return (0, "") if v is None else (1, v.lower() if isinstance(v, str) else v)
        self.layoutAboutToBeChanged.emit()
        self._rows.sort(key=key, reverse=order == Qt.SortOrder.DescendingOrder)
        self.layoutChanged.emit()

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.headers)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        if role == Qt.ItemDataRole.DisplayRole:
            v = self._rows[index.row()][0][index.column()]
            fmt = self.formats.get(index.column())
            return "" if v is None else (fmt(v) if fmt else str(v))
        if role == Qt.ItemDataRole.TextAlignmentRole and index.column() in self.right_cols:
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.headers[section]
        return None
