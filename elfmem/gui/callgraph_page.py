"""Call graph page: lazy callee tree with stack numbers, callers list, worst-case summary, DOT export."""
from __future__ import annotations

from html import escape
from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (QFileDialog, QHBoxLayout, QLabel, QListWidget, QListWidgetItem, QMessageBox,
                               QPushButton, QSplitter, QTextBrowser, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

from ..callgraph import CallGraph, estimate_worst_case, stack_lookup, to_dot
from ..models import Symbol

KEY = Qt.ItemDataRole.UserRole
DUMMY = "__dummy__"


class CallGraphPage(QWidget):
    symbol_requested = Signal(int)     # ELF function address (graph key >= 0)
    rebuild_disasm_requested = Signal()
    reload_ci_requested = Signal()
    use_selected_requested = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.graph: Optional[CallGraph] = None
        self.symbols: list[Symbol] = []
        self._lookup: dict = {}
        self._worst: dict = {}
        self._callers: dict = {}
        self.root: Optional[int] = None

        self.status = QLabel("No call graph yet. Load a build directory containing .ci files "
                             "(compile with -fcallgraph-info=su,da), or build one from disassembly.", wordWrap=True)
        self.status.setMinimumWidth(0)
        sel = QPushButton("Use selected function")
        ci = QPushButton("Reload .ci from build dir")
        dis = QPushButton("Build from disassembly")
        dot = QPushButton("Export DOT…")
        sel.clicked.connect(self.use_selected_requested.emit)
        ci.clicked.connect(self.reload_ci_requested.emit)
        dis.clicked.connect(self.rebuild_disasm_requested.emit)
        dot.clicked.connect(self._export_dot)
        bar = QHBoxLayout()
        for b in (sel, ci, dis, dot):
            bar.addWidget(b)
        bar.addStretch(1)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(4)
        self.tree.setHeaderLabels(["Function (what it calls)", "Own stack (B)", "Worst case from here (B)", "Notes"])
        self.tree.setColumnWidth(0, 230)
        self.tree.setColumnWidth(1, 95)
        self.tree.setColumnWidth(2, 150)
        self.tree.header().setStretchLastSection(True)
        self.tree.setAlternatingRowColors(True)
        self.tree.itemExpanded.connect(self._expand)
        self.tree.itemDoubleClicked.connect(self._open)
        self.tree.currentItemChanged.connect(self._on_current)
        self.callers_list = QListWidget()
        self.callers_list.itemDoubleClicked.connect(lambda it: self._emit_key(it.data(KEY)))
        self.summary = QTextBrowser()
        right = QSplitter(Qt.Orientation.Vertical)
        box = QWidget()
        bl = QVBoxLayout(box)
        bl.setContentsMargins(0, 0, 0, 0)
        bl.addWidget(QLabel("Callers of the selected node (double-click to open):"))
        bl.addWidget(self.callers_list)
        right.addWidget(self.summary)
        right.addWidget(box)
        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(self.tree)
        split.addWidget(right)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 1)
        split.setSizes([700, 300])
        lay = QVBoxLayout(self)
        lay.addWidget(self.status)
        lay.addLayout(bar)
        lay.addWidget(split, 1)

    # ------------------------------------------------------------ data
    def set_graph(self, graph: Optional[CallGraph], symbols: list[Symbol]) -> None:
        self.graph, self.symbols = graph, symbols
        self.refresh_stack()
        if graph is None:
            self.tree.clear()
            return
        self._callers = graph.callers()
        n_edges = sum(len(v) for v in graph.edges.values())
        self.status.setText(f"Source: {graph.origin}. {len(graph.names):,} nodes, {n_edges:,} edges, {len(graph.indirect)} "
                            f"function(s) with indirect calls.  " + " ".join(graph.warnings[:2]))

    def refresh_stack(self) -> None:
        """Call after stack data changed (.su loaded) so numbers and estimates are recomputed."""
        if self.graph is not None:
            self._lookup = stack_lookup(self.graph, self.symbols)
            self._worst.clear()
            if self.root is not None:
                self.show_root(self.root)

    def _w(self, key: int):
        if key not in self._worst:
            self._worst[key] = estimate_worst_case(self.graph, self.symbols, key, self._lookup)
        return self._worst[key]

    # ------------------------------------------------------------ tree
    def show_root(self, key: int) -> bool:
        if self.graph is None:
            return False
        self.root = key
        self.tree.clear()
        if key not in self.graph.names and key not in self.graph.edges:
            self.summary.setHtml("<p>This function does not appear in the call graph (it makes no calls and is never "
                                 "called, or it is not part of the analysed objects).</p>")
            return False
        item = self._make_item(key, set())
        self.tree.addTopLevelItem(item)
        item.setExpanded(True)
        self.tree.setCurrentItem(item)
        self._show_summary(key)
        return True

    def _make_item(self, key: int, ancestors: set[int]) -> QTreeWidgetItem:
        g = self.graph
        st = self._lookup.get(key)
        notes = []
        if key in ancestors:
            notes.append("recursion (not expanded again)")
        if key in g.indirect:
            notes.append("indirect calls")
        if key < 0:
            notes.append("no ELF symbol (external / inlined / removed)")
        if st is None:
            notes.append("no stack data")
        elif st[1] == "dynamic":
            notes.append("dynamic stack")
        elif st[1] == "dynamic_bounded":
            notes.append("dynamic (bounded)")
        est = self._w(key)
        worst = f"{'' if est.reliable else '≥ '}{est.bound:,}"
        it = QTreeWidgetItem([g.node_name(key), "" if st is None else f"{st[0]:,}", worst, "; ".join(notes)])
        it.setData(0, KEY, key)
        for c in (1, 2):
            it.setTextAlignment(c, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        if key not in ancestors and g.edges.get(key):
            it.addChild(QTreeWidgetItem([DUMMY]))
        return it

    def _expand(self, item: QTreeWidgetItem) -> None:
        if item.childCount() != 1 or item.child(0).text(0) != DUMMY:
            return
        item.takeChild(0)
        key = item.data(0, KEY)
        anc = {key}
        p = item.parent()
        while p is not None:
            anc.add(p.data(0, KEY))
            p = p.parent()
        kids = sorted(self.graph.edges.get(key, ()), key=lambda k: (-self._w(k).bound, self.graph.node_name(k)))
        for i, k in enumerate(kids):
            child = self._make_item(k, anc)
            if i == 0 and kids and self._w(k).bound > 0:
                f = QFont(child.font(0))
                f.setBold(True)
                for c in range(4):
                    child.setFont(c, f)
            item.addChild(child)

    # ------------------------------------------------------------ selection / summary
    def _on_current(self, cur, _prev) -> None:
        self.callers_list.clear()
        if cur is None or self.graph is None or cur.text(0) == DUMMY:
            return
        key = cur.data(0, KEY)
        for c in sorted(self._callers.get(key, ()), key=self.graph.node_name):
            it = QListWidgetItem(self.graph.node_name(c))
            it.setData(KEY, c)
            self.callers_list.addItem(it)

    def _open(self, item, _col) -> None:
        self._emit_key(item.data(0, KEY))

    def _emit_key(self, key) -> None:
        if key is not None and key >= 0:
            self.symbol_requested.emit(key)

    def _show_summary(self, key: int) -> None:
        est = self._w(key)
        g = self.graph
        names = " → ".join(escape(g.node_name(a)) for a in est.path[:30]) + (" …" if len(est.path) > 30 else "")
        verdict = ("<b style='color:#2e7d32'>No limiting issue found on the analysed paths.</b> Interrupt context and "
                   "callers outside this graph are still not included." if est.reliable else
                   "<b style='color:#c0392b'>Lower bound only</b> - a reliable worst case cannot be established.")
        issues = "".join(f"<li>{escape(i)}</li>" for i in est.issues[:40]) or "<li>none</li>"
        self.summary.setHtml(f"<h4>{escape(g.node_name(key))}: {'≥ ' if not est.reliable else ''}{est.bound:,} bytes along "
                             f"the deepest known path</h4><p>{verdict}</p><p><b>Path:</b> {names}</p>"
                             f"<p><b>Issues / limitations:</b></p><ul>{issues}</ul>"
                             f"<p style='color:gray'>Source: {escape(g.origin)}. Per-function values come from .su (matched) or .ci data.</p>")

    def _export_dot(self) -> None:
        if self.graph is None:
            QMessageBox.information(self, "No call graph", "Build or load a call graph first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export call graph", "callgraph.dot", "Graphviz DOT (*.dot)")
        if path:
            try:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(to_dot(self.graph, self.symbols, self.root))
            except OSError as exc:
                QMessageBox.critical(self, "Export failed", str(exc))
