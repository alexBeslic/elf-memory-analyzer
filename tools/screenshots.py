"""Render README screenshots offscreen: PYTHONPATH=. python tools/screenshots.py ELF BUILD_DIR OUT_DIR"""
import os, sys, time
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtWidgets import QApplication
from elfmem.gui.main_window import MainWindow

elf, build, out = sys.argv[1:4]
app = QApplication([])
w = MainWindow(); w.resize(1500, 900); w.show()

def wait(cond, t=20):
    end = time.time() + t
    while time.time() < end and not cond():
        app.processEvents(); time.sleep(0.01)

w.open_elf(elf); wait(lambda: w.res and w.res.debug)
w.load_build_dir(build); wait(lambda: w.res.su and w._graph)
w.mem_page.regions.setRowCount(0); w.mem_page._add_row("FLASH", "0x0", "0x10000"); w.mem_page._add_row("RAM", "0x4000", "0x2000"); w.mem_page._apply()

def shot(name, page):
    w.nav.setCurrentRow(page)
    for _ in range(30): app.processEvents(); time.sleep(0.01)
    w.grab().save(os.path.join(out, name))

sym = {s.name: s.id for s in w.res.elf.symbols}
shot("overview.png", 0)
w.show_symbol(sym["big_function"]); w.inspector.tabs.setCurrentWidget(w.inspector.view_stack)
wait(lambda: "----" in w.inspector.asm.edit.toPlainText())
shot("functions_assembly.png", 1)
w.show_symbol(sym["message"]); w.inspector.tabs.setCurrentWidget(w.inspector.view_stack)
shot("data_initial_value.png", 2)
shot("visualization.png", 4)
w.show_symbol(sym["main"]); w.show_callgraph_for_selected()
top = w.cg_page.tree.topLevelItem(0); w.cg_page.tree.expandItem(top)
for i in range(top.childCount()): w.cg_page.tree.expandItem(top.child(i))
shot("callgraph.png", 6)
