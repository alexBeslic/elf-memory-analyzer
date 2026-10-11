"""Render README screenshots offscreen from a demo ELF: python tools/screenshots.py ELF BUILD_DIR OUT_DIR"""
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
w.load_build_dir(build); wait(lambda: w.res.su)
w.mem_page.regions.setRowCount(0); w.mem_page._add_row("FLASH", "0x0", "0x10000"); w.mem_page._add_row("RAM", "0x4000", "0x2000"); w.mem_page._apply()
def shot(name, page):
    w.nav.setCurrentRow(page)
    for _ in range(30): app.processEvents(); time.sleep(0.01)
    w.grab().save(os.path.join(out, name))
shot("overview.png", 0)
fid = next(s.id for s in w.res.functions if s.name == "big_function")
w.show_symbol(fid); w.inspector.tabs.setCurrentWidget(w.inspector.asm)
wait(lambda: "----" in w.inspector.asm.edit.toPlainText())
shot("functions_assembly.png", 1)
shot("visualization.png", 4)
shot("stack.png", 5)
