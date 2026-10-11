"""Application entry point."""
from __future__ import annotations

import logging
import sys


def main(argv: list[str] | None = None) -> int:
    from PySide6.QtWidgets import QApplication
    from .main_window import MainWindow

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    argv = list(sys.argv if argv is None else argv)
    app = QApplication(argv)
    app.setApplicationName("ELF Memory Analyzer")
    app.setOrganizationName("elfmem")
    win = MainWindow()
    win.show()
    if len(argv) > 1:
        win.open_elf(argv[1])
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
