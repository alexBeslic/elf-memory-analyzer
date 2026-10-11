"""Background execution helper: run a function in the global QThreadPool, report via signals."""
from __future__ import annotations

import logging
from typing import Any, Callable

from PySide6.QtCore import QObject, QRunnable, Signal, Slot

log = logging.getLogger(__name__)


class WorkerSignals(QObject):
    finished = Signal(object)
    failed = Signal(str)
    progress = Signal(str)


class Worker(QRunnable):
    """Runs ``fn(*args, progress=<callable>, **kwargs)`` off the GUI thread.

    Results are delivered through queued signals, so slots run on the GUI thread.
    Workers must never mutate objects the GUI is reading.
    """

    def __init__(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self.fn, self.args, self.kwargs = fn, args, kwargs
        self.signals = WorkerSignals()
        self.setAutoDelete(False)  # lifetime managed by the owner (signals object must outlive run())

    def run(self) -> None:
        try:
            result = self.fn(*self.args, progress=self.signals.progress.emit, **self.kwargs)
        except Exception as exc:  # report every failure to the UI instead of dying silently
            log.exception("Background task failed")
            self.signals.failed.emit(f"{type(exc).__name__}: {exc}")
        else:
            self.signals.finished.emit(result)


class Task(QObject):
    """Owns a Worker and forwards its signals to Python callbacks on the GUI thread.

    Being a QObject living in the GUI thread guarantees queued (thread-safe) delivery.
    """
    done = Signal(object)

    def __init__(self, fn, *args, on_done, on_fail=None, on_progress=None, parent=None, **kwargs) -> None:
        super().__init__(parent)
        self.worker = Worker(fn, *args, **kwargs)
        self._on_done, self._on_fail, self._on_progress = on_done, on_fail, on_progress
        self.worker.signals.finished.connect(self._finished)
        self.worker.signals.failed.connect(self._failed)
        self.worker.signals.progress.connect(self._progress)

    @Slot(object)
    def _finished(self, result) -> None:
        try:
            self._on_done(result)
        finally:
            self.done.emit(self)

    @Slot(str)
    def _failed(self, message: str) -> None:
        try:
            if self._on_fail:
                self._on_fail(message)
        finally:
            self.done.emit(self)

    @Slot(str)
    def _progress(self, message: str) -> None:
        if self._on_progress:
            self._on_progress(message)
