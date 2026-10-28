"""Runs the analysis pipeline in a background thread."""

from __future__ import annotations

import copy
import threading
import traceback
from pathlib import Path

from PySide6.QtCore import QObject, Signal, Slot

from pdftrace.config import Settings
from pdftrace.core.models import StepRun
from pdftrace.core.pipeline import Pipeline
from pdftrace.utils.paths import InputError


class AnalysisWorker(QObject):
    step = Signal(object)
    finished = Signal(object)
    failed = Signal(str, str)

    def __init__(self, path: Path, settings: Settings) -> None:
        super().__init__()
        self.path = path
        self.settings = settings
        self.cancel_event = threading.Event()

    def cancel(self) -> None:
        self.cancel_event.set()

    @Slot()
    def run(self) -> None:
        def progress(step: StepRun) -> None:
            self.step.emit(copy.copy(step))

        try:
            analysis = Pipeline(settings=self.settings).run(self.path, progress, self.cancel_event)
        except InputError as exc:
            self.failed.emit(str(exc), "")
        except Exception as exc:  # shown to the user, details go to Diagnostics
            self.failed.emit(f"Unexpected error: {type(exc).__name__}: {exc}", traceback.format_exc())
        else:
            self.finished.emit(analysis)
