"""Orchestration of the analyzers.

The pipeline is UI-agnostic: progress is reported through a callback and
cancellation through a :class:`threading.Event`, so the same code backs the
CLI, the GUI worker thread and the tests.
"""

from __future__ import annotations

import threading
import time
import traceback
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from pdftrace import TOOL_NAME, __version__
from pdftrace.config import Settings, default_settings
from pdftrace.core.analyzer import AnalysisCancelled, AnalysisContext, Analyzer
from pdftrace.core.hashing import hash_file
from pdftrace.core.models import FileInfo, PDFAnalysis, StepRun, StepState, ToolStatus
from pdftrace.integrations.toolbox import Toolbox
from pdftrace.utils.logging import get_logger, log_event
from pdftrace.utils.paths import validate_pdf_path

_LOG = get_logger("pipeline")

ProgressCallback = Callable[[StepRun], None]


def new_analysis(path: Path) -> PDFAnalysis:
    """Create an analysis skeleton with file information and hashes."""
    stat = path.stat()
    return PDFAnalysis(
        tool=TOOL_NAME,
        tool_version=__version__,
        analyzed_at_utc=datetime.now(UTC).isoformat(timespec="seconds"),
        file=FileInfo(
            path=str(path),
            name=path.name,
            size=stat.st_size,
            filesystem_mtime_utc=datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(timespec="seconds"),
        ),
        hashes=hash_file(path),
    )


def default_analyzers() -> list[Analyzer]:
    """The standard analyzer chain, in execution order."""
    from pdftrace.analyzers.crosscheck import CrossCheckAnalyzer
    from pdftrace.analyzers.findings import FindingsAnalyzer
    from pdftrace.analyzers.fonts import FontsAnalyzer
    from pdftrace.analyzers.image_evidence import ImageEvidenceAnalyzer
    from pdftrace.analyzers.images import ImagesAnalyzer
    from pdftrace.analyzers.interactive import InteractiveAnalyzer
    from pdftrace.analyzers.metadata import MetadataAnalyzer
    from pdftrace.analyzers.objects import ObjectsAnalyzer
    from pdftrace.analyzers.ocr import OcrAnalyzer
    from pdftrace.analyzers.structure import StructureAnalyzer
    from pdftrace.analyzers.text import TextAnalyzer
    from pdftrace.analyzers.toolbox import ToolboxAnalyzer

    return [
        MetadataAnalyzer(),
        StructureAnalyzer(),
        ObjectsAnalyzer(),
        FontsAnalyzer(),
        ImagesAnalyzer(),
        ImageEvidenceAnalyzer(),
        TextAnalyzer(),
        InteractiveAnalyzer(),
        CrossCheckAnalyzer(),
        OcrAnalyzer(),
        ToolboxAnalyzer(),
        FindingsAnalyzer(),
    ]


def _tesseract_status(settings: Settings) -> ToolStatus:
    from pdftrace.integrations.tesseract import Tesseract

    tess = Tesseract(settings)
    exe = tess.executable()
    if not exe:
        return ToolStatus("tesseract", False, None, None, "Not found (optional, OCR)", "ocr")
    return ToolStatus("tesseract", True, exe, tess.version(), f"languages: {', '.join(tess.languages())}", "ocr")


class Pipeline:
    """Runs a sequence of analyzers and collects their results."""

    def __init__(
        self,
        analyzers: Sequence[Analyzer] | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.analyzers = list(analyzers) if analyzers is not None else default_analyzers()
        self.settings = settings or default_settings()

    def steps(self) -> list[StepRun]:
        return [StepRun("hashing", "File & hashes")] + [StepRun(a.name, a.label) for a in self.analyzers]

    def run(
        self,
        pdf_path: str | Path,
        progress: ProgressCallback | None = None,
        cancel_event: threading.Event | None = None,
    ) -> PDFAnalysis:
        """Analyse ``pdf_path``. Raises :class:`InputError` for unusable input."""
        path = validate_pdf_path(pdf_path)
        cancel = cancel_event or threading.Event()
        steps = self.steps()
        notify = progress or (lambda _step: None)

        first = steps[0]
        first.state = StepState.RUNNING
        notify(first)
        start = time.monotonic()
        analysis = new_analysis(path)
        first.state, first.duration_s = StepState.DONE, time.monotonic() - start
        notify(first)

        analysis.settings = {k: v for k, v in vars(self.settings).items() if not k.startswith("_")}
        ctx = AnalysisContext(path, analysis, self.settings, cancel)
        analysis.tools = [*ctx.poppler.status(), *Toolbox(self.settings).statuses(), _tesseract_status(self.settings)]
        try:
            for analyzer, step in zip(self.analyzers, steps[1:], strict=True):
                if cancel.is_set():
                    step.state = StepState.CANCELLED
                    notify(step)
                    continue
                self._run_step(analyzer, step, ctx, notify)
        finally:
            ctx.close()
        analysis.steps = steps
        return analysis

    def _run_step(self, analyzer: Analyzer, step: StepRun, ctx: AnalysisContext, notify: ProgressCallback) -> None:
        step.state = StepState.RUNNING
        notify(step)
        start = time.monotonic()
        try:
            result = analyzer.analyze(ctx)
            if result.section and result.payload is not None:
                setattr(ctx.analysis, result.section, result.payload)
            step.diagnostics.extend(result.diagnostics)
            step.message = result.message
            step.state = StepState.SKIPPED if result.skipped else StepState.DONE
        except AnalysisCancelled:
            step.state = StepState.CANCELLED
            step.message = "Cancelled"
        except Exception as exc:  # an analyzer must never abort the whole run
            step.state = StepState.ERROR
            step.message = f"{type(exc).__name__}: {exc}"
            step.diagnostics.append(traceback.format_exc())
            log_event(_LOG, 40, "analyzer.error", analyzer=analyzer.name, error=str(exc))
        step.duration_s = time.monotonic() - start
        notify(step)


def analyze(
    pdf_path: str | Path,
    settings: Settings | None = None,
    progress: ProgressCallback | None = None,
    cancel_event: threading.Event | None = None,
) -> PDFAnalysis:
    """Convenience wrapper: run the default pipeline on ``pdf_path``."""
    return Pipeline(settings=settings).run(pdf_path, progress, cancel_event)
