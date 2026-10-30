"""Analyzer plug-in contract.

An analyzer is an independent unit that reads the PDF (through the shared
:class:`AnalysisContext`) and returns an :class:`AnalysisResult`. The pipeline
stores each result in the matching section of :class:`PDFAnalysis`, so adding
a new analyzer (qpdf, mutool, ExifTool, OCR, YARA ...) needs no GUI change:
register it and its output appears in the JSON report, in Diagnostics and -
through findings rules - in every view.
"""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

from pdftrace.config import Settings, default_settings
from pdftrace.core.models import PDFAnalysis
from pdftrace.integrations.pdfplumber_adapter import PDFOpenError, open_pdf
from pdftrace.integrations.poppler import Poppler


class AnalysisCancelled(RuntimeError):
    """Raised inside an analyzer when the user cancels the analysis."""


@dataclass
class AnalysisResult:
    """Output of one analyzer."""

    #: Attribute of :class:`PDFAnalysis` that receives ``payload``.
    #: ``None`` means the analyzer updates the analysis in place (e.g. findings).
    section: str | None
    payload: Any = None
    diagnostics: list[str] = field(default_factory=list)
    skipped: bool = False
    message: str | None = None


class AnalysisContext:
    """Shared, lazily initialised resources for one analysis run."""

    def __init__(
        self,
        path: Path,
        analysis: PDFAnalysis,
        settings: Settings | None = None,
        cancel_event: threading.Event | None = None,
    ) -> None:
        self.path = path
        self.analysis = analysis
        self.settings = settings or default_settings()
        self.cancel_event = cancel_event or threading.Event()
        self.poppler = Poppler(self.settings)
        self._pdf: Any = None
        self._pdf_error: str | None = None
        self._raw: bytes | None = None
        self._pike: Any = None
        self._pike_error: str | None = None
        self._xref_chain: Any = None

    def check_cancelled(self) -> None:
        if self.cancel_event.is_set():
            raise AnalysisCancelled("Analysis cancelled by user")

    @property
    def raw_bytes(self) -> bytes:
        """The file content (read once; the file itself is never modified)."""
        if self._raw is None:
            self._raw = self.path.read_bytes()
        return self._raw

    def xref_chain(self) -> Any:
        """Revisions reconstructed from startxref and the /Prev chain (computed once)."""
        if self._xref_chain is None:
            from pdftrace.core.xref_chain import walk_xref_chain

            self._xref_chain = walk_xref_chain(self.raw_bytes)
        return self._xref_chain

    def pdf(self) -> Any:
        """pdfplumber document, opened once. Raises :class:`PDFOpenError`."""
        if self._pdf is None and self._pdf_error is None:
            try:
                self._pdf = open_pdf(self.path)
            except PDFOpenError as exc:
                self._pdf_error = str(exc)
        if self._pdf is None:
            raise PDFOpenError(self._pdf_error or "PDF could not be opened")
        return self._pdf

    def pike(self) -> Any:
        """pikepdf document (read-only), opened once. Raises :class:`PDFOpenError`."""
        if self._pike is None and self._pike_error is None:
            from pdftrace.integrations.pikepdf_adapter import open_pike

            try:
                self._pike = open_pike(self.path)
            except PDFOpenError as exc:
                self._pike_error = str(exc)
        if self._pike is None:
            raise PDFOpenError(self._pike_error or "pikepdf could not open the file")
        return self._pike

    def close(self) -> None:
        if self._pike is not None:
            try:
                self._pike.close()
            finally:
                self._pike = None
        if self._pdf is not None:
            try:
                self._pdf.close()
            finally:
                self._pdf = None
        self._raw = None
        self._xref_chain = None


class Analyzer(ABC):
    """Base class for analyzers."""

    #: Stable identifier (used in JSON and logs).
    name: ClassVar[str]
    #: Human readable label (used in the GUI progress list).
    label: ClassVar[str]

    @abstractmethod
    def analyze(self, ctx: AnalysisContext) -> AnalysisResult:
        """Analyse the PDF referenced by ``ctx`` and return the result."""

    def run_standalone(self, pdf_path: Path, settings: Settings | None = None) -> AnalysisResult:
        """Run this analyzer alone on ``pdf_path`` (useful for scripts and tests)."""
        from pdftrace.core.pipeline import new_analysis

        path = Path(pdf_path).resolve()
        ctx = AnalysisContext(path, new_analysis(path), settings)
        try:
            return self.analyze(ctx)
        finally:
            ctx.close()
