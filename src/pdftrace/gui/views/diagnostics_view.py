"""Diagnostics: dependency status, pipeline steps, technical details and errors."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QPlainTextEdit, QSplitter

from pdftrace.config import Settings
from pdftrace.core.models import PDFAnalysis, ToolStatus
from pdftrace.gui.views.base import AnalysisView
from pdftrace.gui.widgets import RecordTable, title
from pdftrace.integrations.poppler import Poppler
from pdftrace.integrations.toolbox import Toolbox


def library_versions() -> list[tuple[str, str]]:
    import fontTools
    import pdfminer
    import pdfplumber
    import PySide6

    return [
        ("pdfplumber", pdfplumber.__version__),
        ("pdfminer.six", pdfminer.__version__),
        ("fontTools", fontTools.version),
        ("PySide6", PySide6.__version__),
    ]


class DiagnosticsView(AnalysisView):
    title = "Diagnostics"

    def __init__(self, settings: Settings, theme: str = "light") -> None:
        super().__init__(settings, theme)
        self.root.addWidget(
            title("Diagnostics", "Configuration of external tools and technical details of the last analysis.")
        )
        self.tools = RecordTable(["Component", "Available", "Version", "Path", "Note"], "tools", searchable=False)
        self.steps = RecordTable(["Step", "State", "Duration (s)", "Message"], "steps", searchable=False)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        splitter = QSplitter(Qt.Orientation.Vertical)
        for w in (self.tools, self.steps, self.log):
            splitter.addWidget(w)
        self.root.addWidget(splitter)
        self.refresh_tools()

    def refresh_tools(self, statuses: list[ToolStatus] | None = None) -> None:
        statuses = statuses or [*Poppler(self.settings).status(), *Toolbox(self.settings).statuses()]
        rows = [(s.name, s.available, s.version, s.path, s.error) for s in statuses]
        rows += [(name, True, version, "python package", None) for name, version in library_versions()]
        self.tools.set_rows(rows)

    def missing_poppler(self) -> list[str]:
        return [
            row[0]
            for row in self.tools.model.rows
            if row[3] != "python package" and row[1] is False and row[0] in ("pdfinfo", "pdffonts", "pdfimages")
        ]

    def add_error(self, message: str, details: str) -> None:
        self.log.appendPlainText(f"ERROR: {message}\n{details}\n")

    def set_analysis(self, analysis: PDFAnalysis | None) -> None:
        super().set_analysis(analysis)
        if analysis is None:
            return
        self.refresh_tools(analysis.tools)
        self.steps.set_rows([(s.label, s.state.value, round(s.duration_s, 3), s.message) for s in analysis.steps])
        lines = []
        for step in analysis.steps:
            for diag in step.diagnostics:
                lines.append(f"[{step.name}] {diag}")
        self.log.setPlainText("\n".join(lines) or "No diagnostics.")
