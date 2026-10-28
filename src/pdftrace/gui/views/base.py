"""Base class shared by all views."""

from __future__ import annotations

from PySide6.QtWidgets import QScrollArea, QVBoxLayout, QWidget

from pdftrace.config import Settings
from pdftrace.core.models import PDFAnalysis


class AnalysisView(QWidget):
    """A page of the main window that renders part of a :class:`PDFAnalysis`."""

    title = "View"

    def __init__(self, settings: Settings, theme: str = "light") -> None:
        super().__init__()
        self.settings = settings
        self.theme = theme
        self.analysis: PDFAnalysis | None = None
        self.root = QVBoxLayout(self)
        self.root.setContentsMargins(18, 14, 18, 14)

    def set_analysis(self, analysis: PDFAnalysis | None) -> None:
        self.analysis = analysis

    def set_theme(self, theme: str) -> None:
        self.theme = theme
        if self.analysis is not None:
            self.set_analysis(self.analysis)


def scroll(widget: QWidget) -> QScrollArea:
    area = QScrollArea()
    area.setWidgetResizable(True)
    area.setWidget(widget)
    area.setFrameShape(QScrollArea.Shape.NoFrame)
    return area


def clear_layout(layout: QVBoxLayout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget() if item is not None else None
        if widget is not None:
            widget.setParent(None)
            widget.deleteLater()
