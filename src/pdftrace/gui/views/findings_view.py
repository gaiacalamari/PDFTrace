"""Findings (with severity filter and evidence) and the reconstructed timeline."""

from __future__ import annotations

import json

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from pdftrace.core.models import PDFAnalysis
from pdftrace.gui.theme import colors
from pdftrace.gui.views.base import AnalysisView
from pdftrace.gui.widgets import RecordTable, title


class FindingsView(AnalysisView):
    title = "Findings"

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.root.addWidget(
            title(
                "Findings", "Technical indicators to support the analyst. They are not conclusions about authenticity."
            )
        )
        self.tabs = QTabWidget()
        findings_tab = QWidget()
        layout = QVBoxLayout(findings_tab)
        bar = QHBoxLayout()
        bar.addWidget(QLabel("Minimum severity"))
        self.severity = QComboBox()
        self.severity.addItems(["info", "notice", "warning"])
        self.severity.currentIndexChanged.connect(self._refresh)
        bar.addWidget(self.severity)
        bar.addStretch(1)
        layout.addLayout(bar)
        self.table = RecordTable(["ID", "Severity", "Category", "Title", "Page", "Rule"], "findings")
        self.table.row_selected.connect(self._show)
        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.table)
        splitter.addWidget(self.detail)
        splitter.setSizes([380, 220])
        layout.addWidget(splitter)
        self.timeline = RecordTable(["Timestamp", "Kind", "Description", "Source", "Caveat"], "timeline")
        self.tabs.addTab(findings_tab, "Findings")
        self.tabs.addTab(self.timeline, "Timeline")
        self.root.addWidget(self.tabs)
        self._rows: list[int] = []

    def set_analysis(self, analysis: PDFAnalysis | None) -> None:
        super().set_analysis(analysis)
        if analysis is None:
            return
        self._refresh()
        self.timeline.set_rows([(e.timestamp, e.kind, e.description, e.source, e.caveat) for e in analysis.timeline])

    def _refresh(self) -> None:
        if not self.analysis:
            return
        minimum = self.severity.currentIndex()
        c = colors(self.theme)
        tint = {"notice": QColor(c["notice"]), "warning": QColor(c["warning"])}
        for color in tint.values():
            color.setAlpha(40)
        self._rows = [i for i, f in enumerate(self.analysis.findings) if f.severity.rank >= minimum]
        self.table.set_rows(
            [
                (f.id, f.severity.value.upper(), f.category, f.title, f.page, f.source)
                for f in (self.analysis.findings[i] for i in self._rows)
            ],
            row_color=lambda row: tint.get(str(row[1]).lower()),
        )
        self.detail.clear()

    def _show(self, row: int) -> None:
        if not self.analysis or row >= len(self._rows):
            return
        f = self.analysis.findings[self._rows[row]]
        evidence = json.dumps(f.evidence, ensure_ascii=False, indent=2) if f.evidence else "{}"
        self.detail.setPlainText(
            f"{f.id}  {f.severity.value.upper()}  [{f.category}]\n{f.title}\n\n"
            f"{f.description}\n\nEvidence:\n{evidence}\n\nSource: {f.source}"
        )
