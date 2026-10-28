"""Text: per-page text, fonts and sizes used, date mentions, exports."""

from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from pdftrace.core import report
from pdftrace.core.models import PDFAnalysis
from pdftrace.gui.views.base import AnalysisView, clear_layout
from pdftrace.gui.widgets import RecordTable, form, title


class TextView(AnalysisView):
    title = "Text"

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.root.addWidget(
            title(
                "Text",
                "Extracted with pdfplumber. Dates found in the content describe events, not the creation of the file.",
            )
        )
        self.summary_holder = QVBoxLayout()
        self.root.addLayout(self.summary_holder)
        self.tabs = QTabWidget()
        text_tab = QWidget()
        text_layout = QVBoxLayout(text_tab)
        bar = QHBoxLayout()
        self.page_combo = QComboBox()
        self.page_combo.currentIndexChanged.connect(self._show_page)
        bar.addWidget(self.page_combo)
        bar.addStretch(1)
        for label, kind in (("Export TXT", "txt"), ("Export JSON", "json"), ("Export words CSV", "csv")):
            button = QPushButton(label)
            button.clicked.connect(lambda _=False, k=kind: self._export(k))
            bar.addWidget(button)
        text_layout.addLayout(bar)
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        text_layout.addWidget(self.text)
        self.pages = RecordTable(["Page", "Chars", "Words", "Text lines", "Density", "Fonts"], "text_pages")
        self.fonts = RecordTable(["Font (as rendered)", "Chars"], "text_fonts")
        self.sizes = RecordTable(["Size (pt)", "Chars"], "text_sizes")
        self.dates = RecordTable(["Text", "Normalized", "Page"], "text_dates")
        self.tabs.addTab(text_tab, "Text")
        self.tabs.addTab(self.pages, "Per page")
        self.tabs.addTab(self.fonts, "Fonts used")
        self.tabs.addTab(self.sizes, "Font sizes")
        self.tabs.addTab(self.dates, "Dates in content")
        self.anomalies = RecordTable(["Page", "Kind", "Description", "Text", "Details", "BBox"], "text_anomalies")
        self.tabs.addTab(self.anomalies, "Anomalies")
        self.root.addWidget(self.tabs, 1)

    def set_analysis(self, analysis: PDFAnalysis | None) -> None:
        super().set_analysis(analysis)
        if analysis is None:
            return
        clear_layout(self.summary_holder)
        t = analysis.text
        self.summary_holder.addWidget(
            form(
                [
                    ("Characters / words / lines", f"{t.total_chars:,} / {t.total_words:,} / {t.total_text_lines:,}"),
                    ("Pages analysed", f"{t.pages_analyzed}{' (truncated)' if t.pages_truncated else ''}"),
                    ("Pages without text", t.empty_pages or "none"),
                    ("Low-text pages", t.low_text_pages or "none"),
                    ("Density outliers", t.density_outliers or "none"),
                ]
            )
        )
        self.page_combo.blockSignals(True)
        self.page_combo.clear()
        self.page_combo.addItems([f"Page {p.number}" for p in analysis.pages])
        self.page_combo.blockSignals(False)
        self._show_page(0)
        self.pages.set_rows([(p.number, p.chars, p.words, p.text_lines, p.density, p.fonts) for p in analysis.pages])
        self.fonts.set_rows(sorted(t.fonts_used.items(), key=lambda kv: -kv[1]))
        self.sizes.set_rows([(float(k), v) for k, v in t.font_sizes.items()])
        self.dates.set_rows([(d.text, d.normalized, d.page) for d in t.date_mentions])
        self.anomalies.set_rows(
            [(x.page, x.kind, x.description, x.text, x.details, x.bbox) for x in analysis.text_forensics.anomalies]
        )

    def _show_page(self, index: int) -> None:
        if self.analysis and 0 <= index < len(self.analysis.pages):
            self.text.setPlainText(self.analysis.pages[index].text)

    def _export(self, kind: str) -> None:
        if not self.analysis:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export", f"text.{kind}")
        if not path:
            return
        if kind == "txt":
            report.write_text(self.analysis, Path(path))
        elif kind == "csv":
            report.write_words_csv(self.analysis, Path(path))
        else:
            data = {
                "summary": self.analysis.to_dict()["text"],
                "pages": [
                    {"page": p.number, "text": p.text, "chars": p.chars, "words": p.words} for p in self.analysis.pages
                ],
            }
            Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
