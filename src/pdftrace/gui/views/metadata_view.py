"""Metadata: Info dictionary, XMP, Info-vs-XMP comparison, revisions, raw XMP."""

from __future__ import annotations

from PySide6.QtGui import QColor
from PySide6.QtWidgets import QPlainTextEdit, QTabWidget

from pdftrace.core.models import PDFAnalysis
from pdftrace.gui.theme import colors
from pdftrace.gui.views.base import AnalysisView
from pdftrace.gui.widgets import RecordTable, form, title


class MetadataView(AnalysisView):
    title = "Metadata"

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.root.addWidget(
            title("Metadata", "Every value shows its source. Differences are neutral indicators that require review.")
        )
        self.tabs = QTabWidget()
        self.info = RecordTable(["Field", "Value", "Source", "Confidence", "Note"], "metadata_info")
        self.xmp = RecordTable(["Property", "Value", "Source", "Note"], "metadata_xmp")
        self.compare = RecordTable(["Field", "Info value", "XMP key", "XMP value", "Status"], "info_vs_xmp")
        self.revisions = RecordTable(["Revision", "Field", "Value"], "info_revisions")
        self.raw = QPlainTextEdit()
        self.raw.setReadOnly(True)
        self.tabs.addTab(self.info, "Info dictionary")
        self.tabs.addTab(self.xmp, "XMP")
        self.tabs.addTab(self.compare, "Info vs XMP")
        self.tabs.addTab(self.revisions, "Revisions")
        self.tabs.addTab(self.raw, "Raw XMP")
        self.cross = RecordTable(["Field", "pdfminer", "pikepdf", "pypdf", "pdfium", "Agreement"], "parser_crosscheck")
        self.tabs.addTab(self.cross, "Parser cross-check")
        self.general_index = self.tabs.addTab(form([]), "Document")
        self.root.addWidget(self.tabs)

    def set_analysis(self, analysis: PDFAnalysis | None) -> None:
        super().set_analysis(analysis)
        if analysis is None:
            return
        m = analysis.metadata
        self.info.set_rows([(v.field, v.value, v.source, v.confidence, v.note) for v in m.info + m.custom])
        self.xmp.set_rows([(v.field, v.value, v.source, v.note) for v in m.xmp])
        warn = QColor(colors(self.theme)["warning"])
        warn.setAlpha(45)
        self.compare.set_rows(
            [(c.field, c.info_value, c.xmp_key, c.xmp_value, c.status) for c in m.comparisons],
            row_color=lambda row: warn if row[4] == "difference" else None,
        )
        self.revisions.set_rows([(r.index, k, v) for r in m.info_revisions for k, v in r.values.items()])
        self.raw.setPlainText(m.xmp_raw or m.xmp_error or "No XMP packet.")
        parsers = analysis.crosscheck.parsers
        differing = {d["field"] for d in analysis.crosscheck.differences}
        fields = sorted({k for data in parsers.values() for k in data})
        warn2 = QColor(colors(self.theme)["notice"])
        warn2.setAlpha(45)
        self.cross.set_rows(
            [
                (
                    f,
                    *[parsers.get(p, {}).get(f) for p in ("pdfminer", "pikepdf", "pypdf", "pdfium")],
                    "differs" if f in differing else "",
                )
                for f in fields
            ],
            row_color=lambda row: warn2 if row[5] == "differs" else None,
        )
        self.tabs.removeTab(self.general_index)
        self.general_index = self.tabs.addTab(
            form(
                [
                    ("PDF header version", m.pdf_version),
                    ("Catalog /Version", m.catalog_version),
                    ("Pages", m.page_count),
                    ("Encrypted", m.encrypted),
                    *[(f"Permission: {k}", v) for k, v in m.permissions.items()],
                    ("Trailer IDs", m.trailer_ids),
                    ("Custom Info keys", [c.field for c in m.custom]),
                    ("Errors", m.errors),
                ]
            ),
            "Document",
        )
