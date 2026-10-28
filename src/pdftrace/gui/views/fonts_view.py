"""Fonts: pdffonts inventory + fontTools details of the selected font."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QSplitter, QTabWidget

from pdftrace.core.models import PDFAnalysis
from pdftrace.gui.views.base import AnalysisView
from pdftrace.gui.widgets import RecordTable, form, title

KNOWN_TABLES = ("head", "hhea", "maxp", "OS/2", "cmap", "name", "post", "glyf", "loca", "hmtx", "CFF", "meta")


class FontsView(AnalysisView):
    title = "Fonts"

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.root.addWidget(
            title(
                "Fonts",
                "Inventory from pdffonts; embedded programs read with fontTools. "
                "head.modified is the build date of the font version.",
            )
        )
        self.table = RecordTable(
            [
                "Font",
                "Type",
                "Encoding",
                "Embedded",
                "Subset",
                "Unicode",
                "Object",
                "Version",
                "Built (head.modified)",
                "Pages",
                "Source",
            ],
            "fonts",
        )
        self.table.row_selected.connect(self._show)
        self.details = QTabWidget()
        self.names = RecordTable(["nameID", "Platform", "Encoding", "Language", "Value"], "font_names")
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.table)
        splitter.addWidget(self.details)
        splitter.setSizes([320, 360])
        self.root.addWidget(splitter)

    def set_analysis(self, analysis: PDFAnalysis | None) -> None:
        super().set_analysis(analysis)
        if analysis is None:
            return
        self.table.set_rows(
            [
                (
                    f.name,
                    f.font_type,
                    f.encoding,
                    f.embedded,
                    f.subset,
                    f.unicode,
                    f.object_id,
                    f.embedded_info.version if f.embedded_info else None,
                    f.embedded_info.head.get("modified") if f.embedded_info else None,
                    f.pages_used,
                    f.source,
                )
                for f in analysis.fonts
            ]
        )
        self.details.clear()
        if analysis.fonts:
            self._show(0)

    def _show(self, row: int) -> None:
        if not self.analysis or row >= len(self.analysis.fonts):
            return
        font = self.analysis.fonts[row]
        info = font.embedded_info
        self.details.clear()
        self.details.addTab(
            form(
                [
                    ("Name", font.name),
                    ("Subset", f"YES (tag {font.subset_tag})" if font.subset else "no"),
                    ("Base name", font.base_name),
                    ("PDF type", font.font_type),
                    ("Encoding", font.encoding),
                    ("Object", f"{font.object_id} {font.generation}" if font.object_id is not None else None),
                    ("Chars rendered", font.chars_rendered),
                    ("Pages", font.pages_used),
                    ("Source", font.source),
                ]
            ),
            "PDF font",
        )
        if not info:
            self.details.addTab(form([("fontTools", "Not embedded or program not readable")]), "Program")
            return
        self.details.addTab(
            form(
                [
                    ("Program format", info.program_format),
                    ("Stream", info.font_file_key),
                    ("Size", f"{info.size_bytes:,} bytes"),
                    ("Family", info.family),
                    ("Subfamily", info.subfamily),
                    ("Full name", info.full_name),
                    ("PostScript name", info.postscript_name),
                    ("Version", info.version),
                    ("Unique ID", info.unique_id),
                    ("Vendor (OS/2)", info.vendor),
                    ("Manufacturer", info.manufacturer),
                    ("Copyright", info.copyright),
                    ("Trademark", info.trademark),
                    ("License", info.license),
                    ("License URL", info.license_url),
                    ("Glyphs", info.glyph_count),
                    ("Unicode code points", info.unicode_codepoints),
                    ("Unicode coverage", info.unicode_coverage),
                    ("Scripts", info.unicode_ranges),
                    ("Error", info.error),
                ]
            ),
            "Program",
        )
        present = set(info.tables)
        checklist = [(t, "✓ present" if t in present else "—") for t in KNOWN_TABLES]
        checklist += [(t, "✓ present") for t in sorted(present - set(KNOWN_TABLES))]
        self.details.addTab(form(checklist), "Tables")
        self.details.addTab(
            form([(f"head.{k}", v) for k, v in info.head.items()] + [(f"meta.{k}", v) for k, v in info.meta.items()]),
            "head / meta",
        )
        self.details.addTab(
            form(
                [(f"OS/2.{k}", v) for k, v in info.os2.items()]
                + [(f"hhea.{k}", v) for k, v in info.hhea.items()]
                + [(f"post.{k}", v) for k, v in info.post.items()]
            ),
            "Metrics",
        )
        self.names.set_rows(
            [
                (n["name_id"], n["platform_id"], n["encoding_id"], n["language_id"], n["value"])
                for n in info.name_records
            ]
        )
        self.details.addTab(self.names, "name table")
