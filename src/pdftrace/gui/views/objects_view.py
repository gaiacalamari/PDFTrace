"""Objects: pikepdf inventory, document features, layers, outline, page boxes."""

from __future__ import annotations

from typing import Any

from PySide6.QtWidgets import QTabWidget

from pdftrace.core.models import PDFAnalysis
from pdftrace.gui.views.base import AnalysisView
from pdftrace.gui.widgets import RecordTable, form, title


class ObjectsView(AnalysisView):
    title = "Objects"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.root.addWidget(title("Objects", "Object-level inventory read with pikepdf (libqpdf), read-only."))
        self.tabs = QTabWidget()
        self.types = RecordTable(["Type / Subtype", "Count"], "objects_by_type")
        self.streams = RecordTable(
            ["Object", "Gen", "Type", "Subtype", "Filters", "Raw bytes", "Decoded bytes", "Decode error"], "streams"
        )
        self.outline = RecordTable(["Level", "Title", "Destination", "Action"], "outline")
        self.layers = RecordTable(["Layer", "Object", "Hidden by default"], "layers")
        self.boxes = RecordTable(
            ["Page", "Rotate", "MediaBox", "CropBox", "BleedBox", "TrimBox", "ArtBox"], "page_boxes"
        )
        self.summary_index = self.tabs.addTab(form([]), "Summary")
        for widget, label in (
            (self.types, "Types"),
            (self.streams, "Streams"),
            (self.outline, "Bookmarks"),
            (self.layers, "Layers"),
            (self.boxes, "Page boxes"),
        ):
            self.tabs.addTab(widget, label)
        self.root.addWidget(self.tabs)

    def set_analysis(self, analysis: PDFAnalysis | None) -> None:
        super().set_analysis(analysis)
        if analysis is None:
            return
        o = analysis.objects
        self.tabs.removeTab(self.summary_index)
        self.summary_index = 0
        self.tabs.insertTab(
            0,
            form(
                [
                    ("Objects", o.total_objects),
                    ("Streams", o.streams),
                    ("PDF version (pikepdf)", o.pdf_version),
                    ("Extension level", o.extension_level),
                    ("Linearized", o.linearized),
                    ("Filters", o.by_filter),
                    ("Catalog features", list(o.catalog_features)),
                    ("Encryption", o.encryption or "none"),
                    ("Permissions", o.permissions),
                    ("Generation > 0", o.nonzero_generation or "none"),
                    ("Thumbnails (pages)", o.thumbnails or "none"),
                    ("PieceInfo", o.piece_info or "none"),
                    ("Output intents", o.output_intents or "none"),
                    ("Page labels", o.page_labels or "none"),
                    ("qpdf warnings", o.qpdf_warnings[:20] or "none"),
                    ("Error", o.error),
                ]
            ),
            "Summary",
        )
        self.tabs.setCurrentIndex(0)
        self.types.set_rows(list(o.by_type.items()))
        streams = {(s.object_id, s.generation): s for s in [*o.largest_streams, *o.undecodable_streams]}
        self.streams.set_rows(
            [
                (
                    s.object_id,
                    s.generation,
                    s.type,
                    s.subtype,
                    s.filters,
                    s.raw_length,
                    s.decoded_length,
                    s.decode_error,
                )
                for s in streams.values()
            ]
        )
        self.outline.set_rows([(x["level"], x["title"], x["dest"], x["action"]) for x in o.outline])
        self.layers.set_rows([(x["name"], x["object"], x["default_off"]) for x in o.layers])
        self.boxes.set_rows(
            [
                (
                    b["page"],
                    b.get("rotate"),
                    b.get("MediaBox"),
                    b.get("CropBox"),
                    b.get("BleedBox"),
                    b.get("TrimBox"),
                    b.get("ArtBox"),
                )
                for b in o.page_boxes
            ]
        )
