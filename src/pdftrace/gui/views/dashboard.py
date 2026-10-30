"""Dashboard: progress while analysing, summary afterwards."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QGridLayout, QGroupBox, QLabel, QVBoxLayout, QWidget

from pdftrace.core import report
from pdftrace.core.models import PDFAnalysis, StepRun, StepState
from pdftrace.gui.views.base import AnalysisView, clear_layout, scroll
from pdftrace.gui.widgets import form, title

ICON = {
    StepState.PENDING: "○",
    StepState.RUNNING: "⟳",
    StepState.DONE: "✓",
    StepState.SKIPPED: "–",
    StepState.ERROR: "✗",
    StepState.CANCELLED: "✗",
}


class DashboardView(AnalysisView):
    title = "Dashboard"

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.content = QWidget()
        self.body = QVBoxLayout(self.content)
        self.root.addWidget(scroll(self.content))
        self.steps: dict[str, StepRun] = {}
        self._welcome()

    def _welcome(self) -> None:
        clear_layout(self.body)
        self.body.addWidget(
            title(
                "PDFTrace",
                "Drop a PDF here or use File ▸ Open. The file is opened read-only; "
                "scripts and links inside it are never executed.",
            )
        )
        self.body.addStretch(1)

    def start(self, steps: list[StepRun], file_name: str) -> None:
        self.steps = {s.name: s for s in steps}
        self._render_progress(file_name)

    def update_step(self, step: StepRun) -> None:
        self.steps[step.name] = step
        self._render_progress()

    def _render_progress(self, file_name: str | None = None) -> None:
        if file_name:
            self._file_name = file_name
        clear_layout(self.body)
        self.body.addWidget(title("Analyzing PDF…", getattr(self, "_file_name", "")))
        for step in self.steps.values():
            text = f"{ICON[step.state]}  {step.label}"
            if step.message and step.state in (StepState.ERROR, StepState.SKIPPED):
                text += f"   ({step.message[:120]})"
            label = QLabel(text)
            label.setStyleSheet("font-size:14px; padding:2px 0;")
            self.body.addWidget(label)
        self.body.addStretch(1)

    def set_analysis(self, analysis: PDFAnalysis | None) -> None:
        super().set_analysis(analysis)
        if analysis is None:
            self._welcome()
            return
        clear_layout(self.body)
        s = report.summary(analysis)
        m = analysis.metadata
        self.body.addWidget(title(analysis.file.name, analysis.file.path))
        hash_box = QGroupBox("File hashes")
        hash_layout = QVBoxLayout(hash_box)
        for label, value in (
            ("SHA-256 (primary)", analysis.hashes.sha256),
            ("SHA-1", analysis.hashes.sha1),
            ("MD5", analysis.hashes.md5),
        ):
            key = QLabel(label)
            key.setObjectName("muted")
            val = QLabel(value)
            val.setObjectName("hash")
            val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            hash_layout.addWidget(key)
            hash_layout.addWidget(val)
        self.body.addWidget(hash_box)

        grid = QGridLayout()
        boxes = [
            ("File", [("Size", f"{analysis.file.size:,} bytes"), ("Analyzed (UTC)", analysis.analyzed_at_utc)]),
            (
                "PDF",
                [
                    ("Version", s["pdf_version"]),
                    ("Pages", s["pages"]),
                    ("Encrypted", s["encrypted"]),
                    ("Linearized", s["linearized"]),
                    (
                        "Revisions (xref chain)"
                        if s["revisions_method"] == "xref_chain"
                        else "Revisions (%%EOF heuristic)",
                        s["revisions"],
                    ),
                    ("Incremental updates", analysis.structure.incremental_updates),
                ],
            ),
            (
                "Metadata",
                [
                    (k, m.info_value(k) or m.xmp_value(x))
                    for k, x in (
                        ("Title", "dc:title"),
                        ("Author", "dc:creator"),
                        ("Creator", "xmp:CreatorTool"),
                        ("Producer", "pdf:Producer"),
                        ("CreationDate", "xmp:CreateDate"),
                        ("ModDate", "xmp:ModifyDate"),
                    )
                ],
            ),
            (
                "Fonts",
                [
                    ("References", s["fonts_total"]),
                    ("Embedded", s["fonts_embedded"]),
                    ("Subset", s["fonts_subset"]),
                    ("Not embedded", s["fonts_not_embedded"]),
                ],
            ),
            (
                "Images",
                [("Image objects", s["images_total"])]
                + [(enc.upper(), n) for enc, n in sorted(s["images_by_encoding"].items())],
            ),
            (
                "Content",
                [
                    ("Objects", s["objects"]),
                    ("Annotations", s["annotations"]),
                    ("JavaScript", s["scripts"]),
                    ("Attachments", s["attachments"]),
                    ("Form fields", s["form_fields"]),
                    ("Signatures", s["signatures"]),
                    ("Images with own metadata", s["images_with_metadata"]),
                    ("Text-layer anomalies", s["text_anomalies"]),
                    ("Parser disagreements", s["parser_disagreements"]),
                    ("OCR: hidden text runs", s["ocr_hidden_runs"] if s["ocr_pages"] else "not run"),
                    ("OCR: visible text not in layer", s["ocr_visible_not_in_layer"] if s["ocr_pages"] else "not run"),
                ],
            ),
            (
                "Findings",
                [(sev.capitalize(), n) for sev, n in s["findings_by_severity"].items()]
                + [(f"{cat} (notice+)", n) for cat, n in sorted(s["anomalies_by_category"].items())],
            ),
        ]
        for i, (name, pairs) in enumerate(boxes):
            box = QGroupBox(name)
            layout = QVBoxLayout(box)
            layout.addWidget(form(pairs))
            grid.addWidget(box, i // 3, i % 3)
        holder = QWidget()
        holder.setLayout(grid)
        self.body.addWidget(holder)
        self.body.addStretch(1)
