"""Interactive content: annotations, actions, JavaScript, attachments, forms, signatures."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QMessageBox, QPlainTextEdit, QPushButton, QSplitter, QTabWidget

from pdftrace.core.models import PDFAnalysis
from pdftrace.gui.views.base import AnalysisView
from pdftrace.gui.widgets import RecordTable, title
from pdftrace.integrations.pikepdf_adapter import extract_attachments


class InteractiveView(AnalysisView):
    title = "Interactive"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.root.addWidget(
            title(
                "Interactive content",
                "Read with pikepdf. Scripts are shown as text and never "
                "executed; links are not opened. Signatures are described, not validated.",
            )
        )
        bar = QHBoxLayout()
        self.save_btn = QPushButton("Save attachments…")
        self.save_btn.clicked.connect(self.save_attachments)
        bar.addWidget(self.save_btn)
        bar.addStretch(1)
        self.root.addLayout(bar)
        self.tabs = QTabWidget()
        self.annots = RecordTable(
            ["Page", "Type", "Author", "Created", "Modified", "Hidden", "Contents", "URI", "Rect"], "annotations"
        )
        self.actions_table = RecordTable(["Location", "Trigger", "Action", "Target"], "actions")
        self.scripts = RecordTable(["Location", "Trigger", "Length", "SHA-256"], "scripts")
        self.code = QPlainTextEdit()
        self.code.setReadOnly(True)
        self.scripts.row_selected.connect(self._show_script)
        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(self.scripts)
        split.addWidget(self.code)
        self.files = RecordTable(
            ["Name", "Description", "Type", "Size", "Declared size", "Created", "Modified", "SHA-256", "Location"],
            "attachments",
        )
        self.fields = RecordTable(["Name", "Type", "Value", "Flags", "Actions"], "form_fields")
        self.sigs = RecordTable(
            [
                "Field",
                "SubFilter",
                "Signing time",
                "Name",
                "Reason",
                "Location",
                "Covers whole file",
                "Bytes after",
                "Certificates",
            ],
            "signatures",
        )
        for widget, label in (
            (self.annots, "Annotations"),
            (self.actions_table, "Actions && links"),
            (split, "JavaScript"),
            (self.files, "Attachments"),
            (self.fields, "Form fields"),
            (self.sigs, "Signatures"),
        ):
            self.tabs.addTab(widget, label)
        self.root.addWidget(self.tabs)

    def set_analysis(self, analysis: PDFAnalysis | None) -> None:
        super().set_analysis(analysis)
        if analysis is None:
            return
        i = analysis.interactive
        self.annots.set_rows(
            [
                (x.page, x.subtype, x.author, x.created, x.modified, x.hidden, x.contents, x.uri, x.rect)
                for x in i.annotations
            ]
        )
        self.actions_table.set_rows([(x.location, x.trigger, x.action_type, x.target) for x in i.actions])
        self.scripts.set_rows([(x.location, x.trigger, x.length, x.sha256) for x in i.scripts])
        self.code.setPlainText("" if i.scripts else "No JavaScript found.")
        self.files.set_rows(
            [
                (
                    x.filename or x.name,
                    x.description,
                    x.mime_type,
                    x.size,
                    x.declared_size,
                    x.created,
                    x.modified,
                    x.sha256,
                    x.location,
                )
                for x in i.embedded_files
            ]
        )
        self.fields.set_rows([(x.name, x.field_type, x.value, x.flags, x.has_actions) for x in i.form_fields])
        self.sigs.set_rows(
            [
                (
                    x.field_name,
                    x.subfilter,
                    x.signing_time,
                    x.name,
                    x.reason,
                    x.location,
                    x.covers_whole_file,
                    x.bytes_after_signed_range,
                    [c.get("subject") for c in x.certificates],
                )
                for x in i.signatures
            ]
        )
        self.save_btn.setEnabled(bool(i.embedded_files))

    def _show_script(self, row: int) -> None:
        if self.analysis and row < len(self.analysis.interactive.scripts):
            s = self.analysis.interactive.scripts[row]
            self.code.setPlainText(
                f"// {s.location} {s.trigger}  ({s.length} chars, SHA-256 {s.sha256})\n"
                f"// Displayed as text only. Not executed.\n\n{s.code}"
            )

    def save_attachments(self) -> None:
        if not self.analysis:
            return
        folder = QFileDialog.getExistingDirectory(self, "Folder for extracted attachments")
        if not folder:
            return
        try:
            written = extract_attachments(Path(self.analysis.file.path), Path(folder))
        except Exception as exc:
            QMessageBox.warning(self, "Attachments", f"Extraction failed: {exc}")
            return
        QMessageBox.information(
            self, "Attachments", "\n".join(f"{p.name}  SHA-256 {h}" for p, h in written) or "No attachment extracted."
        )
