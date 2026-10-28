"""Report preview and export."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QMessageBox, QPushButton, QTextBrowser

from pdftrace.core import report
from pdftrace.core.models import PDFAnalysis
from pdftrace.gui.views.base import AnalysisView
from pdftrace.gui.widgets import title


class ReportView(AnalysisView):
    title = "Report"

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.root.addWidget(
            title(
                "Report",
                "Preview of the HTML report (simplified rendering). Exported "
                "files are self-contained and load no external resources.",
            )
        )
        bar = QHBoxLayout()
        for label, kind in (
            ("Export JSON…", "json"),
            ("Export HTML…", "html"),
            ("Export Markdown…", "md"),
            ("Export CSV tables…", "csv"),
        ):
            button = QPushButton(label)
            button.clicked.connect(lambda _=False, k=kind: self.export(k))
            bar.addWidget(button)
        bar.addStretch(1)
        self.root.addLayout(bar)
        self.browser = QTextBrowser()
        self.browser.setOpenLinks(False)
        self.browser.setOpenExternalLinks(False)
        self.root.addWidget(self.browser, 1)

    def set_analysis(self, analysis: PDFAnalysis | None) -> None:
        super().set_analysis(analysis)
        self.browser.setHtml(report.to_html(analysis) if analysis else "")

    def export(self, kind: str) -> None:
        if not self.analysis:
            return
        stem = Path(self.analysis.file.name).stem + "_forensics"
        try:
            if kind == "csv":
                folder = QFileDialog.getExistingDirectory(self, "Folder for CSV tables")
                if not folder:
                    return
                files = report.write_csv_dir(self.analysis, Path(folder))
                QMessageBox.information(self, "Exported", f"{len(files)} CSV files written to {folder}")
                return
            path, _ = QFileDialog.getSaveFileName(self, "Export report", f"{stem}.{kind}")
            if not path:
                return
            writer = {"json": report.write_json, "html": report.write_html, "md": report.write_markdown}[kind]
            writer(self.analysis, Path(path))
        except OSError as exc:
            QMessageBox.warning(self, "Export failed", str(exc))
