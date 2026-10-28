"""Images: pdfimages inventory, thumbnail preview and extraction."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices, QPixmap
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from pdftrace.core.models import ImageInfo, PDFAnalysis
from pdftrace.gui.views.base import AnalysisView
from pdftrace.gui.widgets import RecordTable, title
from pdftrace.integrations.poppler import Poppler
from pdftrace.integrations.process import ToolFailed, ToolNotFound


class ImagesView(AnalysisView):
    title = "Images"

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.poppler = Poppler(self.settings)
        self._tmp = Path(tempfile.mkdtemp(prefix="pdftrace-thumbs-"))
        self.root.addWidget(
            title(
                "Images",
                "Raster images listed by pdfimages. Thumbnails are extracted "
                "to a private temporary folder; the PDF is never modified.",
            )
        )
        self.table = RecordTable(
            [
                "Page",
                "Num",
                "Object",
                "Type",
                "Width",
                "Height",
                "Color",
                "Comp",
                "BPC",
                "Encoding",
                "x-ppi",
                "y-ppi",
                "Size",
                "Ratio",
                "Source",
            ],
            "images",
        )
        self.table.row_selected.connect(self._preview)
        self.preview = QLabel("Select an image")
        self.preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.preview.setMinimumWidth(260)
        self.open_btn = QPushButton("Open image")
        self.extract_btn = QPushButton("Extract selected…")
        self.extract_all_btn = QPushButton("Extract all…")
        self.open_btn.clicked.connect(self._open)
        self.extract_btn.clicked.connect(self._extract_selected)
        self.extract_all_btn.clicked.connect(self._extract_all)
        side = QWidget()
        side_layout = QVBoxLayout(side)
        side_layout.addWidget(self.preview, 1)
        buttons = QHBoxLayout()
        for b in (self.open_btn, self.extract_btn, self.extract_all_btn):
            buttons.addWidget(b)
        side_layout.addLayout(buttons)
        splitter = QSplitter()
        splitter.addWidget(self.table)
        splitter.addWidget(side)
        splitter.setSizes([700, 320])
        self.evidence = RecordTable(
            [
                "Object",
                "Pages",
                "Format",
                "Size",
                "Camera",
                "Software",
                "Dates",
                "GPS",
                "ICC profile",
                "JPEG quality (est.)",
                "Progressive",
                "SHA-256 (raw)",
            ],
            "image_metadata",
        )
        self.evidence.row_selected.connect(self._show_evidence)
        self.evidence_detail = QPlainTextEdit()
        self.evidence_detail.setReadOnly(True)
        evidence_split = QSplitter(Qt.Orientation.Vertical)
        evidence_split.addWidget(self.evidence)
        evidence_split.addWidget(self.evidence_detail)
        tabs = QTabWidget()
        tabs.addTab(splitter, "Images (pdfimages)")
        tabs.addTab(evidence_split, "Embedded metadata (EXIF / XMP / IPTC / ICC)")
        self.root.addWidget(tabs)
        self._current: Path | None = None

    def set_analysis(self, analysis: PDFAnalysis | None) -> None:
        super().set_analysis(analysis)
        if analysis is None:
            return
        self.table.set_rows(
            [
                (
                    i.page,
                    i.index,
                    i.object_id,
                    i.image_type,
                    i.width,
                    i.height,
                    i.color,
                    i.components,
                    i.bpc,
                    i.encoding,
                    i.x_ppi,
                    i.y_ppi,
                    i.size,
                    i.ratio,
                    i.source,
                )
                for i in analysis.images
            ]
        )
        self.evidence.set_rows(
            [
                (
                    e.object_id,
                    e.pages,
                    e.format,
                    f"{e.width}x{e.height}",
                    e.camera,
                    e.software,
                    e.dates,
                    {k: v for k, v in e.gps.items() if k in ("latitude", "longitude")},
                    e.icc_description,
                    e.jpeg_quality_estimate,
                    e.progressive,
                    e.raw_sha256,
                )
                for e in analysis.image_evidence
            ]
        )
        enabled = self.poppler.available("pdfimages")
        for b in (self.open_btn, self.extract_btn, self.extract_all_btn):
            b.setEnabled(enabled)
            b.setToolTip("" if enabled else "pdfimages (Poppler) is required")
        self.preview.setText("Select an image" if enabled else "Thumbnails need pdfimages (Poppler).")

    def _show_evidence(self, row: int) -> None:
        if not self.analysis or row >= len(self.analysis.image_evidence):
            return
        import json

        e = self.analysis.image_evidence[row]
        blocks = {
            "EXIF": e.exif,
            "GPS": e.gps,
            "XMP": e.xmp,
            "IPTC": e.iptc,
            "Other": {
                "filters": e.filters,
                "colorspace": e.colorspace,
                "bpc": e.bpc,
                "dpi": e.dpi,
                "jfif": e.jfif,
                "adobe": e.adobe,
                "raw_length": e.raw_length,
                "error": e.error,
            },
        }
        self.evidence_detail.setPlainText(
            "\n\n".join(
                f"[{k}]\n{json.dumps(v, ensure_ascii=False, indent=2, default=str)}" for k, v in blocks.items() if v
            )
        )

    def _image(self, row: int) -> ImageInfo | None:
        if self.analysis and 0 <= row < len(self.analysis.images):
            return self.analysis.images[row]
        return None

    def _preview(self, row: int) -> None:
        image = self._image(row)
        if not image or image.index is None or not self.poppler.available("pdfimages") or not self.analysis:
            return
        try:
            path = self.poppler.extract_single_image(
                Path(self.analysis.file.path), image.page, image.index, self._tmp, fmt="png"
            )
        except (ToolFailed, ToolNotFound) as exc:
            self.preview.setText(f"Preview failed:\n{exc}")
            return
        self._current = path
        pixmap = QPixmap(str(path)) if path else QPixmap()
        if pixmap.isNull():
            self.preview.setText("No preview available")
            return
        self.preview.setPixmap(
            pixmap.scaled(300, 300, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
        )

    def _open(self) -> None:
        if self._current and self._current.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._current)))

    def _extract_selected(self) -> None:
        if not self.analysis:
            return
        rows = self.table.selected_source_rows()
        if not rows:
            return
        target = QFileDialog.getExistingDirectory(self, "Output directory")
        if not target:
            return
        written = []
        for row in rows:
            image = self._image(row)
            if image and image.index is not None:
                try:
                    path = self.poppler.extract_single_image(
                        Path(self.analysis.file.path), image.page, image.index, Path(target)
                    )
                    if path:
                        written.append(path)
                except (ToolFailed, ToolNotFound) as exc:
                    QMessageBox.warning(self, "Extraction failed", str(exc))
                    return
        QMessageBox.information(self, "Images extracted", f"{len(written)} file(s) written to {target}")

    def _extract_all(self) -> None:
        if not self.analysis:
            return
        target = QFileDialog.getExistingDirectory(self, "Output directory")
        if not target:
            return
        try:
            files = self.poppler.extract_images(Path(self.analysis.file.path), Path(target))
        except (ToolFailed, ToolNotFound) as exc:
            QMessageBox.warning(self, "Extraction failed", str(exc))
            return
        QMessageBox.information(self, "Images extracted", f"{len(files)} file(s) written to {target}")

    def closeEvent(self, event: object) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)
        super().closeEvent(event)  # type: ignore[arg-type]

    def cleanup(self) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)
