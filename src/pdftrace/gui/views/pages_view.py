"""Page Inspector: object counts and bounding boxes, optional page rendering."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QRectF, Qt, QTimer
from PySide6.QtGui import QColor, QImage, QPainter, QPen, QPixmap
from PySide6.QtWidgets import (
    QCheckBox,
    QGraphicsScene,
    QGraphicsView,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSpinBox,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from pdftrace.core.models import PDFAnalysis
from pdftrace.gui.views.base import AnalysisView, clear_layout, scroll
from pdftrace.gui.widgets import form, title

KIND_COLORS = {"word": "#2f6690", "rect": "#a86a00", "line": "#6b4c9a", "curve": "#2d6a3e", "image": "#9e2a2b"}
RENDER_DPI = 110


class PagesView(AnalysisView):
    title = "Pages"

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.root.addWidget(
            title(
                "Page Inspector",
                "Bounding boxes from pdfplumber (points, top-left "
                "origin). Rendering uses pypdfium2 without forms or JavaScript.",
            )
        )
        bar = QHBoxLayout()
        bar.addWidget(QLabel("Page"))
        self.page = QSpinBox()
        self.page.setMinimum(1)
        self.page.valueChanged.connect(self._draw)
        bar.addWidget(self.page)
        self.toggles: dict[str, QCheckBox] = {}
        for kind in KIND_COLORS:
            box = QCheckBox(kind + "s")
            box.setChecked(kind != "word")
            box.toggled.connect(self._draw)
            self.toggles[kind] = box
            bar.addWidget(box)
        self.render_box = QCheckBox("Render page")
        self.render_box.toggled.connect(self._draw)
        bar.addWidget(self.render_box)
        zoom_in, zoom_out = QPushButton("+"), QPushButton("−")
        zoom_in.clicked.connect(self.zoom_in)
        zoom_out.clicked.connect(self.zoom_out)
        fit = QPushButton("Fit")
        fit.clicked.connect(self.fit)
        bar.addWidget(zoom_out)
        bar.addWidget(zoom_in)
        bar.addWidget(fit)
        bar.addStretch(1)
        self.root.addLayout(bar)
        self.scene = QGraphicsScene()
        self.view = QGraphicsView(self.scene)
        self.view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.stats = QWidget()
        self.stats_layout = QVBoxLayout(self.stats)
        splitter = QSplitter()
        splitter.addWidget(scroll(self.stats))
        splitter.addWidget(self.view)
        splitter.setSizes([260, 760])
        self.root.addWidget(splitter, 1)
        self._render_cache: dict[int, QPixmap] = {}
        self._fitted = False

    def zoom_in(self) -> None:
        self.view.scale(1.25, 1.25)

    def zoom_out(self) -> None:
        self.view.scale(0.8, 0.8)

    def fit(self) -> None:
        self.view.resetTransform()
        self.view.fitInView(self.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)
        self._fitted = True

    def showEvent(self, event: object) -> None:
        super().showEvent(event)  # type: ignore[arg-type]
        if self.analysis is not None and not self._fitted:
            QTimer.singleShot(0, self.fit)

    def set_analysis(self, analysis: PDFAnalysis | None) -> None:
        super().set_analysis(analysis)
        self._render_cache.clear()
        if analysis is None or not analysis.pages:
            self.scene.clear()
            return
        self.page.setMaximum(len(analysis.pages))
        self._fitted = False
        self._draw()
        if self.isVisible():
            self.fit()

    def _draw(self) -> None:
        if not self.analysis or not self.analysis.pages:
            return
        page = self.analysis.pages[self.page.value() - 1]
        clear_layout(self.stats_layout)
        self.stats_layout.addWidget(
            form(
                [
                    ("Page", page.number),
                    ("Dimensions", f"{page.width} x {page.height} pt"),
                    ("Rotation", page.rotation),
                    ("MediaBox", page.mediabox),
                    ("CropBox", page.cropbox),
                    ("Chars", f"{page.chars:,}"),
                    ("Words", f"{page.words:,}"),
                    ("Text lines", page.text_lines),
                    ("Lines", page.lines),
                    ("Rectangles", page.rects),
                    ("Curves", page.curves),
                    ("Images", page.images),
                    ("Annotations", page.annotations),
                    ("Hyperlinks", page.hyperlinks),
                    ("Density (chars / 10,000 pt²)", page.density),
                    ("Boxes truncated", page.boxes_truncated),
                    ("Error", page.error),
                ]
            )
        )
        self.stats_layout.addStretch(1)
        self.scene.clear()
        scale = RENDER_DPI / 72
        self.scene.setSceneRect(QRectF(0, 0, page.width * scale, page.height * scale))
        if self.render_box.isChecked():
            pixmap = self._render(page.number)
            if pixmap is not None:
                self.scene.addPixmap(pixmap)
        else:
            self.scene.addRect(
                QRectF(0, 0, page.width * scale, page.height * scale), QPen(QColor("#9aa6b4")), QColor("#ffffff")
            )
        for box in page.boxes:
            toggle = self.toggles.get(box.kind)
            if not toggle or not toggle.isChecked():
                continue
            pen = QPen(QColor(KIND_COLORS[box.kind]))
            pen.setWidthF(1.0)
            rect = QRectF(
                box.x0 * scale,
                box.top * scale,
                max(0.5, (box.x1 - box.x0) * scale),
                max(0.5, (box.bottom - box.top) * scale),
            )
            item = self.scene.addRect(rect, pen)
            item.setToolTip(f"{box.kind}: {box.label or ''}  [{box.x0}, {box.top}, {box.x1}, {box.bottom}]")

    def _render(self, number: int) -> QPixmap | None:
        if number in self._render_cache:
            return self._render_cache[number]
        if not self.analysis:
            return None
        try:
            from pdftrace.integrations.pdfplumber_adapter import opened

            with opened(Path(self.analysis.file.path)) as pdf:
                image = pdf.pages[number - 1].to_image(resolution=RENDER_DPI).original.convert("RGB")
            data = image.tobytes("raw", "RGB")
            qimage = QImage(data, image.width, image.height, image.width * 3, QImage.Format.Format_RGB888)
            pixmap = QPixmap.fromImage(qimage.copy())
        except Exception:
            return None
        self._render_cache[number] = pixmap
        return pixmap

    def select_page(self, number: int) -> None:
        self.page.setValue(number)

    def keyPressEvent(self, event: object) -> None:
        key = getattr(event, "key", lambda: None)()
        if key == Qt.Key.Key_PageDown:
            self.page.setValue(self.page.value() + 1)
        elif key == Qt.Key.Key_PageUp:
            self.page.setValue(self.page.value() - 1)
        else:
            super().keyPressEvent(event)  # type: ignore[arg-type]
