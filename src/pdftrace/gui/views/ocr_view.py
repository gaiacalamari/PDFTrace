"""OCR: Tesseract on the rendered pages, compared with the PDF text layer."""

from __future__ import annotations

import sys
import threading
from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, Qt, QThread, Signal, Slot
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from pdftrace.analyzers.ocr import run_ocr
from pdftrace.core import report
from pdftrace.core.findings import FindingsEngine
from pdftrace.core.models import OcrResult, PDFAnalysis
from pdftrace.core.timeline import build_timeline
from pdftrace.gui.views.base import AnalysisView
from pdftrace.gui.views.toolbox_view import install_script, launch_install
from pdftrace.gui.widgets import RecordTable, title
from pdftrace.integrations.tesseract import Tesseract


class OcrWorker(QObject):
    progress = Signal(int, int)
    finished = Signal(object)

    def __init__(self, analysis: PDFAnalysis, settings: Any) -> None:
        super().__init__()
        self.analysis, self.settings = analysis, settings
        self.cancel_event = threading.Event()

    @Slot()
    def run(self) -> None:
        result = run_ocr(self.analysis, self.settings, self.cancel_event.is_set, self.progress.emit)
        self.finished.emit(result)


class OcrView(AnalysisView):
    title = "OCR"
    analysis_updated = Signal(object)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._thread: QThread | None = None
        self._worker: OcrWorker | None = None
        self.root.addWidget(
            title(
                "OCR",
                "Pages are rendered (PDFium, no scripts) and read by Tesseract. Recognised words are compared by "
                "position with the text layer: text in the file but not visible, and visible text missing from the "
                "text layer.",
            )
        )
        bar = QHBoxLayout()
        bar.addWidget(QLabel("Languages"))
        self.langs = QComboBox()
        self.langs.setEditable(True)
        self.langs.setMinimumWidth(140)
        bar.addWidget(self.langs)
        bar.addWidget(QLabel("DPI"))
        self.dpi = QSpinBox()
        self.dpi.setRange(100, 600)
        self.dpi.setSingleStep(50)
        self.dpi.setValue(self.settings.ocr_dpi)
        bar.addWidget(self.dpi)
        bar.addWidget(QLabel("Max pages"))
        self.max_pages = QSpinBox()
        self.max_pages.setRange(1, 100_000)
        self.max_pages.setValue(self.settings.ocr_max_pages)
        bar.addWidget(self.max_pages)
        self.run_btn = QPushButton("Run OCR")
        self.cancel_btn = QPushButton("Cancel")
        self.export_btn = QPushButton("Export OCR text…")
        self.install_btn = QPushButton("Install Tesseract…")
        self.run_btn.clicked.connect(self.start)
        self.cancel_btn.clicked.connect(self.cancel)
        self.export_btn.clicked.connect(self.export_text)
        self.install_btn.clicked.connect(self.install)
        for b in (self.run_btn, self.cancel_btn, self.export_btn, self.install_btn):
            bar.addWidget(b)
        bar.addStretch(1)
        self.state = QLabel("")
        self.state.setObjectName("muted")
        bar.addWidget(self.state)
        self.root.addLayout(bar)

        self.tabs = QTabWidget()
        self.pages = RecordTable(
            [
                "Page",
                "OCR words",
                "Mean confidence",
                "Layer words",
                "Layer words seen",
                "Hidden runs",
                "Visible not in layer",
                "Note",
            ],
            "ocr_pages",
        )
        self.hidden = RecordTable(["Page", "Text in the layer, not visible", "Words", "BBox (pt)"], "ocr_hidden")
        self.missing = RecordTable(["Page", "Visible text, not in the layer", "Words", "BBox (pt)"], "ocr_missing")
        text_tab = QWidget()
        text_layout = QVBoxLayout(text_tab)
        self.page_combo = QComboBox()
        self.page_combo.currentIndexChanged.connect(self._show_page)
        split = QSplitter(Qt.Orientation.Horizontal)
        self.ocr_text = QPlainTextEdit()
        self.ocr_text.setReadOnly(True)
        self.layer_text = QPlainTextEdit()
        self.layer_text.setReadOnly(True)
        split.addWidget(self._labeled("OCR (rendered page)", self.ocr_text))
        split.addWidget(self._labeled("Text layer (pdfplumber)", self.layer_text))
        text_layout.addWidget(self.page_combo)
        text_layout.addWidget(split)
        for widget, label in (
            (self.hidden, "Hidden from view"),
            (self.missing, "Not in text layer"),
            (self.pages, "Pages"),
            (text_tab, "OCR vs text layer"),
        ):
            self.tabs.addTab(widget, label)
        self.root.addWidget(self.tabs, 1)
        self.refresh_engine()

    @staticmethod
    def _labeled(text: str, widget: QWidget) -> QWidget:
        holder = QWidget()
        layout = QVBoxLayout(holder)
        layout.setContentsMargins(0, 0, 0, 0)
        label = QLabel(text)
        label.setObjectName("muted")
        layout.addWidget(label)
        layout.addWidget(widget)
        return holder

    def refresh_engine(self) -> None:
        tess = Tesseract(self.settings)
        exe = tess.executable()
        current = self.langs.currentText()
        self.langs.clear()
        if exe:
            installed = [lang for lang in tess.languages() if lang != "osd"]
            auto = tess.resolve_languages("auto")
            self.langs.addItems([auto, *[lang for lang in installed if lang != auto]])
            if current:
                self.langs.setCurrentText(current)
            self.state.setText(f"Tesseract {tess.version() or ''} - languages: {', '.join(installed) or 'none'}")
        else:
            self.state.setText("Tesseract not found")
        self.install_btn.setVisible(not exe and sys.platform == "win32" and install_script() is not None)
        self._set_running(self._thread is not None)

    def _set_running(self, running: bool) -> None:
        available = Tesseract(self.settings).executable() is not None
        has_pdf = self.analysis is not None
        self.run_btn.setEnabled(has_pdf and available and not running)
        self.cancel_btn.setEnabled(running)
        self.export_btn.setEnabled(has_pdf and bool(self.analysis and self.analysis.ocr.pages) and not running)

    # ---------------------------------------------------------------- results
    def set_analysis(self, analysis: PDFAnalysis | None) -> None:
        super().set_analysis(analysis)
        self._render(analysis.ocr if analysis else OcrResult())
        self._set_running(self._thread is not None)

    def _render(self, o: OcrResult) -> None:
        self.pages.set_rows(
            [
                (
                    p.page,
                    p.words,
                    p.mean_confidence,
                    p.layer_words,
                    p.layer_words_seen,
                    len(p.unseen_layer_text),
                    len(p.visible_not_in_layer),
                    p.error,
                )
                for p in o.pages
            ]
        )
        self.hidden.set_rows([(r.page, r.text, r.words, r.bbox) for p in o.pages for r in p.unseen_layer_text])
        self.missing.set_rows([(r.page, r.text, r.words, r.bbox) for p in o.pages for r in p.visible_not_in_layer])
        self.page_combo.blockSignals(True)
        self.page_combo.clear()
        self.page_combo.addItems([f"Page {p.page}" for p in o.pages])
        self.page_combo.blockSignals(False)
        self._show_page(0)
        if o.pages:
            self.state.setText(f"Tesseract {o.version} [{o.languages}] {o.dpi} dpi - {len(o.pages)} page(s)")

    def _show_page(self, index: int) -> None:
        if not self.analysis or not (0 <= index < len(self.analysis.ocr.pages)):
            self.ocr_text.setPlainText("")
            self.layer_text.setPlainText("")
            return
        page = self.analysis.ocr.pages[index]
        self.ocr_text.setPlainText(page.text)
        layer = next((p.text for p in self.analysis.pages if p.number == page.page), "")
        self.layer_text.setPlainText(layer)

    # ------------------------------------------------------------------- run
    def start(self) -> None:
        if self.analysis is None or self._thread is not None:
            return
        settings = self.settings.with_overrides(
            ocr_languages=self.langs.currentText().strip() or "auto",
            ocr_dpi=self.dpi.value(),
            ocr_max_pages=self.max_pages.value(),
        )
        self._thread = QThread(self)
        self._worker = OcrWorker(self.analysis, settings)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(lambda done, total: self.state.setText(f"OCR page {done}/{total}…"))
        self._worker.finished.connect(self._finished)
        self._worker.finished.connect(self._thread.quit)
        self._thread.finished.connect(self._cleanup)
        self._set_running(True)
        self.state.setText("Rendering and recognising pages…")
        self._thread.start()

    def cancel(self) -> None:
        if self._worker is not None:
            self._worker.cancel_event.set()

    def _finished(self, result: OcrResult) -> None:
        if self.analysis is None:
            return
        self.analysis.ocr = result
        self.analysis.timeline = build_timeline(self.analysis)
        self.analysis.findings = FindingsEngine().evaluate(self.analysis, self.settings)
        self._render(result)
        if result.error:
            self.state.setText(result.error)
        self.tabs.setCurrentIndex(0)
        self.analysis_updated.emit(self.analysis)

    def _cleanup(self) -> None:
        if self._worker is not None:
            self._worker.deleteLater()
        if self._thread is not None:
            self._thread.deleteLater()
        self._worker, self._thread = None, None
        self._set_running(False)

    def export_text(self) -> None:
        if not self.analysis:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export OCR text", "ocr.txt", "Text (*.txt)")
        if path:
            report.write_ocr_text(self.analysis, Path(path))

    def install(self) -> None:
        script = install_script()
        if script is None:
            return
        if (
            QMessageBox.question(
                self,
                "Install Tesseract",
                "Tesseract and the Italian and English language data "
                "will be installed with Scoop (internet required). Press 'Run OCR' again when the "
                "PowerShell window has finished. Continue?",
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        launch_install(["-OcrOnly"])

    def showEvent(self, event: Any) -> None:
        super().showEvent(event)
        if self._thread is None:
            self.refresh_engine()

    def cleanup(self) -> None:
        self.cancel()
        if self._thread is not None:
            self._thread.quit()
            self._thread.wait(5000)
