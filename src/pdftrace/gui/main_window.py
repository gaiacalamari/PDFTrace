"""Main window: navigation, file handling, background analysis, status bar."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QSettings, QThread
from PySide6.QtGui import QAction, QDragEnterEvent, QDropEvent, QKeySequence
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from pdftrace import TOOL_NAME, __version__
from pdftrace.config import Settings, default_settings
from pdftrace.core.models import PDFAnalysis, StepRun, StepState
from pdftrace.core.pipeline import Pipeline
from pdftrace.gui.theme import apply_theme
from pdftrace.gui.views.base import AnalysisView
from pdftrace.gui.views.dashboard import DashboardView
from pdftrace.gui.views.diagnostics_view import DiagnosticsView
from pdftrace.gui.views.findings_view import FindingsView
from pdftrace.gui.views.fonts_view import FontsView
from pdftrace.gui.views.images_view import ImagesView
from pdftrace.gui.views.interactive_view import InteractiveView
from pdftrace.gui.views.metadata_view import MetadataView
from pdftrace.gui.views.objects_view import ObjectsView
from pdftrace.gui.views.ocr_view import OcrView
from pdftrace.gui.views.pages_view import PagesView
from pdftrace.gui.views.report_view import ReportView
from pdftrace.gui.views.text_view import TextView
from pdftrace.gui.views.toolbox_view import ToolboxView
from pdftrace.gui.worker import AnalysisWorker

MAX_RECENT = 10


class MainWindow(QMainWindow):
    def __init__(self, settings: Settings | None = None) -> None:
        super().__init__()
        self.settings = settings or default_settings()
        self.store = QSettings("pdftrace", "PDFTrace")
        self.theme = str(self.store.value("theme", "light"))
        self.analysis: PDFAnalysis | None = None
        self._thread: QThread | None = None
        self._worker: AnalysisWorker | None = None
        self._current_path: Path | None = None

        self.setWindowTitle(TOOL_NAME)
        self.resize(1320, 860)
        self.setAcceptDrops(True)

        self.views: list[AnalysisView] = [
            DashboardView(self.settings, self.theme),
            MetadataView(self.settings, self.theme),
            FontsView(self.settings, self.theme),
            ImagesView(self.settings, self.theme),
            TextView(self.settings, self.theme),
            PagesView(self.settings, self.theme),
            ObjectsView(self.settings, self.theme),
            InteractiveView(self.settings, self.theme),
            OcrView(self.settings, self.theme),
            FindingsView(self.settings, self.theme),
            ToolboxView(self.settings, self.theme),
            ReportView(self.settings, self.theme),
            DiagnosticsView(self.settings, self.theme),
        ]
        self.dashboard = self.views[0]
        self.diagnostics = self.views[-1]
        self.toolbox_view = next(v for v in self.views if isinstance(v, ToolboxView))
        self.toolbox_view.analysis_updated.connect(self._on_toolbox_updated)
        self.ocr_view = next(v for v in self.views if isinstance(v, OcrView))
        self.ocr_view.analysis_updated.connect(self._on_ocr_updated)
        assert isinstance(self.dashboard, DashboardView)
        assert isinstance(self.diagnostics, DiagnosticsView)

        self.nav = QListWidget()
        self.nav.setObjectName("nav")
        self.nav.setFixedWidth(190)
        self.stack = QStackedWidget()
        for view in self.views:
            self.nav.addItem(view.title)
            self.stack.addWidget(view)
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.nav.setCurrentRow(0)

        brand = QLabel("PDFTrace")
        brand.setObjectName("brand")
        side = QWidget()
        side_layout = QVBoxLayout(side)
        side_layout.setContentsMargins(0, 0, 0, 0)
        side_layout.setSpacing(0)
        side_layout.addWidget(brand)
        side_layout.addWidget(self.nav, 1)
        central = QWidget()
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(side)
        layout.addWidget(self.stack, 1)
        self.setCentralWidget(central)

        self.status_label = QLabel("Ready")
        self.pages_label = QLabel("")
        self.progress = QProgressBar()
        self.progress.setMaximumWidth(220)
        self.progress.setVisible(False)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setVisible(False)
        self.cancel_button.clicked.connect(self.cancel_analysis)
        bar = self.statusBar()
        bar.addWidget(self.status_label, 1)
        bar.addPermanentWidget(self.progress)
        bar.addPermanentWidget(self.cancel_button)
        bar.addPermanentWidget(self.pages_label)
        self._build_menu()
        self._check_dependencies()

    # ----------------------------------------------------------------- menus
    def _build_menu(self) -> None:
        file_menu = self.menuBar().addMenu("&File")
        open_action = QAction("&Open PDF…", self)
        open_action.setShortcut(QKeySequence.StandardKey.Open)
        open_action.triggered.connect(self.open_dialog)
        file_menu.addAction(open_action)
        self.recent_menu = QMenu("Open &recent", self)
        file_menu.addMenu(self.recent_menu)
        self.reanalyze_action = QAction("Re-&analyse", self)
        self.reanalyze_action.setShortcut(QKeySequence("F5"))
        self.reanalyze_action.triggered.connect(self._reanalyze)
        file_menu.addAction(self.reanalyze_action)
        file_menu.addSeparator()
        quit_action = QAction("&Quit", self)
        quit_action.setShortcut(QKeySequence.StandardKey.Quit)
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)
        view_menu = self.menuBar().addMenu("&View")
        self.dark_action = QAction("&Dark mode", self, checkable=True)
        self.dark_action.setChecked(self.theme == "dark")
        self.dark_action.toggled.connect(self._toggle_dark)
        view_menu.addAction(self.dark_action)
        help_menu = self.menuBar().addMenu("&Help")
        about = QAction("&About", self)
        about.triggered.connect(self._about)
        help_menu.addAction(about)
        self._refresh_recent()

    def _reanalyze(self) -> None:
        if self._current_path is not None:
            self.start_analysis(self._current_path)

    def _toggle_dark(self, on: bool) -> None:
        self.set_theme("dark" if on else "light")

    def _about(self) -> None:
        QMessageBox.about(
            self,
            TOOL_NAME,
            f"<b>{TOOL_NAME}</b> {__version__}<br>Open source PDF forensic "
            "tool for PDF files (Apache-2.0).<br>Findings are technical indicators for a qualified "
            "analyst, not conclusions.",
        )

    def _refresh_recent(self) -> None:
        self.recent_menu.clear()
        recent = [p for p in self._recent() if Path(p).exists()]
        for path in recent:
            action = self.recent_menu.addAction(path)
            action.setData(path)
            action.triggered.connect(self._open_recent)
        self.recent_menu.setEnabled(bool(recent))

    def _open_recent(self) -> None:
        action = self.sender()
        if isinstance(action, QAction) and action.data():
            self.start_analysis(Path(str(action.data())))

    def _recent(self) -> list[str]:
        value = self.store.value("recent", [])
        if isinstance(value, str):
            return [value]
        return [str(v) for v in value] if isinstance(value, list) else []

    def _remember(self, path: Path) -> None:
        recent = [str(path)] + [p for p in self._recent() if p != str(path)]
        self.store.setValue("recent", recent[:MAX_RECENT])
        self._refresh_recent()

    # ---------------------------------------------------------------- themes
    def set_theme(self, theme: str) -> None:
        self.theme = theme
        self.store.setValue("theme", theme)
        app = QApplication.instance()
        if isinstance(app, QApplication):
            apply_theme(app, theme)
        for view in self.views:
            view.set_theme(theme)

    # ------------------------------------------------------------ dependency
    def _check_dependencies(self) -> None:
        missing = self.diagnostics.missing_poppler()  # type: ignore[attr-defined]
        if missing:
            self.status_label.setText(
                f"Poppler not found ({', '.join(missing)}): analysis will use fallbacks. See Diagnostics."
            )

    # ------------------------------------------------------------ drag&drop
    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if any(u.isLocalFile() for u in event.mimeData().urls()):
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        for url in event.mimeData().urls():
            if url.isLocalFile():
                self.start_analysis(Path(url.toLocalFile()))
                break

    # ------------------------------------------------------------- analysis
    def open_dialog(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open PDF", "", "PDF files (*.pdf);;All files (*)")
        if path:
            self.start_analysis(Path(path))

    def start_analysis(self, path: Path) -> None:
        if self._thread is not None:
            QMessageBox.information(self, TOOL_NAME, "An analysis is already running.")
            return
        self._current_path = path
        pipeline_steps = Pipeline(settings=self.settings).steps()
        self.dashboard.start(pipeline_steps, str(path))  # type: ignore[attr-defined]
        self.nav.setCurrentRow(0)
        self.progress.setRange(0, len(pipeline_steps))
        self.progress.setValue(0)
        self.progress.setVisible(True)
        self.cancel_button.setVisible(True)
        self.status_label.setText(f"Analyzing {path.name}…")

        self._thread = QThread(self)
        self._worker = AnalysisWorker(path, self.settings)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.step.connect(self._on_step)
        self._worker.finished.connect(self._on_finished)
        self._worker.failed.connect(self._on_failed)
        self._worker.finished.connect(self._thread.quit)
        self._worker.failed.connect(self._thread.quit)
        self._thread.finished.connect(self._cleanup_thread)
        self._thread.start()

    def cancel_analysis(self) -> None:
        if self._worker is not None:
            self._worker.cancel()
            self.status_label.setText("Cancelling…")

    def _on_step(self, step: StepRun) -> None:
        self.dashboard.update_step(step)  # type: ignore[attr-defined]
        if step.state not in (StepState.PENDING, StepState.RUNNING):
            self.progress.setValue(self.progress.value() + 1)

    def _on_finished(self, analysis: PDFAnalysis) -> None:
        self.analysis = analysis
        for view in self.views:
            view.set_analysis(analysis)
        cancelled = any(s.state == StepState.CANCELLED for s in analysis.steps)
        errors = [s for s in analysis.steps if s.state == StepState.ERROR]
        text = "Analysis cancelled (partial results)" if cancelled else "Analysis complete"
        if errors:
            text += f" with {len(errors)} step error(s): see Diagnostics"
        self.status_label.setText(text)
        self.pages_label.setText(f"{analysis.metadata.page_count or len(analysis.pages)} pages")
        self.setWindowTitle(f"{analysis.file.name} — {TOOL_NAME}")
        self._remember(Path(analysis.file.path))

    def _on_toolbox_updated(self, analysis: PDFAnalysis) -> None:
        for view in self.views:
            if view is not self.toolbox_view:
                view.set_analysis(analysis)

    def _on_ocr_updated(self, analysis: PDFAnalysis) -> None:
        for view in self.views:
            if view is not self.ocr_view:
                view.set_analysis(analysis)

    def _on_failed(self, message: str, details: str) -> None:
        self.status_label.setText("Analysis failed")
        self.diagnostics.add_error(message, details)  # type: ignore[attr-defined]
        box = QMessageBox(QMessageBox.Icon.Warning, TOOL_NAME, message, parent=self)
        if details:
            box.setInformativeText("Technical details are available in Diagnostics.")
        box.exec()
        self.dashboard.set_analysis(self.analysis)

    def _cleanup_thread(self) -> None:
        self.progress.setVisible(False)
        self.cancel_button.setVisible(False)
        if self._worker is not None:
            self._worker.deleteLater()
        if self._thread is not None:
            self._thread.deleteLater()
        self._worker, self._thread = None, None

    def closeEvent(self, event: object) -> None:
        if self._worker is not None:
            self._worker.cancel()
        if self._thread is not None:
            self._thread.quit()
            self._thread.wait(5000)
        for view in self.views:
            cleanup = getattr(view, "cleanup", None)
            if callable(cleanup):
                cleanup()
        super().closeEvent(event)  # type: ignore[arg-type]
