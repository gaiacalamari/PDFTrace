"""Toolbox: run third-party open source PDF tools from the GUI."""

from __future__ import annotations

import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, Qt, QThread, QUrl, Signal, Slot
from PySide6.QtGui import QDesktopServices
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

from pdftrace.core import report
from pdftrace.core.findings import FindingsEngine
from pdftrace.core.models import ExternalToolRun, PDFAnalysis
from pdftrace.core.timeline import build_timeline
from pdftrace.frozen import bundled_dir, is_frozen
from pdftrace.gui.views.base import AnalysisView
from pdftrace.gui.widgets import RecordTable, title
from pdftrace.integrations.toolbox import Toolbox, ToolSpec


def install_script() -> Path | None:
    """The Windows installer script shipped with the source tree or the standalone build."""
    folder = bundled_dir("scripts")
    if folder and (folder / "install-tools.ps1").is_file():
        return folder / "install-tools.ps1"
    return None


def launch_install(extra: list[str]) -> None:
    """Start the bundled installer script in a new PowerShell window (Windows)."""
    script = install_script()
    if script is None:
        return
    args = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), *extra]
    if is_frozen() and "-OcrOnly" not in extra:
        args.append("-SkipPoppler")  # Poppler is bundled with the standalone build
    subprocess.Popen(args, creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0))


class ToolboxWorker(QObject):
    run_done = Signal(object)
    finished = Signal()

    def __init__(self, toolbox: Toolbox, specs: list[ToolSpec], pdf: Path) -> None:
        super().__init__()
        self.toolbox, self.specs, self.pdf = toolbox, specs, pdf
        self.cancel_event = threading.Event()

    @Slot()
    def run(self) -> None:
        self.toolbox.run_tools(self.specs, self.pdf, self.cancel_event.is_set, self.run_done.emit)
        self.finished.emit()


class ToolboxView(AnalysisView):
    title = "Toolbox"
    #: Emitted after tool runs, so that the main window refreshes findings in every view.
    analysis_updated = Signal(object)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.toolbox = Toolbox(self.settings)
        self._thread: QThread | None = None
        self._worker: ToolboxWorker | None = None
        self.root.addWidget(
            title(
                "Toolbox",
                "Third-party open source tools run on the same file, read-only, without shell, with timeouts. "
                "Outputs are stored verbatim with their SHA-256 and included in reports.",
            )
        )
        bar = QHBoxLayout()
        self.run_selected_btn = QPushButton("Run selected")
        self.run_all_btn = QPushButton("Run all available")
        self.cancel_btn = QPushButton("Cancel")
        self.refresh_btn = QPushButton("Re-detect tools")
        self.export_btn = QPushButton("Save raw outputs…")
        self.homepage_btn = QPushButton("Open homepage")
        self.install_btn = QPushButton("Install optional tools…")
        self.install_btn.setVisible(sys.platform == "win32" and install_script() is not None)
        self.install_btn.clicked.connect(self.install_tools)
        self.run_selected_btn.clicked.connect(self.run_selected)
        self.run_all_btn.clicked.connect(self.run_all)
        self.cancel_btn.clicked.connect(self.cancel)
        self.refresh_btn.clicked.connect(self.refresh_tools)
        self.export_btn.clicked.connect(self.export_outputs)
        self.homepage_btn.clicked.connect(self.open_homepage)
        for b in (
            self.run_selected_btn,
            self.run_all_btn,
            self.cancel_btn,
            self.refresh_btn,
            self.export_btn,
            self.homepage_btn,
            self.install_btn,
        ):
            bar.addWidget(b)
        bar.addStretch(1)
        self.state = QLabel("")
        self.state.setObjectName("muted")
        bar.addWidget(self.state)
        self.root.addLayout(bar)

        self.tools_table = RecordTable(
            ["Tool", "Category", "Available", "Version", "Licence", "Actions", "Location"], "toolbox_tools"
        )
        self.runs_table = RecordTable(["Tool", "Action", "Status", "Exit", "Duration (s)", "Summary"], "toolbox_runs")
        self.runs_table.row_selected.connect(self._show_run)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setPlaceholderText("Select a run to see command, output and parsed summary.")
        lower = QSplitter(Qt.Orientation.Horizontal)
        lower.addWidget(self.runs_table)
        lower.addWidget(self.output)
        lower.setSizes([520, 560])
        tabs = QTabWidget()
        tools_tab = QWidget()
        tools_layout = QVBoxLayout(tools_tab)
        tools_layout.setContentsMargins(0, 0, 0, 0)
        tools_layout.addWidget(self.tools_table)
        tabs.addTab(tools_tab, "Available tools")
        tabs.addTab(lower, "Results")
        self.tabs = tabs
        self.root.addWidget(tabs, 1)
        self.refresh_tools()
        self._set_running(False)

    # ------------------------------------------------------------- tools list
    def refresh_tools(self) -> None:
        self.toolbox = Toolbox(self.settings)
        rows = []
        for spec in self.toolbox.tools:
            status = self.toolbox.status(spec)
            rows.append(
                (
                    spec.name,
                    spec.category,
                    status.available,
                    status.version,
                    spec.license,
                    ", ".join(a.label for a in spec.actions),
                    status.path if status.available else spec.install_hint,
                )
            )
        self.tools_table.set_rows(rows)
        available = sum(1 for r in rows if r[2])
        self.state.setText(f"{available}/{len(rows)} tools available")
        for error in self.toolbox.errors:
            self.output.appendPlainText(f"Custom tools file: {error}")

    def _selected_specs(self) -> list[ToolSpec]:
        return [self.toolbox.tools[i] for i in self.tools_table.selected_source_rows()]

    def install_tools(self) -> None:
        script = install_script()
        if script is None:
            return
        answer = QMessageBox.question(
            self,
            "Install optional tools",
            "The optional analysis tools (qpdf, ExifTool, Ghostscript, pdftk, pdfcpu, MuPDF) will be installed "
            "with Scoop in the user profile. An internet connection is required and a PowerShell window will "
            "show the progress.\n\nWhen it finishes, press 'Re-detect tools'. Continue?",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        launch_install([])

    def open_homepage(self) -> None:
        for spec in self._selected_specs()[:1]:
            if spec.homepage.startswith("https://"):
                QDesktopServices.openUrl(QUrl(spec.homepage))

    # ------------------------------------------------------------------ runs
    def set_analysis(self, analysis: PDFAnalysis | None) -> None:
        super().set_analysis(analysis)
        self._render_runs()
        self._set_running(self._thread is not None)

    def _render_runs(self) -> None:
        runs = self.analysis.external_runs if self.analysis else []
        self.runs_table.set_rows(
            [
                (r.tool_name, r.action_label, r.status, r.returncode, r.duration_s, report._short(r.parsed, 120))
                for r in runs
            ]
        )

    def run_selected(self) -> None:
        specs = [s for s in self._selected_specs() if self.toolbox.base_command(s)]
        if not specs:
            QMessageBox.information(self, "Toolbox", "Select one or more available tools in the list.")
            return
        self._start(specs)

    def run_all(self) -> None:
        self._start(self.toolbox.select("all"))

    def _start(self, specs: list[ToolSpec]) -> None:
        if self.analysis is None:
            QMessageBox.information(self, "Toolbox", "Open and analyse a PDF first.")
            return
        if self._thread is not None or not specs:
            return
        ids = {s.id for s in specs}
        self.analysis.external_runs = [r for r in self.analysis.external_runs if r.tool_id not in ids]
        self._render_runs()
        self.tabs.setCurrentIndex(1)
        self._thread = QThread(self)
        self._worker = ToolboxWorker(self.toolbox, specs, Path(self.analysis.file.path))
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.run_done.connect(self._on_run)
        self._worker.finished.connect(self._on_finished)
        self._worker.finished.connect(self._thread.quit)
        self._thread.finished.connect(self._cleanup)
        self._set_running(True)
        self.state.setText(f"Running {len(specs)} tool(s)…")
        self._thread.start()

    def cancel(self) -> None:
        if self._worker is not None:
            self._worker.cancel_event.set()
            self.state.setText("Cancelling after the current action…")

    def _on_run(self, run: ExternalToolRun) -> None:
        if self.analysis is not None:
            self.analysis.external_runs.append(run)
            self._render_runs()

    def _on_finished(self) -> None:
        if self.analysis is not None:
            self.analysis.timeline = build_timeline(self.analysis)
            self.analysis.findings = FindingsEngine().evaluate(self.analysis, self.settings)
            self.analysis_updated.emit(self.analysis)
            runs = self.analysis.external_runs
            bad = sum(1 for r in runs if r.status != "ok")
            self.state.setText(f"{len(runs)} actions completed, {bad} not ok. Findings updated.")

    def _cleanup(self) -> None:
        if self._worker is not None:
            self._worker.deleteLater()
        if self._thread is not None:
            self._thread.deleteLater()
        self._worker, self._thread = None, None
        self._set_running(False)

    def _set_running(self, running: bool) -> None:
        has_pdf = self.analysis is not None
        self.run_selected_btn.setEnabled(has_pdf and not running)
        self.run_all_btn.setEnabled(has_pdf and not running)
        self.cancel_btn.setEnabled(running)
        self.refresh_btn.setEnabled(not running)
        self.export_btn.setEnabled(has_pdf and not running and bool(self.analysis and self.analysis.external_runs))

    def _show_run(self, row: int) -> None:
        if not self.analysis or row >= len(self.analysis.external_runs):
            return
        r = self.analysis.external_runs[row]
        import json

        parsed = json.dumps(r.parsed, ensure_ascii=False, indent=2, default=str) if r.parsed else "{}"
        self.output.setPlainText(
            f"{r.tool_name} {r.version or ''} [{r.license}]\n$ {' '.join(r.command)}\n"
            f"status: {r.status}   exit code: {r.returncode}   duration: {r.duration_s}s   started: {r.started_utc}\n"
            f"stdout SHA-256: {r.stdout_sha256}{'   (truncated)' if r.truncated else ''}\n"
            f"{('error: ' + r.error) if r.error else ''}\n\n--- parsed ---\n{parsed}\n\n--- stdout ---\n{r.stdout}\n"
            f"--- stderr ---\n{r.stderr}"
        )

    def export_outputs(self) -> None:
        if not self.analysis:
            return
        folder = QFileDialog.getExistingDirectory(self, "Folder for raw tool outputs")
        if folder:
            files = report.write_tool_outputs(self.analysis, Path(folder))
            QMessageBox.information(self, "Toolbox", f"{len(files)} files written (MANIFEST.tsv lists SHA-256).")

    def cleanup(self) -> None:
        self.cancel()
        if self._thread is not None:
            self._thread.quit()
            self._thread.wait(5000)
