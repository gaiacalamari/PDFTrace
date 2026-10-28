"""Offscreen smoke test of the GUI (skipped when PySide6 is not installed)."""

import os

import pytest

pytest.importorskip("PySide6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def test_views_render_analysis(analyses) -> None:  # type: ignore[no-untyped-def]
    from PySide6.QtWidgets import QApplication

    from pdftrace.gui.main_window import MainWindow

    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    analysis = analyses["rich"]
    window._on_finished(analysis)
    for row in range(window.nav.count()):
        window.nav.setCurrentRow(row)
        app.processEvents()
    fonts_view = window.views[2]
    assert fonts_view.table.model.rowCount() == len(analysis.fonts)  # type: ignore[attr-defined]
    findings_view = window.views[9]
    toolbox_view = window.views[10]
    assert window.views[8].title == "OCR"
    assert toolbox_view.title == "Toolbox" and toolbox_view.tools_table.model.rowCount() >= 14  # type: ignore[attr-defined]
    assert findings_view.table.model.rowCount() == len(analysis.findings)  # type: ignore[attr-defined]
    fonts_view.table.search.setText("FixtureSans")  # type: ignore[attr-defined]
    assert fonts_view.table.proxy.rowCount() == 1  # type: ignore[attr-defined]
    window.set_theme("dark")
    window.set_theme("light")
    window.close()
