"""Light and dark themes (Fusion style + palette + a small stylesheet)."""

from __future__ import annotations

from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication

THEMES: dict[str, dict[str, str]] = {
    "light": {
        "window": "#f4f6f9",
        "base": "#ffffff",
        "alt": "#eef2f6",
        "text": "#1d2a3a",
        "muted": "#5b6778",
        "accent": "#2f6690",
        "rule": "#d5dbe3",
        "sidebar": "#1d2a3a",
        "sidebar_text": "#dce3ec",
        "info": "#2f6690",
        "notice": "#a86a00",
        "warning": "#9e2a2b",
        "ok": "#2d6a3e",
    },
    "dark": {
        "window": "#161c24",
        "base": "#1e2630",
        "alt": "#242e3a",
        "text": "#dfe6ee",
        "muted": "#93a0b0",
        "accent": "#6fa8d6",
        "rule": "#33404f",
        "sidebar": "#10151b",
        "sidebar_text": "#c5cfdb",
        "info": "#6fa8d6",
        "notice": "#e0a33a",
        "warning": "#e07070",
        "ok": "#6cc08a",
    },
}


def colors(name: str) -> dict[str, str]:
    return THEMES.get(name, THEMES["light"])


def apply_theme(app: QApplication, name: str) -> None:
    c = colors(name)
    app.setStyle("Fusion")
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(c["window"]))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(c["text"]))
    palette.setColor(QPalette.ColorRole.Base, QColor(c["base"]))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(c["alt"]))
    palette.setColor(QPalette.ColorRole.Text, QColor(c["text"]))
    palette.setColor(QPalette.ColorRole.Button, QColor(c["alt"]))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(c["text"]))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(c["accent"]))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(c["base"]))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor(c["text"]))
    palette.setColor(QPalette.ColorRole.PlaceholderText, QColor(c["muted"]))
    app.setPalette(palette)
    app.setStyleSheet(
        f"""
        QListWidget#nav {{ background:{c["sidebar"]}; color:{c["sidebar_text"]}; border:none;
            font-size:14px; padding-top:8px; }}
        QListWidget#nav::item {{ padding:9px 16px; }}
        QListWidget#nav::item:selected {{ background:{c["accent"]}; color:#ffffff; }}
        QLabel#brand {{ background:{c["sidebar"]}; color:#ffffff; font-size:15px; font-weight:600;
            padding:16px 16px 6px 16px; }}
        QLabel#h1 {{ font-size:20px; font-weight:600; }}
        QLabel#muted {{ color:{c["muted"]}; }}
        QLabel#hash {{ font-family:monospace; font-size:13px; }}
        QGroupBox {{ border:1px solid {c["rule"]}; margin-top:14px; padding:10px 8px 8px 8px;
            background:{c["base"]}; }}
        QGroupBox::title {{ subcontrol-origin: margin; left:8px; padding:0 4px; font-weight:600; }}
        QTableView {{ gridline-color:{c["rule"]}; selection-background-color:{c["accent"]}; }}
        QHeaderView::section {{ background:{c["alt"]}; padding:5px; border:none;
            border-bottom:1px solid {c["rule"]}; font-weight:600; }}
        QPlainTextEdit, QTextBrowser {{ background:{c["base"]}; }}
        QPushButton {{ padding:5px 12px; }}
        """
    )
