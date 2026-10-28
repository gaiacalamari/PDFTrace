"""GUI entry point: ``pdftrace-gui [file.pdf]``."""

from __future__ import annotations

import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    from pdftrace.frozen import dispatch_helper

    helper_code = dispatch_helper(list(sys.argv[1:] if argv is None else argv[1:]))
    if helper_code is not None:
        return helper_code
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        print("PySide6 is not installed. Install the GUI extra: pip install 'pdftrace[gui]'", file=sys.stderr)
        return 2
    from pdftrace.gui.main_window import MainWindow
    from pdftrace.gui.theme import apply_theme

    args = list(sys.argv if argv is None else argv)
    app = QApplication(args)
    app.setApplicationName("PDFTrace")
    window = MainWindow()
    apply_theme(app, window.theme)
    window.show()
    files = [a for a in args[1:] if not a.startswith("-")]
    if files:
        window.start_analysis(Path(files[0]))
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
