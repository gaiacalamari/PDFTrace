# PyInstaller spec for PDFTrace (one-folder build).
#
# Produces dist/PDFTrace/ with two executables sharing the same libraries:
#   PDFTrace(.exe)      - desktop GUI, no console window
#   pdftrace-cli(.exe)  - command line; also used as Python interpreter for Toolbox helpers
# Build with: python scripts/build_standalone.py   (see docs/PACKAGING.md)
import os
import sys

from PyInstaller.utils.hooks import collect_all, collect_submodules, copy_metadata

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))  # noqa: F821 - provided by PyInstaller
sys.path.insert(0, os.path.join(ROOT, "src"))
from pdftrace.frozen import SCRIPT_STDLIB  # noqa: E402

datas, binaries, hiddenimports = [], [], []
for package in ("pikepdf", "pypdfium2", "pypdfium2_raw", "pdfplumber", "pdfminer", "fontTools"):
    d, b, h = collect_all(package)
    datas += d
    binaries += b
    hiddenimports += h
hiddenimports += collect_submodules("pdftrace") + list(SCRIPT_STDLIB) + ["pypdf", "cryptography"]
for dist in ("pikepdf", "pypdf", "pdfplumber", "pdfminer.six", "fonttools", "pypdfium2", "pillow", "cryptography",
             "PySide6"):
    datas += copy_metadata(dist)
extra_files = [
    (os.path.join(ROOT, "scripts", "install-tools.ps1"), "scripts"),
    (os.path.join(ROOT, "LICENSE"), "."),
    (os.path.join(ROOT, "NOTICE"), "."),
    (os.path.join(ROOT, "README.md"), "."),
    (os.path.join(ROOT, "README.it.md"), "."),
]
datas += [(src, dst) for src, dst in extra_files if os.path.exists(src)]  # optional documents may be absent
icon = os.path.join(ROOT, "packaging", "pdftrace.ico")
icon = icon if os.path.exists(icon) else None

common = dict(
    pathex=[os.path.join(ROOT, "src")],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    # Optional imports of the dependencies that PDFTrace does not need (keeps the bundle small)
    excludes=["tkinter", "pytest", "mypy", "ruff", "numpy", "scipy", "pandas", "matplotlib", "cv2", "IPython",
              "lxml", "sympy", "notebook", "jupyter", "PyQt5", "PyQt6"],
)
gui = Analysis([os.path.join(ROOT, "scripts", "entry_gui.py")], **common)  # noqa: F821
cli = Analysis([os.path.join(ROOT, "scripts", "entry_cli.py")], **common)  # noqa: F821

gui_exe = EXE(  # noqa: F821
    PYZ(gui.pure),  # noqa: F821
    gui.scripts,
    [],
    exclude_binaries=True,
    name="PDFTrace",
    console=False,
    icon=icon,
)
cli_exe = EXE(  # noqa: F821
    PYZ(cli.pure),  # noqa: F821
    cli.scripts,
    [],
    exclude_binaries=True,
    name="pdftrace-cli",
    console=True,
    icon=icon,
)
COLLECT(gui_exe, gui.binaries, gui.datas, cli_exe, cli.binaries, cli.datas, name="PDFTrace")  # noqa: F821
