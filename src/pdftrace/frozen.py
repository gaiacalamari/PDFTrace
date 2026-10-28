"""Support for standalone (PyInstaller) builds.

A frozen build has no separate Python interpreter, so the console executable
``pdftrace-cli`` doubles as one for helper processes started by the Toolbox:

* ``pdftrace-cli --pdftrace-run-script <script.py> [args]`` runs a bundled Python
  tool such as pdfid.py or pdf-parser.py;
* ``pdftrace-cli --pdftrace-pyrunner <pikepdf|pypdf> <pdf>`` runs an isolated
  library check (see ``integrations/pyrunners.py``).

Helper processes keep the isolation and timeout guarantees of normal runs.
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

RUN_SCRIPT = "--pdftrace-run-script"
PYRUNNER = "--pdftrace-pyrunner"
#: Standard library modules used by bundled scripts (pdfid, pdf-parser) and therefore
#: listed as hidden imports in packaging/pdftrace.spec.
SCRIPT_STDLIB = (
    "optparse",
    "zipfile",
    "xml.dom.minidom",
    "binascii",
    "hashlib",
    "json",
    "zlib",
    "fnmatch",
    "glob",
    "textwrap",
    "collections",
    "datetime",
    "urllib.request",
    "string",
    "math",
    "struct",
    "re",
    "os",
    "time",
    "traceback",
    "io",
)


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def app_dir() -> Path:
    """Folder containing the executables (or the source tree root when not frozen)."""
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def helper_executable() -> str | None:
    """Console executable used to run helper processes in a frozen build."""
    if not is_frozen():
        return None
    for name in ("pdftrace-cli.exe", "pdftrace-cli"):
        candidate = app_dir() / name
        if candidate.is_file():
            return str(candidate)
    return None


def bundled_dir(name: str) -> Path | None:
    """A folder shipped next to the executables (``poppler``, ``tools``, ``scripts``)."""
    for base in (app_dir(), Path(getattr(sys, "_MEIPASS", app_dir()))):
        folder = base / name
        if folder.is_dir():
            return folder
    return None


def dispatch_helper(argv: list[str]) -> int | None:
    """Handle helper invocations; returns an exit code, or ``None`` for normal startup."""
    if len(argv) >= 2 and argv[0] == RUN_SCRIPT:
        script = argv[1]
        sys.argv = [script, *argv[2:]]
        try:
            runpy.run_path(script, run_name="__main__")
        except SystemExit as exc:
            code = exc.code
            return code if isinstance(code, int) else (0 if code is None else 1)
        return 0
    if len(argv) >= 1 and argv[0] == PYRUNNER:
        from pdftrace.integrations.pyrunners import main as pyrunner_main

        return pyrunner_main(argv[1:])
    return None
