"""Toolbox: registry and runner for third-party open source PDF analysis tools.

Each tool is described by a :class:`ToolSpec` (where to find it, licence,
read-only actions). Only options verified against real installations are
used; see ``docs/TOOLS.md`` for the versions tested. Every action is
read-only: options that write or modify files (``pdfresurrect -w``, ``qpdf``
output modes, ``exiftool`` write tags, ``pdfdetach -save``...) are never used.

Additional tools can be declared by the analyst in a TOML file
(``PDFTRACE_TOOLS_FILE`` or ``~/.pdftrace/tools.toml``); their output is
stored verbatim.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import re
import shlex
import shutil
import sys
import time
import tomllib
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from pdftrace.config import Settings
from pdftrace.core.models import ExternalToolRun, ToolStatus
from pdftrace.frozen import PYRUNNER, RUN_SCRIPT, bundled_dir, helper_executable, is_frozen
from pdftrace.integrations import tool_parsers
from pdftrace.integrations.process import ToolFailed, ToolNotFound, find_executable, run_tool

PDF = "{pdf}"


@dataclass(frozen=True)
class ToolAction:
    id: str
    label: str
    args: tuple[str, ...]
    parser: str | None = None
    ok_codes: tuple[int, ...] = (0,)
    description: str = ""


@dataclass(frozen=True)
class ToolSpec:
    id: str
    name: str
    category: str
    license: str
    homepage: str
    actions: tuple[ToolAction, ...]
    #: ``exe`` (native program), ``python-script`` (a .py file run with Python),
    #: ``python-module`` (a library, run through ``pdftrace.integrations.pyrunners``)
    kind: str = "exe"
    executables: tuple[str, ...] = ()
    version_args: tuple[str, ...] = ("--version",)
    version_pattern: str = r"(\d+(?:\.\d+)+)"
    poppler: bool = False
    module: str | None = None
    install_hint: str = ""
    notes: str = ""
    custom: bool = False
    command_prefix: tuple[str, ...] = field(default=())

    @property
    def env_var(self) -> str:
        return "PDFTRACE_TOOL_" + re.sub(r"[^A-Z0-9]", "_", self.id.upper())


def _a(
    id_: str, label: str, *args: str, parser: str | None = None, ok: tuple[int, ...] = (0,), description: str = ""
) -> ToolAction:
    return ToolAction(id_, label, tuple(args), parser, ok, description)


#: Built-in tools. Options verified on: qpdf 11.9.0, MuPDF 1.23.10, ExifTool 12.76,
#: pdfresurrect 0.23, Ghostscript 10.02.1, pdftk-java 3.3.3, pdfcpu 0.16.0, Poppler 24.02,
#: pdfid 0.2.10, pdf-parser 0.7.14, pikepdf 10.5.1, pypdf 5.9.0.
BUILTIN_TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "qpdf",
        "qpdf",
        "validation",
        "Apache-2.0",
        "https://github.com/qpdf/qpdf",
        (
            _a(
                "check",
                "Structure check",
                "--check",
                PDF,
                parser="qpdf_check",
                ok=(0, 2, 3),
                description="Checks syntax, xref and stream encoding (exit 2 = errors, 3 = warnings).",
            ),
            _a("show-encryption", "Encryption", "--show-encryption", PDF),
            _a("show-xref", "Cross-reference", "--show-xref", PDF),
        ),
        executables=("qpdf",),
        install_hint="apt install qpdf | scoop install qpdf",
    ),
    ToolSpec(
        "mutool",
        "MuPDF mutool",
        "structure",
        "AGPL-3.0",
        "https://mupdf.com",
        (
            _a("info", "Document info", "info", PDF),
            _a("info-fonts-images", "Fonts and images", "info", "-F", "-I", PDF),
            _a("trailer", "Trailer", "show", PDF, "trailer"),
            _a("xref", "Cross-reference", "show", PDF, "xref"),
        ),
        executables=("mutool",),
        version_args=("-v",),
        install_hint="apt install mupdf-tools | scoop install mupdf (extras)",
    ),
    ToolSpec(
        "exiftool",
        "ExifTool",
        "metadata",
        "Artistic-1.0-Perl OR GPL-1.0-or-later",
        "https://exiftool.org",
        (_a("metadata", "All metadata (JSON)", "-j", "-a", "-G1", "-u", PDF, parser="exiftool_json"),),
        executables=("exiftool",),
        version_args=("-ver",),
        install_hint="apt install libimage-exiftool-perl | scoop install exiftool",
    ),
    ToolSpec(
        "pdfresurrect",
        "pdfresurrect",
        "revisions",
        "GPL-3.0-or-later",
        "https://github.com/enferex/pdfresurrect",
        (
            _a("versions", "Number of versions", PDF, "-q", parser="pdfresurrect_versions"),
            _a("info", "Versions and creator info", PDF, "-i"),
        ),
        executables=("pdfresurrect",),
        version_args=("-v",),
        version_pattern=r"v(\d+(?:\.\d+)+)",
        install_hint="apt install pdfresurrect (no Windows build: use WSL)",
        notes="The write option (-w) is never used.",
    ),
    ToolSpec(
        "ghostscript",
        "Ghostscript",
        "rendering",
        "AGPL-3.0",
        "https://www.ghostscript.com",
        (
            _a(
                "render-check",
                "Interpretation check (no output)",
                "-dSAFER",
                "-dBATCH",
                "-dNOPAUSE",
                "-sDEVICE=nullpage",
                "-q",
                PDF,
                parser="ghostscript_check",
                description="Interprets every page with -dSAFER and discards the output; reports errors.",
            ),
        ),
        executables=("gs", "gswin64c", "gswin32c"),
        install_hint="apt install ghostscript | scoop install ghostscript",
    ),
    ToolSpec(
        "pdftk",
        "pdftk-java",
        "metadata",
        "GPL-2.0-or-later",
        "https://gitlab.com/pdftk-java/pdftk",
        (_a("dump-data", "Info, bookmarks and page data", PDF, "dump_data_utf8", parser="pdftk_dump"),),
        executables=("pdftk",),
        install_hint="apt install pdftk-java | scoop install pdftk",
    ),
    ToolSpec(
        "pdfcpu",
        "pdfcpu",
        "validation",
        "Apache-2.0",
        "https://github.com/pdfcpu/pdfcpu",
        (
            _a("validate", "Validation (relaxed)", "validate", PDF, parser="pdfcpu_validate", ok=(0, 1)),
            _a("info", "Document info (JSON)", "info", "-j", PDF, parser="pdfcpu_info"),
        ),
        executables=("pdfcpu",),
        version_args=("version",),
        install_hint="scoop install pdfcpu | https://github.com/pdfcpu/pdfcpu/releases",
        notes="pdfcpu may create its configuration folder in the user profile on first run.",
    ),
    ToolSpec(
        "pdfsig",
        "Poppler pdfsig",
        "signatures",
        "GPL-2.0-or-later",
        "https://poppler.freedesktop.org",
        (_a("signatures", "Digital signatures", PDF, parser="pdfsig", ok=(0, 1, 2)),),
        executables=("pdfsig",),
        version_args=("-v",),
        poppler=True,
        install_hint="apt install poppler-utils (not in the Windows Poppler build)",
    ),
    ToolSpec(
        "pdfdetach",
        "Poppler pdfdetach",
        "attachments",
        "GPL-2.0-or-later",
        "https://poppler.freedesktop.org",
        (_a("list", "Embedded files", "-list", PDF, parser="pdfdetach_list"),),
        executables=("pdfdetach",),
        version_args=("-v",),
        poppler=True,
        install_hint="apt install poppler-utils",
    ),
    ToolSpec(
        "pdfinfo-extra",
        "Poppler pdfinfo (scripts, URLs, XMP)",
        "active-content",
        "GPL-2.0-or-later",
        "https://poppler.freedesktop.org",
        (
            _a("js", "JavaScript listing (not executed)", "-js", PDF, parser="pdfinfo_js"),
            _a("url", "URLs in objects", "-url", PDF, parser="pdfinfo_url"),
            _a("meta", "Raw XMP", "-meta", PDF),
        ),
        executables=("pdfinfo",),
        version_args=("-v",),
        poppler=True,
        install_hint="apt install poppler-utils",
    ),
    ToolSpec(
        "pdfid",
        "pdfid (Didier Stevens)",
        "triage",
        "Public domain",
        "https://github.com/DidierStevens/DidierStevensSuite",
        (_a("triage", "Keyword triage", PDF, parser="pdfid"),),
        kind="python-script",
        executables=("pdfid.py", "pdfid"),
        install_hint="scripts/install-tools: downloads pdfid.py into ~/.pdftrace/tools",
    ),
    ToolSpec(
        "pdf-parser",
        "pdf-parser (Didier Stevens)",
        "structure",
        "Public domain",
        "https://github.com/DidierStevens/DidierStevensSuite",
        (_a("stats", "Object statistics", "-a", PDF),),
        kind="python-script",
        executables=("pdf-parser.py", "pdf-parser"),
        install_hint="scripts/install-tools: downloads pdf-parser.py into ~/.pdftrace/tools",
    ),
    ToolSpec(
        "pikepdf",
        "pikepdf (libqpdf)",
        "validation",
        "MPL-2.0",
        "https://github.com/pikepdf/pikepdf",
        (_a("check", "Syntax check", PDF, parser="json"),),
        kind="python-module",
        module="pikepdf",
        install_hint="core dependency",
    ),
    ToolSpec(
        "pypdf",
        "pypdf (strict mode)",
        "validation",
        "BSD-3-Clause",
        "https://github.com/py-pdf/pypdf",
        (_a("strict", "Strict parsing", PDF, parser="json"),),
        kind="python-module",
        module="pypdf",
        install_hint="core dependency",
    ),
)


def _custom_tools_file(settings: Settings) -> Path | None:
    configured = settings.tools_file or os.environ.get("PDFTRACE_TOOLS_FILE")
    path = Path(configured).expanduser() if configured else Path.home() / ".pdftrace" / "tools.toml"
    return path if path.is_file() else None


def load_custom_tools(settings: Settings) -> tuple[list[ToolSpec], list[str]]:
    """Analyst-defined tools from TOML. Returns (specs, errors)."""
    specs: list[ToolSpec] = []
    errors: list[str] = []
    path = _custom_tools_file(settings)
    entries: list[dict[str, object]] = []
    if path:
        try:
            entries = list(tomllib.loads(path.read_text("utf-8")).get("tool", []))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            errors.append(f"{path}: {exc}")
    if settings.external_metadata_cmd:  # backward compatible single-command adapter
        entries.append(
            {
                "id": "dbxmetadata",
                "name": "dbxMetadata Forensics (custom)",
                "command": shlex.split(settings.external_metadata_cmd),
            }
        )
    builtin_ids = {t.id for t in BUILTIN_TOOLS}
    for entry in entries:
        command = entry.get("command")
        tool_id = str(entry.get("id", "")).strip()
        if not tool_id or tool_id in builtin_ids or not isinstance(command, list) or not command:
            errors.append(f"Invalid custom tool entry: {entry!r}")
            continue
        args = [str(c) for c in command[1:]]
        if PDF not in args:
            args.append(PDF)
        specs.append(
            ToolSpec(
                tool_id,
                str(entry.get("name", tool_id)),
                str(entry.get("category", "custom")),
                str(entry.get("license", "unknown")),
                str(entry.get("homepage", "")),
                (ToolAction("run", "Run", tuple(args), None, tuple(entry.get("ok_codes", [0]))),),  # type: ignore[arg-type]
                executables=(str(command[0]),),
                version_args=(),
                custom=True,
                notes="Analyst-defined tool: output stored verbatim, not parsed.",
            )
        )
    return specs, errors


def _python_interpreter() -> str | None:
    if not is_frozen():
        return sys.executable
    return shutil.which("python3") or shutil.which("python") or shutil.which("py")


def _script_command(path: str) -> list[str] | None:
    """Command prefix for a Python script tool (frozen builds use their own interpreter)."""
    helper = helper_executable()
    if helper:
        return [helper, RUN_SCRIPT, path]
    python = _python_interpreter()
    return [python, path] if python else None


def _module_command(tool_id: str) -> list[str] | None:
    helper = helper_executable()
    if helper:
        return [helper, PYRUNNER, tool_id]
    if is_frozen():
        return None
    return [sys.executable, "-m", "pdftrace.integrations.pyrunners", tool_id]


class Toolbox:
    """Locate, describe and run the registered tools."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        custom, self.errors = load_custom_tools(settings)
        self.tools: list[ToolSpec] = [*BUILTIN_TOOLS, *custom]
        self._resolved: dict[str, list[str] | None] = {}
        self._versions: dict[str, str | None] = {}

    def get(self, tool_id: str) -> ToolSpec | None:
        return next((t for t in self.tools if t.id == tool_id), None)

    def select(self, selection: str | Iterable[str] | None) -> list[ToolSpec]:
        """``"all"`` -> every available tool; otherwise ids (unknown ids are ignored)."""
        if selection is None:
            return []
        if isinstance(selection, str):
            if selection.strip().lower() in {"", "none"}:
                return []
            if selection.strip().lower() == "all":
                return [t for t in self.tools if self.base_command(t)]
            selection = [s.strip() for s in selection.split(",")]
        wanted = list(selection)
        return [t for t in self.tools if t.id in wanted]

    # ---------------------------------------------------------------- discovery
    def _find_file(self, spec: ToolSpec) -> str | None:
        override = os.environ.get(spec.env_var)
        if override:
            return override if Path(override).is_file() else find_executable(override)
        bundled = bundled_dir("tools")
        dirs = [
            d
            for d in (
                os.environ.get("PDFTRACE_TOOLS_DIR"),
                str(Path.home() / ".pdftrace" / "tools"),
                str(bundled) if bundled else None,
            )
            if d
        ]
        if spec.poppler and self.settings.poppler_path:
            dirs.insert(0, self.settings.poppler_path)
        for name in spec.executables:
            for directory in dirs:
                found = find_executable(name, directory)
                if found or (spec.kind == "python-script" and (Path(directory) / name).is_file()):
                    return found or str(Path(directory) / name)
            if spec.custom and Path(name).is_file():
                return name
            found = shutil.which(name)
            if found:
                return found
        return None

    def base_command(self, spec: ToolSpec) -> list[str] | None:
        """Command prefix to run ``spec`` (``None`` when unavailable)."""
        if spec.id in self._resolved:
            return self._resolved[spec.id]
        command: list[str] | None = None
        if spec.kind == "python-module":
            if spec.module and importlib.util.find_spec(spec.module):
                command = _module_command(spec.id)
        else:
            path = self._find_file(spec)
            if path and spec.kind == "python-script" and path.endswith(".py"):
                command = _script_command(path)
            elif path:
                command = [path]
        self._resolved[spec.id] = command
        return command

    def version(self, spec: ToolSpec) -> str | None:
        if spec.id in self._versions:
            return self._versions[spec.id]
        version = None
        base = self.base_command(spec)
        if base and spec.kind == "python-module" and spec.module:
            try:
                from importlib.metadata import version as dist_version

                version = dist_version(spec.module)
            except Exception:
                version = None
        elif base and spec.version_args:
            try:
                result = run_tool(base[0], [*base[1:], *spec.version_args], timeout_s=20)
                match = re.search(spec.version_pattern, result.stdout + "\n" + result.stderr)
                version = match.group(1) if match else None
            except (ToolFailed, ToolNotFound):
                version = None
        self._versions[spec.id] = version
        return version

    def status(self, spec: ToolSpec) -> ToolStatus:
        base = self.base_command(spec)
        if not base:
            hint = f"Not found. {spec.install_hint}".strip() if spec.install_hint else "Not found."
            return ToolStatus(
                spec.id,
                False,
                None,
                None,
                f"{hint} (override: {spec.env_var})",
                "custom" if spec.custom else "optional",
            )
        return ToolStatus(
            spec.id, True, " ".join(base), self.version(spec), None, "custom" if spec.custom else "optional"
        )

    def statuses(self) -> list[ToolStatus]:
        return [self.status(t) for t in self.tools]

    # ---------------------------------------------------------------- running
    def run_action(self, spec: ToolSpec, action: ToolAction, pdf: Path) -> ExternalToolRun:
        started = datetime.now(UTC).isoformat(timespec="seconds")
        run = ExternalToolRun(
            tool_id=spec.id,
            tool_name=spec.name,
            action_id=action.id,
            action_label=action.label,
            category=spec.category,
            license=spec.license,
            version=self.version(spec),
            started_utc=started,
        )
        base = self.base_command(spec)
        if not base:
            run.status, run.error = "unavailable", self.status(spec).error
            return run
        args = [*base[1:], *[str(pdf) if a == PDF else a for a in action.args]]
        run.command = [base[0], *args]
        start = time.monotonic()
        try:
            result = run_tool(base[0], args, self.settings.tool_timeout_s, self.settings.max_tool_output)
        except ToolFailed as exc:  # timeout
            run.status, run.error, run.timed_out = "timeout", str(exc), True
            if exc.result:
                run.stdout, run.stderr = exc.result.stdout, exc.result.stderr
            run.duration_s = round(time.monotonic() - start, 3)
            return run
        except ToolNotFound as exc:
            run.status, run.error = "error", str(exc)
            return run
        run.duration_s = round(result.duration_s, 3)
        run.returncode, run.stdout, run.stderr, run.truncated = (
            result.returncode,
            result.stdout,
            result.stderr,
            result.truncated,
        )
        run.stdout_sha256 = hashlib.sha256(result.stdout.encode("utf-8", "replace")).hexdigest()
        run.status = "ok" if result.returncode in action.ok_codes else "error"
        if action.parser:
            parser: Callable[[str, str, int | None], dict[str, object]] | None = tool_parsers.PARSERS.get(action.parser)
            if parser:
                try:
                    run.parsed = parser(result.stdout, result.stderr, result.returncode)
                except Exception as exc:  # a parser must never break the run
                    run.parsed = {"parser_error": f"{type(exc).__name__}: {exc}"}
        return run

    def run_tools(
        self,
        specs: Iterable[ToolSpec],
        pdf: Path,
        cancelled: Callable[[], bool] = lambda: False,
        progress: Callable[[ExternalToolRun], None] | None = None,
    ) -> list[ExternalToolRun]:
        runs: list[ExternalToolRun] = []
        for spec in specs:
            for action in spec.actions:
                if cancelled():
                    return runs
                run = self.run_action(spec, action, pdf)
                runs.append(run)
                if progress:
                    progress(run)
        return runs
