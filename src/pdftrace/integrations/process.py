"""Safe execution of external command line tools.

* arguments are always passed as a list (never through a shell);
* stdin is closed, a timeout is enforced and output size is capped;
* on Windows no console window is opened.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from pdftrace.utils.logging import get_logger, log_event

_LOG = get_logger("process")


class ToolNotFound(RuntimeError):
    """The requested external executable is not available."""


class ToolFailed(RuntimeError):
    """The external tool ran but returned an error or timed out."""

    def __init__(self, message: str, result: ToolResult | None = None) -> None:
        super().__init__(message)
        self.result = result


@dataclass
class ToolResult:
    command: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False
    truncated: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def find_executable(name: str, search_dir: str | None = None) -> str | None:
    """Locate ``name`` in ``search_dir`` (if given) or on ``PATH``."""
    if search_dir:
        for candidate in (name, f"{name}.exe"):
            path = Path(search_dir) / candidate
            if path.is_file() and os.access(path, os.X_OK):
                return str(path)
        return None
    return shutil.which(name)


def run_tool(
    executable: str,
    args: list[str],
    timeout_s: float,
    max_output: int = 4_000_000,
    cwd: str | None = None,
) -> ToolResult:
    """Run ``executable`` with ``args`` and capture its output."""
    command = [executable, *[str(a) for a in args]]
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
    start = time.monotonic()
    log_event(_LOG, 10, "tool.start", command=command)
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout_s,
            check=False,
            cwd=cwd,
            creationflags=creationflags,
        )
    except subprocess.TimeoutExpired as exc:
        duration = time.monotonic() - start
        result = ToolResult(
            command=command,
            returncode=None,
            stdout=_decode(exc.stdout or b"", max_output)[0],
            stderr=_decode(exc.stderr or b"", max_output)[0],
            duration_s=duration,
            timed_out=True,
        )
        log_event(_LOG, 30, "tool.timeout", command=command, timeout_s=timeout_s)
        raise ToolFailed(f"{Path(executable).name} timed out after {timeout_s:.0f}s", result) from exc
    except OSError as exc:
        raise ToolNotFound(f"Cannot execute {executable}: {exc}") from exc
    stdout, cut_out = _decode(completed.stdout, max_output)
    stderr, cut_err = _decode(completed.stderr, max_output)
    result = ToolResult(
        command=command,
        returncode=completed.returncode,
        stdout=stdout,
        stderr=stderr,
        duration_s=time.monotonic() - start,
        truncated=cut_out or cut_err,
    )
    log_event(_LOG, 10, "tool.end", command=command, rc=completed.returncode)
    return result


def _decode(data: bytes, limit: int) -> tuple[str, bool]:
    truncated = len(data) > limit
    return data[:limit].decode("utf-8", errors="replace"), truncated
