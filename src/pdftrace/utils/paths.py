"""Input validation for untrusted file paths."""

from __future__ import annotations

from pathlib import Path


class InputError(ValueError):
    """Raised when the input file cannot be analysed at all."""


def validate_pdf_path(path: str | Path) -> Path:
    """Resolve and validate a path to a regular, readable file.

    The path is made absolute so that it can never be mistaken for a command
    line option by an external tool (absolute paths never start with ``-``).
    The content is *not* required to be a valid PDF: malformed files are
    analysed best-effort and the problems are reported as findings.
    """
    candidate = Path(path).expanduser()
    try:
        resolved = candidate.resolve(strict=True)
    except (FileNotFoundError, RuntimeError, OSError) as exc:
        raise InputError(f"File not found: {candidate}") from exc
    if not resolved.is_file():
        raise InputError(f"Not a regular file: {resolved}")
    try:
        with resolved.open("rb") as handle:
            handle.read(1)
    except OSError as exc:
        raise InputError(f"File is not readable: {resolved} ({exc})") from exc
    return resolved


def safe_output_dir(path: str | Path) -> Path:
    """Create (if needed) and return an absolute output directory."""
    out = Path(path).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    if not out.is_dir():
        raise InputError(f"Output path is not a directory: {out}")
    return out
