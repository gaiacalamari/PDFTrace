"""Out-of-process runners for Python PDF libraries (pikepdf, pypdf).

Invoked as ``python -m pdftrace.integrations.pyrunners <tool> <pdf>`` so that a
crash or hang in a library is isolated and subject to the Toolbox timeout.
Prints one JSON object on stdout.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any


def pikepdf_check(path: str) -> dict[str, Any]:
    import pikepdf

    try:
        with pikepdf.open(path) as pdf:
            problems = pdf.check_pdf_syntax()
            return {
                "opened": True,
                "pdf_version": pdf.pdf_version,
                "linearized": pdf.is_linearized,
                "encrypted": pdf.is_encrypted,
                "objects": len(pdf.objects),
                "pages": len(pdf.pages),
                "problems": [str(p) for p in problems][:500],
            }
    except Exception as exc:
        return {"opened": False, "error": f"{type(exc).__name__}: {exc}", "problems": []}


def pypdf_strict(path: str) -> dict[str, Any]:
    import pypdf

    messages: list[str] = []

    class Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            messages.append(record.getMessage())

    logging.getLogger("pypdf").addHandler(Collect())
    result: dict[str, Any] = {}
    try:
        reader = pypdf.PdfReader(path, strict=True)
        result.update(strict_ok=True, pages=len(reader.pages), xmp=reader.xmp_metadata is not None)
    except Exception as exc:
        result.update(strict_ok=False, strict_error=f"{type(exc).__name__}: {exc}")
        try:
            reader = pypdf.PdfReader(path, strict=False)
            result.update(lenient_pages=len(reader.pages))
        except Exception as exc2:
            result.update(lenient_error=f"{type(exc2).__name__}: {exc2}")
    result["warnings"] = messages[:500]
    return result


RUNNERS = {"pikepdf": pikepdf_check, "pypdf": pypdf_strict}


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] not in RUNNERS:
        print(json.dumps({"error": "usage: pyrunners <pikepdf|pypdf> <pdf>"}))
        return 2
    print(json.dumps(RUNNERS[argv[0]](argv[1]), default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
