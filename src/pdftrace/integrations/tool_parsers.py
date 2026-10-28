"""Parsers for the output of Toolbox actions.

Each parser receives ``(stdout, stderr, returncode)`` and returns a small,
JSON-compatible summary used by findings and reports. The raw output is
always kept as well. Formats were checked on the versions listed in
``integrations/toolbox.py``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

Parsed = dict[str, Any]


def qpdf_check(out: str, err: str, rc: int | None) -> Parsed:
    lines = [ln.strip() for ln in (out + "\n" + err).splitlines() if ln.strip()]
    warnings = [ln for ln in lines if ln.startswith("WARNING")]
    errors = [ln for ln in lines if ln.startswith(("ERROR", "qpdf: ")) or ": error" in ln.lower()]
    clean = any("No syntax or stream encoding errors found" in ln for ln in lines)
    return {
        "clean": clean and rc == 0,
        "exit_code": rc,
        "warnings": warnings[:200],
        "errors": errors[:200],
        "warning_count": len(warnings),
    }


def exiftool_json(out: str, err: str, rc: int | None) -> Parsed:
    data = json.loads(out) if out.strip() else []
    tags = data[0] if data else {}
    skip = ("System:", "ExifTool:", "SourceFile")
    return {"tags": {k: v for k, v in tags.items() if not k.startswith(skip)}, "tag_count": len(tags)}


def pdfresurrect_versions(out: str, err: str, rc: int | None) -> Parsed:
    match = re.search(r":\s*(\d+)\s*$", out.strip())
    return {"versions": int(match.group(1)) if match else None}


def ghostscript_check(out: str, err: str, rc: int | None) -> Parsed:
    text = out + "\n" + err
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    problems = [ln for ln in lines if "Error" in ln or "error" in ln or "warning" in ln.lower()]
    return {"clean": not lines, "problems": problems[:100], "message_lines": len(lines)}


def pdftk_dump(out: str, err: str, rc: int | None) -> Parsed:
    info: dict[str, str] = {}
    key = None
    pages = None
    for line in out.splitlines():
        if line.startswith("InfoKey: "):
            key = line[9:]
        elif line.startswith("InfoValue: ") and key:
            info[key] = line[11:]
            key = None
        elif line.startswith("NumberOfPages: "):
            pages = int(line.split(":", 1)[1])
        elif line.startswith("PdfID0: "):
            info["PdfID0"] = line[8:]
        elif line.startswith("PdfID1: "):
            info["PdfID1"] = line[8:]
    return {"info": info, "pages": pages}


def pdfcpu_validate(out: str, err: str, rc: int | None) -> Parsed:
    text = (out + "\n" + err).strip()
    ok = "validation ok" in text and rc == 0
    notes = [ln.strip() for ln in text.splitlines() if ln.startswith(("pdfcpu ", "validate "))]
    return {"valid": ok, "messages": notes[:100]}


def pdfcpu_info(out: str, err: str, rc: int | None) -> Parsed:
    start = out.find("{")
    data = json.loads(out[start:]) if start >= 0 else {}
    infos = data.get("infos") or [{}]
    keep = (
        "version",
        "pageCount",
        "title",
        "author",
        "producer",
        "creator",
        "creationDate",
        "modificationDate",
        "tagged",
        "linearized",
        "usingXRefStreams",
        "usingObjectStreams",
        "signatures",
        "form",
        "encrypted",
        "appendOnly",
    )
    return {k: infos[0].get(k) for k in keep if k in infos[0]}


def pdfsig(out: str, err: str, rc: int | None) -> Parsed:
    text = out + "\n" + err
    none = "does not contain any signatures" in text
    count = len(re.findall(r"^Signature #\d+", text, re.M))
    return {"signatures": 0 if none else count, "nss_warning": "NSS_Init failed" in text}


def pdfdetach_list(out: str, err: str, rc: int | None) -> Parsed:
    match = re.search(r"(\d+)\s+embedded files?", out)
    names = [ln.split(":", 1)[1].strip() for ln in out.splitlines() if re.match(r"^\d+:", ln)]
    return {"embedded_files": int(match.group(1)) if match else len(names), "names": names[:200]}


def pdfinfo_js(out: str, err: str, rc: int | None) -> Parsed:
    return {"has_javascript": bool(out.strip()), "length": len(out)}


def pdfinfo_url(out: str, err: str, rc: int | None) -> Parsed:
    rows = [ln.split(None, 2) for ln in out.splitlines()[1:] if ln.strip()]
    urls = [r[2] for r in rows if len(r) == 3]
    return {"urls": urls[:500], "url_count": len(urls)}


_PDFID_LINE = re.compile(r"^\s*(\S.*?)\s+(\d+)(?:\((\d+)\))?\s*$")


def pdfid(out: str, err: str, rc: int | None) -> Parsed:
    counts: dict[str, int] = {}
    header = None
    for line in out.splitlines():
        if line.strip().startswith("PDF Header:"):
            header = line.split(":", 1)[1].strip()
            continue
        match = _PDFID_LINE.match(line)
        if match and not line.startswith("PDFiD"):
            counts[match.group(1)] = int(match.group(2))
    return {"header": header, "counts": counts}


def as_json(out: str, err: str, rc: int | None) -> Parsed:
    result: Parsed = json.loads(out) if out.strip() else {}
    return result


PARSERS: dict[str, Callable[[str, str, int | None], Parsed]] = {
    "qpdf_check": qpdf_check,
    "exiftool_json": exiftool_json,
    "pdfresurrect_versions": pdfresurrect_versions,
    "ghostscript_check": ghostscript_check,
    "pdftk_dump": pdftk_dump,
    "pdfcpu_validate": pdfcpu_validate,
    "pdfcpu_info": pdfcpu_info,
    "pdfsig": pdfsig,
    "pdfdetach_list": pdfdetach_list,
    "pdfinfo_js": pdfinfo_js,
    "pdfinfo_url": pdfinfo_url,
    "pdfid": pdfid,
    "json": as_json,
}
