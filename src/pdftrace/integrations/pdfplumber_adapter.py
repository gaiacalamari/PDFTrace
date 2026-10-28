"""Access to the PDF object model through pdfplumber / pdfminer.six.

pdfplumber (MIT) is used for page content (chars, words, lines, rects,
curves, images); its underlying pdfminer.six ``PDFDocument`` (MIT) is used for
low-level objects: trailers, the Info dictionary, the XMP stream and font
programs. Neither library executes JavaScript or follows links.
"""

from __future__ import annotations

import contextlib
import io
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pdfplumber
from pdfminer.pdftypes import PDFObjRef, PDFStream, resolve1
from pdfminer.psparser import PSLiteral
from pdfminer.utils import decode_text

FONT_FILE_KEYS = ("FontFile", "FontFile2", "FontFile3")


class PDFOpenError(RuntimeError):
    """pdfminer could not parse the file."""


def open_pdf(path: Path) -> Any:
    """Open ``path`` with pdfplumber (read-only). Raises :class:`PDFOpenError`."""
    try:
        return pdfplumber.open(str(path))
    except Exception as exc:  # pdfminer raises many exception types
        raise PDFOpenError(f"{type(exc).__name__}: {exc}") from exc


def open_bytes(data: bytes) -> Any:
    """Open an in-memory PDF (used to read earlier revisions)."""
    try:
        return pdfplumber.open(io.BytesIO(data))
    except Exception as exc:
        raise PDFOpenError(f"{type(exc).__name__}: {exc}") from exc


def to_text(value: Any) -> str | None:
    """Convert a pdfminer value to readable text without guessing too much."""
    value = resolve1(value)
    if value is None:
        return None
    if isinstance(value, bytes):
        try:
            return decode_text(value)
        except Exception:
            return value.decode("latin-1", errors="replace")
    if isinstance(value, PSLiteral):
        name = value.name
        return name.decode("latin-1") if isinstance(name, bytes) else str(name)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(to_text(v) or "" for v in value) + "]"
    if isinstance(value, dict):
        return "<<" + ", ".join(f"/{k}" for k in value) + ">>"
    if isinstance(value, PDFStream):
        return "<stream>"
    return str(value)


def literal_name(value: Any) -> str | None:
    value = resolve1(value)
    if isinstance(value, PSLiteral):
        name = value.name
        return name.decode("latin-1") if isinstance(name, bytes) else str(name)
    if isinstance(value, bytes):
        return value.decode("latin-1", errors="replace")
    return None if value is None else str(value)


def info_dicts(pdf: Any) -> list[dict[str, Any]]:
    """Info dictionaries referenced by the trailers, newest revision first."""
    result: list[dict[str, Any]] = []
    for info in getattr(pdf.doc, "info", []) or []:
        resolved = resolve1(info)
        if isinstance(resolved, dict):
            result.append(resolved)
    return result


def trailer_ids(pdf: Any) -> list[list[str]]:
    """``/ID`` arrays of every trailer, hex encoded."""
    ids: list[list[str]] = []
    for xref in getattr(pdf.doc, "xrefs", []) or []:
        trailer = getattr(xref, "trailer", {}) or {}
        raw = resolve1(trailer.get("ID"))
        if isinstance(raw, list):
            ids.append([bytes(resolve1(v)).hex() if isinstance(resolve1(v), bytes) else str(v) for v in raw])
    return ids


def catalog(pdf: Any) -> dict[str, Any]:
    cat = getattr(pdf.doc, "catalog", None)
    return cat if isinstance(cat, dict) else {}


def xmp_bytes(pdf: Any, limit: int) -> bytes | None:
    """Raw XMP packet referenced by the catalog ``/Metadata`` entry."""
    stream = resolve1(catalog(pdf).get("Metadata"))
    if not isinstance(stream, PDFStream):
        return None
    data = stream.get_data()
    if len(data) > limit:
        raise ValueError(f"XMP packet larger than limit ({len(data)} > {limit} bytes)")
    return bytes(data)


def get_object(pdf: Any, objid: int) -> Any:
    try:
        return resolve1(pdf.doc.getobj(objid))
    except Exception:
        return None


@dataclass
class FontProgram:
    key: str
    subtype: str | None
    data: bytes


def font_descriptor(font: dict[str, Any]) -> dict[str, Any] | None:
    """Descriptor of a font dictionary (descending into Type0 fonts)."""
    descriptor = resolve1(font.get("FontDescriptor"))
    if isinstance(descriptor, dict):
        return descriptor
    descendants = resolve1(font.get("DescendantFonts"))
    if isinstance(descendants, list) and descendants:
        child = resolve1(descendants[0])
        if isinstance(child, dict):
            descriptor = resolve1(child.get("FontDescriptor"))
            if isinstance(descriptor, dict):
                return descriptor
    return None


def font_program(pdf: Any, objid: int, limit: int) -> FontProgram | None:
    """Decoded embedded font program for the font dictionary ``objid``."""
    font = get_object(pdf, objid)
    if not isinstance(font, dict):
        return None
    descriptor = font_descriptor(font)
    if not descriptor:
        return None
    for key in FONT_FILE_KEYS:
        stream = resolve1(descriptor.get(key))
        if isinstance(stream, PDFStream):
            raw_len = resolve1(stream.attrs.get("Length1") or stream.attrs.get("Length"))
            if isinstance(raw_len, int) and raw_len > limit:
                raise ValueError(f"Font program larger than limit ({raw_len} bytes)")
            data = stream.get_data()
            if len(data) > limit:
                raise ValueError(f"Font program larger than limit ({len(data)} bytes)")
            return FontProgram(key, literal_name(stream.attrs.get("Subtype")), bytes(data))
    return None


@dataclass
class ResourceFont:
    object_id: int | None
    base_font: str
    subtype: str
    encoding: str | None
    embedded: bool
    has_to_unicode: bool
    pages: list[int]


def enumerate_fonts(pdf: Any) -> list[ResourceFont]:
    """Fonts referenced by page resources (fallback when pdffonts is missing).

    Only direct page resources are inspected; fonts used exclusively inside
    form XObjects or annotations are not listed (pdffonts does list them).
    """
    found: dict[Any, ResourceFont] = {}
    for page in pdf.pages:
        resources = resolve1(page.page_obj.attrs.get("Resources")) or {}
        fonts = resolve1(resources.get("Font")) if isinstance(resources, dict) else None
        if not isinstance(fonts, dict):
            continue
        for ref in fonts.values():
            objid = ref.objid if isinstance(ref, PDFObjRef) else None
            key = objid if objid is not None else id(ref)
            if key in found:
                if page.page_number not in found[key].pages:
                    found[key].pages.append(page.page_number)
                continue
            font = resolve1(ref)
            if not isinstance(font, dict):
                continue
            descriptor = font_descriptor(font)
            embedded = descriptor is not None and any(k in descriptor for k in FONT_FILE_KEYS)
            encoding = resolve1(font.get("Encoding"))
            found[key] = ResourceFont(
                object_id=objid,
                base_font=literal_name(font.get("BaseFont")) or "[none]",
                subtype=literal_name(font.get("Subtype")) or "unknown",
                encoding=literal_name(encoding) if not isinstance(encoding, dict) else "Custom",
                embedded=embedded,
                has_to_unicode="ToUnicode" in font,
                pages=[page.page_number],
            )
    return list(found.values())


@contextlib.contextmanager
def opened(path: Path) -> Iterator[Any]:
    pdf = open_pdf(path)
    try:
        yield pdf
    finally:
        with contextlib.suppress(Exception):
            pdf.close()
