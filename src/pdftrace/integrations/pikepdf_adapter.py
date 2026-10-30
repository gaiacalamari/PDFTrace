"""Helpers around pikepdf (MPL-2.0, libqpdf).

pikepdf opens the file read-only here: nothing is ever saved. Values are
converted to plain Python types so that analyzers never hold pikepdf objects.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pikepdf

from pdftrace.integrations.pdfplumber_adapter import PDFOpenError

MAX_DEPTH = 64
Stream = pikepdf.Stream
Dictionary = pikepdf.Dictionary
Array = pikepdf.Array


def read_generalized(stream: Any) -> bytes:
    """Stream data with generalized filters removed (keeps image codecs such as DCT)."""
    return bytes(stream.read_bytes(pikepdf.StreamDecodeLevel.generalized))


def open_pike(path: Path) -> pikepdf.Pdf:
    try:
        return pikepdf.open(str(path))
    except pikepdf.PasswordError as exc:
        raise PDFOpenError(f"Password required: {exc}") from exc
    except Exception as exc:  # pikepdf raises PdfError and others on damaged files
        raise PDFOpenError(f"{type(exc).__name__}: {exc}") from exc


def info_from_bytes(data: bytes) -> dict[str, str] | None:
    """Trailer /Info of an in-memory PDF (used for earlier revisions pdfminer rejects)."""
    import io

    try:
        with pikepdf.open(io.BytesIO(data)) as pdf:
            info = pdf.trailer.get("/Info")
            if not isinstance(info, pikepdf.Dictionary):
                return None
            return {str(k).lstrip("/"): text(v) or "" for k, v in info.items()}
    except Exception as exc:  # damaged or truncated data: pikepdf raises several types
        raise PDFOpenError(f"{type(exc).__name__}: {exc}") from exc


def text(value: Any) -> str | None:
    """Plain string for a pikepdf scalar (names keep their leading slash)."""
    if value is None:
        return None
    try:
        if isinstance(value, pikepdf.String):
            return str(value)
        if isinstance(value, pikepdf.Name):
            return str(value)
        items: Any = value
        if isinstance(value, (pikepdf.Array, list)):
            return "[" + ", ".join(text(v) or "" for v in items) + "]"
        if isinstance(value, pikepdf.Dictionary):
            return "<<" + ", ".join(str(k) for k in items.keys()) + ">>"
        return str(value)
    except Exception:
        return repr(value)


def name(value: Any) -> str | None:
    t = text(value)
    return t[1:] if t and t.startswith("/") else t


def get(obj: Any, key: str) -> Any:
    try:
        return obj.get(key) if obj is not None else None
    except Exception:
        return None


def numbers(value: Any) -> list[float]:
    try:
        return [round(float(v), 2) for v in value]
    except Exception:
        return []


def filters(stream: Any) -> list[str]:
    value = get(stream, "/Filter")
    if value is None:
        return []
    if isinstance(value, pikepdf.Array):
        entries: Any = value
        return [name(v) or "" for v in entries]
    return [name(value) or ""]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def objgen(obj: Any) -> tuple[int, int]:
    try:
        num, gen = obj.objgen
        return int(num), int(gen)
    except Exception:
        return 0, 0


def walk_outline(first: Any, level: int = 1, limit: int = 5000) -> Iterator[dict[str, Any]]:
    """Depth-first walk of /Outlines (/First, /Next), cycle and size safe."""
    seen: set[tuple[int, int]] = set()
    stack: list[tuple[Any, int]] = [(first, level)]
    count = 0
    while stack and count < limit:
        item, depth = stack.pop()
        while item is not None and count < limit:
            key = objgen(item)
            if key != (0, 0) and key in seen:
                break
            seen.add(key)
            count += 1
            dest = get(item, "/Dest")
            action = get(item, "/A")
            yield {
                "level": depth,
                "title": text(get(item, "/Title")),
                "dest": (text(dest) or "")[:120] if dest is not None else None,
                "action": name(get(action, "/S")) if action is not None else None,
            }
            child = get(item, "/First")
            if child is not None and depth < MAX_DEPTH:
                stack.append((get(item, "/Next"), depth))
                item, depth = child, depth + 1
                continue
            item = get(item, "/Next")


def name_tree_items(tree: Any, limit: int = 10000) -> list[tuple[str, Any]]:
    """Items of a name tree (``/Names`` arrays under ``/Kids``)."""
    items: list[tuple[str, Any]] = []
    stack = [(tree, 0)]
    while stack and len(items) < limit:
        node, depth = stack.pop()
        if node is None or depth > MAX_DEPTH:
            continue
        names = get(node, "/Names")
        if names is not None:
            for i in range(0, len(names) - 1, 2):
                items.append((text(names[i]) or "", names[i + 1]))
        kids = get(node, "/Kids")
        if kids is not None:
            stack.extend((k, depth + 1) for k in kids)
    return items


def extract_attachments(path: Path, out_dir: Path) -> list[tuple[Path, str]]:
    """Write every embedded file (EmbeddedFiles tree and file attachment annotations).

    Returns ``(path, sha256)`` pairs. Files are written with a sanitised name and
    are never opened or executed.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[tuple[Path, str]] = []
    with open_pike(path) as pdf:
        specs: list[tuple[str, Any]] = []
        names = get(get(pdf.Root, "/Names"), "/EmbeddedFiles")
        specs += name_tree_items(names) if names is not None else []
        for number, page in enumerate(pdf.pages, start=1):
            for annot in get(page.obj, "/Annots") or []:
                if name(get(annot, "/Subtype")) == "FileAttachment" and get(annot, "/FS") is not None:
                    specs.append((f"page{number}-annotation", get(annot, "/FS")))
        for index, (label, spec) in enumerate(specs, start=1):
            stream = get(get(spec, "/EF"), "/F") or get(get(spec, "/EF"), "/UF")
            if stream is None:
                continue
            data = stream.read_bytes()
            original = text(get(spec, "/UF")) or text(get(spec, "/F")) or label or "attachment"
            safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in Path(original).name)[:120]
            target = out_dir / f"{index:03d}_{safe or 'attachment'}"
            target.write_bytes(data)
            written.append((target, sha256(data)))
    return written
