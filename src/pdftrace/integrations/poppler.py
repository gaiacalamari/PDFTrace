"""Poppler command line tools: ``pdfinfo``, ``pdffonts`` and ``pdfimages``.

Poppler is GPL software and is only *executed* as a separate process; it is
never linked into this package. Output formats parsed here were verified
against poppler-utils 24.02 (see docs/DEPENDENCIES.md):

* ``pdffonts``: ``name type encoding emb sub uni object ID``;
* ``pdfimages -list``: ``page num type width height color comp bpc enc interp
  object ID x-ppi y-ppi size ratio``;
* ``pdfimages -p``: output files named ``<root>-<page:03>-<num:03>.<ext>``; with
  ``-f/-l`` the number restarts at 0 for the selected range.
"""

from __future__ import annotations

import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

from pdftrace.config import Settings
from pdftrace.core.models import ImageInfo, ToolStatus
from pdftrace.integrations.process import (
    ToolFailed,
    ToolNotFound,
    ToolResult,
    find_executable,
    run_tool,
)

POPPLER_TOOLS = ("pdfinfo", "pdffonts", "pdfimages")

#: Font types printed by pdffonts (FontInfo.cc), longest first for suffix matching.
PDFFONTS_TYPES = sorted(
    [
        "Type 1",
        "Type 1C",
        "Type 1C (OT)",
        "Type 3",
        "TrueType",
        "TrueType (OT)",
        "CID Type 0",
        "CID Type 0C",
        "CID Type 0C (OT)",
        "CID TrueType",
        "CID TrueType (OT)",
        "unknown",
    ],
    key=len,
    reverse=True,
)


@dataclass
class PdffontsRow:
    name: str
    font_type: str
    encoding: str
    embedded: bool
    subset: bool
    unicode: bool
    object_id: int | None
    generation: int | None


class Poppler:
    """Discovery and invocation of the Poppler utilities."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._paths: dict[str, str | None] = {}

    def path(self, tool: str) -> str | None:
        if tool not in self._paths:
            self._paths[tool] = find_executable(tool, self.settings.poppler_path)
        return self._paths[tool]

    def available(self, tool: str) -> bool:
        return self.path(tool) is not None

    def status(self) -> list[ToolStatus]:
        """Availability and version of each tool, for the Diagnostics view."""
        statuses: list[ToolStatus] = []
        for tool in POPPLER_TOOLS:
            exe = self.path(tool)
            if not exe:
                where = self.settings.poppler_path or "PATH"
                statuses.append(ToolStatus(tool, False, None, None, f"{tool} not found in {where}", "poppler"))
                continue
            try:
                res = run_tool(exe, ["-v"], timeout_s=15)
                text = (res.stderr or res.stdout).strip().splitlines()
                version = text[0] if text else None
                statuses.append(ToolStatus(tool, True, exe, version, None, "poppler"))
            except (ToolFailed, ToolNotFound) as exc:
                statuses.append(ToolStatus(tool, False, exe, None, str(exc), "poppler"))
        return statuses

    def _run(self, tool: str, args: list[str], cwd: str | None = None) -> ToolResult:
        exe = self.path(tool)
        if not exe:
            raise ToolNotFound(f"{tool} not found (install Poppler or set PDFTRACE_POPPLER_PATH)")
        result = run_tool(exe, args, self.settings.tool_timeout_s, self.settings.max_tool_output, cwd=cwd)
        if not result.ok:
            detail = (result.stderr or result.stdout).strip()[:500]
            raise ToolFailed(f"{tool} exited with code {result.returncode}: {detail}", result)
        return result

    # -- pdfinfo ---------------------------------------------------------------
    def pdfinfo(self, pdf: Path) -> tuple[dict[str, str], ToolResult]:
        result = self._run("pdfinfo", ["-isodates", str(pdf)])
        return parse_key_value(result.stdout), result

    def pdfinfo_meta(self, pdf: Path) -> tuple[str, ToolResult]:
        result = self._run("pdfinfo", ["-meta", str(pdf)])
        return result.stdout, result

    # -- pdffonts --------------------------------------------------------------
    def pdffonts(self, pdf: Path) -> tuple[list[PdffontsRow], ToolResult]:
        result = self._run("pdffonts", [str(pdf)])
        return parse_pdffonts(result.stdout), result

    # -- pdfimages -------------------------------------------------------------
    def pdfimages_list(self, pdf: Path) -> tuple[list[ImageInfo], ToolResult]:
        result = self._run("pdfimages", ["-list", str(pdf)])
        return parse_pdfimages_list(result.stdout), result

    def extract_images(
        self,
        pdf: Path,
        out_dir: Path,
        page: int | None = None,
        fmt: str = "all",
        root: str = "img",
    ) -> list[Path]:
        """Extract images into ``out_dir``.

        ``fmt`` is ``all`` (native formats where possible) or ``png``.
        """
        if fmt not in {"all", "png"}:
            raise ValueError("fmt must be 'all' or 'png'")
        out_dir.mkdir(parents=True, exist_ok=True)
        args = [f"-{fmt}", "-p"]
        if page is not None:
            args += ["-f", str(int(page)), "-l", str(int(page))]
        args += [str(pdf), str(out_dir / root)]
        self._run("pdfimages", args)
        return sorted(p for p in out_dir.glob(f"{root}-*") if p.is_file())

    def extract_single_image(self, pdf: Path, page: int, index: int, out_dir: Path, fmt: str = "all") -> Path | None:
        """Extract the image with document-wide list number ``index`` (``pdfimages -list``).

        With ``-f/-l`` pdfimages restarts numbering at 0, so the document-wide
        number is converted to its position among the images of ``page``.
        """
        images, _ = self.pdfimages_list(pdf)
        numbers = sorted(i.index for i in images if i.page == page and i.index is not None)
        if index not in numbers:
            return None
        position = numbers.index(index)
        with tempfile.TemporaryDirectory(prefix="pdftrace-img-") as tmp:
            files = self.extract_images(pdf, Path(tmp), page=page, fmt=fmt)
            wanted = f"img-{int(page):03d}-{position:03d}."
            for file in files:
                if file.name.startswith(wanted):
                    out_dir.mkdir(parents=True, exist_ok=True)
                    suffix = file.name.split(".", 1)[1]
                    target = out_dir / f"img-p{int(page):03d}-n{int(index):03d}.{suffix}"
                    target.write_bytes(file.read_bytes())
                    return target
        return None


def parse_key_value(text: str) -> dict[str, str]:
    """Parse ``Key:   value`` lines as printed by pdfinfo."""
    data: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        if key and key not in data:
            data[key] = value.strip()
    return data


def _yes(value: str) -> bool:
    return value.strip().lower() == "yes"


def parse_pdffonts(text: str) -> list[PdffontsRow]:
    """Parse pdffonts output.

    Columns are parsed from the right (object ID, uni, sub, emb) because long
    font names overflow the fixed-width name column.
    """
    rows: list[PdffontsRow] = []
    lines = text.splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line.startswith("----")) + 1
    except StopIteration:
        return rows
    for line in lines[start:]:
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) < 7:
            continue
        gen, objnum, uni, sub, emb = parts[-1], parts[-2], parts[-3], parts[-4], parts[-5]
        prefix = line[: _rfind_token(line, emb, len(parts) - 5)].rstrip()
        prefix_body, _, encoding = prefix.rpartition(" ")
        prefix_body = prefix_body.rstrip()
        font_type = "unknown"
        name = prefix_body
        for candidate in PDFFONTS_TYPES:
            if prefix_body.endswith(" " + candidate) or prefix_body == candidate:
                font_type = candidate
                name = prefix_body[: -len(candidate)].strip()
                break
        rows.append(
            PdffontsRow(
                name=name or "[none]",
                font_type=font_type,
                encoding=encoding,
                embedded=_yes(emb),
                subset=_yes(sub),
                unicode=_yes(uni),
                object_id=int(objnum) if objnum.isdigit() else None,
                generation=int(gen) if gen.isdigit() else None,
            )
        )
    return rows


def _rfind_token(line: str, token: str, token_index: int) -> int:
    """Return the character offset of the ``token_index``-th whitespace token."""
    offsets = [m.start() for m in re.finditer(r"\S+", line)]
    return offsets[token_index] if token_index < len(offsets) else len(line)


def _int(value: str) -> int | None:
    return int(value) if value.lstrip("-").isdigit() else None


def _float(value: str) -> float | None:
    try:
        return float(value)
    except ValueError:
        return None


def parse_pdfimages_list(text: str) -> list[ImageInfo]:
    """Parse ``pdfimages -list`` output (16 whitespace separated columns)."""
    images: list[ImageInfo] = []
    lines = text.splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line.startswith("----")) + 1
    except StopIteration:
        return images
    for line in lines[start:]:
        parts = line.split()
        if len(parts) < 16:
            continue
        images.append(
            ImageInfo(
                page=_int(parts[0]) or 0,
                index=_int(parts[1]),
                image_type=parts[2],
                width=_int(parts[3]),
                height=_int(parts[4]),
                color=parts[5],
                components=_int(parts[6]),
                bpc=_int(parts[7]),
                encoding=parts[8],
                interpolate=_yes(parts[9]),
                object_id=_int(parts[10]),
                generation=_int(parts[11]),
                x_ppi=_float(parts[12]),
                y_ppi=_float(parts[13]),
                size=parts[14],
                ratio=parts[15],
                source="pdfimages",
            )
        )
    return images
