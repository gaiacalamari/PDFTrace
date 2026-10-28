"""Fonts: pdffonts inventory, enriched with fontTools data for embedded programs."""

from __future__ import annotations

import re

from pdftrace.core.analyzer import AnalysisContext, AnalysisResult, Analyzer
from pdftrace.core.models import FontInfo
from pdftrace.integrations import pdfplumber_adapter as pa
from pdftrace.integrations.fonttools_adapter import inspect_program
from pdftrace.integrations.process import ToolFailed, ToolNotFound

SUBSET_TAG = re.compile(r"^([A-Z]{6})\+(.+)$")

#: pdfminer /Subtype -> pdffonts-like type label (fallback mode only).
_SUBTYPE_LABEL = {
    "Type1": "Type 1",
    "MMType1": "Type 1",
    "TrueType": "TrueType",
    "Type3": "Type 3",
    "Type0": "Type 0 (composite)",
}


def split_subset(name: str) -> tuple[str | None, str]:
    match = SUBSET_TAG.match(name)
    return (match.group(1), match.group(2)) if match else (None, name)


class FontsAnalyzer(Analyzer):
    name = "fonts"
    label = "Fonts"

    def analyze(self, ctx: AnalysisContext) -> AnalysisResult:
        fonts: list[FontInfo] = []
        diagnostics: list[str] = []
        message = None
        if ctx.poppler.available("pdffonts"):
            try:
                rows, result = ctx.poppler.pdffonts(ctx.path)
                if result.stderr.strip():
                    diagnostics.append(f"pdffonts stderr: {result.stderr.strip()[:2000]}")
                for row in rows:
                    tag, base = split_subset(row.name)
                    fonts.append(
                        FontInfo(
                            name=row.name,
                            base_name=base,
                            subset_tag=tag,
                            font_type=row.font_type,
                            encoding=row.encoding,
                            embedded=row.embedded,
                            subset=row.subset,
                            unicode=row.unicode,
                            object_id=row.object_id,
                            generation=row.generation,
                            source="pdffonts",
                        )
                    )
            except (ToolFailed, ToolNotFound) as exc:
                diagnostics.append(f"pdffonts failed: {exc}")
        if not fonts and not ctx.poppler.available("pdffonts"):
            message = "pdffonts not available: using pdfminer page-resource fallback"
            diagnostics.append(message)
            fonts = self._fallback(ctx, diagnostics)

        try:
            pdf = ctx.pdf()
        except pa.PDFOpenError as exc:
            diagnostics.append(f"Embedded font programs not read: {exc}")
            return AnalysisResult("fonts", fonts, diagnostics, message=message)
        for font in fonts:
            ctx.check_cancelled()
            if not font.embedded or font.object_id is None:
                continue
            try:
                program = pa.font_program(pdf, font.object_id, ctx.settings.max_font_bytes)
            except Exception as exc:
                diagnostics.append(f"{font.name}: font program not read ({exc})")
                continue
            if program is None:
                diagnostics.append(f"{font.name}: no FontFile stream found in descriptor")
                continue
            font.embedded_info = inspect_program(program, font.subset)
        return AnalysisResult("fonts", fonts, diagnostics, message=message)

    @staticmethod
    def _fallback(ctx: AnalysisContext, diagnostics: list[str]) -> list[FontInfo]:
        try:
            pdf = ctx.pdf()
        except pa.PDFOpenError as exc:
            diagnostics.append(f"Fallback font enumeration failed: {exc}")
            return []
        fonts: list[FontInfo] = []
        for item in pa.enumerate_fonts(pdf):
            tag, base = split_subset(item.base_font)
            fonts.append(
                FontInfo(
                    name=item.base_font,
                    base_name=base,
                    subset_tag=tag,
                    font_type=_SUBTYPE_LABEL.get(item.subtype, item.subtype),
                    encoding=item.encoding,
                    embedded=item.embedded,
                    subset=tag is not None,
                    unicode=item.has_to_unicode,
                    object_id=item.object_id,
                    generation=0 if item.object_id is not None else None,
                    source="pdfminer_page_resources",
                    pages_used=sorted(item.pages),
                )
            )
        return fonts
