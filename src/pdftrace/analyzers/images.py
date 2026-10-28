"""Embedded raster images: pdfimages inventory (pdfplumber fallback)."""

from __future__ import annotations

from typing import Any

from pdftrace.core.analyzer import AnalysisContext, AnalysisResult, Analyzer
from pdftrace.core.models import ImageInfo
from pdftrace.integrations import pdfplumber_adapter as pa
from pdftrace.integrations.process import ToolFailed, ToolNotFound

_FILTER_LABEL = {
    "DCTDecode": "jpeg",
    "JPXDecode": "jpx",
    "JBIG2Decode": "jbig2",
    "CCITTFaxDecode": "ccitt",
    "FlateDecode": "image",
    "RunLengthDecode": "image",
    "LZWDecode": "image",
}


class ImagesAnalyzer(Analyzer):
    name = "images"
    label = "Images"

    def analyze(self, ctx: AnalysisContext) -> AnalysisResult:
        diagnostics: list[str] = []
        if ctx.poppler.available("pdfimages"):
            try:
                images, result = ctx.poppler.pdfimages_list(ctx.path)
                if result.stderr.strip():
                    diagnostics.append(f"pdfimages stderr: {result.stderr.strip()[:2000]}")
                return AnalysisResult("images", images, diagnostics)
            except (ToolFailed, ToolNotFound) as exc:
                diagnostics.append(f"pdfimages failed: {exc}; using pdfplumber fallback")
        else:
            diagnostics.append("pdfimages not available: using pdfplumber fallback (no ppi/size data)")
        return AnalysisResult("images", self._fallback(ctx, diagnostics), diagnostics, message="pdfplumber fallback")

    @staticmethod
    def _fallback(ctx: AnalysisContext, diagnostics: list[str]) -> list[ImageInfo]:
        try:
            pdf = ctx.pdf()
        except pa.PDFOpenError as exc:
            diagnostics.append(f"Image enumeration failed: {exc}")
            return []
        images: list[ImageInfo] = []
        for page in pdf.pages[: ctx.settings.max_pages_text]:
            ctx.check_cancelled()
            for number, image in enumerate(page.images):
                images.append(_from_plumber(page.page_number, number, image))
        return images


def _from_plumber(page_number: int, index: int, image: dict[str, Any]) -> ImageInfo:
    stream = image.get("stream")
    attrs = getattr(stream, "attrs", {}) or {}
    filters = pa.to_text(attrs.get("Filter")) or ""
    first_filter = filters.strip("[]").split(",")[0].strip() if filters else ""
    width, height = (image.get("srcsize") or (None, None))[:2]
    colorspace = image.get("colorspace")
    color = pa.to_text(colorspace[0]) if isinstance(colorspace, list) and colorspace else None
    return ImageInfo(
        page=page_number,
        index=index,
        object_id=getattr(stream, "objid", None),
        generation=0 if getattr(stream, "objid", None) is not None else None,
        image_type="smask" if image.get("imagemask") else "image",
        width=int(width) if width else None,
        height=int(height) if height else None,
        color=color,
        components=None,
        bpc=image.get("bits"),
        encoding=_FILTER_LABEL.get(first_filter, first_filter or None),
        interpolate=None,
        x_ppi=None,
        y_ppi=None,
        size=None,
        ratio=None,
        source="pdfplumber",
        bbox=[round(float(image.get(k, 0)), 2) for k in ("x0", "top", "x1", "bottom")],
    )
