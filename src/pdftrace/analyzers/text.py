"""Text and layout per page (pdfplumber), plus date mentions in the content."""

from __future__ import annotations

import re
import statistics
from collections import Counter
from typing import Any

from pdftrace.analyzers.text_forensics import inspect_page
from pdftrace.core.analyzer import AnalysisContext, AnalysisResult, Analyzer
from pdftrace.core.models import Box, DateMention, PageInfo, TextForensics, TextSummary
from pdftrace.integrations import pdfplumber_adapter as pa

MONTHS = {
    **dict.fromkeys(["gennaio", "january", "jan"], 1),
    **dict.fromkeys(["febbraio", "february", "feb"], 2),
    **dict.fromkeys(["marzo", "march", "mar"], 3),
    **dict.fromkeys(["aprile", "april", "apr"], 4),
    **dict.fromkeys(["maggio", "may"], 5),
    **dict.fromkeys(["giugno", "june", "jun"], 6),
    **dict.fromkeys(["luglio", "july", "jul"], 7),
    **dict.fromkeys(["agosto", "august", "aug"], 8),
    **dict.fromkeys(["settembre", "september", "sep", "sept"], 9),
    **dict.fromkeys(["ottobre", "october", "oct"], 10),
    **dict.fromkeys(["novembre", "november", "nov"], 11),
    **dict.fromkeys(["dicembre", "december", "dec"], 12),
}
_MONTH_ALT = "|".join(sorted(MONTHS, key=len, reverse=True))
DATE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b((?:19|20)\d{2})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])\b"), "ymd"),
    (re.compile(r"\b(0?[1-9]|[12]\d|3[01])[/.\-](0?[1-9]|1[0-2])[/.\-]((?:19|20)\d{2})\b"), "dmy"),
    (re.compile(rf"\b(0?[1-9]|[12]\d|3[01])\s+({_MONTH_ALT})\.?\s+((?:19|20)\d{{2}})\b", re.I), "d_month_y"),
    (re.compile(rf"\b({_MONTH_ALT})\.?\s+((?:19|20)\d{{2}})\b", re.I), "month_y"),
]
MAX_DATE_MENTIONS = 1000


def find_dates(text: str, page: int) -> list[DateMention]:
    """Dates written in the text. Numeric d/m/y values are read day-first."""
    mentions: list[DateMention] = []
    covered: list[tuple[int, int]] = []
    for pattern, kind in DATE_PATTERNS:
        for match in pattern.finditer(text):
            if any(s <= match.start() < e for s, e in covered):
                continue
            covered.append((match.start(), match.end()))
            groups = match.groups()
            if kind == "ymd":
                norm = f"{groups[0]}-{groups[1]}-{groups[2]}"
            elif kind == "dmy":
                norm = f"{groups[2]}-{int(groups[1]):02d}-{int(groups[0]):02d}"
            elif kind == "d_month_y":
                norm = f"{groups[2]}-{MONTHS[groups[1].lower()]:02d}-{int(groups[0]):02d}"
            else:
                norm = f"{groups[1]}-{MONTHS[groups[0].lower()]:02d}"
            mentions.append(DateMention(" ".join(match.group(0).split()), page, norm))
    return mentions


def _bbox(obj: dict[str, Any]) -> tuple[float, float, float, float]:
    return (
        round(float(obj.get("x0", 0)), 2),
        round(float(obj.get("top", 0)), 2),
        round(float(obj.get("x1", 0)), 2),
        round(float(obj.get("bottom", 0)), 2),
    )


class TextAnalyzer(Analyzer):
    name = "text"
    label = "Text & layout"

    def analyze(self, ctx: AnalysisContext) -> AnalysisResult:
        try:
            pdf = ctx.pdf()
        except pa.PDFOpenError as exc:
            return AnalysisResult(None, skipped=True, message=f"PDF parser error: {exc}")
        settings = ctx.settings
        summary = TextSummary()
        pages: list[PageInfo] = []
        all_pages = pdf.pages
        limit = settings.max_pages_text
        summary.pages_truncated = len(all_pages) > limit
        image_boxes: dict[tuple[int, int | None], list[list[float]]] = {}
        diagnostics: list[str] = []

        forensics = TextForensics()
        for page in all_pages[:limit]:
            ctx.check_cancelled()
            info = self._analyze_page(page, settings.max_words_per_page, settings.max_shapes_per_page)
            if not info.error:
                try:
                    forensics.anomalies.extend(inspect_page(page, page.chars, info.number))
                except Exception as exc:
                    diagnostics.append(f"page {info.number}: text checks failed ({exc})")
            for box in info.boxes:
                if box.kind == "image":
                    key = (info.number, int(box.label) if box.label and box.label.isdigit() else None)
                    image_boxes.setdefault(key, []).append([box.x0, box.top, box.x1, box.bottom])
            if info.error:
                diagnostics.append(f"page {info.number}: {info.error}")
            pages.append(info)
            summary.total_chars += info.chars
            summary.total_words += info.words
            summary.total_text_lines += info.text_lines
            for name, count in info.fonts.items():
                summary.fonts_used[name] = summary.fonts_used.get(name, 0) + count
            for size, count in info.font_sizes.items():
                summary.font_sizes[size] = summary.font_sizes.get(size, 0) + count
            if len(summary.date_mentions) < MAX_DATE_MENTIONS:
                summary.date_mentions.extend(find_dates(info.text, info.number))
            with_close = getattr(page, "close", None)
            if callable(with_close):
                with_close()

        summary.pages_analyzed = len(pages)
        summary.date_mentions = summary.date_mentions[:MAX_DATE_MENTIONS]
        summary.empty_pages = [p.number for p in pages if p.chars == 0]
        summary.low_text_pages = [p.number for p in pages if 0 < p.chars < settings.low_text_chars]
        densities = [p.density for p in pages if p.chars > 0]
        if len(densities) >= 3:
            median = statistics.median(densities)
            factor = settings.density_factor
            summary.density_outliers = [
                p.number
                for p in pages
                if p.chars > 0 and median > 0 and (p.density > median * factor or p.density < median / factor)
            ]
        ctx.analysis.pages = pages
        ctx.analysis.text = summary
        for anomaly in forensics.anomalies:
            forensics.counts[anomaly.kind] = forensics.counts.get(anomaly.kind, 0) + 1
        ctx.analysis.text_forensics = forensics
        self._link_fonts(ctx, pages)
        self._link_images(ctx, image_boxes)
        return AnalysisResult(None, diagnostics=diagnostics)

    @staticmethod
    def _analyze_page(page: Any, max_words: int, max_shapes: int) -> PageInfo:
        info = PageInfo(
            number=page.page_number,
            width=round(float(page.width), 2),
            height=round(float(page.height), 2),
            rotation=int(getattr(page, "rotation", 0) or 0),
            mediabox=[round(float(v), 2) for v in page.mediabox],
            cropbox=[round(float(v), 2) for v in page.cropbox],
        )
        try:
            chars = page.chars
            info.chars = len(chars)
            info.visible_chars = sum(1 for c in chars if str(c.get("text", "")).strip())
            info.fonts = dict(Counter(str(c.get("fontname")) for c in chars))
            info.font_sizes = dict(Counter(f"{float(c.get('size', 0)):.1f}" for c in chars))
            words = page.extract_words(extra_attrs=["fontname", "size"])
            info.words = len(words)
            info.text = page.extract_text() or ""
            info.text_lines = sum(1 for line in info.text.splitlines() if line.strip())
            info.lines, info.rects, info.curves = len(page.lines), len(page.rects), len(page.curves)
            info.images = len(page.images)
            info.annotations = len(page.annots)
            info.hyperlinks = len(page.hyperlinks)
            area = info.width * info.height
            info.density = round(info.chars / (area / 10_000), 3) if area else 0.0
            boxes: list[Box] = []
            for word in words[:max_words]:
                boxes.append(Box(*_bbox(word), kind="word", label=str(word.get("text", ""))[:80]))
            shapes = [("rect", page.rects), ("line", page.lines), ("curve", page.curves)]
            for kind, objects in shapes:
                for obj in objects[:max_shapes]:
                    boxes.append(Box(*_bbox(obj), kind=kind))
            for image in page.images:
                objid = getattr(image.get("stream"), "objid", None)
                boxes.append(Box(*_bbox(image), kind="image", label=str(objid) if objid else None))
            info.boxes = boxes
            info.boxes_truncated = len(words) > max_words or any(len(o) > max_shapes for _, o in shapes)
        except Exception as exc:  # malformed content streams
            info.error = f"{type(exc).__name__}: {exc}"
        return info

    @staticmethod
    def _link_fonts(ctx: AnalysisContext, pages: list[PageInfo]) -> None:
        by_name = {f.name: f for f in ctx.analysis.fonts}
        for page in pages:
            for name, count in page.fonts.items():
                font = by_name.get(name)
                if font is None:
                    continue
                font.chars_rendered += count
                if page.number not in font.pages_used:
                    font.pages_used.append(page.number)

    @staticmethod
    def _link_images(ctx: AnalysisContext, boxes: dict[tuple[int, int | None], list[list[float]]]) -> None:
        for image in ctx.analysis.images:
            if image.bbox is not None:
                continue
            candidates = boxes.get((image.page, image.object_id))
            if candidates:
                image.bbox = candidates.pop(0)
