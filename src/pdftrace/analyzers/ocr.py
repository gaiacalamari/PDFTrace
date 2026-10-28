"""OCR of the rendered pages (Tesseract) and comparison with the PDF text layer.

Each page is rendered with PDFium (pypdfium2, no forms or JavaScript) and read
by Tesseract. The words recognised in the *image* are then matched by position
with the words of the *text layer* extracted by pdfplumber:

* text-layer words with no recognised text at their position are text present
  in the file but not visible in the rendering (white, tiny, covered, outside
  the page, behind images...);
* recognised words with no text-layer word at their position are visible text
  that is not in the text layer (scans, text drawn as images or vectors).

Matching is spatial, so OCR misreadings do not matter; short isolated words are
ignored to limit false positives. Results are indicators to verify visually.
"""

from __future__ import annotations

import re
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path

from pdftrace.config import Settings
from pdftrace.core.analyzer import AnalysisContext, AnalysisResult, Analyzer
from pdftrace.core.models import Box, OcrPage, OcrResult, OcrRun, OcrWord, PageInfo, PDFAnalysis
from pdftrace.integrations.process import ToolFailed, ToolNotFound
from pdftrace.integrations.tesseract import Tesseract

MARGIN_PT = 1.5
MIN_RUN_CHARS = 6
MIN_CONF_VISIBLE = 60.0
MAX_IMAGE_SIDE = 12_000
_ALNUM = re.compile(r"[\W_]+", re.UNICODE)


def _norm_len(text: str) -> int:
    return len(_ALNUM.sub("", text))


def _intersects(a: list[float], b: list[float], margin: float = MARGIN_PT) -> bool:
    return not (a[2] + margin < b[0] or b[2] + margin < a[0] or a[3] + margin < b[1] or b[3] + margin < a[1])


def _union(boxes: list[list[float]]) -> list[float]:
    return [
        round(min(b[0] for b in boxes), 2),
        round(min(b[1] for b in boxes), 2),
        round(max(b[2] for b in boxes), 2),
        round(max(b[3] for b in boxes), 2),
    ]


def _same_line(a: list[float], b: list[float]) -> bool:
    """True when two boxes belong to the same text line and are close horizontally."""
    height = max(a[3] - a[1], b[3] - b[1], 0.1)
    same_row = abs(a[1] - b[1]) <= 0.6 * height
    return same_row and (b[0] - a[2]) <= 3 * height + 2


def _runs(items: list[tuple[str, list[float], bool]], page: int, source: str, min_words: int) -> list[OcrRun]:
    """Group consecutive flagged items into runs long enough to be meaningful."""
    runs: list[OcrRun] = []
    current: list[tuple[str, list[float]]] = []

    def flush() -> None:
        if current:
            text = " ".join(t for t, _ in current)
            if len(current) >= min_words or _norm_len(text) >= MIN_RUN_CHARS:
                runs.append(OcrRun(page, text[:500], _union([b for _, b in current]), len(current), source))
        current.clear()

    for text, bbox, flagged in items:
        if flagged and current and not _same_line(current[-1][1], bbox):
            flush()
        if flagged:
            current.append((text, bbox))
        else:
            flush()
    flush()
    return runs


def compare_page(layer: list[Box], ocr: list[OcrWord], page: int) -> tuple[int, list[OcrRun], list[OcrRun]]:
    """Return (layer words seen, unseen layer runs, visible-but-not-in-layer runs). Coordinates in points."""
    layer_items = []
    seen = 0
    for word in layer:
        bbox = [word.x0, word.top, word.x1, word.bottom]
        visible = any(_intersects(bbox, w.bbox) for w in ocr)
        seen += visible
        layer_items.append((word.label or "", bbox, not visible))
    ocr_items = []
    for w in ocr:
        missing = (
            w.conf >= MIN_CONF_VISIBLE
            and _norm_len(w.text) >= 2
            and not any(_intersects(w.bbox, [b.x0, b.top, b.x1, b.bottom]) for b in layer)
        )
        ocr_items.append((w.text, w.bbox, missing))
    return (
        seen,
        _runs(layer_items, page, "text_layer_not_rendered", 3),
        _runs(ocr_items, page, "rendered_not_in_text_layer", 2),
    )


def _to_points(words: list[OcrWord], dpi: float, info: PageInfo) -> list[OcrWord]:
    """Pixel coordinates of the rendered CropBox -> pdfplumber coordinates (points, MediaBox top-left)."""
    scale = 72.0 / dpi
    media, crop = info.mediabox, info.cropbox
    dx = (crop[0] - media[0]) if len(crop) == 4 and len(media) == 4 else 0.0
    dy = (media[3] - crop[3]) if len(crop) == 4 and len(media) == 4 else 0.0
    return [
        OcrWord(
            w.text,
            w.conf,
            [
                round(w.bbox[0] * scale + dx, 2),
                round(w.bbox[1] * scale + dy, 2),
                round(w.bbox[2] * scale + dx, 2),
                round(w.bbox[3] * scale + dy, 2),
            ],
        )
        for w in words
    ]


def run_ocr(
    analysis: PDFAnalysis,
    settings: Settings,
    cancelled: Callable[[], bool] = lambda: False,
    progress: Callable[[int, int], None] | None = None,
) -> OcrResult:
    """OCR every page (up to ``settings.ocr_max_pages``) and compare it with the text layer."""
    import pypdfium2 as pdfium

    tess = Tesseract(settings)
    result = OcrResult(executable=tess.executable(), dpi=settings.ocr_dpi)
    if not result.executable:
        result.error = (
            "Tesseract not found. Install it (Windows: Toolbox > Install optional tools, or "
            "scoop install tesseract) or set PDFTRACE_TESSERACT."
        )
        return result
    result.available = True
    result.version = tess.version()
    result.tessdata_dir = tess.tessdata_dir()
    result.languages = tess.resolve_languages(settings.ocr_languages)
    pages_info = {p.number: p for p in analysis.pages}
    try:
        doc = pdfium.PdfDocument(analysis.file.path)
    except Exception as exc:
        result.error = f"Rendering failed: {type(exc).__name__}: {exc}"
        return result
    try:
        total = min(len(doc), settings.ocr_max_pages)
        result.pages_truncated = len(doc) > total
        with tempfile.TemporaryDirectory(prefix="pdftrace-ocr-") as tmp:
            for index in range(total):
                if cancelled():
                    break
                number = index + 1
                page_result = OcrPage(page=number)
                try:
                    page = doc[index]
                    width, height = page.get_size()
                    dpi = min(float(settings.ocr_dpi), MAX_IMAGE_SIDE * 72.0 / max(width, height, 1.0))
                    image_path = Path(tmp) / f"page-{number:04d}.png"
                    # grayscale: Tesseract misses dark text on coloured highlights in RGB renderings
                    page.render(scale=dpi / 72.0).to_pil().convert("L").save(image_path)
                    page.close()
                    words_px = tess.ocr_image(image_path, result.languages, int(dpi))
                    image_path.unlink(missing_ok=True)
                    info = pages_info.get(number)
                    words = _to_points(words_px, dpi, info) if info else []
                    page_result.words = len(words_px)
                    confs = [w.conf for w in words_px if w.conf >= 0]
                    page_result.mean_confidence = round(sum(confs) / len(confs), 1) if confs else None
                    page_result.text = " ".join(w.text for w in words_px)
                    if info and info.rotation % 360 == 0:
                        layer = [b for b in info.boxes if b.kind == "word"]
                        page_result.layer_words = len(layer)
                        (
                            page_result.layer_words_seen,
                            page_result.unseen_layer_text,
                            page_result.visible_not_in_layer,
                        ) = compare_page(layer, words, number)
                    elif info:
                        page_result.error = "Rotated page: OCR text kept, positional comparison skipped"
                except (ToolFailed, ToolNotFound) as exc:
                    page_result.error = str(exc)
                except Exception as exc:  # rendering problems on damaged pages
                    page_result.error = f"{type(exc).__name__}: {exc}"
                result.pages.append(page_result)
                if progress:
                    progress(number, total)
    finally:
        doc.close()
    return result


class OcrAnalyzer(Analyzer):
    name = "ocr"
    label = "OCR (Tesseract)"

    def analyze(self, ctx: AnalysisContext) -> AnalysisResult:
        if not ctx.settings.ocr:
            return AnalysisResult(None, skipped=True, message="OCR not requested")
        cancel: threading.Event = ctx.cancel_event
        result = run_ocr(ctx.analysis, ctx.settings, cancel.is_set)
        ctx.check_cancelled()
        message = result.error or f"{len(result.pages)} page(s), languages {result.languages}"
        return AnalysisResult("ocr", result, message=message)
