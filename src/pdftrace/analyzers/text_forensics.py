"""Heuristic checks on the text layer of a page (pdfplumber character data).

Detected patterns (all heuristic, to be verified visually):

* ``invisible_text``: text drawn in white or with render mode not visible;
* ``outside_page``: characters outside the visible page area (CropBox);
* ``tiny_text``: characters smaller than 1 pt;
* ``overlapping_text``: the same character drawn twice at the same place
  (typical of text placed over earlier text);
* ``covered_text``: text under a filled dark rectangle (ineffective redaction);
* ``font_change_in_line``: a short run with a different font family or size
  inside an otherwise uniform text line (a common trace of local edits).
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any

from pdftrace.core.models import TextAnomaly

MAX_PER_KIND_PER_PAGE = 50
_STYLE = re.compile(r"[-,](bold|italic|oblique|regular|semibold|light|medium|black|bolditalic|boldoblique)\b.*$", re.I)


def family(fontname: str) -> str:
    """Font family without subset tag and style suffix."""
    base = fontname.split("+", 1)[-1]
    return _STYLE.sub("", base).replace("MT", "").strip().lower()


def _is_white(color: Any) -> bool:
    if color is None:
        return False
    values = color if isinstance(color, (list, tuple)) else (color,)
    try:
        floats = [float(v) for v in values]
    except (TypeError, ValueError):
        return False
    if len(floats) == 1:
        return floats[0] >= 0.98
    if len(floats) == 3:
        return all(v >= 0.98 for v in floats)
    if len(floats) == 4:  # CMYK
        return all(v <= 0.02 for v in floats)
    return False


def _is_dark(color: Any) -> bool:
    values = color if isinstance(color, (list, tuple)) else (color,)
    try:
        floats = [float(v) for v in values]
    except (TypeError, ValueError):
        return False
    if len(floats) == 1:
        return floats[0] <= 0.15
    if len(floats) == 3:
        return all(v <= 0.15 for v in floats)
    if len(floats) == 4:
        return floats[3] >= 0.85
    return False


def _union(chars: list[dict[str, Any]]) -> list[float]:
    """Box enclosing all the given characters."""
    return [
        round(min(float(c["x0"]) for c in chars), 2),
        round(min(float(c["top"]) for c in chars), 2),
        round(max(float(c["x1"]) for c in chars), 2),
        round(max(float(c["bottom"]) for c in chars), 2),
    ]


def _bbox(c: dict[str, Any]) -> list[float]:
    return [round(float(c["x0"]), 2), round(float(c["top"]), 2), round(float(c["x1"]), 2), round(float(c["bottom"]), 2)]


def inspect_page(page: Any, chars: list[dict[str, Any]], number: int) -> list[TextAnomaly]:
    found: list[TextAnomaly] = []
    counts: Counter[str] = Counter()

    def add(kind: str, description: str, text: str, bbox: list[float] | None, **details: Any) -> None:
        if counts[kind] < MAX_PER_KIND_PER_PAGE:
            found.append(TextAnomaly(number, kind, description, text[:200], bbox, details))
        counts[kind] += 1

    visible = [c for c in chars if str(c.get("text", "")).strip()]
    if not visible:
        return found
    x0, top, x1, bottom = (float(v) for v in page.bbox)

    white = [c for c in visible if _is_white(c.get("non_stroking_color"))]
    if white:
        add(
            "invisible_text",
            f"{len(white)} character(s) drawn in white",
            "".join(c["text"] for c in white),
            _union(white),
            chars=len(white),
        )
    outside = [c for c in visible if c["x1"] < x0 or c["x0"] > x1 or c["bottom"] < top or c["top"] > bottom]
    if outside:
        add(
            "outside_page",
            f"{len(outside)} character(s) outside the visible page area",
            "".join(c["text"] for c in outside),
            _union(outside),
            chars=len(outside),
        )
    tiny = [c for c in visible if float(c.get("size", 0)) < 1.0]
    if tiny:
        add(
            "tiny_text",
            f"{len(tiny)} character(s) smaller than 1 pt",
            "".join(c["text"] for c in tiny),
            _union(tiny),
            chars=len(tiny),
        )

    positions: dict[tuple[str, int, int], list[dict[str, Any]]] = defaultdict(list)
    for c in visible:
        if float(c.get("size", 0)) < 1.0:  # glyphs this small collide by construction (reported as tiny_text)
            continue
        positions[(c["text"], round(float(c["x0"]) * 2), round(float(c["top"]) * 2))].append(c)
    duplicates = [group for group in positions.values() if len(group) > 1]
    if duplicates:
        sample = "".join(g[0]["text"] for g in duplicates[:80])
        fonts = sorted({str(c.get("fontname")) for g in duplicates for c in g})
        add(
            "overlapping_text",
            f"{len(duplicates)} character(s) drawn twice at the same position",
            sample,
            _bbox(duplicates[0][0]),
            chars=len(duplicates),
            fonts=fonts[:10],
        )

    dark_rects = [
        r
        for r in page.rects
        if r.get("fill") and _is_dark(r.get("non_stroking_color")) and float(r["width"]) > 2 and float(r["height"]) > 2
    ]
    for rect in dark_rects[:200]:
        covered = [
            c
            for c in visible
            if c["x0"] >= rect["x0"] - 0.5
            and c["x1"] <= rect["x1"] + 0.5
            and c["top"] >= rect["top"] - 0.5
            and c["bottom"] <= rect["bottom"] + 0.5
            and not _is_white(c.get("non_stroking_color"))
        ]
        if len(covered) >= 2:
            add(
                "covered_text",
                f"{len(covered)} character(s) under a filled dark rectangle",
                "".join(c["text"] for c in covered),
                [round(float(rect[k]), 2) for k in ("x0", "top", "x1", "bottom")],
                chars=len(covered),
            )

    lines: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for c in visible:
        matrix = c.get("matrix")
        baseline = float(matrix[5]) if matrix and len(matrix) == 6 else float(c["bottom"])
        lines[round(baseline)].append(c)
    for line_chars in lines.values():
        if len(line_chars) < 12:
            continue
        line_chars.sort(key=lambda c: float(c["x0"]))
        fam = Counter(family(str(c.get("fontname", ""))) for c in line_chars)
        size = Counter(round(float(c.get("size", 0)) * 2) / 2 for c in line_chars)
        main_family, main_count = fam.most_common(1)[0]
        main_size = size.most_common(1)[0][0]
        odd = [
            c
            for c in line_chars
            if family(str(c.get("fontname", ""))) != main_family
            or abs(round(float(c.get("size", 0)) * 2) / 2 - main_size) >= 1.0
        ]
        odd = [c for c in odd if c["text"].strip() not in {"•", "·", "-", "–", "—", "*"}]
        if 0 < len(odd) <= max(1, len(line_chars) // 4) and main_count >= len(line_chars) * 0.6:
            add(
                "font_change_in_line",
                "Short run with a different font family or size within a text line",
                "".join(c["text"] for c in line_chars),
                _bbox(odd[0]),
                odd_text="".join(c["text"] for c in odd),
                odd_fonts=sorted({str(c.get("fontname")) for c in odd}),
                odd_sizes=sorted({round(float(c.get("size", 0)), 1) for c in odd}),
                line_font=main_family,
                line_size=main_size,
            )
    return found
