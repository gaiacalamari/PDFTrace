"""Inspection of embedded font programs with fontTools (MIT).

Supported programs:

* ``FontFile2`` - TrueType, parsed with ``fontTools.ttLib.TTFont``;
* ``FontFile3`` with ``/Subtype /OpenType`` - parsed with ``TTFont``;
* ``FontFile3`` with ``/Subtype /Type1C`` or ``/CIDFontType0C`` - bare CFF,
  parsed with ``fontTools.cffLib.CFFFontSet``;
* ``FontFile`` - Type 1: fontTools has no parser for PDF-embedded Type 1
  programs, so only the clear-text header is read (FontName, version, Notice).
"""

from __future__ import annotations

import io
import re
import unicodedata
from datetime import UTC, datetime, timedelta
from typing import Any

from fontTools.cffLib import CFFFontSet
from fontTools.ttLib import TTFont

from pdftrace.core.models import EmbeddedFontInfo
from pdftrace.integrations.pdfplumber_adapter import FontProgram

_EPOCH_1904 = datetime(1904, 1, 1, tzinfo=UTC)

NAME_IDS = {
    0: "copyright",
    1: "family",
    2: "subfamily",
    3: "unique_id",
    4: "full_name",
    5: "version",
    6: "postscript_name",
    7: "trademark",
    8: "manufacturer",
    13: "license",
    14: "license_url",
}


def font_timestamp(seconds: int) -> str | None:
    """Convert a ``head`` timestamp (seconds since 1904-01-01 UTC) to ISO 8601."""
    try:
        return (_EPOCH_1904 + timedelta(seconds=int(seconds))).isoformat()
    except (OverflowError, ValueError):
        return None


def inspect_program(program: FontProgram, subset: bool | None = None) -> EmbeddedFontInfo:
    """Read everything useful from an embedded font program. Never raises."""
    info = EmbeddedFontInfo(font_file_key=program.key, size_bytes=len(program.data))
    try:
        if program.key == "FontFile2" or (program.key == "FontFile3" and program.subtype == "OpenType"):
            info.program_format = "TrueType" if program.key == "FontFile2" else "OpenType"
            _from_sfnt(program.data, info, subset)
        elif program.key == "FontFile3":
            info.program_format = f"CFF ({program.subtype or 'unknown subtype'})"
            _from_cff(program.data, info)
        else:
            info.program_format = "Type 1"
            _from_type1(program.data, info)
    except Exception as exc:  # fontTools raises assorted exceptions on bad data
        info.error = f"{type(exc).__name__}: {exc}"
    return info


def _clean(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.decode("latin-1", errors="replace")
    if isinstance(value, float):
        return round(value, 4)
    return value


def _from_sfnt(data: bytes, info: EmbeddedFontInfo, subset: bool | None) -> None:
    font = TTFont(io.BytesIO(data), lazy=True, recalcTimestamp=False, recalcBBoxes=False)
    info.tables = sorted(str(tag) for tag in font.keys() if tag != "GlyphOrder")
    if "name" in font:
        for record in font["name"].names:
            try:
                text = record.toUnicode()
            except Exception:
                text = record.string.decode("latin-1", errors="replace")
            info.name_records.append(
                {
                    "name_id": record.nameID,
                    "platform_id": record.platformID,
                    "encoding_id": record.platEncID,
                    "language_id": record.langID,
                    "value": text,
                }
            )
            attr = NAME_IDS.get(record.nameID)
            if attr and getattr(info, attr) is None:
                setattr(info, attr, text)
    if "head" in font:
        head = font["head"]
        info.head = {
            "font_revision": round(float(head.fontRevision), 4),
            "units_per_em": head.unitsPerEm,
            "created": font_timestamp(head.created),
            "modified": font_timestamp(head.modified),
            "created_raw": head.created,
            "modified_raw": head.modified,
            "flags": head.flags,
            "mac_style": head.macStyle,
            "checksum_adjustment": head.checkSumAdjustment,
            "bbox": [head.xMin, head.yMin, head.xMax, head.yMax],
        }
    if "OS/2" in font:
        os2 = font["OS/2"]
        info.vendor = _clean(getattr(os2, "achVendID", None))
        info.os2 = {
            "version": os2.version,
            "vendor_id": info.vendor,
            "weight_class": os2.usWeightClass,
            "width_class": os2.usWidthClass,
            "fs_type": os2.fsType,
            "fs_selection": os2.fsSelection,
            "typo_ascender": getattr(os2, "sTypoAscender", None),
            "typo_descender": getattr(os2, "sTypoDescender", None),
            "win_ascent": getattr(os2, "usWinAscent", None),
            "win_descent": getattr(os2, "usWinDescent", None),
            "x_height": getattr(os2, "sxHeight", None),
            "cap_height": getattr(os2, "sCapHeight", None),
        }
    if "hhea" in font:
        hhea = font["hhea"]
        info.hhea = {
            "ascent": hhea.ascent,
            "descent": hhea.descent,
            "line_gap": hhea.lineGap,
            "advance_width_max": hhea.advanceWidthMax,
        }
    if "post" in font:
        post = font["post"]
        info.post = {
            "format": _clean(post.formatType),
            "italic_angle": _clean(post.italicAngle),
            "is_fixed_pitch": post.isFixedPitch,
        }
    if "meta" in font:
        info.meta = {str(k): _clean(v) for k, v in font["meta"].data.items()}
    if "maxp" in font:
        info.glyph_count = font["maxp"].numGlyphs
    codepoints = _cmap_codepoints(font)
    info.unicode_codepoints = len(codepoints) if codepoints is not None else None
    info.unicode_ranges = _blocks(codepoints or set())
    info.unicode_coverage = _coverage_label(codepoints, subset)


def _cmap_codepoints(font: TTFont) -> set[int] | None:
    if "cmap" not in font:
        return None
    best = font["cmap"].getBestCmap()
    if best is None:
        return set()
    return {cp for cp in best if cp > 0}


def _blocks(codepoints: set[int]) -> list[str]:
    """Rough script summary based on Unicode character names."""
    scripts: dict[str, int] = {}
    for cp in codepoints:
        try:
            name = unicodedata.name(chr(cp))
        except ValueError:
            continue
        script = name.split(" ")[0]
        scripts[script] = scripts.get(script, 0) + 1
    return [f"{k} ({v})" for k, v in sorted(scripts.items(), key=lambda kv: -kv[1])[:12]]


def _coverage_label(codepoints: set[int] | None, subset: bool | None) -> str:
    if codepoints is None:
        return "no cmap"
    if not codepoints:
        return "none (no Unicode cmap)"
    if subset:
        return "partial (subset)"
    return "complete for mapped glyphs" if len(codepoints) > 200 else "partial"


def _from_cff(data: bytes, info: EmbeddedFontInfo) -> None:
    cff = CFFFontSet()
    cff.decompile(io.BytesIO(data), None)
    info.tables = ["CFF"]
    if not cff.fontNames:
        return
    name = cff.fontNames[0]
    top = cff[name]
    info.postscript_name = name
    info.full_name = _clean(getattr(top, "FullName", None))
    info.family = _clean(getattr(top, "FamilyName", None))
    info.subfamily = _clean(getattr(top, "Weight", None))
    info.version = _clean(getattr(top, "version", None))
    notice = _clean(getattr(top, "Notice", None))
    info.copyright = _clean(getattr(top, "Copyright", None)) or notice
    info.trademark = notice if info.copyright != notice else None
    charstrings = getattr(top, "CharStrings", None)
    info.glyph_count = len(charstrings) if charstrings is not None else None
    info.unicode_coverage = "not available (CFF has no cmap)"


_T1_FIELDS = {
    "postscript_name": re.compile(rb"/FontName\s*/(\S+)"),
    "version": re.compile(rb"/version\s*\((.*?)\)\s*readonly", re.S),
    "copyright": re.compile(rb"/Notice\s*\((.*?)\)\s*readonly", re.S),
    "full_name": re.compile(rb"/FullName\s*\((.*?)\)\s*readonly", re.S),
    "family": re.compile(rb"/FamilyName\s*\((.*?)\)\s*readonly", re.S),
}


def _from_type1(data: bytes, info: EmbeddedFontInfo) -> None:
    header = data[:65536]
    for attr, pattern in _T1_FIELDS.items():
        match = pattern.search(header)
        if match:
            setattr(info, attr, match.group(1).decode("latin-1", errors="replace"))
    info.tables = ["Type1 clear-text header"]
    info.unicode_coverage = "not available (Type 1)"
