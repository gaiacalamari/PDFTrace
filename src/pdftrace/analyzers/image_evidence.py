"""Metadata hidden inside embedded images (pikepdf + Pillow).

JPEG streams (DCTDecode) are stored in the PDF as complete JPEG files and
often keep EXIF (camera, software, dates, GPS), XMP, IPTC, ICC profiles and
quantization tables. Images are decoded in memory only.
"""

from __future__ import annotations

import io
import re
from collections import defaultdict
from typing import Any

from pdftrace.analyzers.metadata import parse_xmp
from pdftrace.core.analyzer import AnalysisContext, AnalysisResult, Analyzer
from pdftrace.core.models import ImageEvidence
from pdftrace.integrations import pikepdf_adapter as pk
from pdftrace.integrations.pdfplumber_adapter import PDFOpenError

MAX_IMAGES = 2000
MAX_RAW_FOR_PIL = 80_000_000
_XMP_RE = re.compile(rb"<x:xmpmeta.*?</x:xmpmeta>", re.S)
EXIF_DATE_TAGS = ("DateTime", "DateTimeOriginal", "DateTimeDigitized")
#: IJG standard luminance quantization table (ITU-T T.81 Annex K), zig-zag order irrelevant for the mean.
_STD_LUMA = [
    16,
    11,
    10,
    16,
    24,
    40,
    51,
    61,
    12,
    12,
    14,
    19,
    26,
    58,
    60,
    55,
    14,
    13,
    16,
    24,
    40,
    57,
    69,
    56,
    14,
    17,
    22,
    29,
    51,
    87,
    80,
    62,
    18,
    22,
    37,
    56,
    68,
    109,
    103,
    77,
    24,
    35,
    55,
    64,
    81,
    104,
    113,
    92,
    49,
    64,
    78,
    87,
    103,
    121,
    120,
    101,
    72,
    92,
    95,
    98,
    112,
    100,
    103,
    99,
]


def jpeg_quality(quantization: dict[int, Any] | None) -> int | None:
    """Rough IJG quality estimate (1-100) from the luminance table; an estimate only."""
    if not quantization or 0 not in quantization:
        return None
    table = list(quantization[0])
    if len(table) != 64:
        return None
    scale = sum(t / s for t, s in zip(table, _STD_LUMA, strict=True)) / 64 * 100
    quality = (200 - scale) / 2 if scale <= 100 else 5000 / scale
    return int(max(1, min(100, round(quality))))


def _clean(value: Any) -> Any:
    if isinstance(value, bytes):
        return value[:64].hex() if not value.isascii() else value.decode("ascii", "replace").strip("\x00 ")
    if isinstance(value, tuple):
        return [_clean(v) for v in value]
    if hasattr(value, "numerator") and hasattr(value, "denominator"):
        try:
            return round(float(value), 6)
        except ZeroDivisionError:
            return None
    return value if isinstance(value, (int, float, str, bool)) or value is None else str(value)


def _gps_decimal(gps: dict[str, Any]) -> dict[str, Any]:
    def conv(values: Any, ref: Any) -> float | None:
        try:
            d, m, s = (float(v) for v in values)
            sign = -1 if str(ref).upper() in ("S", "W") else 1
            return round(sign * (d + m / 60 + s / 3600), 7)
        except Exception:
            return None

    lat = conv(gps.get("GPSLatitude"), gps.get("GPSLatitudeRef"))
    lon = conv(gps.get("GPSLongitude"), gps.get("GPSLongitudeRef"))
    return {"latitude": lat, "longitude": lon} if lat is not None and lon is not None else {}


def inspect_image_bytes(raw: bytes, evidence: ImageEvidence) -> None:
    """Fill ``evidence`` from an encoded image (JPEG/JPX). Never raises."""
    from PIL import ExifTags, Image, ImageCms, IptcImagePlugin

    match = _XMP_RE.search(raw)
    if match:
        try:
            evidence.xmp = {v.field: v.value for v in parse_xmp(match.group(0))}
        except Exception as exc:
            evidence.xmp = {"_error": str(exc)}
    try:
        with Image.open(io.BytesIO(raw)) as img:
            evidence.format = img.format
            info = img.info
            evidence.progressive = bool(info.get("progressive") or info.get("progression"))
            evidence.jfif = _clean(info.get("jfif_version"))
            evidence.adobe = _clean(info.get("adobe"))
            if info.get("dpi"):
                evidence.dpi = [round(float(v), 2) for v in info["dpi"]]
            evidence.jpeg_quality_estimate = jpeg_quality(getattr(img, "quantization", None))
            exif = img.getexif()
            tags = {ExifTags.TAGS.get(k, str(k)): _clean(v) for k, v in exif.items()}
            for ifd_id in (ExifTags.IFD.Exif, ExifTags.IFD.Interop):
                try:
                    tags.update({ExifTags.TAGS.get(k, str(k)): _clean(v) for k, v in exif.get_ifd(ifd_id).items()})
                except Exception:  # noqa: S112 - optional IFD
                    continue
            tags.pop("MakerNote", None)
            evidence.exif = tags
            try:
                gps = {
                    ExifTags.GPSTAGS.get(k, str(k)): _clean(v) for k, v in exif.get_ifd(ExifTags.IFD.GPSInfo).items()
                }
            except Exception:
                gps = {}
            if gps:
                evidence.gps = {**gps, **_gps_decimal(gps)}
            make, model = tags.get("Make"), tags.get("Model")
            evidence.camera = " ".join(str(x) for x in (make, model) if x) or None
            evidence.software = tags.get("Software") or evidence.xmp.get("xmp:CreatorTool")
            for tag in EXIF_DATE_TAGS:
                if tags.get(tag):
                    evidence.dates[f"exif:{tag}"] = str(tags[tag])
            for key, value in evidence.xmp.items():
                if key.endswith(("CreateDate", "ModifyDate", "MetadataDate", "DateCreated")):
                    evidence.dates[key] = str(value)
            try:
                iptc = IptcImagePlugin.getiptcinfo(img) or {}
                evidence.iptc = {f"{k[0]}:{k[1]}": _clean(v) for k, v in iptc.items()}
            except Exception:
                evidence.iptc = {}
            icc = info.get("icc_profile")
            if icc:
                try:
                    profile = ImageCms.ImageCmsProfile(io.BytesIO(icc))
                    evidence.icc_description = ImageCms.getProfileDescription(profile).strip()
                except Exception:
                    evidence.icc_description = f"ICC profile ({len(icc)} bytes, unreadable)"
    except Exception as exc:
        evidence.error = f"{type(exc).__name__}: {exc}"[:300]


class ImageEvidenceAnalyzer(Analyzer):
    name = "image_evidence"
    label = "Image metadata (EXIF/XMP/ICC)"

    def analyze(self, ctx: AnalysisContext) -> AnalysisResult:
        try:
            pdf = ctx.pike()
        except PDFOpenError as exc:
            return AnalysisResult(None, skipped=True, message=f"pikepdf: {exc}")
        pages_of: dict[tuple[int, int], set[int]] = defaultdict(set)
        objects: dict[tuple[int, int], Any] = {}
        for number, page in enumerate(pdf.pages, start=1):
            ctx.check_cancelled()
            for xobj in self._image_xobjects(page.obj):
                key = pk.objgen(xobj)
                pages_of[key].add(number)
                objects.setdefault(key, xobj)
        evidence: list[ImageEvidence] = []
        for key, xobj in list(objects.items())[:MAX_IMAGES]:
            ctx.check_cancelled()
            evidence.append(self._inspect(key, xobj, sorted(pages_of[key])))
        return AnalysisResult("image_evidence", evidence)

    @staticmethod
    def _image_xobjects(page_obj: Any, depth: int = 0) -> list[Any]:
        """Image XObjects of a page, including those nested in form XObjects."""
        found: list[Any] = []
        xobjects = pk.get(pk.get(page_obj, "/Resources"), "/XObject")
        if xobjects is None or depth > 8:
            return found
        for key in xobjects.keys():
            xobj = xobjects.get(key)
            subtype = pk.name(pk.get(xobj, "/Subtype"))
            if subtype == "Image":
                found.append(xobj)
            elif subtype == "Form":
                found.extend(ImageEvidenceAnalyzer._image_xobjects(xobj, depth + 1))
        return found

    @staticmethod
    def _inspect(key: tuple[int, int], xobj: Any, pages: list[int]) -> ImageEvidence:
        raw = bytes(xobj.read_raw_bytes())
        filters = pk.filters(xobj)
        cs = pk.get(xobj, "/ColorSpace")
        evidence = ImageEvidence(
            object_id=key[0],
            pages=pages,
            filters=filters,
            width=int(pk.get(xobj, "/Width") or 0) or None,
            height=int(pk.get(xobj, "/Height") or 0) or None,
            colorspace=(pk.text(cs) or "")[:80] if cs is not None else None,
            bpc=int(pk.get(xobj, "/BitsPerComponent")) if pk.get(xobj, "/BitsPerComponent") is not None else None,
            raw_length=len(raw),
            raw_sha256=pk.sha256(raw),
        )
        last = filters[-1] if filters else None
        if last in ("DCTDecode", "JPXDecode") and len(raw) <= MAX_RAW_FOR_PIL:
            payload = raw if len(filters) == 1 else None
            if payload is None:
                try:
                    payload = pk.read_generalized(xobj)
                except Exception as exc:
                    evidence.error = f"{type(exc).__name__}: {exc}"
            if payload:
                inspect_image_bytes(payload, evidence)
        else:
            evidence.format = {
                "FlateDecode": "raw (Flate)",
                "JBIG2Decode": "JBIG2",
                "CCITTFaxDecode": "CCITT",
                None: "raw",
            }.get(last, last)
            is_icc = isinstance(cs, pk.Array) and len(cs) > 1 and pk.name(cs[0]) == "ICCBased"
            icc = cs[1] if is_icc else None
            if icc is not None:
                try:
                    from PIL import ImageCms

                    profile = ImageCms.ImageCmsProfile(io.BytesIO(bytes(icc.read_bytes())))
                    evidence.icc_description = ImageCms.getProfileDescription(profile).strip()
                except Exception:
                    evidence.icc_description = None
        return evidence
