"""Chronology of every timestamp found in the file, with its meaning."""

from __future__ import annotations

from pdftrace.core.models import PDFAnalysis, TimelineEvent
from pdftrace.utils.pdfdates import as_aware, parse_any_date, to_iso

_INFO_MEANING = {
    "CreationDate": ("pdf_creation", "Declared creation of the PDF (often the export time)"),
    "ModDate": ("pdf_modification", "Declared last modification of the PDF"),
}
_XMP_MEANING = {
    "xmp:CreateDate": ("pdf_creation", "XMP creation date"),
    "xmp:ModifyDate": ("pdf_modification", "XMP modification date"),
    "xmp:MetadataDate": ("metadata_modification", "XMP metadata last changed"),
}
META_CAVEAT = "Metadata value: can be set or rewritten by software."


def build_timeline(analysis: PDFAnalysis) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    meta = analysis.metadata
    for revision in meta.info_revisions:
        for key, (kind, text) in _INFO_MEANING.items():
            value = revision.values.get(key)
            parsed = parse_any_date(value)
            if parsed:
                label = text if revision.index == 0 else f"{text} (older revision #{revision.index})"
                events.append(
                    TimelineEvent(to_iso(parsed) or "", kind, label, "pdf_info_dictionary", "direct", META_CAVEAT)
                )
    for item in meta.xmp:
        if item.field in _XMP_MEANING or item.field.endswith("stEvt:when"):
            kind, text = _XMP_MEANING.get(item.field, ("xmp_history", f"XMP history event ({item.field})"))
            parsed = parse_any_date(str(item.value))
            if parsed:
                events.append(TimelineEvent(to_iso(parsed) or "", kind, text, "xmp_packet", "direct", META_CAVEAT))
    for font in analysis.fonts:
        info = font.embedded_info
        if not info or not info.head:
            continue
        if info.head.get("modified"):
            events.append(
                TimelineEvent(
                    info.head["modified"],
                    "font_build",
                    f"Build date of embedded font {font.name} (version {info.version or '?'})",
                    "fonttools_head_table",
                    "direct",
                    "Set by the font vendor: the PDF cannot have been generated with this font "
                    "program before this date, unless the font file itself was altered.",
                )
            )
        if info.head.get("created"):
            events.append(
                TimelineEvent(
                    info.head["created"],
                    "font_design",
                    f"Original creation of font design {font.base_name}",
                    "fonttools_head_table",
                    "direct",
                    "Refers to the font project, not to the PDF.",
                )
            )
    _interactive_events(analysis, events)
    _image_events(analysis, events)
    seen: set[str] = set()
    for mention in analysis.text.date_mentions:
        key = f"{mention.normalized}|{mention.text}"
        if not mention.normalized or key in seen:
            continue
        seen.add(key)
        events.append(
            TimelineEvent(
                mention.normalized,
                "content_date",
                f'Date written in the content: "{mention.text}" (page {mention.page})',
                "pdfplumber_text",
                "direct",
                "Date of an event described by the document, not of the file.",
            )
        )
    return sorted(events, key=_sort_key)


def _sort_key(event: TimelineEvent) -> str:
    parsed = parse_any_date(event.timestamp)
    return (to_iso(as_aware(parsed)) if parsed else None) or event.timestamp


def _add(events: list[TimelineEvent], value: str | None, kind: str, description: str, source: str, caveat: str) -> None:
    parsed = parse_any_date(value) if value else None
    if parsed:
        events.append(TimelineEvent(to_iso(parsed) or "", kind, description, source, "direct", caveat))


def _exif_date(value: str) -> str | None:
    """EXIF dates use ``YYYY:MM:DD HH:MM:SS``."""
    if len(value) >= 19 and value[4] == ":" and value[7] == ":":
        return value[:10].replace(":", "-") + "T" + value[11:19]
    return value


def _interactive_events(analysis: PDFAnalysis, events: list[TimelineEvent]) -> None:
    inter = analysis.interactive
    for a in inter.annotations:
        who = f" by {a.author}" if a.author else ""
        _add(
            events,
            a.created,
            "annotation_created",
            f"{a.subtype} annotation created{who} (page {a.page})",
            "pikepdf_annotation",
            META_CAVEAT,
        )
        _add(
            events,
            a.modified,
            "annotation_modified",
            f"{a.subtype} annotation modified{who} (page {a.page})",
            "pikepdf_annotation",
            META_CAVEAT,
        )
    for f in inter.embedded_files:
        _add(
            events,
            f.created,
            "attachment_created",
            f"Embedded file {f.filename or f.name}: creation date",
            "pikepdf_embedded_file",
            "Declared by the software that attached the file.",
        )
        _add(
            events,
            f.modified,
            "attachment_modified",
            f"Embedded file {f.filename or f.name}: modification date",
            "pikepdf_embedded_file",
            "Declared by the software that attached the file.",
        )
    for s in inter.signatures:
        _add(
            events,
            s.signing_time,
            "signature",
            f"Signing time declared in {s.field_name} ({s.name or 'unknown signer'})",
            "pikepdf_signature",
            "Declared by the signer's software; not a trusted timestamp.",
        )


def _image_events(analysis: PDFAnalysis, events: list[TimelineEvent]) -> None:
    for image in analysis.image_evidence:
        for key, value in image.dates.items():
            date = _exif_date(value) if key.startswith("exif:") else value
            _add(
                events,
                date,
                "image_metadata",
                f"Image object {image.object_id}: {key}",
                "pillow_image_metadata",
                "Written by the camera or editing software of the image; EXIF dates usually have no time zone.",
            )
