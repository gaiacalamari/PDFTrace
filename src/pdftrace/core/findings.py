"""Findings engine: rule based technical indicators for the analyst.

Rules never label a document as forged or malicious. Wording is neutral
("difference", "requires review") and every finding carries its evidence.
New rules are plain functions registered with :func:`rule`.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from typing import Any

from pdftrace.config import Settings, default_settings
from pdftrace.core.models import Finding, FontInfo, PDFAnalysis, Severity
from pdftrace.utils.pdfdates import as_aware, parse_any_date

Draft = tuple[str, Severity, str, str, dict[str, Any], int | None]
Rule = Callable[[PDFAnalysis, Settings], Iterator[Draft]]
_RULES: list[Rule] = []

KNOWN_PROCESSORS = {
    "iText": r"\bitext",
    "Apache PDFBox": r"pdfbox",
    "pdftk": r"pdftk",
    "qpdf": r"\bqpdf\b",
    "Ghostscript": r"ghostscript|gpl ghostscript",
    "PyPDF": r"pypdf",
    "pikepdf": r"pikepdf",
    "PDFsharp": r"pdfsharp",
    "Aspose": r"aspose",
    "iLovePDF": r"ilovepdf",
    "Smallpdf": r"smallpdf",
    "Nitro": r"nitro",
    "PDF-XChange": r"pdf-xchange",
    "Foxit": r"foxit",
    "Adobe Acrobat": r"acrobat",
}
UNCOMMON_ENCODINGS = {"jbig2", "ccitt", "jpx"}
STANDARD_ENCODINGS = {"WinAnsi", "MacRoman", "Standard", "WinAnsiEncoding", "MacRomanEncoding", "StandardEncoding"}
STANDARD_VERSIONS = {"1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7", "2.0"}


def rule(func: Rule) -> Rule:
    """Register a findings rule."""
    _RULES.append(func)
    return func


def registered_rules() -> list[Rule]:
    return list(_RULES)


class FindingsEngine:
    """Evaluate all registered rules and number the resulting findings."""

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules = rules if rules is not None else registered_rules()

    def evaluate(self, analysis: PDFAnalysis, settings: Settings | None = None) -> list[Finding]:
        settings = settings or default_settings()
        findings: list[Finding] = []
        for check in self.rules:
            try:
                drafts = list(check(analysis, settings))
            except Exception as exc:  # a broken rule must not hide the others
                drafts = [
                    ("engine", Severity.INFO, f"Rule {check.__name__} failed", f"{type(exc).__name__}: {exc}", {}, None)
                ]
            for category, severity, title, description, evidence, page in drafts:
                findings.append(
                    Finding("", category, severity, title, description, page, evidence, f"rule:{check.__name__}")
                )
        findings.sort(key=lambda f: (-f.severity.rank, f.category, f.page or 0))
        for number, finding in enumerate(findings, start=1):
            finding.id = f"F-{number:03d}"
        return findings


def _date(value: str | None) -> datetime | None:
    parsed = parse_any_date(value)
    return as_aware(parsed) if parsed else None


# --------------------------------------------------------------------- metadata
@rule
def metadata_presence(a: PDFAnalysis, s: Settings) -> Iterator[Draft]:
    m = a.metadata
    if not m.info and not m.xmp_present:
        yield (
            "metadata",
            Severity.NOTICE,
            "No document metadata",
            "Neither an Info dictionary nor an XMP packet was found. Some producers omit them; "
            "metadata may also have been removed. Requires review.",
            {},
            None,
        )
    elif m.info and not m.xmp_present:
        yield (
            "metadata",
            Severity.INFO,
            "No XMP packet",
            "Only the Info dictionary is present; there is no XMP counterpart to compare.",
            {},
            None,
        )
    elif m.xmp_present and not m.info:
        yield (
            "metadata",
            Severity.INFO,
            "No Info dictionary",
            "Only XMP metadata is present (normal for PDF 2.0, where Info is deprecated).",
            {},
            None,
        )
    if m.info and not m.info_value("CreationDate"):
        yield (
            "metadata",
            Severity.NOTICE,
            "Missing creation date",
            "The Info dictionary has no CreationDate entry.",
            {},
            None,
        )
    if m.xmp_error:
        yield ("metadata", Severity.NOTICE, "XMP could not be parsed", m.xmp_error, {}, None)
    for error in m.errors:
        yield ("metadata", Severity.NOTICE, "Metadata extraction problem", error, {}, None)


@rule
def metadata_dates(a: PDFAnalysis, s: Settings) -> Iterator[Draft]:
    m = a.metadata
    now = datetime.now(UTC)
    pairs = [
        ("Info", m.info_value("CreationDate"), m.info_value("ModDate")),
        ("XMP", m.xmp_value("xmp:CreateDate"), m.xmp_value("xmp:ModifyDate")),
    ]
    for label, created_raw, modified_raw in pairs:
        created, modified = _date(created_raw), _date(modified_raw)
        if created and modified and modified < created:
            yield (
                "metadata",
                Severity.WARNING,
                f"{label}: modification date earlier than creation date",
                "The declared modification precedes the declared creation. Requires review.",
                {"creation": created_raw, "modification": modified_raw},
                None,
            )
        for name, raw, value in (("creation", created_raw, created), ("modification", modified_raw, modified)):
            if value and value > now:
                yield (
                    "metadata",
                    Severity.WARNING,
                    f"{label}: {name} date in the future",
                    "The date is later than the time of analysis.",
                    {"value": raw},
                    None,
                )
            if raw and value is None:
                yield (
                    "metadata",
                    Severity.NOTICE,
                    f"{label}: unparseable {name} date",
                    "The date string does not follow the expected format.",
                    {"value": raw},
                    None,
                )
    raw_created = m.info_value("CreationDate")
    parsed = parse_any_date(raw_created)
    if parsed and parsed.tzinfo is None:
        yield (
            "metadata",
            Severity.INFO,
            "Creation date without time zone",
            "The Info CreationDate has no UTC offset; its absolute instant is ambiguous.",
            {"value": raw_created},
            None,
        )


@rule
def metadata_consistency(a: PDFAnalysis, s: Settings) -> Iterator[Draft]:
    for comp in a.metadata.comparisons:
        if comp.status == "difference":
            yield (
                "metadata",
                Severity.NOTICE,
                f"Metadata difference: {comp.field}",
                f"PDF Info and XMP contain different values for {comp.field}. Requires review; "
                "some software updates only one of the two blocks.",
                {"info": comp.info_value, "xmp": comp.xmp_value, "xmp_key": comp.xmp_key},
                None,
            )
        elif comp.status == "only_info" and comp.field in {"CreationDate", "ModDate", "Producer"}:
            yield (
                "metadata",
                Severity.INFO,
                f"{comp.field} only in Info dictionary",
                f"The XMP packet has no {comp.xmp_key}.",
                {"info": comp.info_value},
                None,
            )
    revisions = a.metadata.info_revisions
    if len(revisions) > 1:
        changed = sorted(
            {k for r in revisions[1:] for k, v in r.values.items() if revisions[0].values.get(k) != v}
            | {k for k in revisions[0].values if any(k not in r.values for r in revisions[1:])}
        )
        yield (
            "metadata",
            Severity.NOTICE,
            "Several Info dictionaries across revisions",
            f"{len(revisions)} trailers reference an Info dictionary; fields that differ between "
            "revisions are listed as evidence (earlier values are recoverable).",
            {"revisions": len(revisions), "changed_fields": changed},
            None,
        )
    doc_id, inst_id = a.metadata.xmp_value("xmpMM:DocumentID"), a.metadata.xmp_value("xmpMM:InstanceID")
    created, modified = a.metadata.xmp_value("xmp:CreateDate"), a.metadata.xmp_value("xmp:ModifyDate")
    if doc_id and inst_id and doc_id == inst_id and created and modified and created != modified:
        yield (
            "metadata",
            Severity.INFO,
            "XMP InstanceID equals DocumentID after modification",
            "The file was modified after creation but the XMP InstanceID was not renewed. Some "
            "libraries do not update it; this is a hint about the processing software.",
            {"document_id": doc_id, "create": created, "modify": modified},
            None,
        )


@rule
def metadata_producer(a: PDFAnalysis, s: Settings) -> Iterator[Draft]:
    producer = a.metadata.info_value("Producer") or a.metadata.xmp_value("pdf:Producer") or ""
    creator = a.metadata.info_value("Creator") or a.metadata.xmp_value("xmp:CreatorTool") or ""
    if not producer and a.metadata.info:
        yield ("metadata", Severity.INFO, "No Producer", "The generating software is not declared.", {}, None)
    detected = [
        name
        for name, pattern in KNOWN_PROCESSORS.items()
        if re.search(pattern, producer, re.I) and not re.search(pattern, creator, re.I)
    ]
    if "modified using" in producer.lower() or (detected and creator):
        yield (
            "metadata",
            Severity.NOTICE,
            "Post-processing by another PDF software",
            "The Producer names software different from the creating application. The file was "
            "likely rewritten after its generation; earlier metadata may have been replaced.",
            {"creator": creator, "producer": producer, "detected": detected},
            None,
        )


# ------------------------------------------------------------------------ fonts
@rule
def font_embedding(a: PDFAnalysis, s: Settings) -> Iterator[Draft]:
    not_embedded = [f.name for f in a.fonts if f.embedded is False]
    if not_embedded:
        yield (
            "fonts",
            Severity.NOTICE,
            f"{len(not_embedded)} font(s) not embedded",
            "Rendering depends on fonts installed on the viewing system.",
            {"fonts": not_embedded},
            None,
        )
    subsets = [f.name for f in a.fonts if f.subset]
    if subsets:
        yield (
            "fonts",
            Severity.INFO,
            f"{len(subsets)} subset font(s)",
            "Only the glyphs used were embedded (normal for most producers).",
            {"fonts": subsets, "tags": [f.subset_tag for f in a.fonts if f.subset_tag]},
            None,
        )
    for font in a.fonts:
        if font.font_type == "Type 3":
            yield (
                "fonts",
                Severity.NOTICE,
                f"Type 3 font: {font.name}",
                "Type 3 glyphs are PDF drawing procedures; common in TeX/scanner output, unusual in office documents.",
                {"object_id": font.object_id},
                None,
            )
        if font.unicode is False and font.chars_rendered and font.encoding not in STANDARD_ENCODINGS:
            yield (
                "fonts",
                Severity.INFO,
                f"No Unicode mapping: {font.name}",
                "Text drawn with this font may not be extractable or searchable.",
                {"object_id": font.object_id, "chars": font.chars_rendered},
                None,
            )
        info = font.embedded_info
        if info and info.error:
            yield (
                "fonts",
                Severity.NOTICE,
                f"Embedded font program not parseable: {font.name}",
                info.error,
                {"object_id": font.object_id, "format": info.program_format},
                None,
            )


@rule
def font_dates(a: PDFAnalysis, s: Settings) -> Iterator[Draft]:
    dated: list[tuple[FontInfo, datetime]] = []
    for font in a.fonts:
        built = _date(font.embedded_info.head.get("modified")) if font.embedded_info else None
        if built is not None:
            dated.append((font, built))
    if not dated:
        return
    latest_font, latest = max(dated, key=lambda item: item[1])
    yield (
        "fonts",
        Severity.NOTICE,
        "Earliest possible generation date from embedded fonts",
        f"The most recent embedded font program ({latest_font.name}, version "
        f"{latest_font.embedded_info.version if latest_font.embedded_info else '?'}) was built on "
        f"{latest.isoformat()}. The PDF cannot have been generated with it before that date, "
        "unless the font program itself was altered.",
        {
            "font": latest_font.name,
            "head_modified": latest.isoformat(),
            "copyright": latest_font.embedded_info.copyright if latest_font.embedded_info else None,
        },
        None,
    )
    declared = {
        "Info CreationDate": _date(a.metadata.info_value("CreationDate")),
        "XMP CreateDate": _date(a.metadata.xmp_value("xmp:CreateDate")),
    }
    for label, created in declared.items():
        if created and latest > created:
            yield (
                "fonts",
                Severity.WARNING,
                f"Embedded font built after the declared {label}",
                f"{latest_font.name} was built on {latest.isoformat()}, after the declared "
                f"{label} ({created.isoformat()}). The declared date is not compatible with the "
                "font program found in the file. Requires review.",
                {"font": latest_font.name, "font_built": latest.isoformat(), "declared": created.isoformat()},
                None,
            )


# ----------------------------------------------------------------------- images
@rule
def image_properties(a: PDFAnalysis, s: Settings) -> Iterator[Draft]:
    uses: dict[int, set[int]] = defaultdict(set)
    for img in a.images:
        if img.object_id is not None:
            uses[img.object_id].add(img.page)
        if img.width and img.height:
            pixels = img.width * img.height
            if pixels >= s.high_res_pixels:
                yield (
                    "images",
                    Severity.INFO,
                    "Very high resolution image",
                    f"{img.width}x{img.height} px ({pixels / 1e6:.1f} MP).",
                    {"object_id": img.object_id},
                    img.page,
                )
            ratio = max(img.width, img.height) / max(1, min(img.width, img.height))
            if min(img.width, img.height) <= 1 or ratio >= 50:
                yield (
                    "images",
                    Severity.INFO,
                    "Unusual image dimensions",
                    f"{img.width}x{img.height} px (strips or 1-pixel images are often used as "
                    "masks, lines or tracking elements).",
                    {"object_id": img.object_id},
                    img.page,
                )
        if img.encoding and img.encoding.lower() in UNCOMMON_ENCODINGS:
            yield (
                "images",
                Severity.INFO,
                f"Uncommon image encoding: {img.encoding}",
                "JBIG2/CCITT are typical of scanners and fax; JPX of some professional workflows.",
                {"object_id": img.object_id},
                img.page,
            )
    for objid, pages in uses.items():
        if len(pages) > 1:
            yield (
                "images",
                Severity.INFO,
                "Image object reused across pages",
                f"Object {objid} is drawn on pages {sorted(pages)} (e.g. logos or backgrounds).",
                {"object_id": objid, "pages": sorted(pages)},
                None,
            )


@rule
def scanned_pages(a: PDFAnalysis, s: Settings) -> Iterator[Draft]:
    image_pages = {i.page for i in a.images if i.image_type != "smask"}
    candidates = [p.number for p in a.pages if p.chars == 0 and p.number in image_pages]
    if candidates:
        yield (
            "images",
            Severity.NOTICE,
            "Image-only pages",
            "Pages with images and no text layer: they may derive from a scan or a raster export.",
            {"pages": candidates},
            None,
        )


# -------------------------------------------------------------------- structure
@rule
def structure_checks(a: PDFAnalysis, s: Settings) -> Iterator[Draft]:
    st = a.structure
    if st.header_version is None:
        yield (
            "structure",
            Severity.WARNING,
            "No PDF header",
            "The %PDF- header was not found in the first 1024 bytes.",
            {},
            None,
        )
    elif st.header_version not in STANDARD_VERSIONS:
        yield ("structure", Severity.NOTICE, f"Unusual PDF version {st.header_version}", "", {}, None)
    if st.header_offset:
        yield (
            "structure",
            Severity.NOTICE,
            "Data before the PDF header",
            f"The header starts at byte {st.header_offset}.",
            {"offset": st.header_offset},
            None,
        )
    if a.metadata.catalog_version and a.metadata.catalog_version != st.header_version:
        yield (
            "structure",
            Severity.INFO,
            "Catalog /Version overrides the header",
            "The catalog declares a different version (typical of incremental updates).",
            {"header": st.header_version, "catalog": a.metadata.catalog_version},
            None,
        )
    if st.encrypted:
        yield (
            "structure",
            Severity.NOTICE,
            "Encrypted PDF",
            "Some objects may not be readable without a password.",
            {},
            None,
        )
    ch = st.xref_chain
    boundaries = [
        {"revision": r.index, "xref_offsets": r.xref_offsets, "kinds": r.kinds, "end": r.end} for r in ch.revisions
    ]
    if ch.method != "xref_chain":
        yield (
            "structure",
            Severity.NOTICE,
            "Cross-reference chain could not be followed",
            "No cross-reference section is reachable from startxref: the revision count is only "
            "estimated from %%EOF markers and may be wrong (embedded data, linearization).",
            {"anomalies": ch.anomalies[:20], "eof_offsets": st.eof_offsets},
            None,
        )
    if st.incremental_updates:
        how = (
            "Revisions reconstructed by following startxref and the /Prev chain of the "
            "cross-reference sections; each earlier revision is the file truncated at the %%EOF "
            "that closes its section."
            if ch.method == "xref_chain"
            else "Revisions estimated from %%EOF markers (heuristic)."
        )
        yield (
            "structure",
            Severity.NOTICE,
            f"{st.incremental_updates} incremental update(s)",
            how,
            {"method": ch.method, "revisions": boundaries},
            None,
        )
    elif ch.method == "xref_chain" and ch.complete and len(ch.revisions) == 1:
        yield (
            "structure",
            Severity.INFO,
            "Single revision",
            "The cross-reference chain has a single revision: if the file was edited, it was fully rewritten.",
            {"revisions": boundaries},
            None,
        )
    if ch.method == "xref_chain" and not ch.complete:
        yield (
            "structure",
            Severity.WARNING,
            "Broken cross-reference chain",
            "The /Prev chain cannot be followed to the original section: older revisions may exist "
            "but are not reachable through the trailer.",
            {"anomalies": ch.anomalies[:20]},
            None,
        )
    if ch.orphan_eof_offsets:
        yield (
            "structure",
            Severity.NOTICE,
            f"{len(ch.orphan_eof_offsets)} %%EOF marker(s) outside the cross-reference chain",
            "These markers do not close any section reachable from the trailer and are not counted "
            "as revisions. They may lie inside embedded data (attachment, nested PDF, binary "
            "stream) or belong to a section no longer referenced by the chain: review the bytes at "
            "these offsets.",
            {"offsets": ch.orphan_eof_offsets[:50], "inside_stream": ch.orphan_eof_in_stream[:50]},
            None,
        )
    if ch.unreachable_xref_offsets:
        outside = [o for o in ch.unreachable_xref_offsets if o not in ch.unreachable_xref_in_stream]
        yield (
            "structure",
            Severity.WARNING if outside else Severity.NOTICE,
            "Cross-reference sections not reachable from the trailer",
            "Well-formed xref sections exist in the file but no startxref or /Prev leads to them. "
            "They may belong to an embedded document or to a revision detached from the chain "
            "(e.g. a trailer written without /Prev)."
            + (
                f" {len(ch.detached_revisions)} of them are complete revisions closed by their own "
                "startxref/%%EOF: the file truncated there is an earlier version that readers no "
                "longer show (see the metadata revisions labelled 'detached')."
                if ch.detached_revisions
                else ""
            ),
            {
                "offsets": ch.unreachable_xref_offsets[:50],
                "inside_stream": ch.unreachable_xref_in_stream[:50],
                "detached_revisions": [
                    {"xref_offset": r.xref_offsets[0], "end": r.end} for r in ch.detached_revisions[:50]
                ],
            },
            None,
        )
    if ch.anomalies and ch.method == "xref_chain":
        yield (
            "structure",
            Severity.NOTICE,
            "Cross-reference chain anomalies",
            "Offsets or pointers that do not match the standard layout; readers may repair or "
            "interpret them differently.",
            {"anomalies": ch.anomalies[:20]},
            None,
        )
    if st.redefined_objects:
        yield (
            "structure",
            Severity.NOTICE,
            "Object numbers defined more than once",
            "The same object number appears in several 'obj' definitions, typically because a "
            "later revision replaced it (heuristic byte scan).",
            {"objects": st.redefined_objects[:50]},
            None,
        )
    size = a.file.size
    outside = [v for v in st.startxref_values if v >= size]
    if outside:
        yield (
            "structure",
            Severity.NOTICE,
            "startxref points outside the file",
            "The cross-reference offset is beyond the end of file: the file may be truncated or "
            "reconstructed by readers.",
            {"startxref": outside, "file_size": size},
            None,
        )
    if st.trailing_bytes_after_eof:
        yield (
            "structure",
            Severity.NOTICE,
            "Data after the last %%EOF",
            f"{st.trailing_bytes_after_eof} non-whitespace bytes follow the end of file marker.",
            {},
            None,
        )
    if st.comments:
        yield (
            "structure",
            Severity.INFO,
            "Comments in the file body",
            "Producer comments can identify the software that wrote the file.",
            {"comments": st.comments[:20]},
            None,
        )
    active = {
        k: st.keyword_counts.get(k, 0)
        for k in ("JavaScript", "JS", "OpenAction", "AA", "Launch", "EmbeddedFile", "SubmitForm")
    }
    if any(active.values()):
        yield (
            "structure",
            Severity.NOTICE,
            "Active content or attachments referenced",
            "Keywords associated with scripts, automatic actions or attachments were found. "
            "They were NOT executed. Requires review.",
            {k: v for k, v in active.items() if v},
            None,
        )
    if st.keyword_counts.get("ByteRange"):
        yield (
            "structure",
            Severity.INFO,
            "Digital signature structures present",
            "Signature dictionaries (/ByteRange) exist; they are not validated by this tool.",
            {"byte_ranges": st.keyword_counts.get("ByteRange")},
            None,
        )
    ids = st.trailer_ids[0] if st.trailer_ids else []
    if not ids:
        yield ("structure", Severity.INFO, "No trailer /ID", "The document has no file identifier.", {}, None)
    elif len(ids) == 2 and ids[0] != ids[1]:
        yield (
            "structure",
            Severity.INFO,
            "Trailer /ID halves differ",
            "The second identifier changes when the file is saved again: the file was probably "
            "saved more than once or rewritten by another program.",
            {"id": ids},
            None,
        )
    for error in st.errors:
        yield ("structure", Severity.NOTICE, "Parser problem", error, {}, None)


# ------------------------------------------------------------------------- text
@rule
def text_checks(a: PDFAnalysis, s: Settings) -> Iterator[Draft]:
    t = a.text
    if a.pages and t.total_chars == 0:
        yield (
            "text",
            Severity.NOTICE,
            "No extractable text",
            "The document has no text layer (scan, rasterised export or missing Unicode mapping).",
            {},
            None,
        )
    elif t.empty_pages:
        yield ("text", Severity.INFO, "Pages without text", "", {"pages": t.empty_pages}, None)
    if t.low_text_pages:
        yield (
            "text",
            Severity.INFO,
            "Pages with very little text",
            f"Fewer than {s.low_text_chars} characters.",
            {"pages": t.low_text_pages},
            None,
        )
    if t.density_outliers:
        yield (
            "text",
            Severity.INFO,
            "Pages with unusual text density",
            "Density differs strongly from the document median.",
            {"pages": t.density_outliers},
            None,
        )
    if t.pages_truncated:
        yield (
            "text",
            Severity.NOTICE,
            "Text analysis truncated",
            f"Only the first {s.max_pages_text} pages were analysed.",
            {},
            None,
        )
    if t.date_mentions:
        yield (
            "text",
            Severity.INFO,
            f"{len(t.date_mentions)} date(s) written in the content",
            "Content dates describe events, not the creation of the file (see Timeline).",
            {"dates": sorted({d.normalized or d.text for d in t.date_mentions})[:30]},
            None,
        )


# ------------------------------------------------------------------------ tools
@rule
def tool_availability(a: PDFAnalysis, s: Settings) -> Iterator[Draft]:
    missing = [t.name for t in a.tools if t.kind == "poppler" and not t.available]
    if missing:
        yield (
            "tools",
            Severity.NOTICE,
            "Analysis limited: Poppler tools missing",
            "Fallbacks were used; image sizes/resolution and some font data may be incomplete.",
            {"missing": missing},
            None,
        )


# --------------------------------------------------------------- external tools
_ACTIVE_PDFID = ("/JS", "/JavaScript", "/AA", "/OpenAction", "/Launch", "/EmbeddedFile", "/XFA", "/RichMedia")


@rule
def external_tools(a: PDFAnalysis, s: Settings) -> Iterator[Draft]:
    """Indicators from third-party tools run through the Toolbox."""
    for run in a.external_runs:
        p = run.parsed
        ev: dict[str, Any] = {
            "tool": run.tool_id,
            "action": run.action_id,
            "version": run.version,
            "exit_code": run.returncode,
        }
        if run.status == "timeout":
            yield (
                "tools",
                Severity.NOTICE,
                f"{run.tool_name} timed out",
                "The tool did not finish within the configured timeout.",
                ev,
                None,
            )
            continue
        if run.status == "error" and not p:
            yield (
                "tools",
                Severity.INFO,
                f"{run.tool_name}: {run.action_label} returned an error",
                (run.stderr or run.stdout or run.error or "").strip()[:400],
                ev,
                None,
            )
        if run.tool_id == "qpdf" and run.action_id == "check" and p and not p.get("clean"):
            yield (
                "structure",
                Severity.NOTICE,
                "qpdf reports structural problems",
                f"{p.get('warning_count', 0)} warning(s) from qpdf --check.",
                {**ev, "warnings": p.get("warnings", [])[:20], "errors": p.get("errors", [])[:20]},
                None,
            )
        if run.tool_id == "pdfcpu" and run.action_id == "validate" and p and not p.get("valid"):
            yield (
                "structure",
                Severity.NOTICE,
                "pdfcpu validation failed",
                "The file does not pass pdfcpu validation (relaxed mode).",
                {**ev, **p},
                None,
            )
        if run.tool_id == "pdfresurrect" and (p.get("versions") or 0) > 1:
            yield (
                "structure",
                Severity.NOTICE,
                f"pdfresurrect: {p['versions']} versions",
                "pdfresurrect detects several versions (incremental saves) of the document.",
                ev,
                None,
            )
        chain_revisions = len(a.structure.xref_chain.revisions)
        if run.tool_id == "pdfresurrect" and p.get("versions") and chain_revisions and p["versions"] != chain_revisions:
            yield (
                "structure",
                Severity.NOTICE,
                "Revision count differs between pdfresurrect and the xref chain",
                f"pdfresurrect reports {p['versions']} version(s), the cross-reference chain "
                f"{chain_revisions}. Compare the %%EOF offsets with the revision boundaries.",
                {**ev, "xref_chain_revisions": chain_revisions, "eof_offsets": a.structure.eof_offsets},
                None,
            )
        if run.tool_id == "pdfid":
            yield from _pdfid_findings(a, p, ev)
        if run.tool_id == "pdfsig" and p.get("signatures"):
            yield (
                "signatures",
                Severity.INFO,
                f"pdfsig: {p['signatures']} signature(s)",
                "See the pdfsig output for signer and validation details.",
                ev,
                None,
            )
        if run.tool_id == "pdfdetach" and p.get("embedded_files"):
            yield (
                "structure",
                Severity.NOTICE,
                f"{p['embedded_files']} embedded file(s)",
                "The PDF carries attachments (listed, not extracted).",
                {**ev, "names": p.get("names")},
                None,
            )
        if run.tool_id == "pdfinfo-extra" and run.action_id == "js" and p.get("has_javascript"):
            yield (
                "structure",
                Severity.NOTICE,
                "JavaScript present (pdfinfo -js)",
                "Scripts are listed by pdfinfo; they were not executed.",
                ev,
                None,
            )
        if run.tool_id == "pdfinfo-extra" and run.action_id == "url" and p.get("url_count"):
            yield (
                "structure",
                Severity.INFO,
                f"{p['url_count']} URL(s) in objects",
                "Links were listed, not opened.",
                {**ev, "urls": p.get("urls", [])[:20]},
                None,
            )
        if run.tool_id == "ghostscript" and p and not p.get("clean"):
            yield (
                "rendering",
                Severity.NOTICE,
                "Ghostscript reports interpretation problems",
                "Errors or warnings while interpreting the pages.",
                {**ev, "problems": p.get("problems")},
                None,
            )
        if run.tool_id == "pikepdf" and (p.get("problems") or p.get("opened") is False):
            yield (
                "structure",
                Severity.NOTICE,
                "pikepdf/libqpdf reports problems",
                str(p.get("error") or f"{len(p.get('problems', []))} problem(s)."),
                {**ev, "problems": p.get("problems", [])[:20]},
                None,
            )
        if run.tool_id == "pypdf" and p.get("strict_ok") is False:
            yield ("structure", Severity.INFO, "pypdf strict parsing fails", str(p.get("strict_error", "")), ev, None)


def _pdfid_findings(a: PDFAnalysis, p: dict[str, Any], ev: dict[str, Any]) -> Iterator[Draft]:
    counts: dict[str, int] = p.get("counts", {})
    active = {k: v for k, v in counts.items() if k in _ACTIVE_PDFID and v}
    if active:
        yield (
            "structure",
            Severity.NOTICE,
            "pdfid: active content keywords",
            "pdfid counts keywords associated with scripts, actions or attachments. Requires review.",
            {**ev, "counts": active},
            None,
        )
    internal = a.structure.keyword_counts
    diff = {
        k: [v, internal.get(k[1:])]
        for k, v in counts.items()
        if k.startswith("/") and k[1:] in internal and internal[k[1:]] != v
    }
    if diff:
        yield (
            "tools",
            Severity.INFO,
            "pdfid counts differ from the internal byte scan",
            "Differences usually come from obfuscated names (pdfid normalises #xx escapes) or from "
            "different matching rules.",
            {**ev, "pdfid_vs_internal": diff},
            None,
        )


# ------------------------------------------------------ deep extraction (1.0)
EDITING_SOFTWARE = re.compile(r"photoshop|gimp|lightroom|affinity|paint\.net|pixelmator|snapseed|canva|picsart", re.I)


@rule
def interactive_content(a: PDFAnalysis, s: Settings) -> Iterator[Draft]:
    inter = a.interactive
    if inter.scripts:
        yield (
            "interactive",
            Severity.NOTICE,
            f"{len(inter.scripts)} JavaScript block(s)",
            "Scripts were extracted as text and not executed. Requires review.",
            {
                "locations": [f"{x.location} {x.trigger}" for x in inter.scripts][:20],
                "sha256": [x.sha256 for x in inter.scripts][:20],
            },
            None,
        )
    risky = [x for x in inter.actions if x.action_type in ("Launch", "SubmitForm", "ImportData", "GoToR", "GoToE")]
    if risky:
        yield (
            "interactive",
            Severity.NOTICE,
            "Actions that open files or send data",
            "Launch/SubmitForm/GoToR-type actions are present (not executed).",
            {"actions": [f"{x.action_type} -> {x.target}" for x in risky][:20]},
            None,
        )
    auto = [x for x in inter.actions if x.trigger == "OpenAction" or x.trigger.startswith("AA")]
    if auto:
        yield (
            "interactive",
            Severity.INFO,
            "Automatic actions",
            "Actions triggered on opening or on page/field events.",
            {"actions": [f"{x.location} {x.trigger}: {x.action_type}" for x in auto][:20]},
            None,
        )
    if inter.embedded_files:
        yield (
            "interactive",
            Severity.NOTICE,
            f"{len(inter.embedded_files)} embedded file(s)",
            "Attachments can carry earlier versions or source documents; they can be extracted for review.",
            {
                "files": [
                    {
                        "name": f.filename or f.name,
                        "size": f.size,
                        "sha256": f.sha256,
                        "created": f.created,
                        "modified": f.modified,
                    }
                    for f in inter.embedded_files
                ][:20]
            },
            None,
        )
        for f in inter.embedded_files:
            if f.size is not None and f.declared_size is not None and f.size != f.declared_size:
                yield (
                    "interactive",
                    Severity.NOTICE,
                    f"Attachment size differs from declared size: {f.filename}",
                    "The /Params /Size value does not match the stored data.",
                    {"declared": f.declared_size, "actual": f.size},
                    None,
                )
    authors = sorted({x.author for x in inter.annotations if x.author})
    dated = [x for x in inter.annotations if x.modified or x.created]
    if authors or dated:
        yield (
            "interactive",
            Severity.INFO,
            "Annotations carry authors or dates",
            "Annotation authors and dates are independent of the document metadata (see Timeline).",
            {"authors": authors[:20], "dated_annotations": len(dated)},
            None,
        )
    hidden = [x for x in inter.annotations if x.hidden and x.subtype not in ("Popup", "Widget")]
    if hidden:
        yield (
            "interactive",
            Severity.NOTICE,
            f"{len(hidden)} hidden annotation(s)",
            "Annotations flagged Hidden/NoView are not displayed but are present in the file.",
            {"annotations": [f"page {x.page} {x.subtype}: {x.contents or ''}"[:120] for x in hidden][:20]},
            None,
        )
    filled = [f for f in inter.form_fields if f.value]
    if filled:
        yield (
            "interactive",
            Severity.INFO,
            f"{len(filled)} form field(s) with a value",
            "Field values may differ from the visible appearance.",
            {"fields": {f.name: f.value for f in filled[:30]}},
            None,
        )
    if inter.form_type == "XFA":
        yield (
            "interactive",
            Severity.NOTICE,
            "XFA form",
            "Content may be generated dynamically by the viewer.",
            {},
            None,
        )


@rule
def signatures(a: PDFAnalysis, s: Settings) -> Iterator[Draft]:
    for sig in a.interactive.signatures:
        ev = {
            "field": sig.field_name,
            "subfilter": sig.subfilter,
            "signing_time": sig.signing_time,
            "signer": [c.get("subject") for c in sig.certificates][:3],
            "byte_range": sig.byte_range,
        }
        yield (
            "signatures",
            Severity.INFO,
            f"Digital signature: {sig.field_name}",
            "Signature dictionary and certificates described; cryptographic validity is not verified.",
            ev,
            None,
        )
        if sig.covers_whole_file is False and (sig.bytes_after_signed_range or 0) > 0:
            yield (
                "signatures",
                Severity.WARNING,
                f"Data added after signature {sig.field_name}",
                f"{sig.bytes_after_signed_range} byte(s) follow the range covered by the signature: the file "
                "was changed after signing (incremental update or appended data). Requires review.",
                ev,
                None,
            )
        elif sig.covers_whole_file is False:
            yield (
                "signatures",
                Severity.NOTICE,
                f"Unusual ByteRange in {sig.field_name}",
                "The signed byte range does not start at 0 or exceeds the file.",
                ev,
                None,
            )
        if sig.error:
            yield ("signatures", Severity.NOTICE, f"Signature not decodable: {sig.field_name}", sig.error, ev, None)


@rule
def image_metadata(a: PDFAnalysis, s: Settings) -> Iterator[Draft]:
    created = _date(a.metadata.info_value("CreationDate") or a.metadata.xmp_value("xmp:CreateDate"))
    seen: dict[str, list[int]] = defaultdict(list)
    for img in a.image_evidence:
        seen[img.raw_sha256].append(img.object_id)
        ev = {
            "object_id": img.object_id,
            "pages": img.pages,
            "camera": img.camera,
            "software": img.software,
            "dates": img.dates,
        }
        if img.exif or img.xmp or img.iptc:
            yield (
                "images",
                Severity.NOTICE,
                f"Embedded image {img.object_id} carries its own metadata",
                "EXIF/XMP/IPTC inside the image stream can reveal the original device, software and dates.",
                ev,
                img.pages[0] if img.pages else None,
            )
        if img.software and EDITING_SOFTWARE.search(str(img.software)):
            yield (
                "images",
                Severity.NOTICE,
                f"Image {img.object_id} processed with image-editing software",
                f"Software tag: {img.software}.",
                ev,
                img.pages[0] if img.pages else None,
            )
        if img.gps:
            yield (
                "images",
                Severity.NOTICE,
                f"Image {img.object_id} contains GPS coordinates",
                "Location data is present in the image metadata.",
                {**ev, "gps": img.gps},
                img.pages[0] if img.pages else None,
            )
        if created:
            for key, value in img.dates.items():
                text = value[:10].replace(":", "-") + value[10:] if key.startswith("exif:") else value
                when = _date(text.replace(" ", "T", 1))
                if when and when > created:
                    yield (
                        "images",
                        Severity.WARNING,
                        f"Image {img.object_id} dated after the declared creation",
                        f"{key} = {value} is later than the declared PDF creation date. EXIF dates have no "
                        "time zone (UTC assumed). Requires review.",
                        {**ev, "declared_creation": created.isoformat()},
                        img.pages[0] if img.pages else None,
                    )
                    break
    duplicates = {h: ids for h, ids in seen.items() if len(ids) > 1}
    if duplicates:
        yield (
            "images",
            Severity.INFO,
            "Identical image data stored in several objects",
            "The same encoded image appears as separate objects (copy-paste or merge).",
            {"objects": list(duplicates.values())[:20]},
            None,
        )


_TEXT_KINDS = {
    "invisible_text": (Severity.NOTICE, "Invisible (white) text"),
    "outside_page": (Severity.NOTICE, "Text outside the visible page"),
    "tiny_text": (Severity.INFO, "Text smaller than 1 pt"),
    "overlapping_text": (Severity.NOTICE, "Text drawn over identical text"),
    "covered_text": (Severity.WARNING, "Text under a filled dark rectangle"),
    "font_change_in_line": (Severity.NOTICE, "Font or size change inside a text line"),
}


@rule
def text_layer(a: PDFAnalysis, s: Settings) -> Iterator[Draft]:
    by_kind: dict[str, list[Any]] = defaultdict(list)
    for anomaly in a.text_forensics.anomalies:
        by_kind[anomaly.kind].append(anomaly)
    explanations = {
        "covered_text": "Possible ineffective redaction: the text is still extractable under the shape.",
        "font_change_in_line": "A short run in a different font or size is a common trace of local edits; "
        "it is also normal for symbols, numbers or emphasis. Compare visually.",
        "overlapping_text": "Repeated text at the same coordinates can derive from overlays or edits.",
        "invisible_text": "Text not visible on screen but present in the text layer (also used by OCR layers).",
        "outside_page": "Text placed outside the CropBox is not displayed.",
        "tiny_text": "Very small text is practically invisible.",
    }
    for kind, items in by_kind.items():
        severity, title = _TEXT_KINDS.get(kind, (Severity.INFO, kind))
        pages = sorted({x.page for x in items})
        yield (
            "text",
            severity,
            f"{title} ({len(items)})",
            explanations.get(kind, ""),
            {"pages": pages, "samples": [{"page": x.page, "text": x.text[:80], **x.details} for x in items[:10]]},
            pages[0] if len(pages) == 1 else None,
        )


@rule
def objects_and_parsers(a: PDFAnalysis, s: Settings) -> Iterator[Draft]:
    o = a.objects
    if o.error:
        yield ("structure", Severity.NOTICE, "pikepdf could not open the file", o.error, {}, None)
    if o.undecodable_streams:
        yield (
            "structure",
            Severity.NOTICE,
            f"{len(o.undecodable_streams)} stream(s) cannot be decoded",
            "Corrupted or deliberately malformed streams.",
            {"objects": [f"{x.object_id} {x.generation}: {x.decode_error}" for x in o.undecodable_streams][:20]},
            None,
        )
    if o.nonzero_generation:
        yield (
            "structure",
            Severity.INFO,
            "Objects with generation number above 0",
            "Object numbers were reused after deletion (an editing trace).",
            {"objects": o.nonzero_generation[:30]},
            None,
        )
    hidden_layers = [x["name"] for x in o.layers if x.get("default_off")]
    if hidden_layers:
        yield (
            "structure",
            Severity.NOTICE,
            "Optional content layers hidden by default",
            "Layers switched off in the default view can hold content that is not displayed.",
            {"layers": hidden_layers},
            None,
        )
    elif o.layers:
        yield (
            "structure",
            Severity.INFO,
            f"{len(o.layers)} optional content layer(s)",
            "",
            {"layers": [x["name"] for x in o.layers]},
            None,
        )
    if o.thumbnails:
        yield (
            "structure",
            Severity.NOTICE,
            "Embedded page thumbnails",
            "Thumbnails are stored images of the pages and may reflect an earlier state of the content.",
            {"pages": o.thumbnails[:50]},
            None,
        )
    if o.piece_info:
        yield (
            "structure",
            Severity.INFO,
            "Application private data (PieceInfo)",
            "Editing applications (e.g. Illustrator, Acrobat) store private data that may include "
            "earlier content or dates.",
            {"entries": o.piece_info[:20]},
            None,
        )
    if o.output_intents:
        yield (
            "structure",
            Severity.INFO,
            "Output intents (PDF/A or PDF/X)",
            "",
            {"intents": o.output_intents[:5]},
            None,
        )
    for diff in a.crosscheck.differences:
        yield (
            "structure",
            Severity.NOTICE,
            f"Parsers disagree on {diff['field']}",
            "Independent PDF libraries read different values: the structure may be ambiguous or damaged.",
            diff,
            None,
        )
    for page in a.crosscheck.pdfium_pages:
        mine, theirs = page.get("pdfplumber_chars"), page.get("pdfium_chars")
        if mine is not None and theirs is not None and abs(mine - theirs) > max(20, 0.2 * max(mine, theirs)):
            yield (
                "text",
                Severity.INFO,
                f"Text extraction differs between parsers (page {page['page']})",
                "pdfplumber and PDFium extract a different amount of text; hidden or duplicated text is a "
                "common cause.",
                page,
                page["page"],
            )


# --------------------------------------------------------------------- OCR (1.2)
@rule
def ocr_comparison(a: PDFAnalysis, s: Settings) -> Iterator[Draft]:
    o = a.ocr
    if not o.pages and not o.error:
        return
    if o.error and not o.available:
        yield ("ocr", Severity.INFO, "OCR not available", o.error, {}, None)
        return
    ev = {"engine": f"tesseract {o.version or ''}".strip(), "languages": o.languages, "dpi": o.dpi}
    unseen = [r for p in o.pages for r in p.unseen_layer_text]
    if unseen:
        pages = sorted({r.page for r in unseen})
        yield (
            "ocr",
            Severity.NOTICE,
            f"Text in the text layer not visible in the rendering ({len(unseen)})",
            "No text was recognised by OCR at the position of these text-layer words: they are present in the "
            "file but not visible on the rendered page (white or tiny text, text covered by shapes or images, "
            "text outside the visible area). Light or very small legitimate text can also be missed by OCR. "
            "Verify visually.",
            {
                **ev,
                "pages": pages,
                "samples": [{"page": r.page, "text": r.text[:120], "bbox": r.bbox} for r in unseen[:15]],
            },
            pages[0] if len(pages) == 1 else None,
        )
    missing = [r for p in o.pages for r in p.visible_not_in_layer]
    if missing:
        pages = sorted({r.page for r in missing})
        yield (
            "ocr",
            Severity.INFO,
            f"Visible text not present in the text layer ({len(missing)})",
            "OCR recognised text where the text layer has none: scanned content, text inside images or drawn as "
            "vector shapes. Such text is not searchable and may differ from what text-based tools report.",
            {
                **ev,
                "pages": pages,
                "samples": [{"page": r.page, "text": r.text[:120], "bbox": r.bbox} for r in missing[:15]],
            },
            pages[0] if len(pages) == 1 else None,
        )
    image_only = [p.page for p in o.pages if p.layer_words == 0 and p.words > 0]
    if image_only:
        yield (
            "ocr",
            Severity.INFO,
            "Text recovered by OCR on pages without a text layer",
            "OCR text is available for pages that contain no extractable text.",
            {**ev, "pages": image_only},
            None,
        )
    low = [p.page for p in o.pages if p.mean_confidence is not None and p.mean_confidence < 60 and p.words >= 20]
    if low:
        yield (
            "ocr",
            Severity.INFO,
            "Low OCR confidence",
            "Recognition quality is low on these pages; OCR-based comparisons are less reliable.",
            {**ev, "pages": low},
            None,
        )
    errors = [f"page {p.page}: {p.error}" for p in o.pages if p.error]
    if errors:
        yield ("ocr", Severity.INFO, "OCR problems on some pages", "", {**ev, "errors": errors[:20]}, None)
