"""Document metadata: Info dictionary (all revisions), XMP, encryption, version."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

from pdftrace.core.analyzer import AnalysisContext, AnalysisResult, Analyzer
from pdftrace.core.models import InfoRevision, Metadata, MetadataComparison, ProvenancedValue
from pdftrace.integrations import pdfplumber_adapter as pa
from pdftrace.utils.pdfdates import as_aware, parse_any_date, to_iso

STANDARD_INFO_KEYS = (
    "Title",
    "Author",
    "Subject",
    "Keywords",
    "Creator",
    "Producer",
    "CreationDate",
    "ModDate",
    "Trapped",
)
DATE_KEYS = {"CreationDate", "ModDate"}

#: Info key -> XMP property used for the Info/XMP comparison (ISO 32000-1 §14.3.2).
INFO_TO_XMP = {
    "Title": "dc:title",
    "Author": "dc:creator",
    "Subject": "dc:description",
    "Keywords": "pdf:Keywords",
    "Creator": "xmp:CreatorTool",
    "Producer": "pdf:Producer",
    "CreationDate": "xmp:CreateDate",
    "ModDate": "xmp:ModifyDate",
}

KNOWN_PREFIXES = {
    "http://purl.org/dc/elements/1.1/": "dc",
    "http://ns.adobe.com/xap/1.0/": "xmp",
    "http://ns.adobe.com/xap/1.0/mm/": "xmpMM",
    "http://ns.adobe.com/pdf/1.3/": "pdf",
    "http://ns.adobe.com/xap/1.0/rights/": "xmpRights",
    "http://ns.adobe.com/xap/1.0/sType/ResourceEvent#": "stEvt",
    "http://ns.adobe.com/xap/1.0/sType/ResourceRef#": "stRef",
    "http://www.aiim.org/pdfa/ns/id/": "pdfaid",
    "http://www.aiim.org/pdfua/ns/id/": "pdfuaid",
    "http://ns.adobe.com/photoshop/1.0/": "photoshop",
    "http://www.w3.org/1999/02/22-rdf-syntax-ns#": "rdf",
    "adobe:ns:meta/": "x",
}
RDF = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
MAX_XMP_PROPERTIES = 5000
MAX_REVISIONS = 20


class MetadataAnalyzer(Analyzer):
    name = "metadata"
    label = "Metadata"

    def analyze(self, ctx: AnalysisContext) -> AnalysisResult:
        meta = Metadata()
        match = re.search(rb"%PDF-(\d\.\d)", ctx.raw_bytes[:1024])
        meta.pdf_version = match.group(1).decode() if match else None
        try:
            pdf = ctx.pdf()
        except pa.PDFOpenError as exc:
            meta.errors.append(f"PDF parser could not open the file: {exc}")
            return AnalysisResult("metadata", meta, message="Parser error; partial metadata")

        revisions = pa.info_dicts(pdf)
        if revisions:
            meta.info_revisions.append(
                InfoRevision(
                    index=0,
                    values={str(k): pa.to_text(v) or "" for k, v in revisions[0].items()},
                    source="current_revision",
                )
            )
        if revisions:
            self._read_info(revisions[0], meta)

        doc = pdf.doc
        meta.encrypted = getattr(doc, "encryption", None) is not None
        for perm in ("is_printable", "is_modifiable", "is_extractable"):
            try:
                meta.permissions[perm.removeprefix("is_")] = bool(getattr(doc, perm))
            except Exception as exc:
                meta.errors.append(f"Permission {perm}: {exc}")
        meta.catalog_version = pa.literal_name(pa.catalog(pdf).get("Version"))
        meta.trailer_ids = [":".join(ids) for ids in pa.trailer_ids(pdf)]
        try:
            meta.page_count = len(pdf.pages)
        except Exception as exc:
            meta.errors.append(f"Page tree: {exc}")

        try:
            raw = pa.xmp_bytes(pdf, ctx.settings.max_xmp_bytes)
        except Exception as exc:
            raw = None
            meta.xmp_error = str(exc)
        if raw is not None:
            meta.xmp_present = True
            meta.xmp_raw = raw.decode("utf-8", errors="replace")
            try:
                meta.xmp = parse_xmp(raw)
            except ET.ParseError as exc:
                meta.xmp_error = f"XMP not parsed: {exc}"
        meta.comparisons = compare_info_xmp(meta)
        self._earlier_revisions(ctx, meta)
        return AnalysisResult("metadata", meta)

    @staticmethod
    def _earlier_revisions(ctx: AnalysisContext, meta: Metadata) -> None:
        """Read the Info dictionary of each earlier revision (file truncated at each %%EOF)."""
        ends = [m.end() for m in re.finditer(rb"%%EOF", ctx.raw_bytes)][:-1]
        for end in reversed(ends[-MAX_REVISIONS:]):
            ctx.check_cancelled()
            try:
                pdf = pa.open_bytes(ctx.raw_bytes[:end])
            except pa.PDFOpenError:
                continue
            try:
                dicts = pa.info_dicts(pdf)
                if dicts:
                    meta.info_revisions.append(
                        InfoRevision(
                            index=len(meta.info_revisions),
                            values={str(k): pa.to_text(v) or "" for k, v in dicts[0].items()},
                            source=f"earlier_revision_truncated_at_byte_{end}",
                        )
                    )
            finally:
                pdf.close()

    @staticmethod
    def _read_info(info: dict[str, Any], meta: Metadata) -> None:
        for key, value in info.items():
            text = pa.to_text(value)
            note = None
            if key in DATE_KEYS:
                parsed = parse_any_date(text)
                note = f"parsed: {to_iso(parsed)}" if parsed else "unparseable date"
            item = ProvenancedValue(str(key), text, "pdf_info_dictionary", "direct", text, note)
            (meta.info if key in STANDARD_INFO_KEYS else meta.custom).append(item)


def _prefix_map(raw: bytes) -> dict[str, str]:
    mapping = dict(KNOWN_PREFIXES)
    for prefix, uri in re.findall(rb'xmlns:([\w.\-]+)\s*=\s*["\']([^"\']+)["\']', raw):
        mapping.setdefault(uri.decode("utf-8", "replace"), prefix.decode("utf-8", "replace"))
    return mapping


def _qname(tag: str, prefixes: dict[str, str]) -> str:
    if tag.startswith("{"):
        uri, _, local = tag[1:].partition("}")
        return f"{prefixes.get(uri, uri)}:{local}"
    return tag


def parse_xmp(raw: bytes) -> list[ProvenancedValue]:
    """Flatten an XMP packet into ``prefix:Property`` values.

    Arrays (rdf:Seq/Bag/Alt) are joined with ``"; "``; structures such as
    ``xmpMM:History`` are flattened as ``xmpMM:History[1]/stEvt:when``.
    ElementTree does not resolve external entities, and the packet size is
    capped before parsing.
    """
    start = raw.find(b"<x:xmpmeta")
    if start < 0:
        start = raw.find(b"<rdf:RDF")
    body = raw[start:] if start >= 0 else raw
    end = body.rfind(b"<?xpacket")
    if end > 0:
        body = body[:end]
    if re.search(rb"<!(?:DOCTYPE|ENTITY)", body, re.I):
        # XMP never needs a DTD; refusing it blocks entity-expansion attacks.
        raise ET.ParseError("DTD/ENTITY declarations present: XMP not parsed for safety")
    root = ET.fromstring(body)  # noqa: S314 - DTDs rejected above; expat resolves no external entities
    prefixes = _prefix_map(raw)
    values: list[ProvenancedValue] = []

    def add(name: str, value: str) -> None:
        if len(values) < MAX_XMP_PROPERTIES:
            note = None
            if name.endswith(("Date", ":when")):
                parsed = parse_any_date(value)
                note = f"parsed: {to_iso(parsed)}" if parsed else None
            values.append(ProvenancedValue(name, value, "xmp_packet", "direct", value, note))

    def walk(element: ET.Element, path: str) -> None:
        for attr, value in element.attrib.items():
            if attr.startswith(f"{{{RDF}}}"):
                continue
            add(f"{path}/{_qname(attr, prefixes)}" if path else _qname(attr, prefixes), value)
        for child in element:
            name = _qname(child.tag, prefixes)
            full = f"{path}/{name}" if path else name
            container = next(
                (c for c in child if c.tag in {f"{{{RDF}}}Seq", f"{{{RDF}}}Bag", f"{{{RDF}}}Alt"}),
                None,
            )
            if container is not None:
                items = list(container)
                if all(len(li) == 0 and not li.attrib.get(f"{{{RDF}}}parseType") for li in items):
                    add(full, "; ".join((li.text or "").strip() for li in items))
                else:
                    for i, li in enumerate(items, start=1):
                        walk(li, f"{full}[{i}]")
                        if (li.text or "").strip() and len(li) == 0:
                            add(f"{full}[{i}]", li.text.strip())  # type: ignore[union-attr]
            elif len(child) or any(not a.startswith(f"{{{RDF}}}") for a in child.attrib):
                walk(child, full)
            else:
                add(full, (child.text or "").strip())

    for description in root.iter(f"{{{RDF}}}Description"):
        walk(description, "")
    return values


def _normalise(value: str | None) -> str:
    return " ".join((value or "").split()).casefold()


def compare_info_xmp(meta: Metadata) -> list[MetadataComparison]:
    """Compare each Info field with its XMP counterpart (neutral wording)."""
    comparisons: list[MetadataComparison] = []
    for info_key, xmp_key in INFO_TO_XMP.items():
        info_value = meta.info_value(info_key)
        xmp_value = meta.xmp_value(xmp_key)
        if not info_value and not xmp_value:
            status = "absent"
        elif info_value and not xmp_value:
            status = "only_info" if meta.xmp_present else "absent_xmp"
        elif xmp_value and not info_value:
            status = "only_xmp"
        elif info_key in DATE_KEYS:
            status = "match" if _same_instant(info_value, xmp_value) else "difference"
        else:
            status = "match" if _normalise(info_value) == _normalise(xmp_value) else "difference"
        comparisons.append(MetadataComparison(info_key, info_key, xmp_key, info_value, xmp_value, status))
    return comparisons


def _same_instant(a: str | None, b: str | None) -> bool:
    da, db = parse_any_date(a), parse_any_date(b)
    if not da or not db:
        return _normalise(a) == _normalise(b)
    if da.tzinfo is None or db.tzinfo is None:
        return da.replace(tzinfo=None) == db.replace(tzinfo=None)
    return as_aware(da) == as_aware(db)
