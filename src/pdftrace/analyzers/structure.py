"""Physical structure: header, revisions, xref, trailers, object usage.

Revisions come from :mod:`pdftrace.core.xref_chain` (startxref and /Prev),
not from the number of %%EOF markers.

The scan works on raw bytes (like pdfid) and therefore also on files that the
PDF parser rejects. Keywords stored inside compressed object streams are not
visible to a byte scan; this limitation is recorded in the diagnostics.
"""

from __future__ import annotations

import re
from collections import Counter

from pdftrace.core.analyzer import AnalysisContext, AnalysisResult, Analyzer
from pdftrace.core.models import StructureInfo
from pdftrace.integrations import pdfplumber_adapter as pa
from pdftrace.integrations.process import ToolFailed, ToolNotFound

KEYWORDS = (
    "JavaScript",
    "JS",
    "OpenAction",
    "AA",
    "Launch",
    "EmbeddedFile",
    "EmbeddedFiles",
    "URI",
    "SubmitForm",
    "GoToR",
    "RichMedia",
    "XFA",
    "AcroForm",
    "ObjStm",
    "Encrypt",
    "Sig",
    "ByteRange",
    "DSS",
    "Metadata",
    "PieceInfo",
)
_KEYWORD_RE = {k: re.compile(rb"/" + k.encode() + rb"(?![A-Za-z0-9])") for k in KEYWORDS}
_OBJ_RE = re.compile(rb"(?<![0-9])(\d{1,10})\s+(\d{1,5})\s+obj\b")
_COMMENT_RE = re.compile(rb"[\r\n]%([ -~]{3,160})(?=[\r\n])")


class StructureAnalyzer(Analyzer):
    name = "structure"
    label = "PDF structure"

    def analyze(self, ctx: AnalysisContext) -> AnalysisResult:
        data = ctx.raw_bytes
        info = StructureInfo()
        diagnostics = ["Byte-level scan: keywords inside compressed object streams are not counted."]
        header = re.search(rb"%PDF-(\d\.\d)", data[:1024])
        if header:
            info.header_version = header.group(1).decode()
            info.header_offset = header.start()
        info.eof_offsets = [m.start() for m in re.finditer(rb"%%EOF", data)]
        info.startxref_values = [int(m.group(1)) for m in re.finditer(rb"startxref\s+(\d+)", data)]
        info.xref_tables = len(re.findall(rb"(?:^|[\r\n])xref\s", data))
        info.xref_streams = len(re.findall(rb"/Type\s*/XRef\b", data))
        info.trailers = len(re.findall(rb"trailer\s*<<", data))
        info.prev_pointers = [int(m.group(1)) for m in re.finditer(rb"/Prev\s+(\d+)", data)]
        info.object_streams = len(re.findall(rb"/Type\s*/ObjStm\b", data))
        info.linearized = re.search(rb"/Linearized\s", data[:4096]) is not None
        info.encrypted = re.search(rb"/Encrypt\s", data) is not None

        numbers = Counter(int(m.group(1)) for m in _OBJ_RE.finditer(data))
        info.object_definitions = sum(numbers.values())
        info.unique_objects = len(numbers)
        info.redefined_objects = sorted(n for n, c in numbers.items() if c > 1)[:500]

        info.keyword_counts = {k: len(p.findall(data)) for k, p in _KEYWORD_RE.items()}
        comments: list[str] = []
        for match in _COMMENT_RE.finditer(data):
            text = match.group(1).decode("ascii", "replace").strip()
            if text.startswith(("PDF-", "%EOF")) or text in comments:
                continue
            comments.append(text)
            if len(comments) >= 50:
                break
        info.comments = comments

        if info.eof_offsets:
            tail = data[info.eof_offsets[-1] + 5 :]
            info.trailing_bytes_after_eof = len(tail.strip(b"\r\n\t \x00"))
        chain = ctx.xref_chain()
        info.xref_chain = chain
        info.linearized = info.linearized or chain.linearized
        info.incremental_updates = max(0, len(chain.revisions) - 1)
        if chain.method != "xref_chain":
            diagnostics.append("Cross-reference chain could not be followed: revisions estimated from %%EOF markers.")
        elif not chain.complete:
            diagnostics.append("Cross-reference chain is broken: older revisions may be missing.")

        try:
            pdf = ctx.pdf()
            info.trailer_ids = pa.trailer_ids(pdf)
            info.catalog_keys = sorted(str(k) for k in pa.catalog(pdf))
        except pa.PDFOpenError as exc:
            info.errors.append(f"PDF parser: {exc}")

        if ctx.poppler.available("pdfinfo"):
            try:
                info.pdfinfo, result = ctx.poppler.pdfinfo(ctx.path)
                if result.stderr.strip():
                    diagnostics.append(f"pdfinfo stderr: {result.stderr.strip()[:2000]}")
            except (ToolFailed, ToolNotFound) as exc:
                info.errors.append(f"pdfinfo: {exc}")
        else:
            diagnostics.append("pdfinfo not available: Poppler cross-check skipped.")
        return AnalysisResult("structure", info, diagnostics)
