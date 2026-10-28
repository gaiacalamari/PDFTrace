"""Parser cross-check: the same facts read by independent PDF parsers.

pdfminer.six (via pdfplumber), pikepdf (libqpdf), pypdf and PDFium (pypdfium2)
are implemented independently; disagreements between them often point to
malformed or deliberately ambiguous structures.
"""

from __future__ import annotations

import logging
from typing import Any

from pdftrace.core.analyzer import AnalysisContext, AnalysisResult, Analyzer
from pdftrace.core.models import ParserCrossCheck
from pdftrace.integrations import pikepdf_adapter as pk
from pdftrace.integrations.pdfplumber_adapter import PDFOpenError

INFO_KEYS = ("Title", "Author", "Subject", "Keywords", "Creator", "Producer", "CreationDate", "ModDate")
PDFIUM_OBJECT_TYPES = {1: "text", 2: "path", 3: "image", 4: "shading", 5: "form"}


class CrossCheckAnalyzer(Analyzer):
    name = "crosscheck"
    label = "Parser cross-check (pikepdf, pypdf, PDFium)"

    def analyze(self, ctx: AnalysisContext) -> AnalysisResult:
        check = ParserCrossCheck()
        meta = ctx.analysis.metadata
        check.parsers["pdfminer"] = {
            "pages": meta.page_count,
            **{k: meta.info_value(k) for k in INFO_KEYS},
            "xmp": meta.xmp_present,
            "encrypted": meta.encrypted,
        }
        self._pikepdf(ctx, check)
        self._pypdf(ctx, check)
        self._pdfium(ctx, check)
        fields = ["pages", *INFO_KEYS, "xmp", "encrypted"]
        for f in fields:
            values = {name: data.get(f) for name, data in check.parsers.items() if f in data}
            normal = {str(v).strip() if v not in (None, "") else "" for v in values.values()}
            if len(normal) > 1:
                check.differences.append({"field": f, "values": values})
        return AnalysisResult("crosscheck", check)

    @staticmethod
    def _pikepdf(ctx: AnalysisContext, check: ParserCrossCheck) -> None:
        try:
            pdf = ctx.pike()
            info = pdf.docinfo
            check.parsers["pikepdf"] = {
                "pages": len(pdf.pages),
                **{k: pk.text(info.get(f"/{k}")) for k in INFO_KEYS},
                "xmp": pk.get(pdf.Root, "/Metadata") is not None,
                "encrypted": bool(pdf.is_encrypted),
            }
        except (PDFOpenError, Exception) as exc:
            check.errors.append(f"pikepdf: {exc}")

    @staticmethod
    def _pypdf(ctx: AnalysisContext, check: ParserCrossCheck) -> None:
        try:
            import pypdf

            logging.getLogger("pypdf").setLevel(logging.ERROR)
            reader = pypdf.PdfReader(str(ctx.path), strict=False)
            raw: Any = reader.metadata or {}
            check.parsers["pypdf"] = {
                "pages": len(reader.pages),
                **{k: (str(raw.get(f"/{k}")) if raw.get(f"/{k}") is not None else None) for k in INFO_KEYS},
                "xmp": reader.xmp_metadata is not None,
                "encrypted": bool(reader.is_encrypted),
            }
        except Exception as exc:
            check.errors.append(f"pypdf: {type(exc).__name__}: {exc}")

    @staticmethod
    def _pdfium(ctx: AnalysisContext, check: ParserCrossCheck) -> None:
        try:
            import pypdfium2 as pdfium

            doc = pdfium.PdfDocument(str(ctx.path))
        except Exception as exc:
            check.errors.append(f"pypdfium2: {type(exc).__name__}: {exc}")
            return
        try:
            meta = doc.get_metadata_dict()
            check.parsers["pdfium"] = {
                "pages": len(doc),
                **{k: (meta.get(k) or None) for k in INFO_KEYS},
                "file_version": doc.get_version(),
                "tagged": bool(doc.is_tagged()),
            }
            plumber_chars = {p.number: p.visible_chars for p in ctx.analysis.pages}
            for index in range(min(len(doc), ctx.settings.max_pages_text)):
                ctx.check_cancelled()
                page = doc[index]
                try:
                    textpage = page.get_textpage()
                    text = textpage.get_text_range()
                    counts: dict[str, int] = {}
                    for obj in page.get_objects(max_depth=4):
                        kind = PDFIUM_OBJECT_TYPES.get(int(obj.type), str(obj.type))
                        counts[kind] = counts.get(kind, 0) + 1
                    visible = sum(1 for ch in text if not ch.isspace())
                    check.pdfium_pages.append(
                        {
                            "page": index + 1,
                            "pdfium_chars": visible,
                            "pdfplumber_chars": plumber_chars.get(index + 1),
                            "objects": counts,
                        }
                    )
                    textpage.close()
                finally:
                    page.close()
        finally:
            doc.close()
