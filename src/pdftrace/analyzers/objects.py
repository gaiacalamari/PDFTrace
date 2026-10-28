"""Object inventory and document features (pikepdf / libqpdf)."""

from __future__ import annotations

from collections import Counter
from typing import Any

from pdftrace.core.analyzer import AnalysisContext, AnalysisResult, Analyzer
from pdftrace.core.models import ObjectInventory, StreamInfo
from pdftrace.integrations import pikepdf_adapter as pk
from pdftrace.integrations.pdfplumber_adapter import PDFOpenError

CATALOG_FEATURES = (
    "/AcroForm",
    "/Names",
    "/Outlines",
    "/OpenAction",
    "/AA",
    "/PageLabels",
    "/OCProperties",
    "/StructTreeRoot",
    "/MarkInfo",
    "/Lang",
    "/ViewerPreferences",
    "/OutputIntents",
    "/PieceInfo",
    "/Perms",
    "/Legal",
    "/DSS",
    "/Threads",
    "/URI",
    "/Collection",
    "/Metadata",
    "/Extensions",
    "/AF",
    "/SpiderInfo",
)
MAX_STREAMS_LISTED = 50
MAX_DECODE_CHECK = 5000


class ObjectsAnalyzer(Analyzer):
    name = "objects"
    label = "Objects (pikepdf)"

    def analyze(self, ctx: AnalysisContext) -> AnalysisResult:
        inv = ObjectInventory()
        try:
            pdf = ctx.pike()
        except PDFOpenError as exc:
            inv.error = str(exc)
            return AnalysisResult("objects", inv, message="pikepdf could not open the file")
        inv.pdf_version = str(pdf.pdf_version)
        inv.extension_level = int(pdf.extension_level)
        inv.linearized = bool(pdf.is_linearized)
        self._security(pdf, inv)
        self._objects(ctx, pdf, inv)
        self._catalog(pdf, inv)
        self._pages(pdf, inv)
        try:
            inv.qpdf_warnings = [str(w) for w in pdf.get_warnings()][:500]
        except Exception:
            inv.qpdf_warnings = []
        return AnalysisResult("objects", inv)

    @staticmethod
    def _security(pdf: Any, inv: ObjectInventory) -> None:
        if pdf.is_encrypted:
            enc = pdf.encryption
            inv.encryption = {
                "V": enc.V,
                "R": enc.R,
                "P": enc.P,
                "bits": enc.bits,
                "stream_method": str(enc.stream_method),
                "string_method": str(enc.string_method),
                "file_method": str(enc.file_method),
            }
        allow = pdf.allow
        for perm in (
            "accessibility",
            "extract",
            "modify_annotation",
            "modify_assembly",
            "modify_form",
            "modify_other",
            "print_lowres",
            "print_highres",
        ):
            inv.permissions[perm] = bool(getattr(allow, perm, False))

    @staticmethod
    def _objects(ctx: AnalysisContext, pdf: Any, inv: ObjectInventory) -> None:
        types: Counter[str] = Counter()
        filters: Counter[str] = Counter()
        streams: list[StreamInfo] = []
        for index, obj in enumerate(pdf.objects):
            if index % 500 == 0:
                ctx.check_cancelled()
            num, gen = pk.objgen(obj)
            if gen:
                inv.nonzero_generation.append(f"{num} {gen}")
            inv.total_objects += 1
            try:
                is_stream = isinstance(obj, pk.Stream)
                is_dict = is_stream or isinstance(obj, pk.Dictionary)
            except Exception:  # noqa: S112 - unreadable object, counted only
                continue
            type_name = pk.name(pk.get(obj, "/Type")) if is_dict else None
            subtype = pk.name(pk.get(obj, "/Subtype")) if is_dict else None
            label = type_name or ("stream" if is_stream else str(getattr(obj, "_type_name", "object")))
            types[f"{label}/{subtype}" if subtype else label] += 1
            if not is_stream:
                continue
            inv.streams += 1
            flist = pk.filters(obj)
            for f in flist or ["(none)"]:
                filters[f] += 1
            info = StreamInfo(num, gen, type_name, subtype, flist, len(obj.read_raw_bytes()))
            if inv.streams <= MAX_DECODE_CHECK and not (
                {"DCTDecode", "JPXDecode", "JBIG2Decode", "CCITTFaxDecode"} & set(flist)
            ):
                try:
                    info.decoded_length = len(obj.read_bytes())
                except Exception as exc:
                    info.decode_error = f"{type(exc).__name__}: {exc}"[:300]
                    inv.undecodable_streams.append(info)
            streams.append(info)
        inv.by_type = dict(types.most_common())
        inv.by_filter = dict(filters.most_common())
        inv.largest_streams = sorted(streams, key=lambda s: -s.raw_length)[:MAX_STREAMS_LISTED]
        inv.nonzero_generation = inv.nonzero_generation[:500]

    @staticmethod
    def _catalog(pdf: Any, inv: ObjectInventory) -> None:
        root = pdf.Root
        for key in CATALOG_FEATURES:
            value = pk.get(root, key)
            if value is not None:
                inv.catalog_features[key[1:]] = (pk.text(value) or "")[:200]
        outlines = pk.get(root, "/Outlines")
        if outlines is not None and pk.get(outlines, "/First") is not None:
            inv.outline = list(pk.walk_outline(pk.get(outlines, "/First")))
        labels = pk.get(root, "/PageLabels")
        if labels is not None:
            nums = pk.get(labels, "/Nums")
            if nums is not None:
                for i in range(0, len(nums) - 1, 2):
                    spec = nums[i + 1]
                    inv.page_labels.append(
                        {
                            "from_page_index": int(nums[i]),
                            "style": pk.name(pk.get(spec, "/S")),
                            "prefix": pk.text(pk.get(spec, "/P")),
                            "start": pk.text(pk.get(spec, "/St")),
                        }
                    )
        ocp = pk.get(root, "/OCProperties")
        if ocp is not None:
            default = pk.get(ocp, "/D")
            off = {pk.objgen(o) for o in (pk.get(default, "/OFF") or [])}
            for group in pk.get(ocp, "/OCGs") or []:
                inv.layers.append(
                    {
                        "name": pk.text(pk.get(group, "/Name")),
                        "object": pk.objgen(group)[0],
                        "default_off": pk.objgen(group) in off,
                    }
                )
        for intent in pk.get(root, "/OutputIntents") or []:
            inv.output_intents.append(
                {
                    "subtype": pk.name(pk.get(intent, "/S")),
                    "identifier": pk.text(pk.get(intent, "/OutputConditionIdentifier")),
                    "info": pk.text(pk.get(intent, "/Info")),
                }
            )
        piece = pk.get(root, "/PieceInfo")
        if piece is not None:
            inv.piece_info = [str(k)[1:] for k in piece.keys()]

    @staticmethod
    def _pages(pdf: Any, inv: ObjectInventory) -> None:
        for number, page in enumerate(pdf.pages, start=1):
            obj = page.obj
            if pk.get(obj, "/Thumb") is not None:
                inv.thumbnails.append(number)
            if pk.get(obj, "/PieceInfo") is not None:
                for key in pk.get(obj, "/PieceInfo").keys():
                    label = f"page {number}: {str(key)[1:]}"
                    if label not in inv.piece_info:
                        inv.piece_info.append(label)
            boxes = {
                k[1:]: pk.numbers(pk.get(obj, k))
                for k in ("/MediaBox", "/CropBox", "/BleedBox", "/TrimBox", "/ArtBox")
                if pk.get(obj, k) is not None
            }
            if len(inv.page_boxes) < 2000:
                inv.page_boxes.append({"page": number, "rotate": pk.text(pk.get(obj, "/Rotate")), **boxes})
