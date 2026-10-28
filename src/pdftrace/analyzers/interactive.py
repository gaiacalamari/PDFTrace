"""Interactive and attached content: annotations, links, forms, attachments,
JavaScript (extracted as text, never executed), actions and digital signatures.

Signature certificates are decoded with ``cryptography`` (Apache-2.0/BSD);
signatures are *described*, not cryptographically validated.
"""

from __future__ import annotations

from typing import Any

from pdftrace.core.analyzer import AnalysisContext, AnalysisResult, Analyzer
from pdftrace.core.models import (
    ActionItem,
    Annotation,
    EmbeddedFile,
    FormField,
    Interactive,
    ScriptItem,
    SignatureInfo,
)
from pdftrace.integrations import pikepdf_adapter as pk
from pdftrace.integrations.pdfplumber_adapter import PDFOpenError
from pdftrace.utils.pdfdates import parse_any_date, to_iso

MAX_CODE = 20_000
MAX_ANNOTS = 20_000
HIDDEN_FLAGS = 0b10 | 0b100000  # Hidden (2) or NoView (32)


def _date(value: Any) -> str | None:
    raw = pk.text(value)
    parsed = parse_any_date(raw)
    return to_iso(parsed) if parsed else raw


class InteractiveAnalyzer(Analyzer):
    name = "interactive"
    label = "Annotations, forms, attachments, scripts, signatures"

    def analyze(self, ctx: AnalysisContext) -> AnalysisResult:
        result = Interactive()
        try:
            pdf = ctx.pike()
        except PDFOpenError as exc:
            result.errors.append(str(exc))
            return AnalysisResult("interactive", result, message="pikepdf could not open the file")
        root = pdf.Root
        self._document_actions(root, result)
        self._names(root, result)
        self._pages(ctx, pdf, result)
        self._forms(root, result)
        self._signatures(ctx, root, result)
        return AnalysisResult("interactive", result)

    # ----------------------------------------------------------- actions/JS
    def _action(self, action: Any, location: str, trigger: str, result: Interactive, depth: int = 0) -> None:
        """Record an action dictionary and its /Next chain; JavaScript code is copied as text."""
        if action is None or depth > 32:
            return
        kind = pk.name(pk.get(action, "/S")) or "?"
        target = None
        if kind == "URI":
            target = pk.text(pk.get(action, "/URI"))
            if target:
                result.links.append(target)
        elif kind in ("Launch", "GoToR", "GoToE", "SubmitForm", "ImportData"):
            f = pk.get(action, "/F")
            target = pk.text(pk.get(f, "/F")) if f is not None and hasattr(f, "get") else pk.text(f)
            if kind == "SubmitForm":
                target = pk.text(pk.get(action, "/F")) or target
        elif kind == "JavaScript":
            js = pk.get(action, "/JS")
            code = ""
            try:
                is_stream = isinstance(js, pk.Stream)
                code = js.read_bytes().decode("utf-8", "replace") if is_stream else (pk.text(js) or "")
            except Exception as exc:
                code = f"<unreadable: {exc}>"
            result.scripts.append(
                ScriptItem(location, trigger, len(code), pk.sha256(code.encode("utf-8")), code[:MAX_CODE])
            )
        result.actions.append(ActionItem(location, trigger, kind, target))
        nxt = pk.get(action, "/Next")
        if nxt is not None:
            for item in nxt if hasattr(nxt, "__len__") and not hasattr(nxt, "keys") else [nxt]:
                self._action(item, location, f"{trigger}/Next", result, depth + 1)

    def _aa(self, obj: Any, location: str, result: Interactive) -> None:
        aa = pk.get(obj, "/AA")
        if aa is not None:
            for key in aa.keys():
                self._action(aa.get(key), location, f"AA{key}", result)

    def _document_actions(self, root: Any, result: Interactive) -> None:
        open_action = pk.get(root, "/OpenAction")
        if open_action is not None and hasattr(open_action, "get") and pk.get(open_action, "/S") is not None:
            self._action(open_action, "Catalog", "OpenAction", result)
        self._aa(root, "Catalog", result)

    def _names(self, root: Any, result: Interactive) -> None:
        names = pk.get(root, "/Names")
        if names is None:
            return
        for key, action in pk.name_tree_items(pk.get(names, "/JavaScript")):
            self._action(action, "Names/JavaScript", key or "(unnamed)", result)
        for key, spec in pk.name_tree_items(pk.get(names, "/EmbeddedFiles")):
            result.embedded_files.append(self._file(spec, key, "Names/EmbeddedFiles"))
        result.named_destinations = len(pk.name_tree_items(pk.get(names, "/Dests")))

    @staticmethod
    def _file(spec: Any, key: str, location: str) -> EmbeddedFile:
        ef = pk.get(spec, "/EF")
        stream = pk.get(ef, "/F") or pk.get(ef, "/UF")
        params = pk.get(stream, "/Params")
        item = EmbeddedFile(
            name=key,
            filename=pk.text(pk.get(spec, "/UF")) or pk.text(pk.get(spec, "/F")),
            description=pk.text(pk.get(spec, "/Desc")),
            mime_type=pk.name(pk.get(stream, "/Subtype")),
            size=None,
            declared_size=int(pk.get(params, "/Size")) if pk.get(params, "/Size") is not None else None,
            created=_date(pk.get(params, "/CreationDate")),
            modified=_date(pk.get(params, "/ModDate")),
            sha256=None,
            declared_checksum=bytes(pk.get(params, "/CheckSum")).hex()
            if pk.get(params, "/CheckSum") is not None
            else None,
            relationship=pk.name(pk.get(spec, "/AFRelationship")),
            location=location,
        )
        if stream is not None:
            try:
                data = stream.read_bytes()
                item.size, item.sha256 = len(data), pk.sha256(data)
            except Exception as exc:
                item.error = f"{type(exc).__name__}: {exc}"
        return item

    # ---------------------------------------------------------------- pages
    def _pages(self, ctx: AnalysisContext, pdf: Any, result: Interactive) -> None:
        for number, page in enumerate(pdf.pages, start=1):
            ctx.check_cancelled()
            self._aa(page.obj, f"page {number}", result)
            for annot in pk.get(page.obj, "/Annots") or []:
                if len(result.annotations) >= MAX_ANNOTS:
                    return
                subtype = pk.name(pk.get(annot, "/Subtype")) or "?"
                flags = pk.get(annot, "/F")
                flag_value = int(flags) if flags is not None else None
                action = pk.get(annot, "/A")
                uri = pk.text(pk.get(action, "/URI")) if action is not None else None
                result.annotations.append(
                    Annotation(
                        page=number,
                        subtype=subtype,
                        rect=pk.numbers(pk.get(annot, "/Rect")),
                        contents=(pk.text(pk.get(annot, "/Contents")) or None),
                        author=pk.text(pk.get(annot, "/T")) if subtype != "Widget" else None,
                        modified=_date(pk.get(annot, "/M")),
                        created=_date(pk.get(annot, "/CreationDate")),
                        uri=uri,
                        action=pk.name(pk.get(action, "/S")) if action is not None else None,
                        flags=flag_value,
                        hidden=bool(flag_value and flag_value & HIDDEN_FLAGS),
                        name=pk.text(pk.get(annot, "/NM")),
                    )
                )
                if action is not None:
                    self._action(action, f"page {number} {subtype} annotation", "A", result)
                self._aa(annot, f"page {number} {subtype} annotation", result)
                if subtype == "FileAttachment" and pk.get(annot, "/FS") is not None:
                    result.embedded_files.append(
                        self._file(pk.get(annot, "/FS"), f"page {number}", "FileAttachment annotation")
                    )

    # ---------------------------------------------------------------- forms
    def _forms(self, root: Any, result: Interactive) -> None:
        acro = pk.get(root, "/AcroForm")
        if acro is None:
            return
        result.form_type = "XFA" if pk.get(acro, "/XFA") is not None else "AcroForm"
        stack = [(f, "") for f in (pk.get(acro, "/Fields") or [])]
        seen: set[tuple[int, int]] = set()
        while stack and len(result.form_fields) < 20_000:
            field, parent = stack.pop()
            key = pk.objgen(field)
            if key != (0, 0) and key in seen:
                continue
            seen.add(key)
            partial = pk.text(pk.get(field, "/T")) or ""
            full = f"{parent}.{partial}" if parent and partial else (partial or parent)
            kids = pk.get(field, "/Kids")
            if kids is not None and any(pk.get(k, "/T") is not None for k in kids):
                stack.extend((k, full) for k in kids)
                continue
            value = pk.get(field, "/V")
            result.form_fields.append(
                FormField(
                    name=full or "(unnamed)",
                    field_type=pk.name(pk.get(field, "/FT")),
                    value=(pk.text(value) or "")[:2000]
                    if value is not None and not isinstance(value, (pk.Stream, pk.Dictionary))
                    else None,
                    flags=int(pk.get(field, "/Ff")) if pk.get(field, "/Ff") is not None else None,
                    has_actions=pk.get(field, "/AA") is not None,
                )
            )
            self._aa(field, f"field {full}", result)

    # ----------------------------------------------------------- signatures
    def _signatures(self, ctx: AnalysisContext, root: Any, result: Interactive) -> None:
        acro = pk.get(root, "/AcroForm")
        if acro is None:
            return
        size = len(ctx.raw_bytes)
        stack = list(pk.get(acro, "/Fields") or [])
        guard = 0
        while stack and guard < 20_000:
            guard += 1
            field = stack.pop()
            stack.extend(pk.get(field, "/Kids") or [])
            if pk.name(pk.get(field, "/FT")) != "Sig" or pk.get(field, "/V") is None:
                continue
            sig = pk.get(field, "/V")
            info = SignatureInfo(
                field_name=pk.text(pk.get(field, "/T")) or "(unnamed)",
                filter=pk.name(pk.get(sig, "/Filter")),
                subfilter=pk.name(pk.get(sig, "/SubFilter")),
                signing_time=_date(pk.get(sig, "/M")),
                name=pk.text(pk.get(sig, "/Name")),
                reason=pk.text(pk.get(sig, "/Reason")),
                location=pk.text(pk.get(sig, "/Location")),
                contact=pk.text(pk.get(sig, "/ContactInfo")),
            )
            try:
                info.byte_range = [int(v) for v in pk.get(sig, "/ByteRange") or []]
                if len(info.byte_range) == 4:
                    a, _b, c, d = info.byte_range
                    info.covers_whole_file = a == 0 and c + d == size
                    info.bytes_after_signed_range = size - (c + d)
                contents = bytes(pk.get(sig, "/Contents") or b"")
                info.contents_length = len(contents)
                info.certificates = describe_pkcs7(contents)
            except Exception as exc:
                info.error = f"{type(exc).__name__}: {exc}"
            result.signatures.append(info)


def _der_length(data: bytes) -> int | None:
    """Total length of the DER element at the start of ``data`` (strips /Contents padding)."""
    if len(data) < 2 or data[0] != 0x30:
        return None
    first = data[1]
    if first < 0x80:
        return 2 + first
    count = first & 0x7F
    if count == 0 or count > 4 or len(data) < 2 + count:
        return None
    return 2 + count + int.from_bytes(data[2 : 2 + count], "big")


def describe_pkcs7(contents: bytes) -> list[dict[str, Any]]:
    """Certificates contained in a PKCS#7/CMS signature (not validated)."""
    from cryptography.hazmat.primitives.serialization import pkcs7

    length = _der_length(contents)
    der = contents[:length] if length else contents.rstrip(b"\x00")
    certs = pkcs7.load_der_pkcs7_certificates(der)
    described = []
    for cert in certs:
        described.append(
            {
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "serial": format(cert.serial_number, "x"),
                "not_before": cert.not_valid_before_utc.isoformat(),
                "not_after": cert.not_valid_after_utc.isoformat(),
                "sha256_fingerprint": cert.fingerprint(
                    __import__("cryptography.hazmat.primitives.hashes", fromlist=["SHA256"]).SHA256()
                ).hex(),
            }
        )
    return described
