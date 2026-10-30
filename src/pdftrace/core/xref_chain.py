"""Revision reconstruction by following the cross-reference chain.

ISO 32000-2, 7.5.5-7.5.8: a reader starts from the last ``startxref``, reads
that cross-reference section (classic table or xref stream) with its trailer,
and follows ``/Prev`` back to the original section. Each section reached is one
revision; the two sections of a linearized file (Annex F) form a single one.
A revision ends at the ``%%EOF`` that closes the ``startxref`` placed right
after its section, and the file truncated there is that earlier version.

Counting ``%%EOF`` occurrences is not used to count revisions: the marker can
occur inside embedded data (an attached PDF, a binary stream) and a linearized
file has one more marker than revisions. Markers that do not close a reachable
section are reported as *orphans*; cross-reference sections found in the bytes
but not reachable from the trailer are reported as *unreachable*; those outside
stream data and closed by their own ``startxref``/``%%EOF`` are *detached
revisions*: complete earlier versions that a conforming reader no longer sees
(e.g. a later writer appended a full xref section without ``/Prev``).

Pure byte parsing with no third-party parser, so it also works on files that
pdfminer or qpdf reject and stays independent from them for cross-checks.
"""

from __future__ import annotations

import bisect
import re

from pdftrace.core.models import RevisionInfo, XrefChain, XrefSection

MAX_SECTIONS = 10_000
MAX_DEPTH = 64
#: Bytes around a declared offset searched when nothing is found exactly there.
OFFSET_WINDOW = 512

_WS = b" \t\r\n\f\x00"
_DELIM = b"()<>[]{}/%"

_EOF_RE = re.compile(rb"%%EOF")
_STARTXREF_RE = re.compile(rb"startxref\s+(\d+)")
_CLOSE_RE = re.compile(rb"startxref\s+(\d+)\s+%%EOF")
_OBJ_HDR_RE = re.compile(rb"(?<![0-9])(\d{1,10})\s+(\d{1,5})\s+obj(?=[\s<\[(/%])")
_XREF_KW_RE = re.compile(rb"(?<![^\r\n])xref(?=\s)")  # at line start, excludes "startxref"
_XREF_TYPE_RE = re.compile(rb"/Type\s*/XRef(?![A-Za-z0-9])")
_REF_TAIL_RE = re.compile(rb"\s+\d+\s+R(?=[\s()<>\[\]{}/%]|$)")
_COMMENT_RE = re.compile(rb"%[^\r\n]*")
_TRAILER_KEYS = ("Size", "Root", "Info", "ID", "Encrypt", "Prev", "XRefStm")


class _ParseError(ValueError):
    pass


# ------------------------------------------------------------------ lexer
def _skip_ws(data: bytes, pos: int) -> int:
    n = len(data)
    while pos < n:
        c = data[pos]
        if c in _WS:
            pos += 1
        elif c == 0x25 and not data.startswith(b"%%EOF", pos):  # comment
            while pos < n and data[pos] not in b"\r\n":
                pos += 1
        else:
            break
    return pos


def _value_end(data: bytes, pos: int, depth: int) -> int:
    """End offset of the PDF object starting at ``pos`` (no evaluation)."""
    if depth > MAX_DEPTH:
        raise _ParseError("nesting too deep")
    n = len(data)
    if pos >= n:
        raise _ParseError("unexpected end of data")
    c = data[pos]
    if data.startswith(b"<<", pos):
        return _parse_dict(data, pos, depth)[1]
    if c == 0x3C:  # <hex string>
        end = data.find(b">", pos)
        if end < 0:
            raise _ParseError("unterminated hex string")
        return end + 1
    if c == 0x5B:  # [array]
        pos += 1
        while True:
            pos = _skip_ws(data, pos)
            if pos >= n:
                raise _ParseError("unterminated array")
            if data[pos] == 0x5D:
                return pos + 1
            pos = _value_end(data, pos, depth + 1)
    if c == 0x28:  # (literal string)
        level, i = 0, pos
        while i < n:
            ch = data[i]
            if ch == 0x5C:
                i += 2
                continue
            if ch == 0x28:
                level += 1
            elif ch == 0x29:
                level -= 1
                if level == 0:
                    return i + 1
            i += 1
        raise _ParseError("unterminated string")
    if c == 0x2F:  # /Name
        i = pos + 1
    elif c in _DELIM:
        raise _ParseError(f"unexpected delimiter {chr(c)!r}")
    else:  # number, keyword, R
        i = pos
    while i < n and data[i] not in _WS and data[i] not in _DELIM:
        i += 1
    if i == pos:
        raise _ParseError("empty token")
    return i


def _parse_dict(data: bytes, pos: int, depth: int = 0) -> tuple[dict[str, bytes], int]:
    """Parse ``<< ... >>`` at ``pos``: top-level keys -> raw value bytes, end offset."""
    pos = _skip_ws(data, pos)
    if not data.startswith(b"<<", pos):
        raise _ParseError("dictionary expected")
    pos += 2
    out: dict[str, bytes] = {}
    while True:
        pos = _skip_ws(data, pos)
        if pos >= len(data):
            raise _ParseError("unterminated dictionary")
        if data.startswith(b">>", pos):
            return out, pos + 2
        if data[pos] != 0x2F:
            raise _ParseError("name expected as dictionary key")
        key_end = _value_end(data, pos, depth + 1)
        key = data[pos + 1 : key_end].decode("latin-1")
        start = _skip_ws(data, key_end)
        end = _value_end(data, start, depth + 1)
        if data[start:end].isdigit():
            ref = _REF_TAIL_RE.match(data, end)
            if ref:
                end = ref.end()
        out[key] = data[start:end]
        pos = end


def _int(raw: bytes | None) -> int | None:
    return int(raw) if raw is not None and raw.isdigit() else None


def _text(raw: bytes) -> str:
    return re.sub(rb"\s+", b" ", raw).decode("latin-1")[:300]


# ----------------------------------------------------------- xref sections
def _object_end(data: bytes, dict_end: int, d: dict[str, bytes]) -> int:
    """End of an indirect stream object (after ``endobj``)."""
    pos = _skip_ws(data, dict_end)
    if not data.startswith(b"stream", pos):
        found = data.find(b"endobj", pos)
        return found + 6 if found >= 0 else dict_end
    pos += 6
    if data.startswith(b"\r\n", pos):
        pos += 2
    elif data[pos : pos + 1] in (b"\n", b"\r"):
        pos += 1
    length = _int(d.get("Length"))
    stream_end = -1
    if length is not None and re.match(rb"\s*endstream", data[pos + length : pos + length + 32]):
        stream_end = data.find(b"endstream", pos + length)
    if stream_end < 0:
        stream_end = data.find(b"endstream", pos)
    if stream_end < 0:
        raise _ParseError("endstream not found")
    found = data.find(b"endobj", stream_end)
    return found + 6 if found >= 0 else stream_end + 9


def _section_at(data: bytes, pos: int, declared: int) -> XrefSection | None:
    """Parse a cross-reference section starting exactly at ``pos``."""
    try:
        if data.startswith(b"xref", pos) and data[pos + 4 : pos + 5] in (b" ", b"\t", b"\r", b"\n", b"\f"):
            trailer_at = data.find(b"trailer", pos + 4)
            if trailer_at < 0 or data.find(b"%%EOF", pos, trailer_at) >= 0:
                return None
            d, end = _parse_dict(data, trailer_at + 7)
            kind = "table"
        else:
            hdr = _OBJ_HDR_RE.match(data, pos)
            if not hdr:
                return None
            d, dict_end = _parse_dict(data, hdr.end())
            if d.get("Type", b"").strip() != b"/XRef":
                return None
            end = _object_end(data, dict_end, d)
            kind = "stream"
    except _ParseError:
        return None
    return XrefSection(
        offset=pos,
        declared_offset=declared,
        kind=kind,
        end=end,
        prev=_int(d.get("Prev")),
        xref_stm=_int(d.get("XRefStm")) if kind == "table" else None,
        trailer={k: _text(d[k]) for k in _TRAILER_KEYS if k in d},
    )


def _locate(data: bytes, declared: int, header_offset: int) -> tuple[XrefSection, str | None] | None:
    """Find the section a declared offset points to, tolerating common writer errors."""
    candidates: list[tuple[int, str | None]] = [(declared, None)]
    if header_offset:
        candidates.append(
            (declared + header_offset, f"offset {declared} is relative to the %PDF header (+{header_offset})")
        )
    for offset, note in candidates:
        if 0 <= offset < len(data):
            section = _section_at(data, _skip_ws(data, offset), declared)
            if section:
                return section, note
    centres = sorted({declared, declared + header_offset})
    starts: set[int] = set()
    for centre in centres:
        lo, hi = max(0, centre - OFFSET_WINDOW), min(len(data), centre + OFFSET_WINDOW)
        starts.update(m.start() for m in _XREF_KW_RE.finditer(data, lo, hi))
        starts.update(m.start() for m in _OBJ_HDR_RE.finditer(data, lo, hi))
    for start in sorted(starts, key=lambda s: min(abs(s - c) for c in centres)):
        section = _section_at(data, start, declared)
        if section:
            return section, f"declared offset {declared}: section found at {start} ({start - declared:+d} bytes)"
    return None


def _section_before(data: bytes, startxref: re.Match[bytes]) -> XrefSection | None:
    """The section that ends right before a ``startxref`` keyword (reader-style repair)."""
    lo = max(0, startxref.start() - 4 * 1024 * 1024)
    starts = [m.start() for m in _XREF_KW_RE.finditer(data, lo, startxref.start())]
    for match in _XREF_TYPE_RE.finditer(data, lo, startxref.start()):
        headers = list(_OBJ_HDR_RE.finditer(data, max(0, match.start() - 512), match.start()))
        if headers:
            starts.append(headers[-1].start())
    for start in sorted(set(starts), reverse=True):
        section = _section_at(data, start, int(startxref.group(1)))
        if section is not None:
            close = _close_after(data, section.end)
            return section if close is not None and close.start() == startxref.start() else None
    return None


def _close_after(data: bytes, anchor: int) -> re.Match[bytes] | None:
    """The ``startxref N %%EOF`` that immediately follows ``anchor``, if any."""
    match = _CLOSE_RE.search(data, anchor)
    if match is None:
        return None
    gap = _COMMENT_RE.sub(b"", data[anchor : match.start()])
    return match if not gap.strip(_WS) else None


def _after_eol(data: bytes, pos: int) -> int:
    if data.startswith(b"\r\n", pos):
        return pos + 2
    if data[pos : pos + 1] in (b"\r", b"\n"):
        return pos + 1
    return pos


class _StreamSpans:
    """Byte ranges of stream data, computed once from object headers and /Length.

    A nested PDF stored in a stream contains its own ``stream``/``endstream``
    keywords, so "nearest keyword" tests fail exactly where they matter. Spans
    are measured with /Length (direct, or an indirect integer object) and the
    scan resumes after each stream, so objects of a nested file are skipped.
    """

    def __init__(self, data: bytes) -> None:
        self.data = data
        self._spans: list[tuple[int, int]] | None = None

    def contains(self, offset: int) -> bool:
        if self._spans is None:
            self._spans = self._compute()
        index = bisect.bisect_right(self._spans, (offset, float("inf"))) - 1
        return index >= 0 and self._spans[index][0] <= offset < self._spans[index][1]

    def _length(self, raw: bytes | None) -> int | None:
        if raw is None:
            return None
        if raw.isdigit():
            return int(raw)
        ref = re.fullmatch(rb"(\d+)\s+(\d+)\s+R", raw)
        if not ref:
            return None
        target = re.search(
            rb"(?<![0-9])" + ref.group(1) + rb"\s+" + ref.group(2) + rb"\s+obj\s+(\d+)\s+endobj", self.data
        )
        return int(target.group(1)) if target else None

    def _compute(self) -> list[tuple[int, int]]:
        data, pos = self.data, 0
        spans: list[tuple[int, int]] = []
        while True:
            hdr = _OBJ_HDR_RE.search(data, pos)
            if hdr is None:
                return spans
            pos = hdr.end()
            try:
                d, dict_end = _parse_dict(data, hdr.end())
            except _ParseError:
                continue
            start = _skip_ws(data, dict_end)
            if not data.startswith(b"stream", start):
                continue
            start = _after_eol(data, start + 6)
            length = self._length(d.get("Length"))
            if length is not None and re.match(rb"\s*endstream", data[start + length : start + length + 32]):
                end = start + length
            else:
                end = data.find(b"endstream", start)
                if end < 0:
                    continue
            spans.append((start, end))
            pos = end


def _linearization(data: bytes, header_offset: int) -> tuple[bool, int | None]:
    first = _OBJ_HDR_RE.search(data, header_offset, header_offset + 1024)
    if not first:
        return False, None
    try:
        d, _ = _parse_dict(data, first.end())
    except _ParseError:
        return False, None
    if "Linearized" not in d:
        return False, None
    return True, _int(d.get("L"))


# ------------------------------------------------------------------ walk
def walk_xref_chain(data: bytes) -> XrefChain:
    """Reconstruct the revisions of ``data`` from its cross-reference chain."""
    chain = XrefChain()
    header = re.search(rb"%PDF-", data[:1024])
    header_offset = header.start() if header else 0
    eof_offsets = [m.start() for m in _EOF_RE.finditer(data)]
    chain.linearized, chain.linearization_length = _linearization(data, header_offset)

    startxrefs = list(_STARTXREF_RE.finditer(data))
    if not startxrefs:
        chain.anomalies.append("no startxref keyword in the file")
        return _eof_fallback(data, chain, eof_offsets)

    hybrid_offsets: set[int] = set()
    seen: set[int] = set()
    declared: int | None = int(startxrefs[-1].group(1))
    via = "last startxref"
    entry = True
    while declared is not None:
        if len(chain.sections) >= MAX_SECTIONS:
            chain.anomalies.append(f"more than {MAX_SECTIONS} sections: walk stopped")
            chain.complete = False
            break
        found = _locate(data, declared, header_offset)
        if found is None and entry:
            repaired = _section_before(data, startxrefs[-1])
            if repaired is not None:
                found = (
                    repaired,
                    f"last startxref {declared} is wrong: using the section that precedes it at {repaired.offset}",
                )
        entry = False
        if found is None:
            chain.anomalies.append(f"{via} points to {declared}, where no cross-reference section was found")
            chain.complete = False
            break
        section, note = found
        if note:
            chain.anomalies.append(note)
        if section.offset in seen:
            chain.anomalies.append(f"/Prev loop: section at {section.offset} reached twice")
            chain.complete = False
            break
        seen.add(section.offset)
        chain.sections.append(section)
        if section.xref_stm is not None:
            companion = _locate(data, section.xref_stm, header_offset)
            if companion is None or companion[0].kind != "stream":
                chain.anomalies.append(
                    f"/XRefStm {section.xref_stm} of section at {section.offset} is not an xref stream"
                )
            else:
                hybrid_offsets.add(companion[0].offset)
        via = f"/Prev of section at {section.offset}"
        declared = section.prev

    if not chain.sections:
        return _eof_fallback(data, chain, eof_offsets)

    _build_revisions(data, chain)
    accounted = {r.eof_offset for r in chain.revisions if r.eof_offset is not None}
    accounted |= _linearization_eofs(data, chain)
    spans = _StreamSpans(data)
    _unreachable_sections(data, chain, seen | hybrid_offsets, spans)
    accounted |= {r.eof_offset for r in chain.detached_revisions if r.eof_offset is not None}
    chain.orphan_eof_offsets = [o for o in eof_offsets if o not in accounted]
    chain.orphan_eof_in_stream = [o for o in chain.orphan_eof_offsets if spans.contains(o)]
    return chain


def _groups(chain: XrefChain) -> list[tuple[list[XrefSection], bool]]:
    """Sections oldest first, grouped into revisions (linearized pair -> one revision)."""
    ordered = list(reversed(chain.sections))
    groups: list[tuple[list[XrefSection], bool]] = []
    start = 0
    if (
        chain.linearized
        and len(ordered) >= 2
        and ordered[1].prev == ordered[0].declared_offset
        and ordered[1].offset < ordered[0].offset
    ):
        groups.append(([ordered[0], ordered[1]], True))
        start = 2
    for section in ordered[start:]:
        groups.append(([section], False))
    for group, _linear in groups[1 if groups and groups[0][1] else 0 :]:
        section = group[0]
        if section.prev is not None and section.prev > section.offset:
            chain.anomalies.append(
                f"section at {section.offset} has /Prev {section.prev} pointing forward "
                "(not explained by linearization)"
            )
    return groups


def _build_revisions(data: bytes, chain: XrefChain) -> None:
    for index, (group, linear) in enumerate(_groups(chain)):
        trailer: dict[str, str] = {}
        for section in group:
            trailer.update(section.trailer)
        revision = RevisionInfo(
            index=index,
            xref_offsets=[s.offset for s in group],
            kinds=[s.kind for s in group],
            linearized=linear,
            trailer=trailer,
        )
        close = _close_after(data, max(s.end for s in group))
        if close is None:
            chain.anomalies.append(
                f"revision {index}: no 'startxref ... %%EOF' right after its cross-reference section"
            )
        else:
            revision.startxref = int(close.group(1))
            revision.eof_offset = close.end() - 5
            revision.end = _after_eol(data, close.end())
            targets = {s.offset for s in group} | {s.declared_offset for s in group}
            if revision.startxref not in targets:
                chain.anomalies.append(
                    f"revision {index}: closing startxref {revision.startxref} does not point to its section"
                )
        chain.revisions.append(revision)
    base = chain.revisions[0] if chain.revisions else None
    if (
        chain.linearization_length is not None
        and base is not None
        and base.linearized
        and base.end is not None
        and base.eof_offset is not None
        and chain.linearization_length not in (base.end, base.eof_offset + 5)
    ):
        chain.anomalies.append(
            f"linearization /L {chain.linearization_length} differs from the end of the "
            f"linearized revision ({base.end})"
        )


def _linearization_eofs(data: bytes, chain: XrefChain) -> set[int]:
    """The %%EOF closing the first-page section of a linearized file is not a revision end."""
    eofs: set[int] = set()
    for revision in chain.revisions:
        if not revision.linearized:
            continue
        first_page = next(s for s in chain.sections if s.offset == min(revision.xref_offsets))
        close = _close_after(data, first_page.end)
        if close is not None:
            eofs.add(close.end() - 5)
    return eofs


def _unreachable_sections(data: bytes, chain: XrefChain, reachable: set[int], spans: _StreamSpans) -> None:
    candidates = [m.start() for m in _XREF_KW_RE.finditer(data)]
    for match in _XREF_TYPE_RE.finditer(data):
        headers = list(_OBJ_HDR_RE.finditer(data, max(0, match.start() - 512), match.start()))
        if headers:
            candidates.append(headers[-1].start())
    for offset in sorted(set(candidates)):
        if offset in reachable:
            continue
        section = _section_at(data, offset, offset)
        if section is None:
            continue
        chain.unreachable_xref_offsets.append(offset)
        if spans.contains(offset):
            chain.unreachable_xref_in_stream.append(offset)
            continue
        close = _close_after(data, section.end)
        if close is not None:
            chain.detached_revisions.append(
                RevisionInfo(
                    index=len(chain.detached_revisions),
                    xref_offsets=[offset],
                    kinds=[section.kind],
                    startxref=int(close.group(1)),
                    eof_offset=close.end() - 5,
                    end=_after_eol(data, close.end()),
                    trailer=section.trailer,
                )
            )


def _eof_fallback(data: bytes, chain: XrefChain, eof_offsets: list[int]) -> XrefChain:
    """Last resort when no section is reachable: one revision per %%EOF (heuristic)."""
    chain.method = "eof_heuristic"
    chain.complete = False
    offsets = eof_offsets[1:] if chain.linearized and len(eof_offsets) > 1 else eof_offsets
    for index, offset in enumerate(offsets):
        chain.revisions.append(RevisionInfo(index=index, eof_offset=offset, end=_after_eol(data, offset + 5)))
    return chain
