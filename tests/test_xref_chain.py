"""Revision reconstruction through startxref and the /Prev chain.

Each test builds a file where counting %%EOF markers gives the wrong answer
(or the right one for the wrong reason) and checks the chain walker.
"""

from __future__ import annotations

import io
import re
import struct
from pathlib import Path

import pikepdf
import pytest

from pdftrace.core.pipeline import analyze
from pdftrace.core.xref_chain import walk_xref_chain
from tests.conftest import titles
from tests.fixtures.builder import PDFBuilder, build_simple, incremental_update


def _base(author: bytes = b"Alice", extra: dict[int, bytes] | None = None) -> tuple[bytes, dict[str, int]]:
    b = PDFBuilder("1.4")
    catalog, pages, page = b.reserve(), b.reserve(), b.reserve()
    content = b.add(b.stream(b"", b"BT /F1 12 Tf 72 720 Td (Hello) Tj ET"))
    font = b.add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    info = b.add(b"<< /Author (" + author + b") /Producer (Fixture) >>")
    b.add(b"<< /Type /Pages /Kids [%d 0 R] /Count 1 >>" % page, pages)
    b.add(
        b"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] /Contents %d 0 R "
        b"/Resources << /Font << /F1 %d 0 R >> >> >>" % (pages, content, font),
        page,
    )
    names = b""
    for body in (extra or {}).values():
        names = b" /Names << /EmbeddedFiles << /Names [(inner.pdf) %d 0 R] >> >>" % b.add(body)
    b.add(b"<< /Type /Catalog /Pages %d 0 R%s >>" % (pages, names), catalog)
    return b.build(catalog, info, ("AA" * 16, "AA" * 16)), {
        "root": catalog,
        "info": info,
        "size": max(b.objects) + 1,
    }


def _last_startxref(data: bytes) -> int:
    return int(re.findall(rb"startxref\s+(\d+)", data)[-1])


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


# --------------------------------------------------------------------- basics
def test_single_revision() -> None:
    data, _ = _base()
    chain = walk_xref_chain(data)
    assert chain.method == "xref_chain" and chain.complete
    assert len(chain.revisions) == 1 and chain.revisions[0].end == len(data)
    assert not chain.orphan_eof_offsets and not chain.unreachable_xref_offsets and not chain.anomalies


def test_incremental_update_truncation_is_byte_exact() -> None:
    base, refs = _base()
    data = incremental_update(base, {refs["info"]: b"<< /Author (Carol) >>"}, refs["root"], refs["info"], refs["size"])
    chain = walk_xref_chain(data)
    assert len(chain.revisions) == 2
    assert data[: chain.revisions[0].end] == base  # the earlier revision is exactly the original file
    assert chain.revisions[1].end == len(data)
    assert chain.revisions[1].trailer["Prev"] == str(_last_startxref(base))


# --------------------------------------------- cases where %%EOF counting fails
def test_eof_inside_embedded_pdf_is_not_a_revision(tmp_path: Path, settings) -> None:  # type: ignore[no-untyped-def]
    inner = build_simple()
    embedded = PDFBuilder.stream(b"/Type /EmbeddedFile", inner)  # uncompressed: inner %%EOF and xref visible
    data, _ = _base(extra={0: embedded})
    assert data.count(b"%%EOF") == 2  # the old method reported one incremental update

    chain = walk_xref_chain(data)
    assert len(chain.revisions) == 1
    assert len(chain.orphan_eof_offsets) == 1 and chain.orphan_eof_in_stream == chain.orphan_eof_offsets
    assert chain.unreachable_xref_offsets == chain.unreachable_xref_in_stream != []

    analysis = analyze(_write(tmp_path, "embedded.pdf", data), settings)
    assert analysis.structure.incremental_updates == 0
    assert len(analysis.metadata.info_revisions) == 1  # no fake earlier revision
    assert "1 %%EOF marker(s) outside the cross-reference chain" in titles(analysis)


def test_linearized_file_is_one_revision(tmp_path: Path, settings) -> None:  # type: ignore[no-untyped-def]
    base, _ = _base()
    out = io.BytesIO()
    with pikepdf.open(io.BytesIO(base)) as pdf:
        pdf.save(out, linearize=True)
    data = out.getvalue()
    assert data.count(b"%%EOF") == 2

    chain = walk_xref_chain(data)
    assert chain.linearized and len(chain.revisions) == 1 and chain.revisions[0].linearized
    assert len(chain.revisions[0].xref_offsets) == 2
    assert not chain.orphan_eof_offsets and not chain.unreachable_xref_offsets

    analysis = analyze(_write(tmp_path, "linear.pdf", data), settings)
    assert analysis.structure.incremental_updates == 0
    assert len(analysis.metadata.info_revisions) == 1  # the first-page section is not an earlier version


def test_update_after_linearization() -> None:
    base, _ = _base()
    out = io.BytesIO()
    with pikepdf.open(io.BytesIO(base)) as pdf:
        pdf.save(out, linearize=True)
    linear = out.getvalue()
    with pikepdf.open(io.BytesIO(linear)) as pdf:  # numbers of the saved file (pikepdf renumbers)
        root, info, size = pdf.trailer.Root.objgen[0], pdf.trailer.Info.objgen[0], int(pdf.trailer.Size)
    data = incremental_update(linear, {info: b"<< /Author (Mallory) >>"}, root, info, size)

    chain = walk_xref_chain(data)
    assert len(chain.revisions) == 2 and chain.revisions[0].linearized
    assert data[: chain.revisions[0].end] == linear
    assert not chain.orphan_eof_offsets


def _xref_stream_update(base: bytes, info: int, root: int, size: int) -> bytes:
    """Append an update whose cross-reference section is an uncompressed xref stream."""
    out = io.BytesIO(base)
    out.seek(0, io.SEEK_END)
    info_at = out.tell()
    out.write(b"%d 0 obj\n<< /Author (Dave) >>\nendobj\n" % info)
    xref_num, xref_at = size, out.tell()
    rows = struct.pack(">BIH", 1, info_at, 0) + struct.pack(">BIH", 1, xref_at, 0)
    out.write(
        b"%d 0 obj\n<< /Type /XRef /Size %d /W [1 4 2] /Index [%d 1 %d 1] /Root %d 0 R /Info %d 0 R "
        b"/Prev %d /Length %d >>\nstream\n"
        % (xref_num, size + 1, info, xref_num, root, info, _last_startxref(base), len(rows))
        + rows
        + b"\nendstream\nendobj\nstartxref\n%d\n%%%%EOF\n" % xref_at
    )
    return out.getvalue()


def test_xref_stream_chain() -> None:
    base, _ = _base()
    out = io.BytesIO()
    with pikepdf.open(io.BytesIO(base)) as pdf:
        pdf.save(out, object_stream_mode=pikepdf.ObjectStreamMode.generate)
    compressed = out.getvalue()
    with pikepdf.open(io.BytesIO(compressed)) as pdf:
        root, info, size = pdf.trailer.Root.objgen[0], pdf.trailer.Info.objgen[0], int(pdf.trailer.Size)
    data = _xref_stream_update(compressed, info, root, size)

    chain = walk_xref_chain(data)
    assert [r.kinds for r in chain.revisions] == [["stream"], ["stream"]]
    assert data[: chain.revisions[0].end] == compressed
    with pikepdf.open(io.BytesIO(data)) as pdf:  # the update is valid for a real reader
        assert str(pdf.trailer.Info.Author) == "Dave"


# ------------------------------------------------------ manipulation evidence
def test_detached_revision_is_reported(tmp_path: Path, settings) -> None:  # type: ignore[no-untyped-def]
    base, refs = _base()
    update = incremental_update(base, {refs["info"]: b"<< /Author (Eve) >>"}, refs["root"], refs["info"], refs["size"])
    data = re.sub(rb" /Prev \d+", b"", update)  # trailer rewritten without /Prev

    chain = walk_xref_chain(data)
    assert len(chain.revisions) == 1 and chain.complete
    assert chain.unreachable_xref_offsets == [_last_startxref(base)]
    assert not chain.unreachable_xref_in_stream
    assert [r.end for r in chain.detached_revisions] == [len(base)]
    assert not chain.orphan_eof_offsets  # its %%EOF closes the detached revision

    analysis = analyze(_write(tmp_path, "detached.pdf", data), settings)
    finding = next(f for f in analysis.findings if f.title == "Cross-reference sections not reachable from the trailer")
    assert finding.severity.value == "warning"
    authors = [(r.values.get("Author"), r.source.split("_")[0]) for r in analysis.metadata.info_revisions]
    assert authors == [("Eve", "current"), ("Alice", "detached")]  # hidden earlier version recovered


def test_prev_loop_terminates() -> None:
    base, refs = _base()
    update = incremental_update(base, {refs["info"]: b"<< /Author (X) >>"}, refs["root"], refs["info"], refs["size"])
    own = _last_startxref(update)
    data = re.sub(rb"/Prev \d+", b"/Prev %d" % own, update)
    chain = walk_xref_chain(data)
    assert not chain.complete and any("loop" in a for a in chain.anomalies)
    assert len(chain.revisions) == 1


def test_offset_slightly_wrong_is_tolerated_and_reported() -> None:
    base, _ = _base()
    good = _last_startxref(base)
    data = base.replace(b"startxref\n%d\n" % good, b"startxref\n%d\n" % (good - 3))
    chain = walk_xref_chain(data)
    assert len(chain.revisions) == 1 and chain.revisions[0].xref_offsets == [good]
    assert any("-3" in a or "+3" in a for a in chain.anomalies)


def test_wrong_entry_startxref_uses_preceding_section() -> None:
    base, _ = _base()
    good = _last_startxref(base)
    data = base.replace(b"startxref\n%d\n" % good, b"startxref\n%d\n" % (good + 5000))
    chain = walk_xref_chain(data)
    assert chain.method == "xref_chain" and chain.revisions[0].xref_offsets == [good]
    assert any("is wrong" in a for a in chain.anomalies)


def test_no_startxref_falls_back_to_heuristic() -> None:
    base, _ = _base()
    data = re.sub(rb"startxref\s+\d+\s+", b"", base)
    chain = walk_xref_chain(data)
    assert chain.method == "eof_heuristic" and not chain.complete
    assert len(chain.revisions) == 1


@pytest.mark.parametrize("junk", [b"", b"JUNK-BEFORE-HEADER\n"])
def test_garbage_is_bounded(junk: bytes) -> None:
    base, _ = _base()
    chain = walk_xref_chain(junk + base[:-40])  # truncated file, possibly shifted
    assert chain.revisions or chain.method == "eof_heuristic"
