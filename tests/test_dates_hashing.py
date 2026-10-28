import hashlib
from datetime import timedelta

from pdftrace.core.hashing import hash_file
from pdftrace.utils.pdfdates import parse_any_date, parse_iso_date, parse_pdf_date


def test_pdf_date_with_offset() -> None:
    d = parse_pdf_date("D:20260827105013+02'00'")
    assert d is not None and (d.year, d.month, d.day, d.hour, d.minute, d.second) == (2026, 8, 27, 10, 50, 13)
    assert d.utcoffset() == timedelta(hours=2)


def test_pdf_date_partial_and_utc() -> None:
    assert parse_pdf_date("D:2024").year == 2024  # type: ignore[union-attr]
    assert parse_pdf_date("D:20240101120000Z").utcoffset() == timedelta(0)  # type: ignore[union-attr]
    assert parse_pdf_date("D:20240101120000").tzinfo is None  # type: ignore[union-attr]
    assert parse_pdf_date("garbage") is None
    assert parse_pdf_date("D:20241399") is None  # invalid month


def test_iso_and_any() -> None:
    d = parse_iso_date("2024-01-10T09:00:00+01:00")
    assert d is not None and d.utcoffset() == timedelta(hours=1)
    assert parse_any_date("2024-01-10") is not None
    assert parse_any_date("D:20240110") == parse_pdf_date("D:20240110")


def test_hashes(tmp_path) -> None:  # type: ignore[no-untyped-def]
    data = b"forensics" * 1000
    path = tmp_path / "x.bin"
    path.write_bytes(data)
    h = hash_file(path)
    assert h.sha256 == hashlib.sha256(data).hexdigest()
    assert h.sha1 == hashlib.sha1(data).hexdigest()
    assert h.md5 == hashlib.md5(data).hexdigest()
