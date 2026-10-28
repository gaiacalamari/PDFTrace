"""Parsing of PDF (ISO 32000 §7.9.4) and XMP (ISO 8601) date strings."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta, timezone

_PDF_DATE = re.compile(
    r"^(?:D:)?(?P<Y>\d{4})(?P<m>\d{2})?(?P<d>\d{2})?(?P<H>\d{2})?(?P<M>\d{2})?(?P<S>\d{2})?"
    r"(?P<tz>[Zz]|[+\-]\d{2}'?(?:\d{2}'?)?)?"
)
_ISO_DATE = re.compile(
    r"^(?P<Y>\d{4})(?:-(?P<m>\d{2})(?:-(?P<d>\d{2})(?:[T ](?P<H>\d{2}):(?P<M>\d{2})"
    r"(?::(?P<S>\d{2})(?:\.\d+)?)?)?)?)?(?P<tz>Z|[+\-]\d{2}:?\d{2})?$"
)


def _tz(value: str | None) -> timezone | None:
    if not value:
        return None
    if value in ("Z", "z"):
        return UTC
    digits = re.sub(r"[^0-9]", "", value[1:])
    hours = int(digits[:2]) if digits[:2] else 0
    minutes = int(digits[2:4]) if digits[2:4] else 0
    delta = timedelta(hours=hours, minutes=minutes)
    return timezone(delta if value[0] == "+" else -delta)


def _build(match: re.Match[str]) -> datetime | None:
    try:
        return datetime(
            int(match["Y"]),
            int(match["m"] or 1),
            int(match["d"] or 1),
            int(match["H"] or 0),
            int(match["M"] or 0),
            int(match["S"] or 0),
            tzinfo=_tz(match["tz"]),
        )
    except ValueError:
        return None


def parse_pdf_date(value: str | None) -> datetime | None:
    """Parse ``D:YYYYMMDDHHmmSSOHH'mm'``. Returns ``None`` when not parseable."""
    if not value:
        return None
    match = _PDF_DATE.match(value.strip())
    return _build(match) if match else None


def parse_iso_date(value: str | None) -> datetime | None:
    """Parse an XMP/ISO 8601 date. Returns ``None`` when not parseable."""
    if not value:
        return None
    match = _ISO_DATE.match(value.strip())
    return _build(match) if match else None


def parse_any_date(value: str | None) -> datetime | None:
    """Try the PDF format for ``D:``/compact values, ISO 8601 otherwise."""
    if not value:
        return None
    text = value.strip()
    if text.startswith("D:") or re.fullmatch(r"\d{8,14}.*", text):
        return parse_pdf_date(text)
    return parse_iso_date(text) or parse_pdf_date(text)


def to_iso(value: datetime | None) -> str | None:
    """ISO 8601 rendering that keeps the original offset (or none if naive)."""
    return value.isoformat() if value else None


def as_aware(value: datetime) -> datetime:
    """Return ``value`` with UTC assumed when it carries no offset."""
    return value if value.tzinfo else value.replace(tzinfo=UTC)
