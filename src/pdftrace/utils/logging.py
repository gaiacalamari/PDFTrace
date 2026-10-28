"""Structured logging helpers.

Log records carry an ``event`` name plus key/value context, rendered as
``event key=value ...``: easy to grep and to parse, with no extra dependency.
"""

from __future__ import annotations

import logging
from typing import Any

LOGGER_NAME = "pdftrace"


class KeyValueFormatter(logging.Formatter):
    """Render ``extra={"ctx": {...}}`` as ``key=value`` pairs."""

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        ctx = getattr(record, "ctx", None)
        if isinstance(ctx, dict) and ctx:
            pairs = " ".join(f"{k}={v!r}" for k, v in ctx.items())
            return f"{base} {pairs}"
        return base


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a child logger of the package logger."""
    return logging.getLogger(LOGGER_NAME if not name else f"{LOGGER_NAME}.{name}")


def configure_logging(level: int = logging.WARNING) -> None:
    """Install a key/value formatter on the package logger (idempotent)."""
    logger = logging.getLogger(LOGGER_NAME)
    if not any(getattr(h, "_pdftrace", False) for h in logger.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(KeyValueFormatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        handler._pdftrace = True  # type: ignore[attr-defined]
        logger.addHandler(handler)
    logger.setLevel(level)


def log_event(logger: logging.Logger, level: int, event: str, **ctx: Any) -> None:
    """Log ``event`` with structured context."""
    logger.log(level, event, extra={"ctx": ctx})
