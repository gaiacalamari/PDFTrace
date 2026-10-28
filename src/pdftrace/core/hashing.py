"""Cryptographic hashes of the input file (read-only, streamed)."""

from __future__ import annotations

import hashlib
from pathlib import Path

from pdftrace.core.models import Hashes

CHUNK = 1024 * 1024


def hash_file(path: Path) -> Hashes:
    """Compute SHA-256 (primary), SHA-1 and MD5 in a single pass."""
    sha256, sha1, md5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()  # noqa: S324
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK):
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
    return Hashes(sha256=sha256.hexdigest(), sha1=sha1.hexdigest(), md5=md5.hexdigest())
