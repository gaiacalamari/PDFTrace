"""Write the test fixture PDFs to tests/fixtures/pdf/ (they are also built on the fly by the tests)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests.fixtures.builder import write_all  # noqa: E402

if __name__ == "__main__":
    for name, path in write_all(ROOT / "tests" / "fixtures" / "pdf").items():
        print(f"{name:12s} {path.stat().st_size:6d} bytes  {path}")
