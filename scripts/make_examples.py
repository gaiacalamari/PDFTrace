"""Regenerate docs/examples/report.{json,html,md} from the synthetic "forensic" fixture."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from tests.fixtures.builder import write_all  # noqa: E402

from pdftrace.config import Settings  # noqa: E402
from pdftrace.core import report  # noqa: E402
from pdftrace.core.pipeline import analyze  # noqa: E402

if __name__ == "__main__":
    out = ROOT / "docs" / "examples"
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        pdf = write_all(Path(tmp))["forensic"]
        analysis = analyze(pdf, Settings(external_tools="all"))
        analysis.file.path = f"examples/{pdf.name}"  # do not leak local paths
        report.write_json(analysis, out / "report.json", include_page_boxes=False)
        report.write_html(analysis, out / "report.html")
        report.write_markdown(analysis, out / "report.md")
    print(f"Examples written to {out}")
