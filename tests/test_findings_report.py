import csv
import json

from pdftrace.core import report
from pdftrace.core.findings import FindingsEngine
from pdftrace.core.models import Severity
from tests.conftest import titles


def test_font_date_warning(analyses) -> None:  # type: ignore[no-untyped-def]
    found = titles(analyses["rich"])
    assert "Embedded font built after the declared Info CreationDate" in found
    assert "Earliest possible generation date from embedded fonts" in found
    assert "Metadata difference: Author" in found
    assert "Post-processing by another PDF software" in found


def test_incremental_findings(analyses) -> None:  # type: ignore[no-untyped-def]
    found = titles(analyses["incremental"])
    assert "1 incremental update(s)" in found
    assert "Info: modification date earlier than creation date" in found
    assert "Several Info dictionaries across revisions" in found
    assert "Object numbers defined more than once" in found


def test_other_findings(analyses) -> None:  # type: ignore[no-untyped-def]
    assert "Image-only pages" in titles(analyses["scanned"])
    assert "1 font(s) not embedded" in titles(analyses["simple"])


def test_neutral_wording_and_ids(analyses) -> None:  # type: ignore[no-untyped-def]
    for analysis in analyses.values():
        ids = [f.id for f in analysis.findings]
        assert ids == [f"F-{i:03d}" for i in range(1, len(ids) + 1)]
        text = " ".join(f"{f.title} {f.description}" for f in analysis.findings).lower()
        assert "forged" not in text and "malicious" not in text and "fake" not in text
        ranks = [f.severity.rank for f in analysis.findings]
        assert ranks == sorted(ranks, reverse=True)


def test_broken_rule_is_isolated(analyses) -> None:  # type: ignore[no-untyped-def]
    def broken(a, s):  # type: ignore[no-untyped-def]
        raise RuntimeError("boom")
        yield

    findings = FindingsEngine([broken]).evaluate(analyses["simple"])
    assert findings[0].severity == Severity.INFO and "boom" in findings[0].description


def test_json_report(analyses) -> None:  # type: ignore[no-untyped-def]
    data = json.loads(report.to_json(analyses["rich"]))
    for key in (
        "file",
        "hashes",
        "metadata",
        "structure",
        "fonts",
        "images",
        "pages",
        "findings",
        "timeline",
        "summary",
        "tools",
        "steps",
    ):
        assert key in data
    assert data["findings"][0]["severity"] in {"info", "notice", "warning"}
    assert data["metadata"]["info"][0]["source"] == "pdf_info_dictionary"


def test_html_escapes_untrusted_values(analyses) -> None:  # type: ignore[no-untyped-def]
    html = report.to_html(analyses["simple"])
    assert "<script>" not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "Content-Security-Policy" in html


def test_markdown(analyses) -> None:  # type: ignore[no-untyped-def]
    md = report.to_markdown(analyses["rich"])
    assert md.startswith("# PDFTrace report") and "## Findings" in md


def test_csv_formula_injection(analyses, tmp_path) -> None:  # type: ignore[no-untyped-def]
    files = report.write_csv_dir(analyses["simple"], tmp_path)
    assert {f.name for f in files} >= {"metadata.csv", "fonts.csv", "findings.csv", "timeline.csv"}
    with (tmp_path / "metadata.csv").open(encoding="utf-8") as handle:
        values = [row["value"] for row in csv.DictReader(handle)]
    assert '\'=HYPERLINK("x")' in values
