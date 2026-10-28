import json
import threading
from pathlib import Path

import pytest

from pdftrace import cli
from pdftrace.core.models import StepState
from pdftrace.core.pipeline import Pipeline
from pdftrace.utils.paths import InputError


@pytest.mark.parametrize("name", ["corrupted", "not_pdf"])
def test_malformed_input_does_not_crash(analyses, name) -> None:  # type: ignore[no-untyped-def]
    analysis = analyses[name]
    assert analysis.hashes.sha256
    assert analysis.findings
    assert all(s.state != StepState.ERROR for s in analysis.steps)


def test_not_pdf_header(analyses) -> None:  # type: ignore[no-untyped-def]
    assert "No PDF header" in [f.title for f in analyses["not_pdf"].findings]


def test_missing_file() -> None:
    with pytest.raises(InputError):
        Pipeline().run("/nonexistent/file.pdf")


def test_cancellation(pdfs, settings) -> None:  # type: ignore[no-untyped-def]
    event = threading.Event()
    event.set()
    analysis = Pipeline(settings=settings).run(pdfs["rich"], cancel_event=event)
    assert analysis.hashes.sha256
    assert all(s.state == StepState.CANCELLED for s in analysis.steps[1:])


def test_file_not_modified(pdfs, settings) -> None:  # type: ignore[no-untyped-def]
    path: Path = pdfs["incremental"]
    before = (path.read_bytes(), path.stat().st_mtime_ns)
    Pipeline(settings=settings).run(path)
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


def test_cli_reports(pdfs, tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    out_json, out_html, out_md = tmp_path / "r.json", tmp_path / "r.html", tmp_path / "r.md"
    code = cli.main(
        [
            str(pdfs["rich"]),
            "--json",
            str(out_json),
            "--html",
            str(out_html),
            "--md",
            str(out_md),
            "--csv",
            str(tmp_path / "csv"),
            "--text",
            str(tmp_path / "t.txt"),
        ]
    )
    assert code == cli.EXIT_OK
    assert json.loads(out_json.read_text("utf-8"))["hashes"]["sha256"]
    assert out_html.read_text("utf-8").startswith("<!DOCTYPE html>")
    assert (tmp_path / "csv" / "findings.csv").exists()
    printed = capsys.readouterr().out
    assert "SHA-256:" in printed and "Findings:" in printed


def test_cli_exit_codes(tmp_path) -> None:  # type: ignore[no-untyped-def]
    assert cli.main(["/nonexistent.pdf", "-q"]) == cli.EXIT_INPUT
    assert cli.main([]) == cli.EXIT_INPUT
    assert cli.main(["--check", "--poppler-path", str(tmp_path)]) == cli.EXIT_ERROR


def test_cli_extract_images(pdfs, tmp_path) -> None:  # type: ignore[no-untyped-def]
    from tests.conftest import HAS_POPPLER

    code = cli.main([str(pdfs["rich"]), "-q", "--extract-images", str(tmp_path / "img")])
    if HAS_POPPLER:
        assert code == cli.EXIT_OK and len(list((tmp_path / "img").iterdir())) == 2
    else:
        assert code == cli.EXIT_ERROR
