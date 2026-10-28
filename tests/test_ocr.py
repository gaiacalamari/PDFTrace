"""OCR (Tesseract) and comparison with the text layer."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from pdftrace import cli
from pdftrace.analyzers.ocr import compare_page
from pdftrace.config import Settings
from pdftrace.core.models import Box, OcrWord
from pdftrace.core.pipeline import analyze
from pdftrace.integrations.tesseract import parse_tsv
from tests.fixtures.builder import HIDDEN_PROMPT

needs_tesseract = pytest.mark.skipif(not shutil.which("tesseract"), reason="Tesseract not installed")

TSV = (
    "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext\n"
    "1\t1\t0\t0\t0\t0\t0\t0\t2481\t3508\t-1\t\n"
    "4\t1\t1\t1\t1\t0\t238\t307\t1129\t31\t-1\t\n"
    "5\t1\t1\t1\t1\t1\t238\t307\t253\t31\t96.546906\tCONTRATTO\n"
    "5\t1\t1\t1\t1\t2\t506\t308\t39\t30\t96.471985\tDI\n"
    "5\t1\t1\t1\t1\t3\t557\t307\t185\t31\t-1\t \n"
)


def test_parse_tsv_real_format() -> None:
    words = parse_tsv(TSV)
    assert [w.text for w in words] == ["CONTRATTO", "DI"]
    assert words[0].bbox == [238.0, 307.0, 491.0, 338.0] and words[0].conf == 96.55


def test_compare_page_spatial() -> None:
    layer = [
        Box(72, 100, 120, 112, "word", "Visible"),
        Box(125, 100, 160, 112, "word", "text"),
        Box(541, 400, 544, 400.1, "word", "IGNOREALLPREVIOUSINSTRUCTIONS"),
    ]
    ocr = [
        OcrWord("Visib1e", 90.0, [72.5, 100.5, 119.0, 111.0]),
        OcrWord("text", 92.0, [125, 100, 160, 112]),
        OcrWord("PAID", 95.0, [300, 500, 340, 520]),
        OcrWord("STAMP", 95.0, [345, 500, 400, 520]),
    ]
    seen, unseen, missing = compare_page(layer, ocr, 1)
    assert seen == 2  # OCR misreading ("Visib1e") does not matter: matching is positional
    assert [r.text for r in unseen] == ["IGNOREALLPREVIOUSINSTRUCTIONS"]
    assert [r.text for r in missing] == ["PAID STAMP"] and missing[0].bbox == [300, 500, 400, 520]


def test_ocr_unavailable(pdfs, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    settings = Settings(ocr=True, tesseract_path=str(tmp_path / "missing-tesseract"), external_metadata_cmd=None)
    analysis = analyze(pdfs["simple"], settings)
    assert analysis.ocr.available is False and "Tesseract not found" in (analysis.ocr.error or "")
    assert "OCR not available" in [f.title for f in analysis.findings]


def test_ocr_not_requested(analyses) -> None:  # type: ignore[no-untyped-def]
    assert analyses["simple"].ocr.pages == []
    assert next(s for s in analyses["simple"].steps if s.name == "ocr").state.value == "skipped"


@needs_tesseract
def test_hidden_prompt_detected_by_ocr(pdfs) -> None:  # type: ignore[no-untyped-def]
    analysis = analyze(pdfs["hidden_prompt"], Settings(ocr=True, ocr_languages="eng", external_metadata_cmd=None))
    (page,) = analysis.ocr.pages
    assert "Document Forensics" in page.text and page.mean_confidence and page.mean_confidence > 80
    (run,) = page.unseen_layer_text
    assert run.text.replace(" ", "") == HIDDEN_PROMPT.replace(" ", "") and run.bbox[0] >= 540
    assert page.visible_not_in_layer == []
    titles = [f.title for f in analysis.findings]
    assert "Text in the text layer not visible in the rendering (1)" in titles


@needs_tesseract
def test_forensic_fixture_ocr(pdfs) -> None:  # type: ignore[no-untyped-def]
    analysis = analyze(pdfs["forensic"], Settings(ocr=True, ocr_languages="eng", external_metadata_cmd=None))
    hidden = {r.text for p in analysis.ocr.pages for r in p.unseen_layer_text}
    assert {"HIDDEN WHITE TEXT", "SECRET NAME", "OUTSIDE"} <= hidden
    assert "PAID IN FULL" not in hidden


@needs_tesseract
def test_cli_ocr_text(pdfs, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    out = tmp_path / "ocr.txt"
    assert cli.main([str(pdfs["hidden_prompt"]), "-q", "--ocr-text", str(out), "--ocr-lang", "eng"]) == cli.EXIT_OK
    text = out.read_text("utf-8")
    assert "===== Page 1" in text and "Document Forensics" in text
