from pdftrace.analyzers.text import find_dates
from pdftrace.core.pipeline import analyze
from tests.conftest import needs_poppler


@needs_poppler
def test_pdffonts_and_fonttools(analyses) -> None:  # type: ignore[no-untyped-def]
    (font,) = analyses["rich"].fonts
    assert font.source == "pdffonts" and font.subset and font.subset_tag == "ABCDEF"
    info = font.embedded_info
    assert info is not None and info.error is None
    assert info.family == "FixtureSans" and info.glyph_count == 4 and info.vendor == "TEST"
    assert info.head["modified"] == "2025-06-01T12:00:00+00:00"
    assert info.head["created"] == "2001-02-03T04:05:06+00:00"
    assert {"head", "cmap", "glyf", "name", "OS/2"} <= set(info.tables)
    assert font.pages_used == [1, 2] and font.chars_rendered > 0


def test_font_fallback_without_poppler(pdfs, no_poppler) -> None:  # type: ignore[no-untyped-def]
    analysis = analyze(pdfs["rich"], no_poppler)
    (font,) = analysis.fonts
    assert font.source == "pdfminer_page_resources" and font.embedded
    assert font.embedded_info is not None and font.embedded_info.glyph_count == 4
    images = analysis.images
    assert {i.source for i in images} == {"pdfplumber"} and {i.page for i in images} == {1, 2}
    assert any(f.title.startswith("Analysis limited") for f in analysis.findings)


@needs_poppler
def test_images_reuse_and_bbox(analyses) -> None:  # type: ignore[no-untyped-def]
    images = analyses["rich"].images
    assert len(images) == 2 and {i.object_id for i in images} == {images[0].object_id}
    assert images[0].width == 4 and images[0].height == 2 and images[0].bbox is not None


def test_pages_and_text(analyses) -> None:  # type: ignore[no-untyped-def]
    page = analyses["simple"].pages[0]
    assert "Hello forensic world" in page.text
    assert (page.width, page.height) == (612.0, 792.0) and page.words == 4
    assert any(b.kind == "word" for b in page.boxes)
    assert analyses["scanned"].text.empty_pages == [1]
    assert analyses["simple"].text.date_mentions[0].normalized == "2024-03-12"


def test_find_dates() -> None:
    found = {
        d.normalized
        for d in find_dates(
            "entro il 30 giugno 2024, idealmente 30/6/2024; pagamento a fine febbraio 2024; ISO 2023-05-01", 1
        )
    }
    assert found == {"2024-06-30", "2024-02", "2023-05-01"}
