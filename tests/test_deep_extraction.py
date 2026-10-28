"""Deep extraction with the Python libraries (pikepdf, Pillow, cryptography, pypdf, PDFium)."""

from __future__ import annotations

from pathlib import Path

from pdftrace import cli
from pdftrace.analyzers.image_evidence import jpeg_quality
from pdftrace.analyzers.text_forensics import family
from pdftrace.core import report
from pdftrace.integrations.pikepdf_adapter import extract_attachments
from tests.conftest import titles
from tests.fixtures.builder import EXIF_SOFTWARE


def test_objects_inventory(analyses) -> None:  # type: ignore[no-untyped-def]
    o = analyses["forensic"].objects
    assert o.error is None and o.total_objects > 10 and o.streams == 3
    assert o.by_type.get("Annot/Link") == 1 and o.by_filter.get("DCTDecode") == 1
    assert {"AcroForm", "OpenAction", "OCProperties", "PieceInfo", "Names"} <= set(o.catalog_features)
    assert o.layers == [{"name": "Hidden layer", "object": o.layers[0]["object"], "default_off": True}]
    assert o.thumbnails == [1] and o.piece_info == ["Illustrator"]
    assert analyses["corrupted"].objects.error


def test_interactive(analyses) -> None:  # type: ignore[no-untyped-def]
    i = analyses["forensic"].interactive
    note = next(a for a in i.annotations if a.subtype == "Text")
    assert (note.author, note.modified, note.hidden) == ("Reviewer", "2023-05-05T10:10:10+02:00", True)
    assert "https://example.org/x" in i.links
    assert [(s.trigger, s.code) for s in i.scripts] == [("OpenAction", 'app.alert("fixture");')]
    assert {f.name: f.value for f in i.form_fields}["amount"] == "1250"
    (attachment,) = i.embedded_files
    assert attachment.filename == "notes.txt" and attachment.size == 12 and attachment.created.startswith("2019-01-01")


def test_signature_described(analyses) -> None:  # type: ignore[no-untyped-def]
    (sig,) = analyses["forensic"].interactive.signatures
    assert sig.field_name == "Signature1" and sig.subfilter == "adbe.pkcs7.detached"
    assert sig.certificates[0]["subject"] == "CN=Fixture Signer"
    assert sig.covers_whole_file is False and sig.bytes_after_signed_range > 0
    assert "Data added after signature Signature1" in titles(analyses["forensic"])


def test_image_exif(analyses) -> None:  # type: ignore[no-untyped-def]
    (img,) = analyses["forensic"].image_evidence
    assert img.format == "JPEG" and img.camera == "FixtureCam Model X" and img.software == EXIF_SOFTWARE
    assert img.dates["exif:DateTimeOriginal"] == "2029:12:31 09:30:00"
    assert round(img.gps["latitude"], 3) == 45.467 and img.jpeg_quality_estimate in range(65, 86)
    found = titles(analyses["forensic"])
    assert any("processed with image-editing software" in t for t in found)
    assert any("contains GPS coordinates" in t for t in found)
    assert any("dated after the declared creation" in t for t in found)


def test_text_layer_anomalies(analyses) -> None:  # type: ignore[no-untyped-def]
    counts = analyses["forensic"].text_forensics.counts
    assert counts == {
        "invisible_text": 1,
        "outside_page": 1,
        "overlapping_text": 1,
        "covered_text": 1,
        "font_change_in_line": 1,
    }
    change = next(a for a in analyses["forensic"].text_forensics.anomalies if a.kind == "font_change_in_line")
    assert change.details["odd_text"] == "9.999"
    assert analyses["rich"].text_forensics.counts == {}


def test_crosscheck(analyses) -> None:  # type: ignore[no-untyped-def]
    x = analyses["rich"].crosscheck
    assert {"pdfminer", "pikepdf", "pypdf", "pdfium"} <= set(x.parsers)
    assert x.differences == [] and x.pdfium_pages[0]["pdfium_chars"] == 8


def test_timeline_includes_new_sources(analyses) -> None:  # type: ignore[no-untyped-def]
    kinds = {e.kind for e in analyses["forensic"].timeline}
    assert {"annotation_modified", "attachment_created", "signature", "image_metadata"} <= kinds


def test_helpers() -> None:
    assert family("ABCDEF+Arial,Bold") == family("ArialMT") == "arial"
    assert (
        jpeg_quality(
            {
                0: [
                    16,
                    11,
                    10,
                    16,
                    24,
                    40,
                    51,
                    61,
                    12,
                    12,
                    14,
                    19,
                    26,
                    58,
                    60,
                    55,
                    14,
                    13,
                    16,
                    24,
                    40,
                    57,
                    69,
                    56,
                    14,
                    17,
                    22,
                    29,
                    51,
                    87,
                    80,
                    62,
                    18,
                    22,
                    37,
                    56,
                    68,
                    109,
                    103,
                    77,
                    24,
                    35,
                    55,
                    64,
                    81,
                    104,
                    113,
                    92,
                    49,
                    64,
                    78,
                    87,
                    103,
                    121,
                    120,
                    101,
                    72,
                    92,
                    95,
                    98,
                    112,
                    100,
                    103,
                    99,
                ]
            }
        )
        == 50
    )


def test_extract_attachments(pdfs, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    ((path, digest),) = extract_attachments(pdfs["forensic"], tmp_path)
    assert path.read_bytes() == b"secret notes" and len(digest) == 64
    assert cli.main([str(pdfs["forensic"]), "-q", "--extract-attachments", str(tmp_path / "cli")]) == cli.EXIT_OK


def test_reports_include_deep_sections(analyses, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    html = report.to_html(analyses["forensic"])
    for heading in ("Interactive content", "Image metadata", "Text layer anomalies", "Parser cross-check"):
        assert heading in html
    assert "app.alert(&quot;fixture&quot;);" in html
    names = {p.name for p in report.write_csv_dir(analyses["forensic"], tmp_path)}
    assert {"annotations.csv", "signatures.csv", "image_metadata.csv", "text_anomalies.csv"} <= names
