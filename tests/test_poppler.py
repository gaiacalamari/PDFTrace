from pathlib import Path

from pdftrace.config import Settings
from pdftrace.integrations.poppler import Poppler, parse_pdffonts, parse_pdfimages_list
from tests.conftest import needs_poppler

PDFFONTS_SAMPLE = """name                                 type              encoding         emb sub uni object ID
------------------------------------ ----------------- ---------------- --- --- --- ---------
BCDEEE+Aptos,Bold                    CID TrueType      Identity-H       yes yes yes     11  0
ABCDEF+AVeryLongFontNameThatOverflowsTheColumn-BoldItalic Type 1C (OT)  Custom  yes yes no  7  0
[none]                               Type 3            Custom           yes no  no      20  0
Helvetica                            Type 1            WinAnsi          no  no  no       5  0
"""

PDFIMAGES_SAMPLE = """page   num  type   width height color comp bpc  enc interp  object ID x-ppi y-ppi size ratio
--------------------------------------------------------------------------------------------
   1     0 image    1920  1080  rgb     3   8  jpeg   no        12  0   300   300  120K 2.0%
   4     1 smask     800   600  gray    1   8  image  yes       31  0    72    72  3.1K 0.7%
"""


def test_parse_pdffonts() -> None:
    rows = parse_pdffonts(PDFFONTS_SAMPLE)
    assert [r.font_type for r in rows] == ["CID TrueType", "Type 1C (OT)", "Type 3", "Type 1"]
    assert rows[1].name == "ABCDEF+AVeryLongFontNameThatOverflowsTheColumn-BoldItalic"
    assert rows[1].encoding == "Custom" and rows[1].object_id == 7
    assert rows[3].embedded is False and rows[0].unicode is True and rows[2].name == "[none]"


def test_parse_pdfimages() -> None:
    images = parse_pdfimages_list(PDFIMAGES_SAMPLE)
    assert len(images) == 2
    first = images[0]
    assert (first.page, first.width, first.height, first.encoding, first.object_id) == (1, 1920, 1080, "jpeg", 12)
    assert images[1].image_type == "smask" and images[1].interpolate is True and images[1].x_ppi == 72.0


def test_missing_poppler_status(no_poppler: Settings) -> None:
    poppler = Poppler(no_poppler)
    assert not poppler.available("pdffonts")
    assert all(not s.available and s.error for s in poppler.status())


@needs_poppler
def test_extract_images(pdfs, settings, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    poppler = Poppler(settings)
    files = poppler.extract_images(pdfs["rich"], tmp_path / "all", fmt="png")
    assert [f.name for f in files] == ["img-001-000.png", "img-002-001.png"]
    single = poppler.extract_single_image(pdfs["rich"], 2, 1, tmp_path / "one")
    assert (single is not None and single.name == "img-p002-n001.png") or single.name.startswith("img-p002-n001.")
