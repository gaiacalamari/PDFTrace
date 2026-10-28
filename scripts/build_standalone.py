"""Build the standalone PDFTrace bundle (portable folder, zip and Windows installer).

Usage (from the repository root, in an environment with ``pip install -e ".[gui,build]"``):

    python scripts/build_standalone.py                 # dist/PDFTrace/
    python scripts/build_standalone.py --download --zip --installer   # Windows release

``--download`` fetches (Windows only) the Poppler build from
github.com/oschwartz10612/poppler-windows, the Tesseract OCR installer from
github.com/tesseract-ocr/tesseract (extracted with 7-Zip) with the language
models of tessdata_fast, and pdfid.py / pdf-parser.py from
github.com/DidierStevens/DidierStevensSuite, and records their SHA-256 in
BUILD-INFO.txt. ``--poppler``, ``--tesseract`` and ``--tools`` use local copies
instead; ``--no-tesseract`` skips OCR.
PyInstaller does not cross-compile: run on each target OS.
"""

from __future__ import annotations

import argparse
import hashlib
import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist" / "PDFTrace"
POPPLER_VERSION = "26.09.0-0"
POPPLER_URL = (
    f"https://github.com/oschwartz10612/poppler-windows/releases/download/v{POPPLER_VERSION}/"
    f"Release-{POPPLER_VERSION}.zip"
)
DIDIER = "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/"
SCRIPTS = ("pdfid.py", "pdf-parser.py")
TESSERACT_VERSION = "5.5.3.20260724"
TESSERACT_URL = (
    "https://github.com/tesseract-ocr/tesseract/releases/download/5.5.3/"
    f"tesseract-ocr-w64-setup-{TESSERACT_VERSION}.exe"
)
TESSDATA = "https://raw.githubusercontent.com/tesseract-ocr/tessdata_fast/main/"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, target: Path) -> Path:
    print(f"download {url}")
    with urllib.request.urlopen(url, timeout=120) as response, target.open("wb") as out:  # noqa: S310
        shutil.copyfileobj(response, out)
    return target


def version() -> str:
    sys.path.insert(0, str(ROOT / "src"))
    from pdftrace import __version__

    return __version__


def run_pyinstaller() -> None:
    import PyInstaller.__main__

    PyInstaller.__main__.run(
        [
            str(ROOT / "packaging" / "pdftrace.spec"),
            "--noconfirm",
            "--clean",
            "--distpath",
            str(ROOT / "dist"),
            "--workpath",
            str(ROOT / "build"),
        ]
    )


def add_poppler(source: Path | None, info: list[str], tmp: Path) -> None:
    if source is None:
        archive = download(POPPLER_URL, tmp / "poppler.zip")
        info.append(f"poppler {POPPLER_VERSION} {POPPLER_URL} sha256={sha256(archive)}")
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(tmp / "poppler")
        found = next((p.parent for p in (tmp / "poppler").rglob("pdffonts.exe")), None)
        if found is None:
            raise SystemExit("pdffonts.exe not found in the Poppler archive")
        source = found
        licences = list((tmp / "poppler").rglob("COPYING*")) + list((tmp / "poppler").rglob("LICENSE*"))
    else:
        info.append(f"poppler local {source}")
        licences = []
    target = DIST / "poppler"
    shutil.copytree(source, target, dirs_exist_ok=True)
    third = DIST / "third-party" / "poppler"
    third.mkdir(parents=True, exist_ok=True)
    for licence in licences:
        shutil.copy2(licence, third / licence.name)
    (third / "SOURCE.txt").write_text(
        "Poppler is licensed under the GNU GPL (version 2 or later). The binaries in the 'poppler' folder come "
        f"from {POPPLER_URL}.\nCorresponding source code: https://poppler.freedesktop.org/ and "
        "https://github.com/oschwartz10612/poppler-windows (build scripts).\n",
        encoding="utf-8",
    )


def _seven_zip() -> str | None:
    candidates = (Path("C:/Program Files/7-Zip/7z.exe"), Path("C:/Program Files (x86)/7-Zip/7z.exe"))
    return shutil.which("7z") or next((str(p) for p in candidates if p.is_file()), None)


def add_tesseract(source: Path | None, languages: list[str], info: list[str], tmp: Path) -> None:
    """Bundle Tesseract (Apache-2.0) in dist/PDFTrace/tesseract with the requested language models."""
    target = DIST / "tesseract"
    if source is None:
        seven = _seven_zip()
        if not seven:
            print("7-Zip not found: Tesseract not bundled (OCR can be installed later from the GUI)")
            info.append("tesseract not bundled (7-Zip missing at build time)")
            return
        setup = download(TESSERACT_URL, tmp / "tesseract-setup.exe")
        info.append(f"tesseract {TESSERACT_VERSION} {TESSERACT_URL} sha256={sha256(setup)}")
        extracted = tmp / "tesseract"
        subprocess.run([seven, "x", "-y", f"-o{extracted}", str(setup)], check=True, stdout=subprocess.DEVNULL)
        source = extracted
    else:
        info.append(f"tesseract local {source}")
    if not (source / "tesseract.exe").is_file() and not (source / "tesseract").is_file():
        raise SystemExit(f"tesseract executable not found in {source}")
    shutil.copytree(
        source, target, dirs_exist_ok=True, ignore=shutil.ignore_patterns("$PLUGINSDIR", "uninstall*", "*.nsi")
    )
    tessdata = target / "tessdata"
    tessdata.mkdir(exist_ok=True)
    for lang in dict.fromkeys([*languages, "osd"]):
        model = tessdata / f"{lang}.traineddata"
        if not model.is_file():
            download(TESSDATA + f"{lang}.traineddata", model)
        info.append(f"tessdata {lang} sha256={sha256(model)}")
    third = DIST / "third-party" / "tesseract"
    third.mkdir(parents=True, exist_ok=True)
    (third / "SOURCE.txt").write_text(
        "Tesseract OCR is licensed under the Apache License 2.0 (https://github.com/tesseract-ocr/tesseract).\n"
        f"Windows build: {TESSERACT_URL}\nLanguage data: https://github.com/tesseract-ocr/tessdata_fast "
        "(Apache-2.0).\n",
        encoding="utf-8",
    )


def add_scripts(source: Path | None, info: list[str], tmp: Path) -> None:
    target = DIST / "tools"
    target.mkdir(parents=True, exist_ok=True)
    for name in SCRIPTS:
        path = (source / name) if source else download(DIDIER + name, tmp / name)
        if path.is_file():
            shutil.copy2(path, target / name)
            info.append(f"{name} sha256={sha256(target / name)} (public domain, Didier Stevens)")


def make_zip(name: str) -> Path:
    archive = ROOT / "dist" / f"{name}.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(DIST.rglob("*")):
            zf.write(path, Path("PDFTrace") / path.relative_to(DIST))
    return archive


def make_installer(ver: str) -> Path | None:
    iscc = shutil.which("iscc") or next(
        (
            str(p)
            for p in (
                Path("C:/Program Files (x86)/Inno Setup 6/ISCC.exe"),
                Path("C:/Program Files/Inno Setup 6/ISCC.exe"),
            )
            if p.is_file()
        ),
        None,
    )
    if not iscc:
        print("Inno Setup (ISCC.exe) not found: installer skipped")
        return None
    script = ROOT / "packaging" / "windows" / "PDFTrace.iss"
    subprocess.run([iscc, f"/DAppVersion={ver}", str(script)], check=True)
    return ROOT / "dist" / f"PDFTrace-{ver}-setup.exe"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--download", action="store_true", help="download Poppler (Windows) and pdfid/pdf-parser")
    parser.add_argument("--poppler", type=Path, help="local folder with pdfinfo/pdffonts/pdfimages to bundle")
    parser.add_argument("--tools", type=Path, help="local folder with pdfid.py and pdf-parser.py to bundle")
    parser.add_argument("--tesseract", type=Path, help="local Tesseract folder (with tesseract.exe) to bundle")
    parser.add_argument("--no-tesseract", action="store_true", help="do not bundle Tesseract OCR")
    parser.add_argument("--ocr-languages", default="ita,eng", help="language models to bundle (default ita,eng)")
    parser.add_argument("--zip", action="store_true", help="create the portable zip")
    parser.add_argument("--installer", action="store_true", help="create the Windows installer (Inno Setup)")
    args = parser.parse_args()

    ver = version()
    system = {"Windows": "windows", "Darwin": "macos"}.get(platform.system(), "linux")
    run_pyinstaller()
    info = [
        f"PDFTrace {ver}",
        f"built {datetime.now(UTC).isoformat(timespec='seconds')} on {platform.platform()}",
        f"python {platform.python_version()}",
    ]
    with tempfile.TemporaryDirectory() as tmp:
        if args.poppler or (args.download and system == "windows"):
            add_poppler(args.poppler, info, Path(tmp))
        if args.tools or args.download:
            add_scripts(args.tools, info, Path(tmp))
        if not args.no_tesseract and (args.tesseract or (args.download and system == "windows")):
            langs = [x.strip() for x in args.ocr_languages.split(",") if x.strip()]
            add_tesseract(args.tesseract, langs, info, Path(tmp))
    (DIST / "BUILD-INFO.txt").write_text("\n".join(info) + "\n", encoding="utf-8")
    print("\n".join(info))
    outputs = [DIST]
    if args.zip:
        outputs.append(make_zip(f"PDFTrace-{ver}-{system}-portable"))
    if args.installer and system == "windows":
        installer = make_installer(ver)
        if installer:
            outputs.append(installer)
    for out in outputs:
        print(f"output: {out}" + (f"  sha256={sha256(out)}" if out.is_file() else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
