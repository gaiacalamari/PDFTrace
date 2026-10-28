"""Tesseract OCR (Apache-2.0) executed as a separate process.

Verified on Tesseract 5.3.4 (Linux) and against the 5.5.3 Windows build:
``tesseract <image> stdout -l <langs> --psm 3 --dpi <dpi> -c tessedit_create_txt=0
-c tessedit_create_tsv=1`` prints a TSV table with the columns ``level page_num block_num par_num line_num word_num
left top width height conf text`` (level 5 = word); ``--tessdata-dir`` selects
the language data folder; ``--list-langs`` lists installed languages.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from pdftrace.config import Settings
from pdftrace.core.models import OcrWord
from pdftrace.frozen import bundled_dir
from pdftrace.integrations.process import ToolFailed, ToolNotFound, find_executable, run_tool

WINDOWS_FOLDERS = (
    Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "Tesseract-OCR",
    Path(os.environ.get("LOCALAPPDATA", "C:/Users/Default/AppData/Local")) / "Programs" / "Tesseract-OCR",
)


class Tesseract:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._exe: str | bool | None = False
        self._version: str | bool | None = False
        self._langs: list[str] | None = None

    # ------------------------------------------------------------- discovery
    def executable(self) -> str | None:
        if self._exe is False:
            self._exe = self._find()
        return self._exe if isinstance(self._exe, str) else None

    def _find(self) -> str | None:
        configured = self.settings.tesseract_path
        if configured:
            return configured if Path(configured).is_file() else find_executable(configured)
        bundled = bundled_dir("tesseract")
        if bundled:
            found = find_executable("tesseract", str(bundled))
            if found:
                return found
        found = find_executable("tesseract")
        if found:
            return found
        if sys.platform == "win32":
            for folder in WINDOWS_FOLDERS:
                found = find_executable("tesseract", str(folder))
                if found:
                    return found
        return None

    def tessdata_dir(self) -> str | None:
        """Language data folder passed with ``--tessdata-dir`` (``None``: Tesseract default)."""
        candidates = [self.settings.tessdata_dir]
        bundled = bundled_dir("tesseract")
        if bundled:
            candidates.append(str(bundled / "tessdata"))
        candidates.append(str(Path.home() / ".pdftrace" / "tessdata"))
        for folder in candidates:
            if folder and Path(folder).is_dir() and any(Path(folder).glob("*.traineddata")):
                return folder
        return None

    def _base_args(self) -> list[str]:
        folder = self.tessdata_dir()
        return ["--tessdata-dir", folder] if folder else []

    def version(self) -> str | None:
        if self._version is False:
            exe = self.executable()
            self._version = None
            if exe:
                try:
                    res = run_tool(exe, ["--version"], timeout_s=20)
                    match = re.search(r"tesseract\s+v?(\d+(?:\.\d+)+)", res.stdout + res.stderr, re.I)
                    self._version = match.group(1) if match else None
                except (ToolFailed, ToolNotFound):
                    self._version = None
        return self._version if isinstance(self._version, str) else None

    def languages(self) -> list[str]:
        if self._langs is None:
            self._langs = []
            exe = self.executable()
            if exe:
                try:
                    res = run_tool(exe, [*self._base_args(), "--list-langs"], timeout_s=20)
                    lines = (res.stdout or res.stderr).splitlines()
                    self._langs = sorted({ln.strip() for ln in lines[1:] if ln.strip() and " " not in ln.strip()})
                except (ToolFailed, ToolNotFound):
                    self._langs = []
        return self._langs

    def resolve_languages(self, requested: str) -> str:
        """``auto`` -> Italian and English when installed (else whatever is available)."""
        installed = [lang for lang in self.languages() if lang != "osd"]
        if requested and requested != "auto":
            return requested
        preferred = [lang for lang in ("ita", "eng") if lang in installed]
        return "+".join(preferred or installed[:2] or ["eng"])

    # ------------------------------------------------------------------- OCR
    def ocr_image(self, image: Path, languages: str, dpi: int) -> list[OcrWord]:
        exe = self.executable()
        if not exe:
            raise ToolNotFound("Tesseract not found")
        # TSV requested with -c parameters rather than the "tsv" config file, which may be
        # missing from a tessdata folder that only holds *.traineddata models.
        args = [
            *self._base_args(),
            str(image),
            "stdout",
            "-l",
            languages,
            "--psm",
            "3",
            "--dpi",
            str(int(dpi)),
            "-c",
            "tessedit_create_txt=0",
            "-c",
            "tessedit_create_tsv=1",
        ]
        result = run_tool(exe, args, self.settings.tool_timeout_s, self.settings.max_tool_output)
        if not result.ok:
            raise ToolFailed(f"tesseract exited with {result.returncode}: {result.stderr.strip()[:300]}", result)
        return parse_tsv(result.stdout)


def parse_tsv(text: str) -> list[OcrWord]:
    """Words (level 5) of a Tesseract TSV output; coordinates in image pixels."""
    words: list[OcrWord] = []
    for line in text.splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) < 12 or parts[0] != "5":
            continue
        token = parts[11].strip()
        if not token:
            continue
        try:
            left, top, width, height = (float(v) for v in parts[6:10])
            conf = float(parts[10])
        except ValueError:
            continue
        words.append(OcrWord(token, round(conf, 2), [left, top, left + width, top + height]))
    return words
