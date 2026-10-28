"""Centralised configuration.

Every tunable limit lives here so that the CLI, the GUI and the tests share the
same defaults. Values can be overridden through environment variables or by
calling :meth:`Settings.with_overrides`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _bundled_poppler() -> str | None:
    """Poppler folder shipped with a standalone build, if any."""
    from pdftrace.frozen import bundled_dir, is_frozen

    if not is_frozen():
        return None
    folder = bundled_dir("poppler")
    return str(folder) if folder else None


@dataclass(frozen=True)
class Settings:
    """Runtime limits and external tool configuration."""

    #: Directory containing Poppler binaries. ``None`` means "search PATH".
    poppler_path: str | None = field(default_factory=lambda: os.environ.get("PDFTRACE_POPPLER_PATH") or None)
    #: Legacy single custom command (registered as the custom tool ``dbxmetadata``).
    external_metadata_cmd: str | None = field(
        default_factory=lambda: os.environ.get("PDFTRACE_DBXMETADATA_CMD") or None
    )
    #: TOML file with analyst-defined tools (default ``~/.pdftrace/tools.toml``).
    tools_file: str | None = field(default_factory=lambda: os.environ.get("PDFTRACE_TOOLS_FILE") or None)
    #: Toolbox tools run by the pipeline: ``"none"``, ``"all"`` or comma separated ids.
    external_tools: str = field(default_factory=lambda: os.environ.get("PDFTRACE_RUN_TOOLS", "none"))
    #: Run OCR (Tesseract) on rendered pages during the pipeline.
    ocr: bool = field(default_factory=lambda: os.environ.get("PDFTRACE_OCR", "") in ("1", "true", "yes"))
    #: Tesseract languages (``"ita+eng"``) or ``"auto"`` (Italian and English when installed).
    ocr_languages: str = field(default_factory=lambda: os.environ.get("PDFTRACE_OCR_LANG", "auto"))
    #: Rendering resolution for OCR.
    ocr_dpi: int = field(default_factory=lambda: _env_int("PDFTRACE_OCR_DPI", 300))
    #: Maximum number of pages processed by OCR.
    ocr_max_pages: int = field(default_factory=lambda: _env_int("PDFTRACE_OCR_MAX_PAGES", 200))
    #: Path of the Tesseract executable (``None``: bundled copy, then PATH and usual folders).
    tesseract_path: str | None = field(default_factory=lambda: os.environ.get("PDFTRACE_TESSERACT") or None)
    #: Folder with ``*.traineddata`` language files (``None``: automatic).
    tessdata_dir: str | None = field(default_factory=lambda: os.environ.get("PDFTRACE_TESSDATA") or None)
    #: Timeout, in seconds, for each external tool invocation.
    tool_timeout_s: float = field(default_factory=lambda: _env_float("PDFTRACE_TOOL_TIMEOUT", 120.0))
    #: Maximum number of pages analysed by the text/layout analyzer.
    max_pages_text: int = field(default_factory=lambda: _env_int("PDFTRACE_MAX_PAGES", 2000))
    #: Maximum number of word boxes kept per page (for the Page Inspector).
    max_words_per_page: int = 20_000
    #: Maximum number of graphic boxes (lines/rects/curves) kept per page.
    max_shapes_per_page: int = 5_000
    #: Maximum size of an XMP packet that will be parsed.
    max_xmp_bytes: int = 8_000_000
    #: Maximum size of an embedded font program passed to fontTools.
    max_font_bytes: int = 64_000_000
    #: Maximum number of characters of stdout/stderr kept per tool call.
    max_tool_output: int = 4_000_000
    #: Pixel count above which an image is reported as very high resolution.
    high_res_pixels: int = 40_000_000
    #: Pages with fewer characters than this are reported as low-text pages.
    low_text_chars: int = 20
    #: A page whose text density differs from the median by this factor is reported.
    density_factor: float = 4.0

    def with_overrides(self, **changes: object) -> Settings:
        """Return a copy with the given fields replaced (``None`` values are ignored)."""
        clean = {k: v for k, v in changes.items() if v is not None}
        return replace(self, **clean)  # type: ignore[arg-type]


def default_settings() -> Settings:
    """Return settings built from defaults and environment variables."""
    return Settings()
