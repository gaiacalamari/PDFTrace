from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from pdftrace.config import Settings
from pdftrace.core.models import PDFAnalysis
from pdftrace.core.pipeline import analyze
from tests.fixtures.builder import write_all

HAS_POPPLER = all(shutil.which(t) for t in ("pdfinfo", "pdffonts", "pdfimages"))
needs_poppler = pytest.mark.skipif(not HAS_POPPLER, reason="Poppler utilities not installed")


@pytest.fixture(scope="session")
def pdfs(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    return write_all(tmp_path_factory.mktemp("fixtures"))


@pytest.fixture(scope="session")
def settings() -> Settings:
    return Settings(poppler_path=None, external_metadata_cmd=None)


@pytest.fixture(scope="session")
def no_poppler(tmp_path_factory: pytest.TempPathFactory) -> Settings:
    """Settings pointing Poppler to an empty directory: simulates a missing dependency."""
    return Settings(poppler_path=str(tmp_path_factory.mktemp("empty_bin")), external_metadata_cmd=None)


@pytest.fixture(scope="session")
def analyses(pdfs: dict[str, Path], settings: Settings) -> dict[str, PDFAnalysis]:
    return {name: analyze(path, settings) for name, path in pdfs.items()}


def titles(analysis: PDFAnalysis) -> list[str]:
    return [f.title for f in analysis.findings]
