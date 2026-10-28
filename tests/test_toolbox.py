"""Toolbox: parsers (on real outputs), custom tools, runner safety and findings."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

from pdftrace import cli
from pdftrace.config import Settings
from pdftrace.core import report
from pdftrace.core.findings import FindingsEngine
from pdftrace.core.models import ExternalToolRun
from pdftrace.integrations import tool_parsers as tp
from pdftrace.integrations.toolbox import BUILTIN_TOOLS, Toolbox

# Real outputs captured from the versions listed in integrations/toolbox.py
QPDF_DAMAGED = """WARNING: x.pdf: file is damaged
WARNING: x.pdf (offset 99999): xref not found
WARNING: x.pdf: Attempting to reconstruct cross-reference table
"""
QPDF_OK = """checking x.pdf
PDF Version: 1.7
File is not encrypted
File is not linearized
No syntax or stream encoding errors found; the file may still contain
errors that qpdf cannot detect
"""
PDFID = """PDFiD 0.2.10 x.pdf
 PDF Header: %PDF-1.7
 obj                  226
 /JS                    1
 /JavaScript            2(1)
 /OpenAction            0
"""
PDFCPU_BAD = """validating(mode=relaxed) x.pdf ...
pdfcpu repaired: xreftable
validate x.pdf: validation error (obj#:1): load catalog: missing root dict
"""


def test_parsers_on_real_outputs() -> None:
    damaged = tp.qpdf_check("", QPDF_DAMAGED, 3)
    assert damaged["clean"] is False and damaged["warning_count"] == 3
    ok = tp.qpdf_check(QPDF_OK, "", 0)
    assert ok["clean"] is True and ok["errors"] == []
    counts = tp.pdfid(PDFID, "", 0)["counts"]
    assert counts == {"obj": 226, "/JS": 1, "/JavaScript": 2, "/OpenAction": 0}
    assert tp.pdfresurrect_versions("incremental.pdf: 2\n", "", 0)["versions"] == 2
    assert tp.pdfcpu_validate(PDFCPU_BAD, "", 1)["valid"] is False
    assert tp.pdfcpu_validate("validating ...\nvalidation ok\n", "", 0)["valid"] is True
    assert tp.pdfsig("", "NSS_Init failed\nFile 'x' does not contain any signatures\n", 2)["signatures"] == 0
    assert tp.pdfdetach_list("0 embedded files\n", "", 0)["embedded_files"] == 0
    assert tp.pdfinfo_url("Page  Type          URL\n   1  Annotation    https://example.org\n", "", 0)["urls"] == [
        "https://example.org"
    ]
    dump = tp.pdftk_dump("InfoBegin\nInfoKey: Author\nInfoValue: Carol\nNumberOfPages: 2\n", "", 0)
    assert dump == {"info": {"Author": "Carol"}, "pages": 2}
    assert tp.ghostscript_check("", "", 0)["clean"] is True


def test_builtin_specs_are_read_only() -> None:
    forbidden = {"-w", "-o", "--output", "-save", "-saveall", "-overwrite_original", "--replace-input"}
    for spec in BUILTIN_TOOLS:
        for action in spec.actions:
            assert "{pdf}" in action.args, spec.id
            assert not forbidden & set(action.args), (spec.id, action.id)


def _custom(tmp_path: Path, body: str, extra: str = "") -> Settings:
    script = tmp_path / "fake_tool.py"
    script.write_text(body, encoding="utf-8")
    toml = tmp_path / "tools.toml"
    py = sys.executable.replace("\\", "/")
    toml.write_text(
        f'[[tool]]\nid = "fake"\nname = "Fake tool"\nlicense = "MIT"\n'
        f'command = ["{py}", "{script.as_posix()}"]\n{extra}',
        encoding="utf-8",
    )
    return Settings(tools_file=str(toml), external_metadata_cmd=None, tool_timeout_s=3)


def test_custom_tool_runs_with_pdf_argument(tmp_path: Path, pdfs) -> None:  # type: ignore[no-untyped-def]
    settings = _custom(tmp_path, "import sys; print('ARG', sys.argv[1])")
    toolbox = Toolbox(settings)
    spec = toolbox.get("fake")
    assert spec is not None and spec.custom
    assert toolbox.status(spec).available
    (run,) = toolbox.run_tools([spec], pdfs["simple"])
    assert run.status == "ok" and run.stdout.strip() == f"ARG {pdfs['simple']}"
    assert run.stdout_sha256 and run.command[-1] == str(pdfs["simple"])


def test_custom_tool_timeout(tmp_path: Path, pdfs) -> None:  # type: ignore[no-untyped-def]
    settings = _custom(tmp_path, "import time; time.sleep(30)").with_overrides(tool_timeout_s=1.0)
    toolbox = Toolbox(settings)
    (run,) = toolbox.run_tools(toolbox.select("fake"), pdfs["simple"])
    assert run.status == "timeout" and run.timed_out
    findings = FindingsEngine().evaluate(_with_runs(pdfs, [run]))
    assert any("timed out" in f.title for f in findings)


def test_invalid_custom_file(tmp_path: Path) -> None:
    toml = tmp_path / "tools.toml"
    toml.write_text('[[tool]]\nid = "qpdf"\ncommand = ["x"]\n', encoding="utf-8")
    toolbox = Toolbox(Settings(tools_file=str(toml), external_metadata_cmd=None))
    assert toolbox.errors and sum(1 for t in toolbox.tools if t.id == "qpdf") == 1


def test_unavailable_tool(tmp_path: Path, pdfs, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("PDFTRACE_TOOL_PDFCPU", str(tmp_path / "missing"))
    toolbox = Toolbox(Settings(external_metadata_cmd=None))
    spec = toolbox.get("pdfcpu")
    assert spec is not None and not toolbox.status(spec).available
    run = toolbox.run_action(spec, spec.actions[0], pdfs["simple"])
    assert run.status == "unavailable" and "PDFTRACE_TOOL_PDFCPU" in (run.error or "")


def _with_runs(pdfs, runs):  # type: ignore[no-untyped-def]
    from pdftrace.core.pipeline import analyze

    analysis = analyze(pdfs["simple"], Settings(external_metadata_cmd=None))
    analysis.external_runs = runs
    return analysis


def test_findings_from_tool_runs(pdfs) -> None:  # type: ignore[no-untyped-def]
    runs = [
        ExternalToolRun(
            "qpdf", "qpdf", "check", "Check", status="ok", returncode=3, parsed=tp.qpdf_check("", QPDF_DAMAGED, 3)
        ),
        ExternalToolRun("pdfid", "pdfid", "triage", "Triage", status="ok", returncode=0, parsed=tp.pdfid(PDFID, "", 0)),
        ExternalToolRun(
            "pdfresurrect", "pdfresurrect", "versions", "Versions", status="ok", returncode=0, parsed={"versions": 3}
        ),
    ]
    titles = [f.title for f in FindingsEngine().evaluate(_with_runs(pdfs, runs))]
    assert "qpdf reports structural problems" in titles
    assert "pdfid: active content keywords" in titles
    assert "pdfresurrect: 3 versions" in titles


def test_tool_outputs_manifest(tmp_path: Path, pdfs) -> None:  # type: ignore[no-untyped-def]
    run = ExternalToolRun("fake", "Fake", "run", "Run", status="ok", stdout="hello", command=["fake", "x.pdf"])
    files = report.write_tool_outputs(_with_runs(pdfs, [run]), tmp_path)
    assert (tmp_path / "fake__run.stdout.txt").read_text() == "hello"
    assert "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" in files[-1].read_text()


def test_cli_with_custom_tool(tmp_path: Path, pdfs, capsys) -> None:  # type: ignore[no-untyped-def]
    settings = _custom(tmp_path, "print('fake output')")
    toml = settings.tools_file
    assert toml
    import os

    os.environ["PDFTRACE_TOOLS_FILE"] = toml
    try:
        assert cli.main(["--list-tools"]) == cli.EXIT_OK
        assert "fake" in capsys.readouterr().out
        out = tmp_path / "raw"
        code = cli.main(
            [str(pdfs["simple"]), "--tools", "fake", "--tool-output", str(out), "--json", str(tmp_path / "r.json")]
        )
        assert code == cli.EXIT_OK and (out / "fake__run.stdout.txt").exists()
        assert '"tool_id": "fake"' in (tmp_path / "r.json").read_text("utf-8")
    finally:
        del os.environ["PDFTRACE_TOOLS_FILE"]


@pytest.mark.skipif(not shutil.which("qpdf"), reason="qpdf not installed")
def test_real_qpdf(pdfs) -> None:  # type: ignore[no-untyped-def]
    toolbox = Toolbox(Settings(external_metadata_cmd=None))
    runs = {r.action_id: r for r in toolbox.run_tools(toolbox.select("qpdf"), pdfs["corrupted"])}
    assert runs["check"].parsed["clean"] is False


@pytest.mark.skipif(not shutil.which("pdfresurrect"), reason="pdfresurrect not installed")
def test_real_pdfresurrect(pdfs) -> None:  # type: ignore[no-untyped-def]
    toolbox = Toolbox(Settings(external_metadata_cmd=None))
    runs = toolbox.run_tools(toolbox.select("pdfresurrect"), pdfs["incremental"])
    assert runs[0].parsed["versions"] == 2


def test_python_module_runners(pdfs) -> None:  # type: ignore[no-untyped-def]
    pytest.importorskip("pikepdf")
    toolbox = Toolbox(Settings(external_metadata_cmd=None))
    (run,) = toolbox.run_tools(toolbox.select("pikepdf"), pdfs["rich"])
    assert run.status == "ok" and run.parsed["opened"] is True and run.parsed["pages"] == 2
