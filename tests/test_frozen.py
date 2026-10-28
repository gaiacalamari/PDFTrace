from pathlib import Path

from pdftrace import frozen
from pdftrace.config import Settings
from pdftrace.integrations.toolbox import Toolbox


def test_dispatch_runs_script(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    script = tmp_path / "hello.py"
    script.write_text("import sys\nprint('args', sys.argv[1:])\nraise SystemExit(3)\n", encoding="utf-8")
    assert frozen.dispatch_helper([frozen.RUN_SCRIPT, str(script), "a", "b"]) == 3
    assert "args ['a', 'b']" in capsys.readouterr().out


def test_dispatch_pyrunner(pdfs, capsys) -> None:  # type: ignore[no-untyped-def]
    assert frozen.dispatch_helper([frozen.PYRUNNER, "pikepdf", str(pdfs["rich"])]) == 0
    assert '"opened": true' in capsys.readouterr().out


def test_normal_startup_not_intercepted() -> None:
    assert frozen.dispatch_helper(["document.pdf"]) is None
    assert frozen.helper_executable() is None and not frozen.is_frozen()


def test_frozen_commands(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    exe = tmp_path / "pdftrace-cli"
    exe.write_text("")
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "pdfid.py").write_text("print('x')")
    monkeypatch.setattr(frozen.sys, "frozen", True, raising=False)
    monkeypatch.setattr(frozen.sys, "executable", str(exe))
    monkeypatch.delenv("PDFTRACE_TOOL_PDFID", raising=False)
    toolbox = Toolbox(Settings(external_metadata_cmd=None))
    pdfid = toolbox.get("pdfid")
    pikepdf = toolbox.get("pikepdf")
    assert pdfid is not None and pikepdf is not None
    assert toolbox.base_command(pikepdf) == [str(exe), frozen.PYRUNNER, "pikepdf"]
    command = toolbox.base_command(pdfid)
    assert command is not None and command[:2] == [str(exe), frozen.RUN_SCRIPT]
