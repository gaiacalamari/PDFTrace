# Contributing

PDFTrace is a forensic tool: correctness and traceability take precedence over new features.

## Ground rules

1. **Do not invent library behaviour.** When integrating a tool or library, cite the version and the
   documentation or source verified in `docs/DEPENDENCIES.md`, and add a test on real output.
2. **Keep provenance.** Every new value must record its `source` and `confidence` (`direct`, `derived`,
   `heuristic`).
3. **Neutral wording.** Findings describe observations ("difference", "requires review"). Never use
   words such as "forged", "fake" or "malicious"; the test suite enforces part of this.
4. **Untrusted input.** Treat every PDF as hostile: no shell, list arguments only, timeouts, size limits,
   escape everything in reports, never execute or follow content from the file.
5. **Separation of layers.** Third-party code is imported only in `integrations/`; the GUI only renders
   `PDFAnalysis`.

## Adding an analyzer

1. Create `src/pdftrace/analyzers/<name>.py` with a subclass of `core.analyzer.Analyzer`
   (`name`, `label`, `analyze(ctx) -> AnalysisResult`).
2. Put any external tool call in `integrations/` using `process.run_tool`.
3. Store results in a new field of `PDFAnalysis` (or in `analysis.external[<name>]`).
4. Register it in `core.pipeline.default_analyzers()` and add rules with `@rule` in `core/findings.py`.
5. Add fixtures (built from code in `tests/fixtures/builder.py`) and tests.

## Adding a Toolbox tool

1. Verify the tool on a real installation: version option, read-only options, output format, exit
   codes, licence. Record them in `docs/TOOLS.md`.
2. Add a `ToolSpec` to `BUILTIN_TOOLS` in `src/pdftrace/integrations/toolbox.py`. Never use options
   that write or modify files.
3. Optionally add a parser in `integrations/tool_parsers.py`, tested on captured real output, and a rule
   in `core/findings.py`.

## Workflow

```bash
pip install -e ".[gui,dev]"
pytest && ruff check src tests && ruff format --check src tests && mypy
```

Use small pull requests with a clear description, and update `CHANGELOG.md`.
Do not add fixtures derived from real cases or containing personal data.
