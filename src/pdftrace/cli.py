"""Command line interface. Uses exactly the same pipeline as the GUI."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from pdftrace import TOOL_NAME, __version__
from pdftrace.config import default_settings
from pdftrace.core import report
from pdftrace.core.models import PDFAnalysis, StepRun, StepState
from pdftrace.core.pipeline import Pipeline
from pdftrace.integrations.poppler import Poppler
from pdftrace.integrations.process import ToolFailed, ToolNotFound
from pdftrace.integrations.toolbox import Toolbox
from pdftrace.utils.logging import configure_logging
from pdftrace.utils.paths import InputError, safe_output_dir

EXIT_OK, EXIT_INPUT, EXIT_ERROR = 0, 2, 3
_MARK = {StepState.DONE: "✓", StepState.SKIPPED: "–", StepState.ERROR: "✗", StepState.CANCELLED: "✗"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pdftrace",
        description=f"{TOOL_NAME}: forensic analysis of PDF files (read-only).",
    )
    parser.add_argument("pdf", nargs="?", help="PDF file to analyse")
    parser.add_argument("--json", metavar="FILE", help="write the full JSON report")
    parser.add_argument("--html", metavar="FILE", help="write the HTML report")
    parser.add_argument("--md", metavar="FILE", help="write the Markdown report")
    parser.add_argument("--csv", metavar="DIR", help="write CSV tables into DIR")
    parser.add_argument("--text", metavar="FILE", help="write extracted text (TXT)")
    parser.add_argument("--extract-images", metavar="DIR", help="extract embedded images (needs pdfimages)")
    parser.add_argument("--extract-attachments", metavar="DIR", help="extract embedded files (not opened)")
    parser.add_argument(
        "--images-format",
        choices=["all", "png"],
        default="all",
        help="native formats (all) or convert everything to PNG",
    )
    parser.add_argument("--poppler-path", metavar="DIR", help="directory containing Poppler binaries")
    parser.add_argument("--timeout", type=float, metavar="S", help="timeout per external tool call")
    parser.add_argument("--max-pages", type=int, metavar="N", help="max pages for text/layout analysis")
    parser.add_argument("--tools", metavar="LIST", help="also run Toolbox tools: 'all' or ids (e.g. qpdf,pdfid)")
    parser.add_argument("--tool-output", metavar="DIR", help="save raw output of each tool action into DIR")
    parser.add_argument("--list-tools", action="store_true", help="list Toolbox tools and exit")
    parser.add_argument(
        "--ocr", action="store_true", help="OCR the rendered pages with Tesseract and compare them with the text layer"
    )
    parser.add_argument("--ocr-lang", metavar="LANGS", help="Tesseract languages, e.g. ita+eng (default: auto)")
    parser.add_argument("--ocr-dpi", type=int, metavar="DPI", help="rendering resolution for OCR (default 300)")
    parser.add_argument("--ocr-pages", type=int, metavar="N", help="maximum pages processed by OCR (default 200)")
    parser.add_argument("--ocr-text", metavar="FILE", help="write the OCR text (TXT), implies --ocr")
    parser.add_argument("--check", action="store_true", help="print dependency diagnostics and exit")
    parser.add_argument("-q", "--quiet", action="store_true", help="only print errors")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def print_summary(analysis: PDFAnalysis) -> None:
    s = report.summary(analysis)
    m = analysis.metadata
    lines = [
        "PDFTrace",
        "========",
        "",
        f"File:      {analysis.file.name}",
        f"Size:      {analysis.file.size:,} bytes",
        f"SHA-256:   {analysis.hashes.sha256}",
        f"SHA-1:     {analysis.hashes.sha1}",
        f"MD5:       {analysis.hashes.md5}",
        "",
        f"PDF:       {s['pdf_version'] or '?'}   Pages: {s['pages']}   "
        f"Encrypted: {'yes' if s['encrypted'] else 'no'}   Revisions: {s['revisions']}",
        f"Creator:   {m.info_value('Creator') or m.xmp_value('xmp:CreatorTool') or '-'}",
        f"Producer:  {m.info_value('Producer') or m.xmp_value('pdf:Producer') or '-'}",
        f"Created:   {m.info_value('CreationDate') or m.xmp_value('xmp:CreateDate') or '-'}",
        f"Modified:  {m.info_value('ModDate') or m.xmp_value('xmp:ModifyDate') or '-'}",
        f"Fonts:     {s['fonts_total']} ({s['fonts_embedded']} embedded, {s['fonts_subset']} subset, "
        f"{s['fonts_not_embedded']} not embedded)",
        f"Images:    {s['images_total']} {s['images_by_encoding'] or ''}",
        f"Text:      {s['chars']:,} chars, {s['words']:,} words, {s['text_anomalies']} text-layer anomalies",
        f"Content:   {s['objects']} objects, {s['annotations']} annotations, {s['scripts']} scripts, "
        f"{s['attachments']} attachments, {s['form_fields']} form fields, {s['signatures']} signatures",
        f"Images:    {s['images_with_metadata']} with own metadata (EXIF/XMP/IPTC)",
        "",
        "Findings:",
    ]
    lines += [f"  {f.severity.value.upper():8s}{f.id}  [{f.category}] {f.title}" for f in analysis.findings]
    if not analysis.findings:
        lines.append("  none")
    if analysis.ocr.pages or analysis.ocr.error:
        o = analysis.ocr
        unseen = sum(len(p.unseen_layer_text) for p in o.pages)
        missing = sum(len(p.visible_not_in_layer) for p in o.pages)
        lines += [
            "",
            f"OCR:       {o.error}"
            if o.error
            else f"OCR:       tesseract {o.version} [{o.languages}] {len(o.pages)} page(s), "
            f"{unseen} hidden text run(s), "
            f"{missing} visible run(s) not in the text layer",
        ]
    if analysis.external_runs:
        lines += ["", "External tools:"]
        lines += [f"  {r.status:11s} {r.tool_id}:{r.action_id} ({r.duration_s:.1f}s)" for r in analysis.external_runs]
    problems = [st for st in analysis.steps if st.state in (StepState.ERROR, StepState.SKIPPED)]
    if problems:
        lines += ["", "Pipeline notes:"]
        lines += [f"  {_MARK[st.state]} {st.label}: {st.message}" for st in problems]
    print("\n".join(lines))


def print_check(poppler: Poppler, toolbox: Toolbox) -> int:
    import fontTools
    import pdfminer
    import pdfplumber

    print(f"{TOOL_NAME} {__version__}\n\nPython libraries:")
    print(f"  pdfplumber   {pdfplumber.__version__}")
    print(f"  pdfminer.six {pdfminer.__version__}")
    print(f"  fontTools    {fontTools.version}")
    try:
        import PySide6

        print(f"  PySide6      {PySide6.__version__} (GUI available)")
    except ImportError:
        print("  PySide6      not installed (GUI unavailable: pip install 'pdftrace[gui]')")
    from pdftrace.integrations.tesseract import Tesseract

    tess = Tesseract(poppler.settings)
    print("\nOCR:")
    if tess.executable():
        print(f"  ✓ tesseract      {tess.version() or ''}  languages: {', '.join(tess.languages()) or 'none'}")
        print(f"    {tess.executable()}" + (f"  (tessdata: {tess.tessdata_dir()})" if tess.tessdata_dir() else ""))
    else:
        print("  – tesseract      not installed (optional: OCR of rendered pages)")
    print("\nRequired external tools (Poppler):")
    ok = True
    for status in poppler.status():
        ok = ok and status.available
        print(f"  {'✓' if status.available else '✗'} {status.name:14s} {status.version or status.error or ''}")
    print("\nOptional tools (Toolbox):")
    for status in toolbox.statuses():
        mark = "✓" if status.available else "–"
        print(f"  {mark} {status.name:14s} {status.version or ('' if status.available else 'not installed')}")
    for error in toolbox.errors:
        print(f"  ! {error}")
    if not ok:
        print(
            "\nPoppler not found: pdffonts/pdfimages/pdfinfo cannot be executed. Install Poppler "
            "and restart, or pass --poppler-path. See README.md."
        )
    return EXIT_OK if ok else EXIT_ERROR


def print_tools(toolbox: Toolbox) -> int:
    for spec in toolbox.tools:
        status = toolbox.status(spec)
        print(f"{'✓' if status.available else '–'} {spec.id:14s} {spec.name} [{spec.license}]")
        print(f"    {spec.homepage}")
        for action in spec.actions:
            print(f"    - {action.id}: {action.label}")
        if not status.available and spec.install_hint:
            print(f"    install: {spec.install_hint}")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    from pdftrace.frozen import dispatch_helper

    raw = list(sys.argv[1:] if argv is None else argv)
    helper_code = dispatch_helper(raw)
    if helper_code is not None:
        return helper_code
    args = build_parser().parse_args(raw)
    configure_logging(logging.DEBUG if args.verbose else logging.WARNING)
    settings = default_settings().with_overrides(
        poppler_path=args.poppler_path,
        tool_timeout_s=args.timeout,
        max_pages_text=args.max_pages,
        external_tools=args.tools,
        ocr=True if (args.ocr or args.ocr_text) else None,
        ocr_languages=args.ocr_lang,
        ocr_dpi=args.ocr_dpi,
        ocr_max_pages=args.ocr_pages,
    )
    if args.check:
        return print_check(Poppler(settings), Toolbox(settings))
    if args.list_tools:
        return print_tools(Toolbox(settings))
    if not args.pdf:
        print("error: a PDF file is required (or use --check)", file=sys.stderr)
        return EXIT_INPUT

    def progress(step: StepRun) -> None:
        if not args.quiet and step.state not in (StepState.PENDING, StepState.RUNNING):
            print(f"  {_MARK.get(step.state, '·')} {step.label}", file=sys.stderr)

    try:
        analysis = Pipeline(settings=settings).run(args.pdf, progress=progress)
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_ERROR

    if not args.quiet:
        print_summary(analysis)
    try:
        written: list[Path] = []
        if args.json:
            written.append(report.write_json(analysis, Path(args.json)))
        if args.html:
            written.append(report.write_html(analysis, Path(args.html)))
        if args.md:
            written.append(report.write_markdown(analysis, Path(args.md)))
        if args.text:
            written.append(report.write_text(analysis, Path(args.text)))
        if args.ocr_text:
            written.append(report.write_ocr_text(analysis, Path(args.ocr_text)))
        if args.tool_output:
            written.extend(report.write_tool_outputs(analysis, safe_output_dir(args.tool_output)))
        if args.csv:
            written.extend(report.write_csv_dir(analysis, safe_output_dir(args.csv)))
        if args.extract_attachments:
            from pdftrace.integrations.pikepdf_adapter import extract_attachments

            target = safe_output_dir(args.extract_attachments)
            for path, digest in extract_attachments(Path(analysis.file.path), target):
                written.append(path)
                if not args.quiet:
                    print(f"  attachment {path.name}  SHA-256 {digest}")
        if args.extract_images:
            poppler = Poppler(settings)
            out = safe_output_dir(args.extract_images)
            written.extend(poppler.extract_images(Path(analysis.file.path), out, fmt=args.images_format))
    except (OSError, InputError, ToolFailed, ToolNotFound) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if written and not args.quiet:
        print("\nWritten:")
        for path in written:
            print(f"  {path}")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
