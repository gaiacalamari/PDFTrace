"""Report generation: JSON, CSV, Markdown and a self-contained HTML report.

All values coming from the PDF are untrusted: HTML output escapes everything,
contains no scripts and loads no external resources.
"""

from __future__ import annotations

import csv
import hashlib
import html
import json
from collections import Counter
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from pdftrace.core.models import PDFAnalysis, Severity

DISCLAIMER = (
    "This report lists technical observations produced automatically. Findings are indicators "
    "for review by a qualified analyst, not conclusions about authenticity, authorship or intent."
)


# ------------------------------------------------------------------ summaries
def summary(analysis: PDFAnalysis) -> dict[str, Any]:
    """Compact figures shared by the dashboard, the CLI and the reports."""
    fonts = analysis.fonts
    enc = Counter((img.encoding or "unknown") for img in analysis.images)
    sev = Counter(f.severity.value for f in analysis.findings)
    by_cat = Counter(f.category for f in analysis.findings if f.severity != Severity.INFO)
    return {
        "pages": analysis.metadata.page_count,
        "pdf_version": analysis.metadata.pdf_version,
        "encrypted": analysis.metadata.encrypted or analysis.structure.encrypted,
        "linearized": analysis.structure.linearized,
        "revisions": len(analysis.structure.eof_offsets) or None,
        "fonts_total": len(fonts),
        "fonts_embedded": sum(1 for f in fonts if f.embedded),
        "fonts_subset": sum(1 for f in fonts if f.subset),
        "fonts_not_embedded": sum(1 for f in fonts if f.embedded is False),
        "images_total": len(analysis.images),
        "images_by_encoding": dict(enc),
        "chars": analysis.text.total_chars,
        "words": analysis.text.total_words,
        "findings_by_severity": {s.value: sev.get(s.value, 0) for s in Severity},
        "anomalies_by_category": dict(by_cat),
        "ocr_pages": len(analysis.ocr.pages),
        "ocr_hidden_runs": sum(len(p.unseen_layer_text) for p in analysis.ocr.pages),
        "ocr_visible_not_in_layer": sum(len(p.visible_not_in_layer) for p in analysis.ocr.pages),
        "annotations": len(analysis.interactive.annotations),
        "scripts": len(analysis.interactive.scripts),
        "attachments": len(analysis.interactive.embedded_files),
        "form_fields": len(analysis.interactive.form_fields),
        "signatures": len(analysis.interactive.signatures),
        "images_with_metadata": sum(1 for e in analysis.image_evidence if e.exif or e.xmp or e.iptc),
        "text_anomalies": len(analysis.text_forensics.anomalies),
        "parser_disagreements": len(analysis.crosscheck.differences),
        "objects": analysis.objects.total_objects,
        "external_tool_actions": len(analysis.external_runs),
        "external_tools_not_ok": sum(1 for r in analysis.external_runs if r.status != "ok"),
    }


# ----------------------------------------------------------------------- JSON
def to_json(analysis: PDFAnalysis, include_page_boxes: bool = True) -> str:
    data = analysis.to_dict()
    data["summary"] = summary(analysis)
    if not include_page_boxes:
        for page in data["pages"]:
            page.pop("boxes", None)
    return json.dumps(data, ensure_ascii=False, indent=2)


def write_json(analysis: PDFAnalysis, path: Path, include_page_boxes: bool = True) -> Path:
    path.write_text(to_json(analysis, include_page_boxes), encoding="utf-8")
    return path


# ------------------------------------------------------------------------ CSV
def _write_csv(path: Path, header: Sequence[str], rows: Iterable[Sequence[Any]]) -> Path:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        for row in rows:
            writer.writerow(["" if v is None else _csv_safe(v) for v in row])
    return path


def _csv_safe(value: Any) -> str:
    """Neutralise spreadsheet formula injection from PDF-controlled strings."""
    text = (
        value
        if isinstance(value, str)
        else json.dumps(value, ensure_ascii=False)
        if isinstance(value, (list, dict))
        else str(value)
    )
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") and not _is_number(text) else text


def _is_number(text: str) -> bool:
    try:
        float(text)
        return True
    except ValueError:
        return False


def write_csv_dir(analysis: PDFAnalysis, directory: Path) -> list[Path]:
    """Write one CSV per table into ``directory``."""
    directory.mkdir(parents=True, exist_ok=True)
    m = analysis.metadata
    files = [
        _write_csv(
            directory / "metadata.csv",
            ["block", "field", "value", "source", "confidence", "note"],
            [("info", v.field, v.value, v.source, v.confidence, v.note) for v in m.info + m.custom]
            + [("xmp", v.field, v.value, v.source, v.confidence, v.note) for v in m.xmp],
        ),
        _write_csv(
            directory / "metadata_comparison.csv",
            ["field", "info", "xmp_key", "xmp", "status"],
            [(c.field, c.info_value, c.xmp_key, c.xmp_value, c.status) for c in m.comparisons],
        ),
        write_fonts_csv(analysis.fonts, directory / "fonts.csv"),
        write_images_csv(analysis.images, directory / "images.csv"),
        _write_csv(
            directory / "pages.csv",
            [
                "page",
                "width",
                "height",
                "rotation",
                "chars",
                "words",
                "text_lines",
                "lines",
                "rects",
                "curves",
                "images",
                "annotations",
                "density",
                "fonts",
            ],
            [
                (
                    p.number,
                    p.width,
                    p.height,
                    p.rotation,
                    p.chars,
                    p.words,
                    p.text_lines,
                    p.lines,
                    p.rects,
                    p.curves,
                    p.images,
                    p.annotations,
                    p.density,
                    p.fonts,
                )
                for p in analysis.pages
            ],
        ),
        write_findings_csv(analysis, directory / "findings.csv"),
        _write_csv(
            directory / "timeline.csv",
            ["timestamp", "kind", "description", "source", "caveat"],
            [(e.timestamp, e.kind, e.description, e.source, e.caveat) for e in analysis.timeline],
        ),
        *_deep_csv(analysis, directory),
        _write_csv(
            directory / "external_tools.csv",
            ["tool", "action", "version", "status", "exit_code", "duration_s", "stdout_sha256", "command", "parsed"],
            [
                (
                    r.tool_id,
                    r.action_id,
                    r.version,
                    r.status,
                    r.returncode,
                    r.duration_s,
                    r.stdout_sha256,
                    " ".join(r.command),
                    r.parsed,
                )
                for r in analysis.external_runs
            ],
        ),
        _write_csv(
            directory / "hashes.csv",
            ["algorithm", "value"],
            [("SHA-256", analysis.hashes.sha256), ("SHA-1", analysis.hashes.sha1), ("MD5", analysis.hashes.md5)],
        ),
    ]
    return files


def _deep_csv(analysis: PDFAnalysis, directory: Path) -> list[Path]:
    inter = analysis.interactive
    return [
        _write_csv(
            directory / "annotations.csv",
            ["page", "subtype", "author", "created", "modified", "contents", "uri", "hidden", "rect"],
            [
                (x.page, x.subtype, x.author, x.created, x.modified, x.contents, x.uri, x.hidden, x.rect)
                for x in inter.annotations
            ],
        ),
        _write_csv(
            directory / "actions.csv",
            ["location", "trigger", "type", "target"],
            [(x.location, x.trigger, x.action_type, x.target) for x in inter.actions],
        ),
        _write_csv(
            directory / "scripts.csv",
            ["location", "trigger", "length", "sha256", "code"],
            [(x.location, x.trigger, x.length, x.sha256, x.code) for x in inter.scripts],
        ),
        _write_csv(
            directory / "attachments.csv",
            [
                "name",
                "filename",
                "description",
                "mime",
                "size",
                "declared_size",
                "created",
                "modified",
                "sha256",
                "location",
            ],
            [
                (
                    x.name,
                    x.filename,
                    x.description,
                    x.mime_type,
                    x.size,
                    x.declared_size,
                    x.created,
                    x.modified,
                    x.sha256,
                    x.location,
                )
                for x in inter.embedded_files
            ],
        ),
        _write_csv(
            directory / "form_fields.csv",
            ["name", "type", "value", "flags"],
            [(x.name, x.field_type, x.value, x.flags) for x in inter.form_fields],
        ),
        _write_csv(
            directory / "signatures.csv",
            [
                "field",
                "subfilter",
                "signing_time",
                "name",
                "reason",
                "location",
                "byte_range",
                "covers_whole_file",
                "bytes_after",
                "certificates",
            ],
            [
                (
                    x.field_name,
                    x.subfilter,
                    x.signing_time,
                    x.name,
                    x.reason,
                    x.location,
                    x.byte_range,
                    x.covers_whole_file,
                    x.bytes_after_signed_range,
                    x.certificates,
                )
                for x in inter.signatures
            ],
        ),
        _write_csv(
            directory / "image_metadata.csv",
            [
                "object_id",
                "pages",
                "format",
                "width",
                "height",
                "camera",
                "software",
                "dates",
                "gps",
                "icc",
                "jpeg_quality_estimate",
                "raw_sha256",
            ],
            [
                (
                    x.object_id,
                    x.pages,
                    x.format,
                    x.width,
                    x.height,
                    x.camera,
                    x.software,
                    x.dates,
                    x.gps,
                    x.icc_description,
                    x.jpeg_quality_estimate,
                    x.raw_sha256,
                )
                for x in analysis.image_evidence
            ],
        ),
        _write_csv(
            directory / "text_anomalies.csv",
            ["page", "kind", "description", "text", "bbox", "details"],
            [(x.page, x.kind, x.description, x.text, x.bbox, x.details) for x in analysis.text_forensics.anomalies],
        ),
        _write_csv(
            directory / "ocr_pages.csv",
            [
                "page",
                "ocr_words",
                "mean_confidence",
                "layer_words",
                "layer_words_seen",
                "hidden_runs",
                "visible_not_in_layer",
                "error",
            ],
            [
                (
                    p.page,
                    p.words,
                    p.mean_confidence,
                    p.layer_words,
                    p.layer_words_seen,
                    len(p.unseen_layer_text),
                    len(p.visible_not_in_layer),
                    p.error,
                )
                for p in analysis.ocr.pages
            ],
        ),
        _write_csv(
            directory / "ocr_differences.csv",
            ["page", "kind", "text", "bbox", "words"],
            [
                (r.page, r.source, r.text, r.bbox, r.words)
                for p in analysis.ocr.pages
                for r in [*p.unseen_layer_text, *p.visible_not_in_layer]
            ],
        ),
        _write_csv(directory / "objects_by_type.csv", ["type", "count"], list(analysis.objects.by_type.items())),
        _write_csv(
            directory / "parser_crosscheck.csv",
            ["parser", "field", "value"],
            [(parser, k, v) for parser, data in analysis.crosscheck.parsers.items() for k, v in data.items()],
        ),
    ]


def write_fonts_csv(fonts: Sequence[Any], path: Path) -> Path:
    return _write_csv(
        path,
        [
            "name",
            "type",
            "encoding",
            "embedded",
            "subset",
            "unicode",
            "object_id",
            "source",
            "version",
            "vendor",
            "copyright",
            "glyphs",
            "head_created",
            "head_modified",
            "pages_used",
        ],
        [
            (
                f.name,
                f.font_type,
                f.encoding,
                f.embedded,
                f.subset,
                f.unicode,
                f.object_id,
                f.source,
                f.embedded_info.version if f.embedded_info else None,
                f.embedded_info.vendor if f.embedded_info else None,
                f.embedded_info.copyright if f.embedded_info else None,
                f.embedded_info.glyph_count if f.embedded_info else None,
                f.embedded_info.head.get("created") if f.embedded_info else None,
                f.embedded_info.head.get("modified") if f.embedded_info else None,
                f.pages_used,
            )
            for f in fonts
        ],
    )


def write_images_csv(images: Sequence[Any], path: Path) -> Path:
    return _write_csv(
        path,
        [
            "page",
            "num",
            "object_id",
            "type",
            "width",
            "height",
            "color",
            "comp",
            "bpc",
            "encoding",
            "x_ppi",
            "y_ppi",
            "size",
            "ratio",
            "source",
        ],
        [
            (
                i.page,
                i.index,
                i.object_id,
                i.image_type,
                i.width,
                i.height,
                i.color,
                i.components,
                i.bpc,
                i.encoding,
                i.x_ppi,
                i.y_ppi,
                i.size,
                i.ratio,
                i.source,
            )
            for i in images
        ],
    )


def write_findings_csv(analysis: PDFAnalysis, path: Path) -> Path:
    return _write_csv(
        path,
        ["id", "severity", "category", "title", "description", "page", "evidence", "source"],
        [
            (f.id, f.severity.value, f.category, f.title, f.description, f.page, f.evidence, f.source)
            for f in analysis.findings
        ],
    )


def write_tool_outputs(analysis: PDFAnalysis, directory: Path) -> list[Path]:
    """Save stdout/stderr of each tool action plus a SHA-256 manifest."""
    directory.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    manifest = ["file\tsha256\tcommand"]
    for run in analysis.external_runs:
        stem = f"{run.tool_id}__{run.action_id}"
        for suffix, content in (("stdout.txt", run.stdout), ("stderr.txt", run.stderr)):
            if not content and suffix == "stderr.txt":
                continue
            path = directory / f"{stem}.{suffix}"
            data = content.encode("utf-8")
            path.write_bytes(data)
            manifest.append(f"{path.name}\t{hashlib.sha256(data).hexdigest()}\t{' '.join(run.command)}")
            written.append(path)
    manifest_path = directory / "MANIFEST.tsv"
    manifest_path.write_text("\n".join(manifest) + "\n", encoding="utf-8")
    return [*written, manifest_path]


def write_ocr_text(analysis: PDFAnalysis, path: Path) -> Path:
    o = analysis.ocr
    header = f"OCR: tesseract {o.version or '?'} languages={o.languages} dpi={o.dpi}\n"
    parts = [f"===== Page {p.page} (OCR, mean confidence {p.mean_confidence}) =====\n{p.text}\n" for p in o.pages]
    path.write_text(header + ("\n".join(parts) if parts else (o.error or "OCR not run")) + "\n", encoding="utf-8")
    return path


def write_text(analysis: PDFAnalysis, path: Path) -> Path:
    parts = [f"===== Page {p.number} =====\n{p.text}\n" for p in analysis.pages]
    path.write_text("\n".join(parts), encoding="utf-8")
    return path


def write_words_csv(analysis: PDFAnalysis, path: Path) -> Path:
    return _write_csv(
        path,
        ["page", "text", "x0", "top", "x1", "bottom"],
        [(p.number, b.label, b.x0, b.top, b.x1, b.bottom) for p in analysis.pages for b in p.boxes if b.kind == "word"],
    )


# ------------------------------------------------------------------- Markdown
def _md(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def _md_table(header: Sequence[str], rows: Iterable[Sequence[Any]]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(_md(v) for v in row) + " |" for row in rows]
    return "\n".join(lines)


def to_markdown(analysis: PDFAnalysis) -> str:
    s = summary(analysis)
    m = analysis.metadata
    out = [
        f"# PDFTrace report: {_md(analysis.file.name)}",
        "",
        f"_{DISCLAIMER}_",
        "",
        "## File",
        _md_table(
            ["Field", "Value"],
            [
                ("Path", analysis.file.path),
                ("Size", f"{analysis.file.size} bytes"),
                ("SHA-256", analysis.hashes.sha256),
                ("SHA-1", analysis.hashes.sha1),
                ("MD5", analysis.hashes.md5),
                ("Analyzed (UTC)", analysis.analyzed_at_utc),
                ("Tool", f"{analysis.tool} {analysis.tool_version}"),
            ],
        ),
        "",
        "## Summary",
        _md_table(["Item", "Value"], [(k, v) for k, v in s.items()]),
        "",
        "## Findings",
        _md_table(
            ["ID", "Severity", "Category", "Title", "Description", "Page"],
            [(f.id, f.severity.value.upper(), f.category, f.title, f.description, f.page) for f in analysis.findings],
        )
        if analysis.findings
        else "No findings.",
        "",
        "## Timeline",
        _md_table(
            ["Timestamp", "Kind", "Description", "Caveat"],
            [(e.timestamp, e.kind, e.description, e.caveat) for e in analysis.timeline],
        )
        if analysis.timeline
        else "No timestamps found.",
        "",
        "## Metadata (Info dictionary)",
        _md_table(["Field", "Value", "Note"], [(v.field, v.value, v.note) for v in m.info + m.custom]),
        "",
        "## Info vs XMP",
        _md_table(
            ["Field", "Info", "XMP key", "XMP", "Status"],
            [(c.field, c.info_value, c.xmp_key, c.xmp_value, c.status) for c in m.comparisons],
        ),
        "",
        "## XMP properties",
        _md_table(["Property", "Value"], [(v.field, v.value) for v in m.xmp]) if m.xmp else "No XMP packet.",
        "",
        "## Fonts",
        _md_table(
            ["Font", "Type", "Emb", "Sub", "Uni", "Obj", "Version", "Built (head.modified)"],
            [
                (
                    f.name,
                    f.font_type,
                    f.embedded,
                    f.subset,
                    f.unicode,
                    f.object_id,
                    f.embedded_info.version if f.embedded_info else "",
                    f.embedded_info.head.get("modified") if f.embedded_info else "",
                )
                for f in analysis.fonts
            ],
        ),
        "",
        "## Images",
        _md_table(
            ["Page", "Obj", "Size", "Color", "BPC", "Encoding", "ppi", "Source"],
            [
                (
                    i.page,
                    i.object_id,
                    f"{i.width}x{i.height}",
                    i.color,
                    i.bpc,
                    i.encoding,
                    f"{i.x_ppi}x{i.y_ppi}" if i.x_ppi else "",
                    i.source,
                )
                for i in analysis.images
            ],
        )
        if analysis.images
        else "No raster images.",
        "",
        "## Structure",
        _md_table(
            ["Item", "Value"],
            [
                ("Header version", analysis.structure.header_version),
                ("%%EOF markers", len(analysis.structure.eof_offsets)),
                ("Incremental updates", analysis.structure.incremental_updates),
                ("xref tables / streams", f"{analysis.structure.xref_tables} / {analysis.structure.xref_streams}"),
                (
                    "Objects (defined / unique)",
                    f"{analysis.structure.object_definitions} / {analysis.structure.unique_objects}",
                ),
                ("Linearized", analysis.structure.linearized),
                ("Trailer IDs", analysis.structure.trailer_ids),
                ("Comments", analysis.structure.comments),
            ],
        ),
        "",
        "## Interactive content",
        _md_table(
            ["Page", "Annotation", "Author", "Modified", "Contents / URI"],
            [(x.page, x.subtype, x.author, x.modified, x.uri or x.contents) for x in analysis.interactive.annotations],
        )
        if analysis.interactive.annotations
        else "No annotations.",
        "",
        _md_table(
            ["Location", "Trigger", "Action", "Target"],
            [(x.location, x.trigger, x.action_type, x.target) for x in analysis.interactive.actions],
        )
        if analysis.interactive.actions
        else "No actions.",
        "",
        _md_table(
            ["Attachment", "Size", "Created", "Modified", "SHA-256"],
            [
                (x.filename or x.name, x.size, x.created, x.modified, x.sha256)
                for x in analysis.interactive.embedded_files
            ],
        )
        if analysis.interactive.embedded_files
        else "No embedded files.",
        "",
        _md_table(
            ["Signature", "SubFilter", "Signing time", "Signer", "Covers whole file"],
            [
                (
                    x.field_name,
                    x.subfilter,
                    x.signing_time,
                    "; ".join(c["subject"] for c in x.certificates),
                    x.covers_whole_file,
                )
                for x in analysis.interactive.signatures
            ],
        )
        if analysis.interactive.signatures
        else "No signatures.",
        "",
        "## Image metadata",
        _md_table(
            ["Object", "Pages", "Format", "Camera", "Software", "Dates", "GPS"],
            [(x.object_id, x.pages, x.format, x.camera, x.software, x.dates, x.gps) for x in analysis.image_evidence],
        )
        if analysis.image_evidence
        else "No images.",
        "",
        "## Text layer anomalies",
        _md_table(
            ["Page", "Kind", "Text", "Details"],
            [(x.page, x.kind, x.text[:80], _short(x.details, 120)) for x in analysis.text_forensics.anomalies],
        )
        if analysis.text_forensics.anomalies
        else "None detected.",
        "",
        "## OCR and text layer",
        _md_table(
            ["Page", "Difference", "Text", "BBox"],
            [
                (r.page, r.source, r.text[:100], r.bbox)
                for p in analysis.ocr.pages
                for r in [*p.unseen_layer_text, *p.visible_not_in_layer]
            ],
        )
        if any(p.unseen_layer_text or p.visible_not_in_layer for p in analysis.ocr.pages)
        else (analysis.ocr.error or ("No difference." if analysis.ocr.pages else "OCR not run.")),
        "",
        "## Parser cross-check",
        _md_table(
            ["Parser", *sorted({k for d in analysis.crosscheck.parsers.values() for k in d})[:8]],
            [
                (name, *[data.get(k) for k in sorted({k for d in analysis.crosscheck.parsers.values() for k in d})[:8]])
                for name, data in analysis.crosscheck.parsers.items()
            ],
        ),
        "",
        "## External tools",
        _md_table(
            ["Tool", "Action", "Version", "Status", "Exit", "Duration (s)", "Summary"],
            [
                (
                    r.tool_name,
                    r.action_label,
                    r.version,
                    r.status,
                    r.returncode,
                    f"{r.duration_s:.2f}",
                    _short(r.parsed),
                )
                for r in analysis.external_runs
            ],
        )
        if analysis.external_runs
        else "No external tool was run.",
        "",
        "## Pipeline",
        _md_table(
            ["Step", "State", "Duration (s)", "Message"],
            [(st.label, st.state.value, f"{st.duration_s:.2f}", st.message) for st in analysis.steps],
        ),
        "",
        "## Tools",
        _md_table(
            ["Tool", "Available", "Version", "Note"],
            [(t.name, t.available, t.version, t.error) for t in analysis.tools],
        ),
        "",
    ]
    return "\n".join(out)


def _short(parsed: dict[str, Any], limit: int = 200) -> str:
    if not parsed:
        return ""
    text = json.dumps({k: v for k, v in parsed.items() if k != "tags"}, ensure_ascii=False, default=str)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def write_markdown(analysis: PDFAnalysis, path: Path) -> Path:
    path.write_text(to_markdown(analysis), encoding="utf-8")
    return path


# ----------------------------------------------------------------------- HTML
_CSS = """
:root{--ink:#1d2a3a;--paper:#fafbfc;--rule:#d5dbe3;--muted:#5b6778;--info:#2f6690;
--notice:#a86a00;--warning:#9e2a2b;--band:#eef2f6}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 system-ui,-apple-system,
"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
main{max-width:1080px;margin:0 auto;padding:40px 28px 80px}
h1,h2{font-family:Charter,"Bitstream Charter","Sitka Text",Cambria,Georgia,serif;font-weight:600}
h1{font-size:30px;line-height:1.2;margin:0 0 6px}
h3{font-size:16px;margin:22px 0 8px}
h2{font-size:21px;margin:44px 0 12px;padding-bottom:6px;border-bottom:2px solid var(--ink)}
p.lede{color:var(--muted);margin:0 0 28px;max-width:72ch}
.custody{border:2px solid var(--ink);padding:18px 22px;background:#fff}
.custody .label{color:var(--muted)}
.custody .hash{font:600 17px/1.4 ui-monospace,"SFMono-Regular",Menlo,Consolas,monospace;
word-break:break-all;margin:4px 0 14px}
.custody dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 18px;margin:0}
dt{color:var(--muted)}dd{margin:0;word-break:break-word}
.figures{display:-webkit-box;display:flex;flex-wrap:wrap;border-left:1px solid var(--rule);
border-top:1px solid var(--rule);margin-top:18px}
.figures div{flex:1 1 130px;min-width:130px;background:#fff;padding:12px 14px;
border-right:1px solid var(--rule);border-bottom:1px solid var(--rule)}.figures b{display:block;font-size:22px}
.figures span{color:var(--muted);font-size:13px}
.wrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:14px;background:#fff}
th,td{text-align:left;vertical-align:top;padding:7px 10px;border-bottom:1px solid var(--rule)}
th{background:var(--band);font-weight:600}
td.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;word-break:break-all}
.finding{display:grid;grid-template-columns:6px 1fr;background:#fff;border:1px solid var(--rule);
margin:8px 0}
.finding .bar{background:var(--info)}.finding.notice .bar{background:var(--notice)}
.finding.warning .bar{background:var(--warning)}
.finding .body{padding:10px 14px}.finding h3{margin:0 0 4px;font-size:15px}
.sev{font-size:12px;font-weight:700;margin-right:8px}.sev.info{color:var(--info)}
.sev.notice{color:var(--notice)}.sev.warning{color:var(--warning)}
.finding p{margin:0 0 6px}.finding pre{margin:0;white-space:pre-wrap;font-size:12px;color:var(--muted)}
.status-difference{color:var(--warning);font-weight:600}.status-match{color:#2d6a3e}
details{background:#fff;border:1px solid var(--rule);margin:6px 0;padding:6px 10px}
summary{cursor:pointer;font-weight:600}
pre.raw{white-space:pre-wrap;word-break:break-all;font-size:12px;max-height:480px;overflow:auto}
p.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:var(--muted)}
footer{margin-top:56px;color:var(--muted);font-size:13px;border-top:1px solid var(--rule);padding-top:12px}
@media (max-width:640px){main{padding:24px 16px}.custody dl{grid-template-columns:1fr}}
@media print{body{background:#fff}.finding{break-inside:avoid}}
"""


HTML_RAW_LIMIT = 20_000


def _ocr_html(analysis: PDFAnalysis) -> str:
    o = analysis.ocr
    if not o.pages:
        return f"<p>{_e(o.error or 'OCR not run.')}</p>"
    head = (
        f"<p>Tesseract {_e(o.version)}, languages {_e(o.languages)}, {o.dpi} dpi, rendering with "
        f"{_e(o.renderer)}. Positions are compared with the text layer.</p>"
    )
    pages = _table(
        [
            "Page",
            "OCR words",
            "Mean confidence",
            "Layer words",
            "Layer words seen",
            "Hidden runs",
            "Visible not in layer",
            "Note",
        ],
        [
            (
                p.page,
                p.words,
                p.mean_confidence,
                p.layer_words,
                p.layer_words_seen,
                len(p.unseen_layer_text),
                len(p.visible_not_in_layer),
                p.error,
            )
            for p in o.pages
        ],
    )
    diffs = [
        (
            r.page,
            "in text layer, not visible" if r.source == "text_layer_not_rendered" else "visible, not in text layer",
            r.text,
            r.bbox,
        )
        for p in o.pages
        for r in [*p.unseen_layer_text, *p.visible_not_in_layer]
    ]
    return (
        head
        + pages
        + (
            _table(["Page", "Difference", "Text", "BBox (pt)"], diffs)
            if diffs
            else "<p>No difference between the rendered pages and the text layer.</p>"
        )
    )


def _deep_html(analysis: PDFAnalysis) -> list[str]:
    inter, objs = analysis.interactive, analysis.objects
    none = "<p>None.</p>"
    scripts = "".join(
        f"<details><summary>{_e(x.location)} {_e(x.trigger)} ({x.length} chars, SHA-256 {_e(x.sha256[:16])}…)"
        f'</summary><pre class="raw">{_e(x.code)}</pre></details>'
        for x in inter.scripts
    )
    return [
        "<h2>Interactive content</h2><h3>Annotations</h3>"
        + (
            _table(
                ["Page", "Type", "Author", "Created", "Modified", "Hidden", "Contents / URI"],
                [
                    (x.page, x.subtype, x.author, x.created, x.modified, x.hidden, x.uri or x.contents)
                    for x in inter.annotations
                ],
            )
            if inter.annotations
            else none
        )
        + "<h3>Actions</h3>"
        + (
            _table(
                ["Location", "Trigger", "Action", "Target"],
                [(x.location, x.trigger, x.action_type, x.target) for x in inter.actions],
            )
            if inter.actions
            else none
        )
        + "<h3>JavaScript (not executed)</h3>"
        + (scripts or none)
        + "<h3>Embedded files</h3>"
        + (
            _table(
                ["Name", "Description", "Type", "Size", "Created", "Modified", "SHA-256"],
                [
                    (x.filename or x.name, x.description, x.mime_type, x.size, x.created, x.modified, x.sha256)
                    for x in inter.embedded_files
                ],
                mono=(6,),
            )
            if inter.embedded_files
            else none
        )
        + "<h3>Form fields</h3>"
        + (
            _table(["Name", "Type", "Value"], [(x.name, x.field_type, x.value) for x in inter.form_fields])
            if inter.form_fields
            else none
        )
        + "<h3>Digital signatures (described, not validated)</h3>"
        + (
            _table(
                [
                    "Field",
                    "SubFilter",
                    "Signing time",
                    "Name",
                    "Reason",
                    "Location",
                    "Covers whole file",
                    "Bytes after",
                    "Certificates",
                ],
                [
                    (
                        x.field_name,
                        x.subfilter,
                        x.signing_time,
                        x.name,
                        x.reason,
                        x.location,
                        x.covers_whole_file,
                        x.bytes_after_signed_range,
                        "; ".join(f"{c['subject']} (issuer {c['issuer']})" for c in x.certificates),
                    )
                    for x in inter.signatures
                ],
            )
            if inter.signatures
            else none
        ),
        "<h2>Image metadata</h2>"
        + (
            _table(
                [
                    "Object",
                    "Pages",
                    "Format",
                    "Size",
                    "Camera",
                    "Software",
                    "Dates",
                    "GPS",
                    "ICC",
                    "JPEG q.",
                    "SHA-256",
                ],
                [
                    (
                        x.object_id,
                        x.pages,
                        x.format,
                        f"{x.width}x{x.height}",
                        x.camera,
                        x.software,
                        x.dates,
                        {k: v for k, v in x.gps.items() if k in ("latitude", "longitude")},
                        x.icc_description,
                        x.jpeg_quality_estimate,
                        x.raw_sha256,
                    )
                    for x in analysis.image_evidence
                ],
                mono=(10,),
            )
            if analysis.image_evidence
            else none
        ),
        "<h2>Text layer anomalies</h2>"
        + (
            _table(
                ["Page", "Kind", "Description", "Text", "Details"],
                [
                    (x.page, x.kind, x.description, x.text, _short(x.details, 160))
                    for x in analysis.text_forensics.anomalies
                ],
            )
            if analysis.text_forensics.anomalies
            else none
        ),
        "<h2>OCR and text layer</h2>" + _ocr_html(analysis),
        "<h2>Objects</h2>"
        + _table(
            ["Item", "Value"],
            [
                ("Objects / streams", f"{objs.total_objects} / {objs.streams}"),
                ("By type", objs.by_type),
                ("Filters", objs.by_filter),
                ("Catalog features", list(objs.catalog_features)),
                ("Layers", objs.layers),
                ("Thumbnails (pages)", objs.thumbnails),
                ("PieceInfo", objs.piece_info),
                ("Output intents", objs.output_intents),
                ("Outline entries", len(objs.outline)),
                ("Page labels", objs.page_labels),
                ("Encryption", objs.encryption),
                ("Permissions", objs.permissions),
                ("Undecodable streams", [f"{x.object_id}: {x.decode_error}" for x in objs.undecodable_streams]),
                ("Generation > 0", objs.nonzero_generation),
                ("qpdf warnings", objs.qpdf_warnings[:20]),
            ],
        ),
        "<h2>Parser cross-check</h2>"
        + _table(["Parser", "Values"], [(name, data) for name, data in analysis.crosscheck.parsers.items()])
        + (
            _table(["Field", "Values per parser"], [(d["field"], d["values"]) for d in analysis.crosscheck.differences])
            if analysis.crosscheck.differences
            else "<p>All parsers agree on the compared fields.</p>"
        ),
    ]


def _external_html(analysis: PDFAnalysis) -> str:
    runs = analysis.external_runs
    if not runs:
        return "<p>No external tool was run.</p>"
    table = _table(
        ["Tool", "Action", "Version", "Licence", "Status", "Exit", "Duration (s)", "Summary"],
        [
            (
                r.tool_name,
                r.action_label,
                r.version,
                r.license,
                r.status,
                r.returncode,
                f"{r.duration_s:.2f}",
                _short(r.parsed),
            )
            for r in runs
        ],
    )
    blocks = []
    for r in runs:
        more = "…[truncated, see JSON report]" if len(r.stdout) > HTML_RAW_LIMIT else ""
        err = f"\n[stderr]\n{_e(r.stderr[:4000])}" if r.stderr.strip() else ""
        blocks.append(
            f"<details><summary>{_e(r.tool_name)}: {_e(r.action_label)} ({_e(r.status)})</summary>"
            f'<p class="mono">{_e(" ".join(r.command))}<br>stdout SHA-256: {_e(r.stdout_sha256)}</p>'
            f'<pre class="raw">{_e(r.stdout[:HTML_RAW_LIMIT])}{more}{err}</pre></details>'
        )
    return table + "".join(blocks)


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _table(header: Sequence[str], rows: Iterable[Sequence[Any]], mono: Sequence[int] = ()) -> str:
    head = "".join(f"<th>{_e(h)}</th>" for h in header)
    body = []
    for row in rows:
        cells = []
        for i, value in enumerate(row):
            cls = ' class="mono"' if i in mono else ""
            cells.append(f"<td{cls}>{_e(value)}</td>")
        body.append("<tr>" + "".join(cells) + "</tr>")
    return f'<div class="wrap"><table><thead><tr>{head}</tr></thead><tbody>{"".join(body)}</tbody></table></div>'


def to_html(analysis: PDFAnalysis) -> str:
    s = summary(analysis)
    m, st = analysis.metadata, analysis.structure
    figures = [
        (s["pages"], "pages"),
        (f"PDF {s['pdf_version'] or '?'}", "header version"),
        (s["revisions"] or "?", "revisions (EOF markers)"),
        (s["fonts_total"], "fonts"),
        (s["fonts_embedded"], "embedded fonts"),
        (s["images_total"], "images"),
        (s["findings_by_severity"]["warning"], "warnings"),
        (s["findings_by_severity"]["notice"], "notices"),
    ]
    findings_html = (
        "".join(
            f'<div class="finding {f.severity.value}"><div class="bar"></div><div class="body">'
            f'<h3><span class="sev {f.severity.value}">{_e(f.severity.value.upper())}</span>'
            f"{_e(f.id)} &middot; {_e(f.title)}</h3><p>{_e(f.description)}</p>"
            f"<pre>{_e(json.dumps(f.evidence, ensure_ascii=False, indent=1)) if f.evidence else ''}</pre>"
            f"</div></div>"
            for f in analysis.findings
        )
        or "<p>No findings.</p>"
    )
    comparison_rows = "".join(
        f"<tr><td>{_e(c.field)}</td><td>{_e(c.info_value)}</td><td>{_e(c.xmp_key)}</td>"
        f'<td>{_e(c.xmp_value)}</td><td class="status-{_e(c.status)}">{_e(c.status)}</td></tr>'
        for c in m.comparisons
    )
    sections = [
        f'<h1>PDFTrace report</h1><p class="lede">{_e(analysis.file.name)}. {_e(DISCLAIMER)}</p>',
        '<section class="custody"><div class="label">SHA-256 (primary hash)</div>'
        f'<div class="hash">{_e(analysis.hashes.sha256)}</div><dl>'
        f"<dt>File</dt><dd>{_e(analysis.file.path)}</dd>"
        f"<dt>Size</dt><dd>{analysis.file.size:,} bytes</dd>"
        f'<dt>SHA-1</dt><dd class="mono">{_e(analysis.hashes.sha1)}</dd>'
        f'<dt>MD5</dt><dd class="mono">{_e(analysis.hashes.md5)}</dd>'
        f"<dt>Analyzed (UTC)</dt><dd>{_e(analysis.analyzed_at_utc)}</dd>"
        f"<dt>Tool</dt><dd>{_e(analysis.tool)} {_e(analysis.tool_version)}</dd></dl></section>",
        '<div class="figures">'
        + "".join(f"<div><b>{_e(v)}</b><span>{_e(k)}</span></div>" for v, k in figures)
        + "</div>",
        f"<h2>Findings</h2>{findings_html}",
        "<h2>Timeline</h2>"
        + (
            _table(
                ["Timestamp", "Kind", "Description", "Source", "Caveat"],
                [(e.timestamp, e.kind, e.description, e.source, e.caveat) for e in analysis.timeline],
                mono=(0,),
            )
            if analysis.timeline
            else "<p>No timestamps found.</p>"
        ),
        "<h2>Metadata</h2>"
        + _table(
            ["Field", "Value", "Source", "Note"], [(v.field, v.value, v.source, v.note) for v in m.info + m.custom]
        ),
        '<h2>Info dictionary vs XMP</h2><div class="wrap"><table><thead><tr><th>Field</th><th>Info</th>'
        f"<th>XMP key</th><th>XMP</th><th>Status</th></tr></thead><tbody>{comparison_rows}</tbody></table></div>",
        "<h2>XMP properties</h2>"
        + (_table(["Property", "Value"], [(v.field, v.value) for v in m.xmp]) if m.xmp else "<p>No XMP packet.</p>"),
        "<h2>Fonts</h2>"
        + _table(
            ["Font", "Type", "Encoding", "Emb", "Sub", "Uni", "Obj", "Version", "Vendor", "Built", "Pages"],
            [
                (
                    f.name,
                    f.font_type,
                    f.encoding,
                    f.embedded,
                    f.subset,
                    f.unicode,
                    f.object_id,
                    f.embedded_info.version if f.embedded_info else "",
                    f.embedded_info.vendor if f.embedded_info else "",
                    f.embedded_info.head.get("modified") if f.embedded_info else "",
                    ", ".join(map(str, f.pages_used)),
                )
                for f in analysis.fonts
            ],
        ),
        "<h2>Images</h2>"
        + (
            _table(
                ["Page", "Obj", "Size", "Color", "BPC", "Encoding", "ppi", "Bytes", "Source"],
                [
                    (
                        i.page,
                        i.object_id,
                        f"{i.width}x{i.height}",
                        i.color,
                        i.bpc,
                        i.encoding,
                        f"{i.x_ppi}x{i.y_ppi}" if i.x_ppi else "",
                        i.size,
                        i.source,
                    )
                    for i in analysis.images
                ],
            )
            if analysis.images
            else "<p>No raster images.</p>"
        ),
        "<h2>Pages</h2>"
        + _table(
            ["Page", "Size (pt)", "Chars", "Words", "Lines", "Rects", "Curves", "Images", "Density"],
            [
                (p.number, f"{p.width} x {p.height}", p.chars, p.words, p.lines, p.rects, p.curves, p.images, p.density)
                for p in analysis.pages
            ],
        ),
        "<h2>Structure</h2>"
        + _table(
            ["Item", "Value"],
            [
                ("Header version", st.header_version),
                ("%%EOF offsets", st.eof_offsets),
                ("startxref", st.startxref_values),
                ("Incremental updates", st.incremental_updates),
                ("xref tables / streams", f"{st.xref_tables} / {st.xref_streams}"),
                ("Objects defined / unique", f"{st.object_definitions} / {st.unique_objects}"),
                ("Object streams", st.object_streams),
                ("Linearized", st.linearized),
                ("Encrypted", st.encrypted),
                ("Trailer IDs", st.trailer_ids),
                ("Comments", st.comments),
                ("Keyword counts", {k: v for k, v in st.keyword_counts.items() if v}),
            ],
        ),
        *_deep_html(analysis),
        "<h2>External tools</h2>" + _external_html(analysis),
        "<h2>Pipeline and tools</h2>"
        + _table(
            ["Step", "State", "Duration (s)", "Message"],
            [(x.label, x.state.value, f"{x.duration_s:.2f}", x.message) for x in analysis.steps],
        )
        + _table(
            ["Tool", "Available", "Path", "Version", "Note"],
            [(t.name, t.available, t.path, t.version, t.error) for t in analysis.tools],
        ),
        f"<footer>{_e(analysis.tool)} {_e(analysis.tool_version)}. The analysed file was opened read-only; "
        "no script or link in it was executed or followed.</footer>",
    ]
    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        f"<title>PDFTrace report: {_e(analysis.file.name)}</title><style>{_CSS}</style></head>"
        f"<body><main>{''.join(sections)}</main></body></html>"
    )


def write_html(analysis: PDFAnalysis, path: Path) -> Path:
    path.write_text(to_html(analysis), encoding="utf-8")
    return path
