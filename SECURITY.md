# Security

## Threat model

The tool is designed so that opening a file cannot execute code from it, alter it, or reach the network.

| Measure | Where |
|---|---|
| The input file is opened read-only; hashes are computed before any parsing | `core/hashing.py`, `core/pipeline.py` |
| No PDF JavaScript is executed; no URL, launch action or attachment is opened or followed | parsers are passive; Page rendering uses pypdfium2 without a form environment |
| External tools run with list arguments, no shell, closed stdin, timeout and capped output | `integrations/process.py` |
| Paths are resolved to absolute paths, so they can never be read as command options | `utils/paths.py` |
| Temporary files are created with `tempfile` in private directories and removed | `integrations/poppler.py`, GUI image view |
| XMP: size limit, packets with DTD/ENTITY declarations are refused, expat resolves no external entities | `analyzers/metadata.py` |
| Size limits for font programs, XMP, tool output, words and shapes per page, pages analysed | `config.py` |
| Toolbox tools: only read-only options (enforced by a test), no shell, timeout, raw output hashed | `integrations/toolbox.py` |
| Python libraries (pikepdf, pypdf) run in a separate process | `integrations/pyrunners.py` |
| JavaScript is extracted as text and never executed; embedded files are extracted only on request and never opened | `analyzers/interactive.py`, `integrations/pikepdf_adapter.py` |
| Images are decoded in memory with Pillow (size limit) to read their metadata | `analyzers/image_evidence.py` |
| OCR: pages are rendered by PDFium without forms or JavaScript into a private temporary folder, and read by Tesseract as a separate process with a timeout | `analyzers/ocr.py`, `integrations/tesseract.py` |
| Malformed files never crash the run: every analyzer failure is isolated and reported | `core/pipeline.py` |
| HTML report: every value escaped, no script, restrictive Content-Security-Policy, no external resources | `core/report.py` |
| CSV export: values starting with `= + - @` are prefixed to prevent formula injection | `core/report.py` |

## Residual risks

- Parsing libraries (pdfminer.six, pypdfium2/PDFium, fontTools, Poppler) may contain vulnerabilities.
  Keep them updated and, for high-risk material, run the tool in a disposable VM without network.
- Toolbox tools are third-party programs with their own vulnerabilities; Ghostscript interprets
  content (with `-dSAFER`). Custom tools are the analyst's responsibility.
- "Open image" hands an extracted image to the operating system's default viewer.
- Decompression bombs: stream sizes are bounded where the libraries allow it, but a crafted file can
  still consume significant memory or CPU; timeouts only apply to external processes.

## Reporting a vulnerability

Vulnerabilities are reported privately through GitHub Security Advisories (repository **Security** tab,
*Report a vulnerability*), not through public issues. A report includes a description and, when
possible, a minimal reproducer without personal or case data. Reports are acknowledged within 7 days.
