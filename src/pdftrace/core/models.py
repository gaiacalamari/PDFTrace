"""Typed, JSON-serialisable data models.

Every value extracted from the PDF keeps its *provenance*: the component that
produced it (``source``) and how directly it was observed (``confidence``):

* ``direct``   - read verbatim from the file or from a tool's output;
* ``derived``  - computed from direct values (e.g. a parsed date, a count);
* ``heuristic``- an interpretation that the analyst must review.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from enum import Enum, StrEnum
from typing import Any


class Severity(StrEnum):
    """Finding severity. Findings are technical indicators, never conclusions."""

    INFO = "info"
    NOTICE = "notice"
    WARNING = "warning"

    @property
    def rank(self) -> int:
        return {"info": 0, "notice": 1, "warning": 2}[self.value]


class StepState(StrEnum):
    """State of one pipeline step, as shown in the GUI and CLI."""

    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    SKIPPED = "skipped"
    ERROR = "error"
    CANCELLED = "cancelled"


@dataclass
class ProvenancedValue:
    """A single extracted value together with where it came from."""

    field: str
    value: Any
    source: str
    confidence: str = "direct"
    raw: str | None = None
    note: str | None = None


@dataclass
class FileInfo:
    path: str
    name: str
    size: int
    #: Modification time of the *analysed copy* on the analyst's file system.
    filesystem_mtime_utc: str | None = None


@dataclass
class Hashes:
    sha256: str
    sha1: str
    md5: str


@dataclass
class MetadataComparison:
    """Info dictionary vs XMP comparison for one logical field."""

    field: str
    info_key: str
    xmp_key: str
    info_value: str | None
    xmp_value: str | None
    #: ``match`` | ``difference`` | ``only_info`` | ``only_xmp`` | ``absent``
    status: str


@dataclass
class InfoRevision:
    """An Info dictionary referenced by one trailer (one revision of the file)."""

    index: int
    values: dict[str, str]
    source: str = "pdfminer_trailer"


@dataclass
class Metadata:
    info: list[ProvenancedValue] = field(default_factory=list)
    custom: list[ProvenancedValue] = field(default_factory=list)
    xmp_present: bool = False
    xmp: list[ProvenancedValue] = field(default_factory=list)
    xmp_raw: str | None = None
    xmp_error: str | None = None
    comparisons: list[MetadataComparison] = field(default_factory=list)
    info_revisions: list[InfoRevision] = field(default_factory=list)
    pdf_version: str | None = None
    catalog_version: str | None = None
    encrypted: bool = False
    permissions: dict[str, bool] = field(default_factory=dict)
    page_count: int | None = None
    trailer_ids: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def info_value(self, key: str) -> str | None:
        for item in self.info:
            if item.field == key:
                return None if item.value is None else str(item.value)
        return None

    def xmp_value(self, key: str) -> str | None:
        for item in self.xmp:
            if item.field == key:
                return None if item.value is None else str(item.value)
        return None


@dataclass
class XrefSection:
    """One cross-reference section reached from ``startxref`` / ``/Prev``."""

    offset: int
    declared_offset: int
    kind: str  # "table" or "stream"
    end: int  # first byte after the trailer dictionary (table) or ``endobj`` (stream)
    prev: int | None = None
    xref_stm: int | None = None  # hybrid-reference file: offset of the companion xref stream
    trailer: dict[str, str] = field(default_factory=dict)  # Size, Root, Info, ID, Encrypt, Prev


@dataclass
class RevisionInfo:
    """One revision of the file, oldest first (index 0 is the original)."""

    index: int
    xref_offsets: list[int] = field(default_factory=list)
    kinds: list[str] = field(default_factory=list)
    startxref: int | None = None  # value of the startxref that closes the revision
    eof_offset: int | None = None  # start of the closing %%EOF
    end: int | None = None  # truncation point: the file up to here is this revision
    linearized: bool = False
    trailer: dict[str, str] = field(default_factory=dict)


@dataclass
class XrefChain:
    """Revisions reconstructed by following startxref and the /Prev chain."""

    #: "xref_chain" when the chain was followed, "eof_heuristic" when it could not be.
    method: str = "xref_chain"
    #: False when the chain breaks before reaching a section without /Prev.
    complete: bool = True
    sections: list[XrefSection] = field(default_factory=list)  # newest first, as walked
    revisions: list[RevisionInfo] = field(default_factory=list)  # oldest first
    linearized: bool = False
    linearization_length: int | None = None  # /L of the linearization dictionary
    orphan_eof_offsets: list[int] = field(default_factory=list)
    orphan_eof_in_stream: list[int] = field(default_factory=list)  # subset (heuristic)
    unreachable_xref_offsets: list[int] = field(default_factory=list)
    unreachable_xref_in_stream: list[int] = field(default_factory=list)  # subset (heuristic)
    #: Unreachable sections outside stream data and closed by their own startxref/%%EOF:
    #: complete earlier versions that a conforming reader no longer sees.
    detached_revisions: list[RevisionInfo] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)


@dataclass
class StructureInfo:
    header_version: str | None = None
    header_offset: int | None = None
    eof_offsets: list[int] = field(default_factory=list)
    startxref_values: list[int] = field(default_factory=list)
    xref_tables: int = 0
    xref_streams: int = 0
    trailers: int = 0
    prev_pointers: list[int] = field(default_factory=list)
    object_definitions: int = 0
    unique_objects: int = 0
    redefined_objects: list[int] = field(default_factory=list)
    object_streams: int = 0
    linearized: bool = False
    encrypted: bool = False
    trailing_bytes_after_eof: int = 0
    incremental_updates: int = 0
    xref_chain: XrefChain = field(default_factory=XrefChain)
    keyword_counts: dict[str, int] = field(default_factory=dict)
    comments: list[str] = field(default_factory=list)
    trailer_ids: list[list[str]] = field(default_factory=list)
    catalog_keys: list[str] = field(default_factory=list)
    pdfinfo: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


@dataclass
class EmbeddedFontInfo:
    """Information read from an embedded font program with fontTools."""

    source: str = "fonttools"
    font_file_key: str | None = None
    program_format: str | None = None
    size_bytes: int = 0
    family: str | None = None
    subfamily: str | None = None
    full_name: str | None = None
    postscript_name: str | None = None
    version: str | None = None
    unique_id: str | None = None
    vendor: str | None = None
    manufacturer: str | None = None
    copyright: str | None = None
    trademark: str | None = None
    license: str | None = None
    license_url: str | None = None
    glyph_count: int | None = None
    unicode_codepoints: int | None = None
    unicode_coverage: str | None = None
    unicode_ranges: list[str] = field(default_factory=list)
    tables: list[str] = field(default_factory=list)
    head: dict[str, Any] = field(default_factory=dict)
    os2: dict[str, Any] = field(default_factory=dict)
    hhea: dict[str, Any] = field(default_factory=dict)
    post: dict[str, Any] = field(default_factory=dict)
    meta: dict[str, str] = field(default_factory=dict)
    name_records: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None


@dataclass
class FontInfo:
    name: str
    base_name: str
    subset_tag: str | None
    font_type: str
    encoding: str | None
    embedded: bool | None
    subset: bool | None
    unicode: bool | None
    object_id: int | None
    generation: int | None
    source: str
    embedded_info: EmbeddedFontInfo | None = None
    pages_used: list[int] = field(default_factory=list)
    chars_rendered: int = 0


@dataclass
class ImageInfo:
    page: int
    index: int | None
    object_id: int | None
    generation: int | None
    image_type: str | None
    width: int | None
    height: int | None
    color: str | None
    components: int | None
    bpc: int | None
    encoding: str | None
    interpolate: bool | None
    x_ppi: float | None
    y_ppi: float | None
    size: str | None
    ratio: str | None
    source: str
    bbox: list[float] | None = None


@dataclass
class Box:
    """A rectangle in PDF points, top-left origin (pdfplumber convention)."""

    x0: float
    top: float
    x1: float
    bottom: float
    kind: str
    label: str | None = None


@dataclass
class PageInfo:
    number: int
    width: float
    height: float
    rotation: int
    mediabox: list[float]
    cropbox: list[float]
    chars: int = 0
    visible_chars: int = 0
    words: int = 0
    text_lines: int = 0
    lines: int = 0
    rects: int = 0
    curves: int = 0
    images: int = 0
    annotations: int = 0
    hyperlinks: int = 0
    fonts: dict[str, int] = field(default_factory=dict)
    font_sizes: dict[str, int] = field(default_factory=dict)
    density: float = 0.0
    text: str = ""
    boxes: list[Box] = field(default_factory=list)
    boxes_truncated: bool = False
    error: str | None = None


@dataclass
class DateMention:
    text: str
    page: int
    normalized: str | None
    source: str = "pdfplumber_text"


@dataclass
class TextSummary:
    total_chars: int = 0
    total_words: int = 0
    total_text_lines: int = 0
    pages_analyzed: int = 0
    pages_truncated: bool = False
    fonts_used: dict[str, int] = field(default_factory=dict)
    font_sizes: dict[str, int] = field(default_factory=dict)
    empty_pages: list[int] = field(default_factory=list)
    low_text_pages: list[int] = field(default_factory=list)
    density_outliers: list[int] = field(default_factory=list)
    date_mentions: list[DateMention] = field(default_factory=list)


@dataclass
class TimelineEvent:
    """A timestamp found in the file, with its meaning and reliability caveat."""

    timestamp: str
    kind: str
    description: str
    source: str
    confidence: str
    caveat: str | None = None


@dataclass
class Finding:
    id: str
    category: str
    severity: Severity
    title: str
    description: str
    page: int | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    source: str = "findings_engine"


@dataclass
class ToolStatus:
    name: str
    available: bool
    path: str | None = None
    version: str | None = None
    error: str | None = None
    kind: str = "external"


@dataclass
class StreamInfo:
    object_id: int
    generation: int
    type: str | None
    subtype: str | None
    filters: list[str]
    raw_length: int
    decoded_length: int | None = None
    decode_error: str | None = None


@dataclass
class ObjectInventory:
    """Object-level inventory read with pikepdf (libqpdf)."""

    source: str = "pikepdf"
    total_objects: int = 0
    streams: int = 0
    by_type: dict[str, int] = field(default_factory=dict)
    by_filter: dict[str, int] = field(default_factory=dict)
    nonzero_generation: list[str] = field(default_factory=list)
    undecodable_streams: list[StreamInfo] = field(default_factory=list)
    largest_streams: list[StreamInfo] = field(default_factory=list)
    catalog_features: dict[str, Any] = field(default_factory=dict)
    encryption: dict[str, Any] = field(default_factory=dict)
    permissions: dict[str, bool] = field(default_factory=dict)
    pdf_version: str | None = None
    extension_level: int | None = None
    linearized: bool | None = None
    page_labels: list[dict[str, Any]] = field(default_factory=list)
    outline: list[dict[str, Any]] = field(default_factory=list)
    layers: list[dict[str, Any]] = field(default_factory=list)
    output_intents: list[dict[str, Any]] = field(default_factory=list)
    piece_info: list[str] = field(default_factory=list)
    thumbnails: list[int] = field(default_factory=list)
    page_boxes: list[dict[str, Any]] = field(default_factory=list)
    qpdf_warnings: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class Annotation:
    page: int
    subtype: str
    rect: list[float]
    contents: str | None = None
    author: str | None = None
    modified: str | None = None
    created: str | None = None
    uri: str | None = None
    action: str | None = None
    flags: int | None = None
    hidden: bool = False
    name: str | None = None
    source: str = "pikepdf"


@dataclass
class FormField:
    name: str
    field_type: str | None
    value: str | None
    flags: int | None = None
    has_actions: bool = False
    source: str = "pikepdf"


@dataclass
class EmbeddedFile:
    name: str
    filename: str | None
    description: str | None
    mime_type: str | None
    size: int | None
    declared_size: int | None
    created: str | None
    modified: str | None
    sha256: str | None
    declared_checksum: str | None = None
    relationship: str | None = None
    location: str = "EmbeddedFiles"
    error: str | None = None
    source: str = "pikepdf"


@dataclass
class ScriptItem:
    location: str
    trigger: str
    length: int
    sha256: str
    code: str
    source: str = "pikepdf"


@dataclass
class ActionItem:
    location: str
    trigger: str
    action_type: str
    target: str | None = None
    source: str = "pikepdf"


@dataclass
class SignatureInfo:
    field_name: str
    filter: str | None = None
    subfilter: str | None = None
    signing_time: str | None = None
    name: str | None = None
    reason: str | None = None
    location: str | None = None
    contact: str | None = None
    byte_range: list[int] = field(default_factory=list)
    covers_whole_file: bool | None = None
    bytes_after_signed_range: int | None = None
    contents_length: int | None = None
    certificates: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    source: str = "pikepdf+cryptography"


@dataclass
class Interactive:
    annotations: list[Annotation] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    form_fields: list[FormField] = field(default_factory=list)
    form_type: str | None = None
    embedded_files: list[EmbeddedFile] = field(default_factory=list)
    scripts: list[ScriptItem] = field(default_factory=list)
    actions: list[ActionItem] = field(default_factory=list)
    signatures: list[SignatureInfo] = field(default_factory=list)
    named_destinations: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass
class ImageEvidence:
    """Metadata found *inside* an embedded image stream (Pillow + XMP parser)."""

    object_id: int
    pages: list[int]
    filters: list[str]
    width: int | None
    height: int | None
    colorspace: str | None
    bpc: int | None
    raw_length: int
    raw_sha256: str
    format: str | None = None
    exif: dict[str, Any] = field(default_factory=dict)
    gps: dict[str, Any] = field(default_factory=dict)
    xmp: dict[str, Any] = field(default_factory=dict)
    iptc: dict[str, Any] = field(default_factory=dict)
    icc_description: str | None = None
    jfif: Any = None
    adobe: Any = None
    progressive: bool | None = None
    jpeg_quality_estimate: int | None = None
    dpi: list[float] | None = None
    camera: str | None = None
    software: str | None = None
    dates: dict[str, str] = field(default_factory=dict)
    error: str | None = None
    source: str = "pikepdf+Pillow"


@dataclass
class TextAnomaly:
    page: int
    kind: str
    description: str
    text: str
    bbox: list[float] | None = None
    details: dict[str, Any] = field(default_factory=dict)
    source: str = "pdfplumber"


@dataclass
class TextForensics:
    anomalies: list[TextAnomaly] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    truncated: bool = False


@dataclass
class ParserCrossCheck:
    """The same facts read by independent parsers (pdfminer, pikepdf, pypdf, PDFium)."""

    parsers: dict[str, dict[str, Any]] = field(default_factory=dict)
    differences: list[dict[str, Any]] = field(default_factory=list)
    pdfium_pages: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class OcrWord:
    text: str
    conf: float
    bbox: list[float]


@dataclass
class OcrRun:
    """Text of the layer (or of the rendering) that has no counterpart in the other source."""

    page: int
    text: str
    bbox: list[float]
    words: int
    source: str


@dataclass
class OcrPage:
    page: int
    words: int = 0
    mean_confidence: float | None = None
    text: str = ""
    layer_words: int = 0
    layer_words_seen: int = 0
    unseen_layer_text: list[OcrRun] = field(default_factory=list)
    visible_not_in_layer: list[OcrRun] = field(default_factory=list)
    error: str | None = None


@dataclass
class OcrResult:
    """OCR of the rendered pages (Tesseract) compared with the PDF text layer."""

    engine: str = "tesseract"
    version: str | None = None
    executable: str | None = None
    tessdata_dir: str | None = None
    languages: str | None = None
    dpi: int | None = None
    renderer: str = "pypdfium2"
    pages: list[OcrPage] = field(default_factory=list)
    pages_truncated: bool = False
    available: bool = False
    error: str | None = None


@dataclass
class ExternalToolRun:
    """One action of a third-party tool run through the Toolbox."""

    tool_id: str
    tool_name: str
    action_id: str
    action_label: str
    category: str = ""
    license: str = ""
    version: str | None = None
    started_utc: str | None = None
    command: list[str] = field(default_factory=list)
    status: str = "pending"
    returncode: int | None = None
    duration_s: float = 0.0
    stdout: str = ""
    stderr: str = ""
    stdout_sha256: str | None = None
    truncated: bool = False
    timed_out: bool = False
    parsed: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    source: str = "toolbox"


@dataclass
class StepRun:
    name: str
    label: str
    state: StepState = StepState.PENDING
    duration_s: float = 0.0
    message: str | None = None
    diagnostics: list[str] = field(default_factory=list)


@dataclass
class PDFAnalysis:
    """Root object: the complete, serialisable result of one analysis."""

    tool: str
    tool_version: str
    analyzed_at_utc: str
    file: FileInfo
    hashes: Hashes
    metadata: Metadata = field(default_factory=Metadata)
    structure: StructureInfo = field(default_factory=StructureInfo)
    fonts: list[FontInfo] = field(default_factory=list)
    images: list[ImageInfo] = field(default_factory=list)
    pages: list[PageInfo] = field(default_factory=list)
    text: TextSummary = field(default_factory=TextSummary)
    objects: ObjectInventory = field(default_factory=ObjectInventory)
    interactive: Interactive = field(default_factory=Interactive)
    image_evidence: list[ImageEvidence] = field(default_factory=list)
    text_forensics: TextForensics = field(default_factory=TextForensics)
    crosscheck: ParserCrossCheck = field(default_factory=ParserCrossCheck)
    ocr: OcrResult = field(default_factory=OcrResult)
    timeline: list[TimelineEvent] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    external: dict[str, Any] = field(default_factory=dict)
    external_runs: list[ExternalToolRun] = field(default_factory=list)
    tools: list[ToolStatus] = field(default_factory=list)
    steps: list[StepRun] = field(default_factory=list)
    settings: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible dictionary (enums become their values)."""
        result: dict[str, Any] = _jsonable(asdict(self))
        return result

    def findings_by_category(self) -> dict[str, list[Finding]]:
        grouped: dict[str, list[Finding]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.category, []).append(finding)
        return grouped


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if is_dataclass(value) and not isinstance(value, type):
        return _jsonable(asdict(value))
    if isinstance(value, bytes):
        return value.hex()
    return value
