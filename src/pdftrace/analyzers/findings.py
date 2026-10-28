"""Findings and timeline stage (always runs last)."""

from __future__ import annotations

from pdftrace.core.analyzer import AnalysisContext, AnalysisResult, Analyzer
from pdftrace.core.findings import FindingsEngine
from pdftrace.core.timeline import build_timeline


class FindingsAnalyzer(Analyzer):
    name = "findings"
    label = "Findings"

    def __init__(self, engine: FindingsEngine | None = None) -> None:
        self.engine = engine or FindingsEngine()

    def analyze(self, ctx: AnalysisContext) -> AnalysisResult:
        ctx.analysis.timeline = build_timeline(ctx.analysis)
        ctx.analysis.findings = self.engine.evaluate(ctx.analysis, ctx.settings)
        return AnalysisResult(None, message=f"{len(ctx.analysis.findings)} findings")
