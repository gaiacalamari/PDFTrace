"""Runs the selected third-party tools of the Toolbox (optional step)."""

from __future__ import annotations

from pdftrace.core.analyzer import AnalysisContext, AnalysisResult, Analyzer
from pdftrace.integrations.toolbox import Toolbox


class ToolboxAnalyzer(Analyzer):
    name = "toolbox"
    label = "External tools (Toolbox)"

    def analyze(self, ctx: AnalysisContext) -> AnalysisResult:
        toolbox = Toolbox(ctx.settings)
        specs = toolbox.select(ctx.settings.external_tools)
        if not specs:
            return AnalysisResult(None, skipped=True, message="No external tool selected")
        runs = toolbox.run_tools(specs, ctx.path, cancelled=ctx.cancel_event.is_set)
        ctx.analysis.external_runs.extend(runs)
        ctx.check_cancelled()
        failed = [r for r in runs if r.status not in ("ok",)]
        return AnalysisResult(
            None, diagnostics=toolbox.errors, message=f"{len(runs)} tool actions, {len(failed)} not ok"
        )
