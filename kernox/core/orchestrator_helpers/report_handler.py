"""Report generation — delegates entirely to kernox.utils.report_generator.generate_pdf_report()."""

from __future__ import annotations

from rich.console import Console
from rich.prompt import Prompt

from kernox.engine.state import SessionState

console = Console()


class ReportHandler:
    def __init__(self, state: SessionState) -> None:
        self._state = state

    def ask_report(self) -> None:
        """Collect output path from user, then call generate_pdf_report()."""
        from kernox.utils.report_generator import generate_pdf_report

        results = self._state.get_tool_results()
        ai_insights = self._state.get_ai_insights()

        if not results and not ai_insights:
            console.print("[dim]No findings to report yet. Run some tools first.[/dim]")
            return

        # Derive a readable target label for the filename
        target = "unknown"
        for r in results:
            if r.target and r.target != "unknown":
                target = r.target
                break

        safe = target.replace("http://", "").replace("https://", "").replace("/", "_")
        default_path = f"/tmp/kernox/report_{safe}.pdf"

        out = Prompt.ask("  Save report to", default=default_path)

        # Build the list format generate_pdf_report() already expects
        report_results = [
            {"tool": r.tool, "parsed": r.parsed}
            for r in results
        ]

        # Build ai_insights list in the format the report generator expects
        insight_dicts = [
            {
                "vulnerability": i.vulnerability,
                "severity": i.severity,
                "tool": i.tool,
                "target": i.target,
                "ai_explanation": i.ai_explanation,
            }
            for i in ai_insights
        ]

        generate_pdf_report(
            target=target,
            results=report_results,
            output_path=out,
            ai_insights=insight_dicts if insight_dicts else None,
        )
