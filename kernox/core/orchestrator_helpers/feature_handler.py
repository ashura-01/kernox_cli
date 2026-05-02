"""
orchestrator_helpers.feature_handler — Single entry point for all feature commands.

Orchestrator calls ONE method per command. All feature logic lives in features/.
"""

from __future__ import annotations

from rich.console import Console
from rich.prompt import Confirm

console = Console()


class FeatureHandler:
    def __init__(self, state, executor=None):
        self._state    = state
        self._executor = executor   # Executor instance for payload builder

    # ── Public command handlers ───────────────────────────────────────────────

    def cve(self, args: str = "") -> None:
        """cve [query|CVE-ID] — search NVD or look up specific CVE."""
        from kernox.features.cve_lookup import interactive_cve_lookup, search_cve, display_cves, lookup_cve_id
        q = args.strip()
        if not q:
            interactive_cve_lookup()
        elif q.upper().startswith("CVE-"):
            result = lookup_cve_id(q)
            from kernox.features.cve_lookup import display_cves
            display_cves([result] if result else [], title=q.upper())
        else:
            cves = search_cve(q, max_results=8)
            display_cves(cves, title=f"CVEs: {q}")

    def payload(self) -> None:
        """payload — interactive msfvenom payload builder."""
        from kernox.features.payload_builder import run_payload_builder
        run_payload_builder(executor=self._executor)

    def log(self, args: str = "") -> None:
        """log [clear] — show or clear the attack timeline."""
        from kernox.features.attack_log import show_attack_log, clear_log
        if args.strip() == "clear":
            if Confirm.ask("Clear attack log?", default=False):
                clear_log()
        else:
            show_attack_log()

    def score(self) -> None:
        """score — show CVSS risk summary for all session findings."""
        from kernox.features.exploit_score import render_session_risk_summary
        insights = self._state.get_ai_insights()
        if not insights:
            console.print("[dim]No findings yet. Run some tools first.[/dim]")
            return
        render_session_risk_summary(insights)

    # ── Called automatically from ai_analyzer after each finding ─────────────

    def auto_enrich(self, vuln_name: str, severity: str,
                    tool: str, target: str, exploit: str = "") -> None:
        """
        Called by ai_analyzer.analyze() for each vulnerability found.
        1. Logs finding to attack_log
        2. Shows CVSS score gauge
        3. Fetches top CVEs from NVD (only for high/critical)
        """
        from kernox.features.attack_log import log_finding
        from kernox.features.exploit_score import render_score_from_finding

        # Always log
        log_finding(vuln_name, severity, tool, target, exploit)

        # Always show score gauge
        render_score_from_finding(
            {"name": vuln_name, "severity": severity},
        )

        # CVE lookup only for high+ to avoid rate limits and noise
        if severity.lower() in ("critical", "high"):
            from kernox.features.cve_lookup import enrich_finding
            enrich_finding(vuln_name, tool)
