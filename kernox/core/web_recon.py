"""
kernox.core.web_recon – Smart web recon chain.

Given a web address, runs a full recon chain:
  1. Port scan + service fingerprint (nmap)
  2. WAF detection (wafw00f)
  3. Web tech detection (whatweb)
  4. SSL/TLS check (sslscan) — if HTTPS
  5. Vulnerability scan (nikto)
  6. Email harvesting (mail_crawler) — OSINT
  7. Directory fuzzing (ffuf) — asks
  8. Subdomain enum (dnsrecon) — asks
  9. CMS detection → wpscan if WordPress found
  10. Nuclei vulnerability scan
"""

from __future__ import annotations
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich import box

console = Console()


class WebReconChain:
    """Orchestrates a full web recon workflow."""

    def __init__(self, orchestrator) -> None:
        self._orc = orchestrator

    def run(self, target: str) -> list[dict]:
        """Run full web recon on *target*. Returns list of result dicts."""
        console.print(
            Panel(
                f"[bold cyan]Web Recon Chain[/bold cyan]\n"
                f"[dim]Target:[/dim] [cyan]{target}[/cyan]\n\n"
                f"[dim]Kernox will run recon steps one by one.\n"
                f"You can skip any step you don't need.[/dim]",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )

        is_https = target.startswith("https://")
        domain = (
            target.replace("https://", "")
            .replace("http://", "")
            .split("/")[0]
            .split(":")[0]
        )
        results = []

        # Step 1 — Port scan
        if self._ask_step("1", "Port scan + service fingerprint", "nmap"):
            r = self._orc._run_tool("nmap", {"target": domain, "mode": "service"})
            if r:
                results.append({"tool": "nmap", "parsed": r[0]})

        # Step 2 — WAF detection
        if self._ask_step("2", "WAF detection", "wafw00f"):
            r = self._orc._run_tool("wafw00f", {"target": target})
            if r:
                results.append({"tool": "wafw00f", "parsed": r[0]})

        # Step 3 — Web tech fingerprint
        if self._ask_step("3", "Web technology fingerprinting", "whatweb"):
            r = self._orc._run_tool("whatweb", {"target": target, "mode": "aggressive"})
            if r:
                results.append({"tool": "whatweb", "parsed": r[0]})
                # Check for WordPress
                techs = " ".join(r[0].get("technologies", [])).lower()
                if "wordpress" in techs or "wp" in techs:
                    console.print("[bold yellow]WordPress detected![/bold yellow]")
                    if self._ask_step("3b", "WordPress deep scan", "wpscan"):
                        wr = self._orc._run_tool(
                            "wpscan", {"target": target, "mode": "full"}
                        )
                        if wr:
                            results.append({"tool": "wpscan", "parsed": wr[0]})

        # Step 4 — SSL/TLS (HTTPS only or ask)
        do_ssl = is_https or Confirm.ask("\nRun SSL/TLS check?", default=is_https)
        if do_ssl:
            if self._ask_step("4", "SSL/TLS vulnerability check", "sslscan"):
                r = self._orc._run_tool("sslscan", {"target": target, "mode": "full"})
                if r:
                    results.append({"tool": "sslscan", "parsed": r[0]})

        # Step 5 — Nikto
        if self._ask_step("5", "Web vulnerability scan", "nikto"):
            r = self._orc._run_tool("nikto", {"target": target, "mode": "full"})
            if r:
                results.append({"tool": "nikto", "parsed": r[0]})
                # Check nikto findings for WordPress
                findings = " ".join(r[0].get("findings", [])).lower()
                if "wordpress" in findings and not any(
                    x["tool"] == "wpscan" for x in results
                ):
                    if Confirm.ask(
                        "WordPress found by nikto — run wpscan?", default=True
                    ):
                        wr = self._orc._run_tool(
                            "wpscan", {"target": target, "mode": "full"}
                        )
                        if wr:
                            results.append({"tool": "wpscan", "parsed": wr[0]})

        # Step 6 — Email harvesting (OSINT)
        if self._ask_step("6", "Email harvesting (OSINT)", "mail_crawler"):
            console.print("[dim]This will crawl the site to find email addresses[/dim]")
            r = self._orc._run_tool(
                "mail_crawler", {"target": target, "max_pages": 200}
            )
            if r:
                results.append({"tool": "mail_crawler", "parsed": r[0]})

        # Step 7 — Directory fuzzing (optional)
        if Confirm.ask("\nRun directory fuzzing? (ffuf)", default=False):
            r = self._orc._run_tool("ffuf", {"target": target, "mode": "dir"})
            if r:
                results.append({"tool": "ffuf", "parsed": r[0]})

        # Step 8 — Subdomain enumeration (optional)
        if Confirm.ask("\nRun subdomain enumeration? (dnsrecon)", default=False):
            r = self._orc._run_tool("dnsrecon", {"target": domain, "mode": "brt"})
            if r:
                results.append({"tool": "dnsrecon", "parsed": r[0]})

        # Step 9 — Nuclei vulnerability scan (optional)
        if Confirm.ask(
            "\nRun nuclei vulnerability scan? (CVEs + misconfigs)", default=True
        ):
            r = self._orc._run_tool("nuclei", {"target": target, "mode": "quick"})
            if r:
                results.append({"tool": "nuclei", "parsed": r[0]})

        # Step 10 — Ask about PDF report
        if results:
            self._ask_pdf(target, results)

        return results

    def _ask_step(self, num: str, desc: str, tool: str) -> bool:
        return Confirm.ask(
            f"\n[bold cyan]Step {num}[/bold cyan] — {desc} ([bold]{tool}[/bold])",
            default=True,
        )

    def _ask_pdf(self, target: str, results: list[dict]) -> None:
        if Confirm.ask(
            "\n[bold yellow]Export findings to PDF report?[/bold yellow]", default=True
        ):
            from kernox.utils.report_generator import generate_pdf_report
            from datetime import datetime

            filename = (
                f"/tmp/kernox_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            )
            generate_pdf_report(target=target, results=results, output_path=filename)
