"""
kernox.core.web_recon – Smart web recon chain.

Given a web address, runs a full recon chain:
  1.  Port scan + service fingerprint (nmap)
  2.  WAF detection (wafw00f)
  3.  Web tech detection (whatweb)
  4.  SSL/TLS check (sslscan) — if HTTPS
  5.  Vulnerability scan (nikto)
  6.  ZAP baseline passive scan
  7.  Email harvesting (mail_crawler + theHarvester) — OSINT
  8.  Directory fuzzing (ffuf) — asks
  9.  Subdomain enum (dnsrecon) — asks
  10. CMS detection → wpscan if WordPress found
  11. Nuclei vulnerability scan
  12. ZAP active scan — optional, asks first (intrusive)

AI post-analysis runs after every step automatically.
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

    def _run(self, tool: str, args: dict) -> dict | None:
        """Run a tool and trigger AI post-analysis. Returns parsed dict or None."""
        r = self._orc._run_tool(tool, args)
        if r:
            parsed, _ = r
            self._orc._post_tool_ai_analysis(tool, parsed, args.get("target", ""))
            return parsed
        return None

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
            parsed = self._run("nmap", {"target": domain, "mode": "service"})
            if parsed:
                results.append({"tool": "nmap", "parsed": parsed})

        # Step 2 — WAF detection
        if self._ask_step("2", "WAF detection", "wafw00f"):
            parsed = self._run("wafw00f", {"target": target})
            if parsed:
                results.append({"tool": "wafw00f", "parsed": parsed})
                if parsed.get("detected"):
                    console.print(f"[bold yellow]⚠ WAF detected: {', '.join(parsed.get('waf_names', ['Unknown']))}[/bold yellow]")
                    console.print("[dim]Active/fuzzing scans may be blocked or rate-limited.[/dim]")

        # Step 3 — Web tech fingerprint
        if self._ask_step("3", "Web technology fingerprinting", "whatweb"):
            parsed = self._run("whatweb", {"target": target, "mode": "aggressive"})
            if parsed:
                results.append({"tool": "whatweb", "parsed": parsed})
                techs = " ".join(parsed.get("technologies", [])).lower()
                if "wordpress" in techs or "wp" in techs:
                    console.print("[bold yellow]WordPress detected![/bold yellow]")
                    if self._ask_step("3b", "WordPress deep scan", "wpscan"):
                        wp = self._run("wpscan", {"target": target, "mode": "full"})
                        if wp:
                            results.append({"tool": "wpscan", "parsed": wp})

        # Step 4 — SSL/TLS (HTTPS only or ask)
        do_ssl = is_https or Confirm.ask("\nRun SSL/TLS check?", default=is_https)
        if do_ssl:
            if self._ask_step("4", "SSL/TLS vulnerability check", "sslscan"):
                ssl_target = domain + (":443" if is_https else ":80")
                parsed = self._run("sslscan", {"target": ssl_target})
                if parsed:
                    results.append({"tool": "sslscan", "parsed": parsed})

        # Step 5 — Nikto
        if self._ask_step("5", "Web vulnerability scan", "nikto"):
            parsed = self._run("nikto", {"target": target, "mode": "full"})
            if parsed:
                results.append({"tool": "nikto", "parsed": parsed})
                findings = " ".join(parsed.get("findings", [])).lower()
                if "wordpress" in findings and not any(x["tool"] == "wpscan" for x in results):
                    if Confirm.ask("WordPress found by nikto — run wpscan?", default=True):
                        wp = self._run("wpscan", {"target": target, "mode": "full"})
                        if wp:
                            results.append({"tool": "wpscan", "parsed": wp})

        # Step 6 — ZAP baseline passive scan
        if self._ask_step("6", "OWASP ZAP passive baseline scan", "zapcli"):
            console.print("[dim]Passive scan — no active attacks, safe to run[/dim]")
            parsed = self._run(
                "zapcli",
                {"target": target, "mode": "baseline", "report_path": f"/tmp/zap_baseline_{domain}.html"},
            )
            if parsed:
                results.append({"tool": "zapcli", "parsed": parsed})

        # Step 7a — Email harvesting via mail_crawler
        if self._ask_step("7a", "Email harvesting — web crawl", "mail_crawler"):
            console.print("[dim]Crawls the site to find email addresses[/dim]")
            parsed = self._run("mail_crawler", {"target": target, "max_pages": 200})
            if parsed:
                results.append({"tool": "mail_crawler", "parsed": parsed})

        # Step 7b — OSINT via theHarvester
        if self._ask_step("7b", "OSINT — emails/subdomains from public sources", "theharvester"):
            console.print("[dim]Queries Google, Bing, crt.sh, certspotter and more[/dim]")
            parsed = self._run(
                "theharvester",
                {"target": domain, "sources": "google,bing,crtsh,certspotter,dnsdumpster,hackertarget"},
            )
            if parsed:
                results.append({"tool": "theharvester", "parsed": parsed})

        # Step 8 — Directory fuzzing (optional)
        if Confirm.ask("\nRun directory fuzzing? (ffuf)", default=False):
            parsed = self._run("ffuf", {"target": target, "mode": "dir"})
            if parsed:
                results.append({"tool": "ffuf", "parsed": parsed})
                findings = parsed.get("findings", [])
                login_paths = [
                    f.get("path", "") for f in findings
                    if any(x in f.get("path", "").lower() for x in ("login", "admin", "wp-login"))
                ]
                if login_paths and Confirm.ask(
                    f"Login page found at {login_paths[0]} — run Hydra brute-force?",
                    default=False,
                ):
                    self._run(
                        "hydra",
                        {"target": domain, "mode": "http-post-form", "form_path": f"/{login_paths[0]}"},
                    )

        # Step 9 — Subdomain enumeration (optional)
        if Confirm.ask("\nRun subdomain enumeration? (dnsrecon)", default=False):
            parsed = self._run("dnsrecon", {"target": domain, "mode": "brt"})
            if parsed:
                results.append({"tool": "dnsrecon", "parsed": parsed})

        # Step 10 — Nuclei vulnerability scan (optional)
        if Confirm.ask("\nRun nuclei vulnerability scan? (CVEs + misconfigs)", default=True):
            parsed = self._run("nuclei", {"target": target, "mode": "quick"})
            if parsed:
                results.append({"tool": "nuclei", "parsed": parsed})

        # Step 11 — ZAP active scan (optional, intrusive — always ask)
        high_issues = sum(
            x["parsed"].get("high", 0) + x["parsed"].get("critical", 0)
            for x in results
            if isinstance(x.get("parsed"), dict)
        )
        if high_issues > 0:
            console.print(f"\n[bold yellow]⚠ {high_issues} high/critical issues found across all scans.[/bold yellow]")
        if Confirm.ask(
            "\nRun ZAP [bold red]active[/bold red] scan? (intrusive — sends attack payloads)",
            default=False,
        ):
            parsed = self._run(
                "zapcli",
                {"target": target, "mode": "active", "report_path": f"/tmp/zap_active_{domain}.html"},
            )
            if parsed:
                results.append({"tool": "zapcli-active", "parsed": parsed})

        # ── AI final summary of entire recon ─────────────────────────────────
        if results:
            self._ai_recon_summary(target, results)
            self._ask_pdf(target, results)

        return results

    def _ai_recon_summary(self, target: str, results: list[dict]) -> None:
        """Ask the AI for a final consolidated summary of the full recon chain."""
        from rich.live import Live
        from rich.spinner import Spinner
        from rich.markdown import Markdown

        lines = [f"Full web recon completed for: {target}\n"]
        for r in results:
            tool = r.get("tool", "?")
            parsed = r.get("parsed", {})
            # Build a quick one-liner per tool
            if tool == "nmap":
                open_p = sum(
                    1 for h in parsed.get("hosts", [])
                    for p in h.get("ports", []) if p.get("state") == "open"
                )
                lines.append(f"- nmap: {open_p} open ports")
            elif tool == "nikto":
                lines.append(f"- nikto: {parsed.get('total', 0)} findings")
            elif tool == "nuclei":
                lines.append(f"- nuclei: critical={parsed.get('critical',0)} high={parsed.get('high',0)} medium={parsed.get('medium',0)}")
            elif tool == "zapcli":
                lines.append(f"- zap baseline: high={parsed.get('high',0)} medium={parsed.get('medium',0)}")
            elif tool == "sslscan":
                lines.append(f"- sslscan: {len(parsed.get('issues', []))} issues, weak protocols: {', '.join(parsed.get('weak_protocols', []))}")
            elif tool == "wpscan":
                lines.append(f"- wpscan: {parsed.get('total_vulns', 0)} vulns, users: {', '.join(parsed.get('users', []))}")
            elif tool == "theharvester":
                lines.append(f"- theharvester: {parsed.get('total_emails',0)} emails, {parsed.get('total_subdomains',0)} subdomains")
            elif tool == "whatweb":
                lines.append(f"- whatweb: {', '.join(parsed.get('technologies', [])[:6])}")
            elif tool == "ffuf":
                lines.append(f"- ffuf: {len(parsed.get('findings', []))} paths found")
            elif tool == "dnsrecon":
                lines.append(f"- dnsrecon: {parsed.get('total_subdomains',0)} subdomains, zone_transfer={parsed.get('zone_transfer_possible',False)}")

        summary_text = "\n".join(lines)

        prompt = f"""You are a senior penetration tester. A full web recon chain just completed.

{summary_text}

Provide a concise executive summary (5-8 bullet points) covering:
1. Most critical findings
2. Likely attack paths
3. Top 3 recommended next steps
4. Overall risk rating (Critical / High / Medium / Low)

Use markdown. Be direct and actionable."""

        try:
            with Live(Spinner("dots", text="[cyan]AI generating final recon summary...[/cyan]"), refresh_per_second=10):
                ai = self._orc._ai
                response = ai.chat(
                    messages=[{"role": "user", "content": prompt}],
                    system="You are a senior penetration tester providing expert analysis.",
                    max_tokens=700,
                )
            if response and not response.startswith("Error:"):
                console.print(Panel(
                    Markdown(response),
                    title="[bold cyan]🤖 AI — Web Recon Final Summary[/bold cyan]",
                    border_style="cyan",
                    box=box.ROUNDED,
                ))
        except Exception:
            pass

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

            ai_insights = [
                {
                    "vulnerability": i.vulnerability,
                    "severity": i.severity,
                    "tool": i.tool,
                    "target": i.target,
                    "ai_explanation": i.ai_explanation,
                }
                for i in self._orc._state.get_ai_insights()
            ]
            filename = (
                f"/tmp/kernox_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            )
            generate_pdf_report(
                target=target,
                results=results,
                output_path=filename,
                ai_insights=ai_insights,
            )


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

        # Step 6 — ZAP baseline passive scan
        if self._ask_step("6", "OWASP ZAP passive baseline scan", "zapcli"):
            console.print("[dim]Passive scan — no active attacks, safe to run[/dim]")
            r = self._orc._run_tool(
                "zapcli",
                {"target": target, "mode": "baseline", "report_path": f"/tmp/zap_baseline_{domain}.html"},
            )
            if r:
                results.append({"tool": "zapcli", "parsed": r[0]})

        # Step 7a — Email harvesting via mail_crawler
        if self._ask_step("7a", "Email harvesting — web crawl", "mail_crawler"):
            console.print("[dim]Crawls the site to find email addresses[/dim]")
            r = self._orc._run_tool(
                "mail_crawler", {"target": target, "max_pages": 200}
            )
            if r:
                results.append({"tool": "mail_crawler", "parsed": r[0]})

        # Step 7b — OSINT via theHarvester
        if self._ask_step("7b", "OSINT — emails/subdomains from public sources", "theharvester"):
            console.print("[dim]Queries Google, Bing, crt.sh, certspotter and more[/dim]")
            r = self._orc._run_tool(
                "theharvester",
                {"target": domain, "sources": "google,bing,crtsh,certspotter,dnsdumpster,hackertarget"},
            )
            if r:
                results.append({"tool": "theharvester", "parsed": r[0]})

        # Step 8 — Directory fuzzing (optional)
        if Confirm.ask("\nRun directory fuzzing? (ffuf)", default=False):
            r = self._orc._run_tool("ffuf", {"target": target, "mode": "dir"})
            if r:
                results.append({"tool": "ffuf", "parsed": r[0]})
                # If login page found, suggest hydra
                findings = r[0].get("findings", [])
                login_paths = [
                    f.get("path", "") for f in findings
                    if any(x in f.get("path", "").lower() for x in ("login", "admin", "wp-login"))
                ]
                if login_paths and Confirm.ask(
                    f"Login page found at {login_paths[0]} — run Hydra brute-force?",
                    default=False,
                ):
                    self._orc._run_tool(
                        "hydra",
                        {
                            "target": domain,
                            "mode": "http-post-form",
                            "form_path": f"/{login_paths[0]}",
                        },
                    )

        # Step 9 — Subdomain enumeration (optional)
        if Confirm.ask("\nRun subdomain enumeration? (dnsrecon)", default=False):
            r = self._orc._run_tool("dnsrecon", {"target": domain, "mode": "brt"})
            if r:
                results.append({"tool": "dnsrecon", "parsed": r[0]})

        # Step 10 — Nuclei vulnerability scan (optional)
        if Confirm.ask(
            "\nRun nuclei vulnerability scan? (CVEs + misconfigs)", default=True
        ):
            r = self._orc._run_tool("nuclei", {"target": target, "mode": "quick"})
            if r:
                results.append({"tool": "nuclei", "parsed": r[0]})

        # Step 11 — ZAP active scan (optional, intrusive — always ask)
        zap_results = [x for x in results if x["tool"] == "zapcli"]
        high_issues = sum(
            x["parsed"].get("high", 0) + x["parsed"].get("critical", 0)
            for x in results
            if isinstance(x.get("parsed"), dict)
        )
        if high_issues > 0:
            console.print(
                f"\n[bold yellow]⚠ {high_issues} high/critical issues found across all scans.[/bold yellow]"
            )
        if Confirm.ask(
            "\nRun ZAP [bold red]active[/bold red] scan? (intrusive — sends attack payloads)",
            default=False,
        ):
            r = self._orc._run_tool(
                "zapcli",
                {"target": target, "mode": "active", "report_path": f"/tmp/zap_active_{domain}.html"},
            )
            if r:
                results.append({"tool": "zapcli-active", "parsed": r[0]})

        # Step 12 — PDF report
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
