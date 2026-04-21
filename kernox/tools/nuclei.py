"""
kernox.tools.nuclei  –  Full-capacity Nuclei vulnerability scanner.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich import box
from rich.table import Table
from rich.panel import Panel
from rich.spinner import Spinner
from rich.live import Live

from kernox.parsers.nuclei_parser import NucleiParser

console = Console()

# ── Template directories nuclei uses ─────────────────────────────────────────
_TEMPLATE_DIRS = [
    os.path.expanduser("~/nuclei-templates"),
    "/root/nuclei-templates",
    os.path.expanduser("~/.local/nuclei-templates"),
    "/usr/share/nuclei-templates",
]

# ── Tag map: detected technology → nuclei tags ───────────────────────────────
_TAG_MAP = {
    "wordpress":     "wordpress,wp",
    "joomla":        "joomla",
    "drupal":        "drupal",
    "apache":        "apache",
    "nginx":         "nginx",
    "iis":           "iis",
    "php":           "php",
    "asp":           "asp",
    "jsp":           "jsp",
    "mysql":         "mysql",
    "postgresql":    "postgres",
    "mongodb":       "mongo",
    "redis":         "redis",
    "elasticsearch": "elasticsearch",
    "grafana":       "grafana",
    "jenkins":       "jenkins",
    "gitlab":        "gitlab",
    "tomcat":        "tomcat",
    "spring":        "spring",
    "laravel":       "laravel",
    "django":        "django",
    "rails":         "rails",
    "express":       "express",
    "drupal":        "drupal",
    "magento":       "magento",
    "opencart":      "opencart",
    "shopify":       "shopify",
    "jira":          "jira",
    "confluence":    "confluence",
    "solr":          "solr",
    "kafka":         "kafka",
    "rabbitmq":      "rabbitmq",
    "prometheus":    "prometheus",
    "kibana":        "kibana",
}


def _is_interactive() -> bool:
    """Return True only when running in a real terminal (not API/headless)."""
    return os.isatty(0)


def _find_templates() -> tuple[bool, str]:
    """Return (found, path) for nuclei templates."""
    for d in _TEMPLATE_DIRS:
        if os.path.isdir(d):
            return True, d
    return False, ""


def _template_age_days(path: str) -> float:
    """How many days old is the template directory (by mtime)."""
    try:
        return (time.time() - os.path.getmtime(path)) / 86400
    except Exception:
        return 0.0


def _update_templates(force: bool = False) -> None:
    """Update nuclei templates silently unless interactive."""
    has, path = _find_templates()

    if not has:
        console.print("[yellow]⚠ Nuclei templates not found. Installing...[/yellow]")
        subprocess.run(
            ["nuclei", "-update-templates"],
            capture_output=not _is_interactive(),
        )
        return

    age = _template_age_days(path)
    if force or age > 7:
        if _is_interactive():
            console.print(f"[dim]Templates are {age:.0f} days old[/dim]")
            if not Confirm.ask("Update templates?", default=False):
                return
        console.print("[dim]Updating nuclei templates...[/dim]")
        subprocess.run(
            ["nuclei", "-update-templates"],
            capture_output=not _is_interactive(),
        )


class NucleiTool:
    name = "nuclei"

    def __init__(self, ai_client=None):
        self._ai_client = ai_client
        self._template_cache: dict = {}

    # ── Public: build_command ────────────────────────────────────────────────

    def build_command(self, target: str, mode: str = "", flags: str = "", **kwargs) -> str:
        """
        Build the nuclei command.

        Priority order:
          1. Raw flags passed in directly → use as-is
          2. AI client available + no mode → ask AI for strategy
          3. Interactive terminal + no mode → show mode picker
          4. mode string provided → build from mode
          5. Fallback → smart auto mode
        """
        context      = kwargs.get("context", {})
        technologies = context.get("technologies", [])
        server       = context.get("server", "")
        severity     = kwargs.get("severity", "")
        threads      = str(kwargs.get("threads", 25))
        rate         = str(kwargs.get("rate_limit", 150))
        output_path  = kwargs.get("output_path", "/tmp/kernox_nuclei")

        tech_tags = self._get_tech_tags(technologies, server)

        _update_templates()

        # ── 1. Raw flags ──────────────────────────────────────────────────────
        if flags:
            return f"nuclei -u '{target}' {flags}"

        # ── 2. AI strategy ────────────────────────────────────────────────────
        if self._ai_client and not mode:
            strategy = self._ai_decide_strategy(target, technologies, tech_tags)
            cmd = strategy.get("command", "")
            if cmd:
                if _is_interactive():
                    console.print(Panel(
                        f"[bold cyan]AI Strategy:[/bold cyan] {strategy.get('analysis', '')}\n\n"
                        f"[bold]Command:[/bold] [yellow]{cmd}[/yellow]\n"
                        f"[bold]Tags:[/bold] {strategy.get('tags', 'auto')}\n"
                        f"[bold]Severity:[/bold] {strategy.get('severity', 'critical,high')}",
                        title="🧠 AI Nuclei Strategy",
                        border_style="cyan",
                        box=box.ROUNDED,
                    ))
                    if Confirm.ask("\nUse this AI-recommended scan?", default=True):
                        return cmd
                    mode = self._pick_mode()
                else:
                    # Headless / API — use AI command directly, no prompts
                    return cmd

        # ── 3. Interactive mode picker (no mode given, real terminal) ─────────
        if not mode and _is_interactive():
            mode = self._pick_mode()

        # ── 4/5. Build from mode (or smart fallback) ──────────────────────────
        return self._build_from_mode(
            mode or "smart",
            target,
            tech_tags,
            severity=severity,
            threads=threads,
            rate=rate,
            output_path=output_path,
        )

    # ── Tech tag resolution ──────────────────────────────────────────────────

    def _get_tech_tags(self, technologies: list, server: str) -> list:
        tags: set[str] = set()
        for tech in technologies:
            tech_lower = tech.lower()
            for key, tag in _TAG_MAP.items():
                if key in tech_lower:
                    tags.update(tag.split(","))
        for key in ("apache", "nginx", "iis"):
            if key in server.lower():
                tags.add(key)
        return list(tags)

    # ── AI strategy ──────────────────────────────────────────────────────────

    def _ai_decide_strategy(self, target: str, technologies: list, tech_tags: list) -> dict:
        tech_str = ", ".join(technologies[:5]) if technologies else "unknown"
        tags_str = ", ".join(tech_tags[:5]) if tech_tags else "auto-detect"
        has_templates, tpl_path = _find_templates()
        tpl_note = f"Templates found at: {tpl_path}" if has_templates else "Templates not found locally."

        prompt = f"""You are a penetration tester planning a nuclei scan.

Target: {target}
Detected technologies: {tech_str}
Suggested tags: {tags_str}
{tpl_note}

Build the optimal nuclei command:
- Use -tags if specific tech detected, otherwise use -t cves/ -t misconfigs/
- Severity: critical,high for quick; add medium for thorough
- Always add: -c 25 -rl 150 -silent -o /tmp/kernox_nuclei.txt -json-export /tmp/kernox_nuclei.json
- Never use interactive flags

Respond ONLY with JSON:
{{
    "analysis": "brief strategy explanation",
    "command": "full ready-to-run nuclei command",
    "tags": "comma-separated tags or 'auto'",
    "severity": "critical,high",
    "estimated_time": "fast/medium/slow"
}}"""

        try:
            spinner_ctx = Live(
                Spinner("dots", text="[dim]AI planning nuclei strategy...[/dim]"),
                refresh_per_second=10,
            ) if _is_interactive() else _NullCtx()

            with spinner_ctx:
                response = self._ai_client.chat(
                    messages=[{"role": "user", "content": prompt}],
                    system="You are a security expert. Return ONLY valid JSON, no markdown.",
                    max_tokens=350,
                    temperature=0.1,
                )

            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                parsed = json.loads(json_match.group())
                # Sanity-check: command must start with nuclei
                if parsed.get("command", "").strip().startswith("nuclei"):
                    return parsed
        except Exception as e:
            console.print(f"[dim red]AI strategy failed: {e}[/dim red]")

        # Deterministic fallback
        if tech_tags:
            tags = ",".join(dict.fromkeys(tech_tags[:6]))
            return {
                "analysis": f"Technology detected: {tech_str}. Targeting specific templates.",
                "command": (
                    f"nuclei -u '{target}' -tags {tags} "
                    f"-severity critical,high -c 25 -rl 150 -silent "
                    f"-o /tmp/kernox_nuclei.txt -json-export /tmp/kernox_nuclei.json"
                ),
                "tags": tags,
                "severity": "critical,high",
                "estimated_time": "medium",
            }

        return {
            "analysis": "No technology detected. Running standard CVE + misconfiguration scan.",
            "command": (
                f"nuclei -u '{target}' -t cves/ -t misconfigs/ -t exposures/ "
                f"-severity critical,high -c 25 -rl 150 -silent "
                f"-o /tmp/kernox_nuclei.txt -json-export /tmp/kernox_nuclei.json"
            ),
            "tags": "auto",
            "severity": "critical,high",
            "estimated_time": "medium",
        }

    # ── Interactive mode picker ───────────────────────────────────────────────

    def _pick_mode(self) -> str:
        console.print("\n[bold cyan]Nuclei Scan Mode[/bold cyan]\n")
        table = Table(
            show_header=True, header_style="bold magenta",
            box=box.SIMPLE_HEAVY, border_style="dim",
        )
        table.add_column("#",    width=4, style="bold cyan")
        table.add_column("Mode", style="bold")
        table.add_column("Description")
        table.add_column("Speed", width=9)

        rows = [
            ("1", "smart",     "AI-powered tech-aware scan (recommended)",        "Adaptive"),
            ("2", "quick",     "Recent CVEs + critical misconfigs",                "Fast"),
            ("3", "full",      "All templates (9000+) — slow",                    "Slow"),
            ("4", "cves",      "CVE templates only, pick year",                   "Medium"),
            ("5", "tech",      "Technology-specific tags (auto-detected)",         "Fast"),
            ("6", "logins",    "Default credentials / login panels",               "Fast"),
            ("7", "severity",  "Filter by custom severity level",                 "Medium"),
            ("8", "workflow",  "Run a predefined nuclei workflow",                 "Medium"),
            ("9", "custom",    "Custom tags, template path or template ID",        "N/A"),
        ]
        for row in rows:
            table.add_row(*row)
        console.print(table)

        choice = Prompt.ask(
            "Select mode",
            choices=[str(i) for i in range(1, 10)],
            default="1",
        )
        return {
            "1": "smart", "2": "quick", "3": "full",   "4": "cves",
            "5": "tech",  "6": "logins","7": "severity","8": "workflow","9": "custom",
        }[choice]

    # ── Command builder ──────────────────────────────────────────────────────

    def _build_from_mode(
        self,
        mode: str,
        target: str,
        tech_tags: list,
        severity: str = "",
        threads: str = "25",
        rate: str = "150",
        output_path: str = "/tmp/kernox_nuclei",
    ) -> str:
        out  = f"-o {output_path}.txt -json-export {output_path}.json"
        base = f"nuclei -u '{target}' -c {threads} -rl {rate} -silent"

        # Allow interactive overrides only in terminal
        if _is_interactive():
            threads = Prompt.ask("Threads", default=threads)
            rate    = Prompt.ask("Rate limit req/s", default=rate)
            base    = f"nuclei -u '{target}' -c {threads} -rl {rate} -silent"

        sev = severity or "critical,high"

        if mode == "smart":
            if tech_tags:
                tags = ",".join(dict.fromkeys(tech_tags[:6]))
                console.print(f"[dim]Smart: using detected tags → {tags}[/dim]")
                return f"{base} -tags {tags} -severity {sev} {out}"
            # No tech detected — cover all common attack vectors
            return (
                f"{base} -t cves/2024/ -t cves/2023/ -t misconfigs/ "
                f"-t exposures/ -t default-logins/ -severity {sev} {out}"
            )

        elif mode == "quick":
            return (
                f"{base} -t cves/2024/ -t cves/2023/ -t misconfigs/ "
                f"-t exposures/ -severity critical,high {out}"
            )

        elif mode == "full":
            if _is_interactive():
                console.print("[yellow]⚠ Full scan uses ALL 9000+ templates. May take hours.[/yellow]")
                if not Confirm.ask("Continue with full scan?", default=False):
                    return self._build_from_mode("quick", target, tech_tags, severity, threads, rate, output_path)
            return f"{base} -t all -severity {sev} {out}"

        elif mode == "cves":
            year = ""
            if _is_interactive():
                console.print("  [green]1[/green] 2024  [green]2[/green] 2023  [green]3[/green] 2022  [green]4[/green] All years")
                c = Prompt.ask("Year", choices=["1","2","3","4"], default="1")
                year = {"1":"2024","2":"2023","3":"2022","4":""}[c]
            else:
                year = "2024"
            tpl = f"cves/{year}/" if year else "cves/"
            return f"{base} -t {tpl} -severity {sev} {out}"

        elif mode == "tech":
            if tech_tags:
                tags = ",".join(dict.fromkeys(tech_tags[:6]))
                console.print(f"[dim]Tech tags: {tags}[/dim]")
                return f"{base} -tags {tags} -severity {sev} {out}"
            console.print("[yellow]No technologies detected — running tech detection scan[/yellow]")
            return f"{base} -t technologies/ {out}"

        elif mode == "logins":
            return f"{base} -t default-logins/ -t exposures/configs/ -severity critical,high,medium {out}"

        elif mode == "severity":
            if _is_interactive():
                sev = Prompt.ask("Severity levels (comma-separated)", default="critical,high,medium")
            return f"{base} -t all -severity {sev} {out}"

        elif mode == "workflow":
            wf = "wordpress-login"
            if _is_interactive():
                console.print("[dim]Available: wordpress-login, api-security, default-credentials[/dim]")
                wf = Prompt.ask("Workflow name", default=wf)
            return f"{base} -w {wf} {out}"

        elif mode == "custom":
            if _is_interactive():
                console.print("  [green]1[/green] Tags  [green]2[/green] Template path  [green]3[/green] Template ID")
                cc = Prompt.ask("Select", choices=["1","2","3"], default="1")
                if cc == "1":
                    tags = Prompt.ask("Tags (e.g., wordpress,rce,lfi)")
                    return f"{base} -tags {tags} {out}"
                elif cc == "2":
                    path = Prompt.ask("Template path")
                    return f"{base} -t {path} {out}"
                elif cc == "3":
                    tid = Prompt.ask("Template ID")
                    return f"{base} -id {tid} {out}"
            # API/headless custom → fall through to smart
            return self._build_from_mode("smart", target, tech_tags, severity, threads, rate, output_path)

        # Unknown mode → safe default
        console.print(f"[dim yellow]Unknown mode '{mode}' — using smart fallback[/dim yellow]")
        return self._build_from_mode("smart", target, tech_tags, severity, threads, rate, output_path)

    # ── Parse ────────────────────────────────────────────────────────────────

    def parse(self, output: str) -> dict:
        """Parse nuclei output."""
        return NucleiParser().parse(output)


# ── Null context manager for headless/non-interactive use ────────────────────

class _NullCtx:
    def __enter__(self): return self
    def __exit__(self, *_): pass
