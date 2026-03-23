"""
kernox.tools.nuclei  –  Nuclei vulnerability scanner wrapper.

Nuclei uses community templates to find vulnerabilities, misconfigs,
exposed panels, default credentials, and CVEs on authorized targets.
"""

from __future__ import annotations

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich import box
from rich.table import Table

from kernox.parsers.nuclei_parser import NucleiParser

console = Console()

# Lightweight template sets (no full download needed)
LIGHTWEIGHT_TEMPLATES = {
    "cves/2021": "~200 CVEs from 2021",
    "cves/2022": "~300 CVEs from 2022",
    "cves/2023": "~400 CVEs from 2023",
    "cves/2024": "~200 CVEs from 2024",
    "misconfigs": "Security misconfigurations",
    "exposures":  "Exposed panels and files",
    "default-logins": "Default credentials",
    "technologies":   "Tech fingerprinting",
    "ssl":            "SSL/TLS issues",
}

TEMPLATE_CATEGORIES = {
    "cves":           "Known CVE vulnerabilities",
    "misconfigs":     "Security misconfigurations",
    "exposures":      "Exposed files, configs, panels",
    "default-logins": "Default credentials check",
    "technologies":   "Technology fingerprinting",
    "osint":          "OSINT information gathering",
    "takeovers":      "Subdomain takeover checks",
    "dns":            "DNS misconfigurations",
    "ssl":            "SSL/TLS issues",
    "headless":       "Browser-based checks",
}

SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]


class NucleiTool:
    name = "nuclei"

    def _check_templates(self) -> str:
        """Check if nuclei templates are available, suggest lightweight install."""
        import os, shutil
        template_dirs = [
            os.path.expanduser("~/nuclei-templates"),
            "/root/nuclei-templates",
            os.path.expanduser("~/.local/nuclei-templates"),
        ]
        for d in template_dirs:
            if os.path.exists(d):
                return d
        # No templates found
        console.print("\n[yellow]⚠ Nuclei templates not found.[/yellow]")
        console.print("[dim]Install lightweight templates (recommended):[/dim]")
        console.print("[cyan]  nuclei -update-templates -t cves/,misconfigs/,exposures/[/cyan]")
        console.print("[dim]Or install ALL templates (300MB):[/dim]")
        console.print("[cyan]  nuclei -update-templates[/cyan]\n")
        return ""

    def build_command(
        self,
        target: str,
        mode: str = "",
        flags: str = "",
        **kwargs,
    ) -> str:
        if flags and not mode:
            return f"nuclei -u '{target}' {flags}"
        mode = mode or self._pick_mode()
        return self._build_from_mode(mode, target)

    def _pick_mode(self) -> str:
        console.print("\n[bold cyan]Nuclei Scan Mode[/bold cyan]\n")
        table = Table(
            show_header=True, header_style="bold magenta",
            box=box.SIMPLE_HEAVY, border_style="dim",
        )
        table.add_column("#", width=4, style="bold cyan")
        table.add_column("Mode", style="bold")
        table.add_column("Description")
        table.add_column("Speed", width=8)

        modes = [
            ("1", "quick",     "CVEs + misconfigs only",                   "Fast"),
            ("2", "full",      "All templates (9000+)",                    "Slow"),
            ("3", "cves",      "Known CVE templates only",                 "Med"),
            ("4", "exposures", "Exposed panels, configs, files",           "Fast"),
            ("5", "logins",    "Default credentials check",                "Med"),
            ("6", "severity",  "Filter by severity level",                 "Med"),
            ("7", "tech",      "Technology detection templates",           "Fast"),
            ("8", "custom",    "Custom template path or tags",             "N/A"),
        ]
        for row in modes:
            table.add_row(*row)
        console.print(table)

        choice = Prompt.ask(
            "Select mode",
            choices=[str(i) for i in range(1, 9)],
            default="1",
        )
        return {
            "1": "quick", "2": "full",     "3": "cves",
            "4": "exposures", "5": "logins", "6": "severity",
            "7": "tech",  "8": "custom",
        }[choice]

    def _build_from_mode(self, mode: str, target: str) -> str:
        out = "-o /tmp/kernox_nuclei.txt -json-export /tmp/kernox_nuclei.json"

        # Common flags
        threads  = Prompt.ask("Threads (higher = faster but noisier)", default="25")
        rate     = Prompt.ask("Rate limit (requests/sec)", default="150")
        base     = f"nuclei -u '{target}' -c {threads} -rl {rate} -silent"

        if mode == "quick":
            # Lightweight — recent CVEs + misconfigs only (~50MB)
            console.print("[dim]Using lightweight templates: recent CVEs + misconfigs[/dim]")
            return (
                f"{base} "
                f"-t cves/2022/ -t cves/2023/ -t cves/2024/ "
                f"-t misconfigs/ -t exposures/ "
                f"-severity critical,high "
                f"{out}"
            )

        elif mode == "full":
            console.print("[yellow]⚠ Full scan uses all downloaded templates. If slow, use quick mode.[/yellow]")
            return f"{base} -t cves/ -t misconfigs/ -t exposures/ -t default-logins/ {out}"

        elif mode == "cves":
            console.print("  [green]1[/green] 2024  [green]2[/green] 2023  [green]3[/green] 2022  [green]4[/green] 2021  [green]5[/green] All")
            yc = Prompt.ask("Year", choices=["1","2","3","4","5"], default="1")
            year_map = {"1":"2024","2":"2023","3":"2022","4":"2021","5":""}
            year = year_map[yc]
            if year:
                return f"{base} -t cves/{year}/ {out}"
            return f"{base} -t cves/ {out}"

        elif mode == "exposures":
            return f"{base} -t exposures/ -t exposed-panels/ {out}"

        elif mode == "logins":
            return f"{base} -t default-logins/ {out}"

        elif mode == "severity":
            console.print("Severity levels: critical, high, medium, low, info")
            sevs = Prompt.ask("Select severity (comma-separated)", default="critical,high")
            return f"{base} -t all -severity {sevs} {out}"

        elif mode == "tech":
            return f"{base} -t technologies/ {out}"

        elif mode == "custom":
            console.print(
                "  [green]1[/green] – Template path  "
                "  [green]2[/green] – Tags  "
                "  [green]3[/green] – Template ID\n"
            )
            cc = Prompt.ask("Select", choices=["1","2","3"], default="1")
            if cc == "1":
                path = Prompt.ask("Template path (e.g. /root/nuclei-templates/)")
                return f"{base} -t {path} {out}"
            elif cc == "2":
                tags = Prompt.ask("Tags (e.g. wp,rce,lfi)")
                return f"{base} -tags {tags} {out}"
            elif cc == "3":
                tid = Prompt.ask("Template ID (e.g. CVE-2021-41773)")
                return f"{base} -id {tid} {out}"

        return f"{base} -t cves/ -t misconfigs/ {out}"

    def parse(self, output: str) -> dict:
        return NucleiParser().parse(output)
