"""Format tool outputs as tables and vulnerabilities."""

import re
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.syntax import Syntax

console = Console()

C = {
    "primary": "cyan",
    "ok": "#55efc4",
    "err": "#ff6b6b",
    "dim": "dim cyan",
    "warn": "#ffa500",
}


class OutputFormatter:
    @staticmethod
    def format_output(tool_name: str, output: str, target: str = "") -> None:
        """Format tool output as a table where possible."""
        if not output or not output.strip():
            return

        table = OutputFormatter._parse_to_table(output)
        if table:
            console.print(table)
        else:
            lines = output.strip().split('\n')[:20]
            for line in lines:
                console.print(f"  {line[:120]}")
            if len(output.split('\n')) > 20:
                console.print(f"  [dim]... and {len(output.split('\n')) - 20} more lines[/dim]")

    @staticmethod
    def _parse_to_table(raw: str) -> Table | None:
        """Try to parse nmap or ffuf style output into a table."""
        lines = [l for l in raw.strip().splitlines() if l.strip()]
        if len(lines) < 2:
            return None

        # nmap: PORT STATE SERVICE VERSION
        nmap_re = re.compile(r"(\d+/\w+)\s+(open|closed|filtered)\s+(\S+)(.*)")
        nmap_rows = [nmap_re.match(l) for l in lines]
        nmap_rows = [m for m in nmap_rows if m]

        if nmap_rows:
            t = Table(
                box=box.MINIMAL,
                show_header=True,
                header_style=f"bold {C['primary']}",
                border_style=C["dim"],
            )
            t.add_column("PORT", style=C["primary"])
            t.add_column("STATE")
            t.add_column("SERVICE", style="white")
            t.add_column("VERSION", style=C["dim"])

            for m in nmap_rows:
                color = C["ok"] if m.group(2) == "open" else C["err"]
                t.add_row(
                    m.group(1),
                    f"[{color}]{m.group(2)}[/{color}]",
                    m.group(3),
                    m.group(4).strip()[:40],
                )
            return t

        # ffuf: Status: 200 /path
        ffuf_re = re.compile(r"Status[:\s\[]*(\d{3})[^\n]*?(\/\S*)", re.IGNORECASE)
        ffuf_rows = [ffuf_re.search(l) for l in lines]
        ffuf_rows = [m for m in ffuf_rows if m]

        if ffuf_rows:
            t = Table(
                box=box.MINIMAL,
                show_header=True,
                header_style=f"bold {C['primary']}",
                border_style=C["dim"],
            )
            t.add_column("STATUS", style=C["primary"])
            t.add_column("PATH", style="white")

            for m in ffuf_rows:
                color = C["ok"] if m.group(1) == "200" else C["err"]
                t.add_row(f"[{color}]{m.group(1)}[/{color}]", m.group(2))
            return t

        return None

    @staticmethod
    def format_vulnerability(vuln: dict) -> None:
        """Display a single vulnerability as a compact panel."""
        severity = vuln.get("severity", "info")
        sev_lower = severity.lower()

        # Map severity to color and icon
        severity_map = {
            "critical": ("#ff0000", "■"),
            "high":     ("#ff6b6b", "▲"),
            "medium":   ("#ffa500", "●"),
            "low":      ("#55efc4", "●"),
            "info":     ("#888888", "▪"),
        }
        col, icon = severity_map.get(sev_lower, ("#888888", "▪"))

        name = vuln.get("name", "Unknown")
        desc = vuln.get("description", "")
        exploit = vuln.get("exploit", "")

        # Build title: severity icon + label + name
        title = f"[{col}]{icon} {severity.upper()}[/{col}] {name}"

        # Body: description only (exploit shown separately below)
        body = desc[:300] if desc else "No description provided."

        # Render panel
        console.print(Panel(
            body,
            title=title,
            border_style=col,
            box=box.ROUNDED,
            padding=(0, 1),
        ))

        # Print exploit command separately with syntax highlighting
        if exploit:
            console.print(Syntax(exploit, "bash", theme="monokai", word_wrap=True))
