"""
kernox.utils.privesc_formatter  –  Rich display for privesc findings.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()

SEV_COLORS = {
    "critical": "bold red",
    "high":     "bold yellow",
    "medium":   "bold cyan",
    "low":      "green",
    "info":     "dim",
}

SEV_ICONS = {
    "critical": "🔴",
    "high":     "🟡",
    "medium":   "🔵",
    "low":      "🟢",
    "info":     "⚪",
}


def format_privesc(parsed: dict) -> None:
    total    = parsed.get("total", 0)
    critical = parsed.get("critical", 0)
    high     = parsed.get("high", 0)
    medium   = parsed.get("medium", 0)
    low      = parsed.get("low", 0)
    kernel   = parsed.get("kernel_version", "?")
    findings = parsed.get("findings", [])
    juicy    = parsed.get("juicy_points", [])

    # ── Summary header ────────────────────────────────────────────────────────
    header = Text()
    header.append(f"  Kernel: ", style="dim")
    header.append(f"{kernel}\n", style="cyan")
    header.append(f"  Total findings: ", style="dim")
    header.append(f"{total}\n", style="bold white")
    header.append(f"  🔴 Critical: ", style="dim")
    header.append(f"{critical}  ", style="bold red")
    header.append(f"🟡 High: ", style="dim")
    header.append(f"{high}  ", style="bold yellow")
    header.append(f"🔵 Medium: ", style="dim")
    header.append(f"{medium}  ", style="bold cyan")
    header.append(f"🟢 Low: ", style="dim")
    header.append(f"{low}", style="green")

    border = "red" if critical > 0 else "yellow" if high > 0 else "cyan"
    console.print(Panel(
        header,
        title="[bold red]⚡ Linux PrivEsc Enumeration[/bold red]",
        border_style=border,
        box=box.ROUNDED,
    ))

    # ── Juicy Points ─────────────────────────────────────────────────────────
    if juicy:
        console.print(f"\n[bold red]🎯 JUICY POINTS ({len(juicy)} found)[/bold red]\n")
        table = Table(
            show_header=True,
            header_style="bold magenta",
            box=box.SIMPLE_HEAVY,
            border_style="red",
            show_lines=True,
        )
        table.add_column("SEV", width=10)
        table.add_column("Category", width=12, style="bold")
        table.add_column("Finding")
        table.add_column("Path", style="cyan")

        for j in juicy:
            sev   = j.get("severity", "info")
            color = SEV_COLORS.get(sev, "white")
            icon  = SEV_ICONS.get(sev, "")
            table.add_row(
                f"[{color}]{icon} {sev.upper()}[/{color}]",
                j.get("category", ""),
                j.get("title", ""),
                j.get("path", "")[:60],
            )
        console.print(table)

    # ── Detailed findings by category ─────────────────────────────────────────
    categories = {}
    for f in findings:
        cat = f.get("category", "other")
        categories.setdefault(cat, []).append(f)

    cat_order = ["sudo","suid","sgid","capabilities","writable","cron","nfs","path","kernel","file"]

    for cat in cat_order:
        if cat not in categories:
            continue
        cat_findings = categories[cat]
        console.print(f"\n[bold magenta]── {cat.upper()} ──[/bold magenta]")

        for f in cat_findings:
            sev   = f.get("severity", "info")
            color = SEV_COLORS.get(sev, "white")
            icon  = SEV_ICONS.get(sev, "")

            lines = [
                f"[{color}]{icon} [{sev.upper()}][/{color}] {f.get('title','')}",
                f"  [dim]Detail:[/dim] {f.get('detail','')}",
            ]
            if f.get("juicy_path"):
                paths = f["juicy_path"].split("\n")
                for p in paths[:5]:
                    lines.append(f"  [cyan]📁 {p}[/cyan]")
            if f.get("exploit_hint"):
                lines.append(f"  [yellow]💡 Hint:[/yellow] {f['exploit_hint'][:120]}")

            console.print("\n".join(lines))

    console.print()
