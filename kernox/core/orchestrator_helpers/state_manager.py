"""Session state display — exhibition quality."""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich import box

console = Console()

SEV_STYLE = {
    "critical": ("#ff6b6b", "CRITICAL"),
    "high":     ("red",     "HIGH"),
    "medium":   ("#00b894", "MEDIUM"),
    "low":      ("cyan",    "LOW"),
    "info":     ("dim",     "INFO"),
}


class StateManager:
    def __init__(self, state, intensity):
        self._state     = state
        self._intensity = intensity

    def print_state(self) -> None:
        results  = self._state.get_tool_results()
        insights = self._state.get_ai_insights()
        hosts    = self._state.hosts
        paths    = self._state.paths

        console.print()

        # ── Summary row ───────────────────────────────────────────────────────
        stats = Table.grid(padding=(0, 3))
        stats.add_column(justify="center")
        stats.add_column(justify="center")
        stats.add_column(justify="center")
        stats.add_column(justify="center")
        stats.add_column(justify="center")

        def _stat(val, label, col="cyan"):
            return f"[bold {col}]{val}[/bold {col}]\n[dim]{label}[/dim]"

        crit_count = sum(1 for i in insights if i.severity.lower() == "critical")
        high_count = sum(1 for i in insights if i.severity.lower() == "high")

        stats.add_row(
            _stat(len(hosts),   "hosts",    "cyan"),
            _stat(len(results), "tools run","#00b894"),
            _stat(len(insights),"findings", "#ff6b6b" if crit_count else "#00b894"),
            _stat(len(paths),   "web targets","cyan"),
            _stat(self._intensity["name"], "mode", "dim cyan"),
        )
        console.print(Panel(stats, title="[bold cyan]Session State[/bold cyan]",
                            border_style="cyan", box=box.ROUNDED))

        # ── Hosts table ───────────────────────────────────────────────────────
        if hosts:
            console.print()
            ht = Table(title="Discovered Hosts", box=box.MINIMAL,
                       header_style="bold cyan", border_style="dim cyan", padding=(0,1))
            ht.add_column("IP",       style="cyan",  width=18)
            ht.add_column("Hostname", style="dim",   width=20)
            ht.add_column("OS",       style="dim",   width=20)
            ht.add_column("Open Ports")
            for ip, h in hosts.items():
                open_ports = ", ".join(
                    f"{p['port']}/{p.get('service','?')}"
                    for p in h.ports if p.get('port')
                )[:80]
                ht.add_row(ip, h.hostname or "—", h.os or "—", open_ports or "—")
            console.print(ht)

        # ── Findings table ────────────────────────────────────────────────────
        if insights:
            console.print()
            ft = Table(title="AI Findings", box=box.MINIMAL,
                       header_style="bold cyan", border_style="dim cyan", padding=(0,1))
            ft.add_column("SEV",     width=10)
            ft.add_column("Finding", style="white")
            ft.add_column("Tool",    style="dim", width=12)
            ft.add_column("Target",  style="dim", width=22)

            for ins in sorted(insights,
                              key=lambda x: ["critical","high","medium","low","info"].index(
                                  x.severity.lower()) if x.severity.lower() in
                                  ["critical","high","medium","low","info"] else 5):
                col, badge = SEV_STYLE.get(ins.severity.lower(), ("white", ins.severity.upper()))
                ft.add_row(
                    f"[{col}]{badge}[/{col}]",
                    ins.vulnerability[:50],
                    ins.tool,
                    ins.target[:22],
                )
            console.print(ft)

        # ── Web paths summary ─────────────────────────────────────────────────
        if paths:
            console.print()
            pt = Table(title="Web Paths Found", box=box.MINIMAL,
                       header_style="bold cyan", border_style="dim cyan", padding=(0,1))
            pt.add_column("Target",  style="cyan")
            pt.add_column("Count",   style="dim", width=8)
            pt.add_column("Sample",  style="dim")
            for target, found in paths.items():
                sample = "  ".join(f["path"] for f in found[:4])
                pt.add_row(target[:40], str(len(found)), sample[:60])
            console.print(pt)

        if not hosts and not insights and not results:
            console.print("[dim]  No data yet. Run a tool to start.[/dim]")

    def clear_all(self, history: list) -> None:
        self._state.reset()
        history.clear()
        console.print("[green]✓ Session cleared[/green]")
