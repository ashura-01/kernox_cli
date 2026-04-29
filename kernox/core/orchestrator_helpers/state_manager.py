"""Session state display and management."""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

C = {
    "primary": "cyan",
    "secondary": "#00b894",
    "dim": "dim cyan",
}

SEV_STYLE = {
    "critical": ("bold red", "CRITICAL"),
    "high": ("red", "HIGH"),
    "medium": ("#00b894", "MEDIUM"),
    "low": ("cyan", "LOW"),
    "info": ("dim white", "INFO"),
}


class StateManager:
    def __init__(self, state, intensity):
        self._state = state
        self._intensity = intensity
    
    def print_state(self) -> None:
        """Print current session state."""
        results = self._state.get_tool_results()
        insights = self._state.get_ai_insights()
        
        console.print()
        console.print(Panel(
            f"[dim]Intensity:[/dim] {self._intensity['name']}\n"
            f"[dim]Tools run:[/dim] {len(results)}\n"
            f"[dim]Findings:[/dim] {len(insights)}",
            title="[bold cyan]Session State[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
        ))
        
        if insights:
            console.print()
            table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
            table.add_column("SEV", width=10)
            table.add_column("FINDING", style="white")
            table.add_column("TOOL", style="dim")
            
            for ins in insights[-15:]:
                color, badge = SEV_STYLE.get(ins.severity.lower(), ("white", ins.severity.upper()))
                table.add_row(
                    f"[{color}]{badge}[/{color}]",
                    ins.vulnerability[:50],
                    f"{ins.tool}@{ins.target}"[:30],
                )
            console.print(table)
    
    def clear_all(self, history) -> None:
        """Clear state and history."""
        self._state.reset()
        history.clear()
        console.print("[green]✓ State and history cleared[/green]")