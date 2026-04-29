"""Session save/load/list — delegates entirely to SessionState which already implements persistence."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from rich import box

from kernox.engine.state import SessionState

console = Console()


class SessionManager:
    def __init__(self, state: SessionState, updater) -> None:
        self._state = state
        self._updater = updater

    def save(self) -> None:
        """Persist current session via SessionState.save()."""
        self._state.save()
        path = self._state._session_file
        console.print(f"[green]✓ Session saved → {path}[/green]")

    def load(self) -> None:
        """Interactively pick and restore a saved session."""
        sessions = SessionState.list_sessions()
        if not sessions:
            console.print("[dim]No saved sessions found.[/dim]")
            return

        table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
        table.add_column("#", width=4)
        table.add_column("Session file", style="white")
        table.add_column("Size", style="dim", width=8)
        for i, p in enumerate(sessions[:10], 1):
            table.add_row(str(i), p.stem, f"{p.stat().st_size // 1024}KB")
        console.print(table)

        choice = Prompt.ask("Load session #", default="1")
        try:
            idx = int(choice) - 1
            if not (0 <= idx < len(sessions)):
                raise ValueError
        except ValueError:
            console.print("[red]✗ Invalid selection[/red]")
            return

        loaded = SessionState.load(sessions[idx])
        # Swap internals so the live state object gets the loaded data
        self._state.__dict__.update(loaded.__dict__)
        console.print("[green]✓ Session loaded[/green]")

    def list_sessions(self) -> None:
        """Print all saved sessions."""
        sessions = SessionState.list_sessions()
        if not sessions:
            console.print("[dim]No saved sessions.[/dim]")
            return

        table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan",
                      title="Saved Sessions")
        table.add_column("File", style="white")
        table.add_column("Size", style="dim")
        for p in sessions:
            table.add_row(p.stem, f"{p.stat().st_size // 1024}KB")
        console.print(table)
