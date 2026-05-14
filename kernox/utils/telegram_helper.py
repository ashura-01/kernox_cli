"""
kernox.utils.telegram_helper – Smart Telegram file sender.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Union
from rich.console import Console
from rich.prompt import Prompt

from kernox.utils.telegram_sender import get_telegram

console = Console()


def _select_files(files: List[Path], file_type: str) -> Union[List[Path], str, None]:
    """
    Show file selection menu.
    Returns: list of files, "ALL" marker, or None
    """
    if not files:
        console.print(f"[dim]No {file_type} files found[/dim]")
        return None

    console.print(f"\n[bold cyan]Available {file_type} files:[/bold cyan]")
    for i, f in enumerate(files, 1):
        # Show file size for context
        size = f.stat().st_size
        if size < 1024:
            size_str = f"{size}B"
        elif size < 1024 * 1024:
            size_str = f"{size // 1024}KB"
        else:
            size_str = f"{size // (1024 * 1024)}MB"
        console.print(f"  [green]{i}.[/green] {f.name} [dim]({size_str})[/dim]")

    console.print(f"  [green]a.[/green] Send all ({len(files)} files)")
    console.print(f"  [green]l.[/green] Send last (most recent)")
    console.print(f"  [green]q.[/green] Cancel")

    choice = Prompt.ask("Select option", default="q")

    if choice.lower() == 'q':
        return None
    if choice.lower() == 'a':
        return "ALL"
    if choice.lower() == 'l':
        return [files[-1]]  # Most recent

    try:
        idx = int(choice) - 1
        if 0 <= idx < len(files):
            return [files[idx]]
    except ValueError:
        pass

    console.print("[red]Invalid selection[/red]")
    return None


def _send_files(files: List[Path], caption_prefix: str) -> int:
    """Send multiple files and return count sent."""
    tg = get_telegram()
    sent = 0
    for f in files:
        if tg.send_file(str(f), f"{caption_prefix} {f.name}"):
            sent += 1
    return sent


def send_output() -> None:
    """Send tool output files from /tmp/kernox/ with smart selection."""
    tmp_dir = Path("/tmp/kernox/")
    if not tmp_dir.exists():
        console.print("[dim]No output files found. Run some tools first.[/dim]")
        return

    # Get all .txt files sorted by modification time (newest last)
    files = sorted(tmp_dir.glob("*.txt"), key=lambda p: p.stat().st_mtime)

    if not files:
        console.print("[dim]No output files found[/dim]")
        return

    result = _select_files(files, "tool output")

    if result is None:
        return
    elif result == "ALL":
        sent = _send_files(files, "⚐")
        console.print(f"[green]✓ Sent {sent} of {len(files)} output files[/green]")
    elif isinstance(result, list):
        sent = _send_files(result, "⚐")
        console.print(f"[green]✓ Sent {sent} file(s)[/green]")


def send_report() -> None:
    """Send PDF reports from /tmp/kernox/."""
    tmp_dir = Path("/tmp/kernox/")
    if not tmp_dir.exists():
        console.print("[dim]No reports found in /tmp/kernox/[/dim]")
        return

    files = sorted(tmp_dir.glob("*.pdf"), key=lambda p: p.stat().st_mtime)

    if not files:
        console.print("[dim]No PDF files found in /tmp/kernox/[/dim]")
        console.print("[dim]Generate a report first using 'report' command[/dim]")
        return

    result = _select_files(files, "reports")

    if result is None:
        return
    elif result == "ALL":
        sent = _send_files(files, "🗎")
        console.print(f"[green]✓ Sent {sent} of {len(files)} reports[/green]")
    elif isinstance(result, list):
        sent = _send_files(result, "🗎")
        console.print(f"[green]✓ Sent {sent} report(s)[/green]")


def send_file(file_path: str) -> None:
    """Send a specific file by path."""
    path = Path(file_path)
    if not path.exists():
        console.print(f"[red]File not found: {file_path}[/red]")
        return

    tg = get_telegram()
    if tg.send_file(str(path), f"📎 {path.name}"):
        console.print(f"[green]✓ Sent: {path.name}[/green]")
    else:
        console.print("[red]✗ Telegram not configured[/red]")
