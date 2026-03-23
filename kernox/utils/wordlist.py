"""
kernox.utils.wordlist  –  Interactive wordlist picker for fuzzing tools.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich import box

console = Console()

# Common Kali wordlist locations
COMMON_WORDLISTS = [
    {
        "name": "dirb/common",
        "path": "/usr/share/wordlists/dirb/common.txt",
        "desc": "Common dirs/files (~4K words) — fast",
        "size": "~4K",
    },
    {
        "name": "dirb/big",
        "path": "/usr/share/wordlists/dirb/big.txt",
        "desc": "Bigger dirb list (~20K words)",
        "size": "~20K",
    },
    {
        "name": "dirbuster/medium",
        "path": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "desc": "DirBuster medium list (~220K words) — thorough",
        "size": "~220K",
    },
    {
        "name": "dirbuster/small",
        "path": "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        "desc": "DirBuster small list (~87K words)",
        "size": "~87K",
    },
    {
        "name": "SecLists/common",
        "path": "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "desc": "SecLists common web content",
        "size": "~4K",
    },
    {
        "name": "SecLists/raft-medium",
        "path": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        "desc": "SecLists raft medium directories",
        "size": "~30K",
    },
    {
        "name": "SecLists/api-endpoints",
        "path": "/usr/share/seclists/Discovery/Web-Content/api/objects.txt",
        "desc": "API endpoint discovery",
        "size": "~500",
    },
    {
        "name": "rockyou (passwords)",
        "path": "/usr/share/wordlists/rockyou.txt",
        "desc": "RockYou passwords — for brute force only",
        "size": "~14M",
    },
]


def pick_wordlist(tool_name: str = "ffuf") -> str:
    """
    Show an interactive wordlist picker.
    Returns the selected wordlist path.
    """
    console.print(f"\n[bold cyan]📂 Wordlist picker for {tool_name}[/bold cyan]\n")

    # Filter to only show wordlists that actually exist
    available = [w for w in COMMON_WORDLISTS if Path(w["path"]).exists()]
    missing   = [w for w in COMMON_WORDLISTS if not Path(w["path"]).exists()]

    table = Table(
        show_header=True,
        header_style="bold magenta",
        box=box.SIMPLE_HEAVY,
        border_style="dim",
    )
    table.add_column("#", width=4, style="bold cyan")
    table.add_column("Name", style="bold")
    table.add_column("Words", width=8, style="dim")
    table.add_column("Description")
    table.add_column("Status", width=10)

    choices: list[str] = []

    for i, w in enumerate(available, 1):
        table.add_row(
            str(i),
            w["name"],
            w["size"],
            w["desc"],
            "[green]✓ found[/green]",
        )
        choices.append(str(i))

    for w in missing:
        table.add_row(
            "-",
            w["name"],
            w["size"],
            w["desc"],
            "[red]✗ missing[/red]",
        )

    console.print(table)
    console.print(f"  [dim]{len(missing)} wordlist(s) not installed on this system.[/dim]\n")

    # Also allow custom path
    choices.append("c")
    console.print("  [green]c[/green] – Enter a custom wordlist path\n")

    if not available:
        console.print("[yellow]⚠ No default wordlists found. Enter a custom path.[/yellow]")
        return _ask_custom_path()

    choice = Prompt.ask(
        "Select wordlist",
        choices=choices,
        default="1",
    )

    if choice == "c":
        return _ask_custom_path()

    selected = available[int(choice) - 1]
    console.print(f"[green]✓ Using:[/green] {selected['path']}\n")
    return selected["path"]


def _ask_custom_path() -> str:
    """Ask user to enter a custom wordlist path."""
    while True:
        path = Prompt.ask("Enter full path to wordlist")
        if Path(path).exists():
            console.print(f"[green]✓ Found: {path}[/green]\n")
            return path
        console.print(f"[red]✗ File not found: {path}[/red]")
        retry = Prompt.ask("Try again?", choices=["y", "n"], default="y")
        if retry == "n":
            # Fall back to dirb common
            fallback = "/usr/share/wordlists/dirb/common.txt"
            console.print(f"[yellow]Using fallback: {fallback}[/yellow]")
            return fallback
