"""
kernox.utils.secure_input  –  Safe, masked prompt helpers.
"""

from __future__ import annotations

import getpass
from typing import Optional

from rich.console import Console

console = Console()


def secure_prompt(prompt: str, *, allow_empty: bool = True) -> Optional[str]:
    """
    Display *prompt* and read a line of input without echoing characters.
    Returns the entered string, or None if the user pressed Enter with no input
    and allow_empty is True.
    """
    try:
        value = getpass.getpass(f"{prompt}: ")
        if not value and not allow_empty:
            console.print("[yellow]No value entered.[/yellow]")
            return None
        return value or None
    except (KeyboardInterrupt, EOFError):
        console.print("\n[yellow]Input cancelled.[/yellow]")
        return None
