"""
kernox.cli  –  Main entry point for the `kernox` command.
"""

from __future__ import annotations

import argparse
import sys

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from kernox.core.first_run import is_first_run
from kernox.core.first_run_setup import run_first_time_setup
from kernox.core.config_menu import open_config_menu
from kernox.core.orchestrator import Orchestrator
from kernox.config.config_store import ConfigStore

console = Console()

# Python packages required by Kernox
REQUIRED_PACKAGES = {
    "rich":         "rich",
    "prompt_toolkit": "prompt_toolkit",
    "requests":     "requests",
    "cryptography": "cryptography",
    "reportlab":    "reportlab",
}


def check_python_deps() -> None:
    """Check required Python packages and warn if missing."""
    missing = []
    for pkg, install_name in REQUIRED_PACKAGES.items():
        try:
            __import__(pkg)
        except ImportError:
            missing.append(install_name)

    if missing:
        console.print(
            f"\n[bold yellow]⚠ Missing Python packages:[/bold yellow] "
            f"{', '.join(missing)}\n"
            f"[dim]Install with:[/dim] "
            f"[cyan]pip install {' '.join(missing)} --break-system-packages[/cyan]\n"
        )


BANNER = r"""
██ ▄█▀▓█████  ██▀███   ███▄    █  ▒█████  ▒██   ██▒
██▄█▒ ▓█   ▀ ▓██ ▒ ██▒ ██ ▀█   █ ▒██▒  ██▒▒▒ █ █ ▒░
▓███▄░ ▒███   ▓██ ░▄█ ▒▓██  ▀█ ██▒▒██░  ██▒░░  █   ░
▓██ █▄ ▒▓█  ▄ ▒██▀▀█▄  ▓██▒  ▐▌██▒▒██   ██░ ░ █ █ ▒ 
▒██▒ █▄░▒████▒░██▓ ▒██▒▒██░   ▓██░░ ████▓▒░▒██▒ ▒██▒
▒ ▒▒ ▓▒░░ ▒░ ░░ ▒▓ ░▒▓░░ ▒░   ▒ ▒ ░ ▒░▒░▒░ ▒▒ ░ ░▓ ░
░ ░▒ ▒░ ░ ░  ░  ░▒ ░ ▒░░ ░░   ░ ▒░  ░ ▒ ▒░ ░░   ░▒ ░
░ ░░ ░    ░     ░░   ░    ░   ░ ░ ░ ░ ░ ▒   ░    ░  
░  ░      ░  ░   ░              ░     ░ ░   ░    ░  
         >>> K E R N O X <<<
"""


def print_banner() -> None:
    console.print(Text(BANNER, style="bold green"))
    console.print(
        Panel(
            "[bold cyan]AI-Powered Security Automation CLI[/bold cyan]\n"
            "[dim]For authorized penetration testing and ethical hacking only.[/dim]",
            border_style="green",
            expand=False,
        )
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kernox",
        description="Kernox – AI-Powered Security Automation CLI",
    )
    parser.add_argument(
        "--config",
        action="store_true",
        help="Open the interactive configuration menu.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Reset all Kernox configuration and start fresh.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    print_banner()

    # ── Check Python dependencies ────────────────────────────────────────────
    check_python_deps()

    # ── Reset flag ──────────────────────────────────────────────────────────
    if args.reset:
        _handle_reset()
        return

    # ── Config flag ─────────────────────────────────────────────────────────
    if args.config:
        open_config_menu()
        return

    # ── First-run detection ─────────────────────────────────────────────────
    if is_first_run():
        console.print("\n[yellow]Welcome to Kernox! Let's get you set up.[/yellow]\n")
        run_first_time_setup()

    # ── Main interactive loop ───────────────────────────────────────────────
    config = ConfigStore()
    orchestrator = Orchestrator(config)

    console.print(
        "\n[bold green]System ready.[/bold green] Type [bold]help[/bold] for commands, "
        "[bold]exit[/bold] to quit.\n"
    )

    try:
        orchestrator.run()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Session ended. Stay ethical.[/yellow]")
        sys.exit(0)


def _handle_reset() -> None:
    from kernox.config.config_store import ConfigStore
    from kernox.security.key_store import KeyStore

    console.print("\n[bold red]Resetting Kernox configuration...[/bold red]")
    try:
        ConfigStore().reset()
        KeyStore().reset()
        console.print("[green]✓ Configuration reset. Run `kernox` to set up again.[/green]")
    except Exception as exc:
        console.print(f"[red]Reset failed: {exc}[/red]")


if __name__ == "__main__":
    main()
