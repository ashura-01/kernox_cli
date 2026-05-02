"""
kernox.cli — Main entry point.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich.align import Align
from rich import box
from rich.table import Table

from kernox.core.first_run import is_first_run
from kernox.core.first_run_setup import run_first_time_setup
from kernox.core.config_menu import open_config_menu
from kernox.core.orchestrator import Orchestrator
from kernox.config.config_store import ConfigStore

console = Console()

REQUIRED_PACKAGES = {
    "rich": "rich",
    "prompt_toolkit": "prompt_toolkit",
    "requests": "requests",
    "cryptography": "cryptography",
    "reportlab": "reportlab",
}

VERSION = "1.0.0"

BANNER = """\
 ██ ▄█▀▓█████  ██▀███   ███▄    █  ▒█████  ▒██   ██▒
 ██▄█▒ ▓█   ▀ ▓██ ▒ ██▒ ██ ▀█   █ ▒██▒  ██▒▒▒ █ █ ▒░
 ▓███▄░ ▒███   ▓██ ░▄█ ▒▓██  ▀█ ██▒▒██░  ██▒░░  █   ░
 ▓██ █▄ ▒▓█  ▄ ▒██▀▀█▄  ▓██▒  ▐▌██▒▒██   ██░ ░ █ █ ▒
 ▒██▒ █▄░▒████▒░██▓ ▒██▒▒██░   ▓██░░ ████▓▒░▒██▒ ▒██▒
 ▒ ▒▒ ▓▒░░ ▒░ ░░ ▒▓ ░▒▓░░ ▒░   ▒ ▒ ░ ▒░▒░▒░ ▒▒ ░ ░▓ ░
 ░ ░▒ ▒░ ░ ░  ░  ░▒ ░ ▒░░ ░░   ░ ▒░  ░ ▒ ▒░ ░░   ░▒ ░
 ░ ░░ ░    ░     ░░   ░    ░   ░ ░ ░ ░ ░ ▒   ░    ░
 ░  ░      ░  ░   ░              ░     ░ ░   ░    ░\
"""


def print_banner() -> None:
    console.print()
    console.print(Align(Text(BANNER, style="bold cyan"), align="center"))
    console.print()

    # Info row
    t = Table.grid(padding=(0, 3))
    t.add_column(style="dim")
    t.add_column(style="dim")
    t.add_column(style="dim")
    t.add_row(
        f"[cyan]v{VERSION}[/cyan]",
        "[#00b894]AI Penetration Testing Agent[/#00b894]",
        f"[dim]{datetime.now().strftime('%Y-%m-%d')}[/dim]",
    )
    console.print(Align(t, align="left"))
    console.print(
        "\n[dim]Type a target (IP/URL), ask a question, or type[/dim] "
        "[cyan]help[/cyan] [dim]for all commands[/dim]\n"
    )


def check_python_deps() -> None:
    missing = [n for p, n in REQUIRED_PACKAGES.items() if not _can_import(p)]
    if missing:
        console.print(
            f"[bold cyan]⚠  Missing packages:[/bold cyan] {', '.join(missing)}\n"
            f"   [dim]pip install {' '.join(missing)} --break-system-packages[/dim]\n"
        )


def _can_import(pkg: str) -> bool:
    try:
        __import__(pkg)
        return True
    except ImportError:
        return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kernox",
        description="Kernox — AI-Powered Penetration Testing CLI",
    )
    parser.add_argument("--config", action="store_true", help="Open configuration menu")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("--reset", action="store_true", help="Reset all configuration")
    parser.add_argument("--target", metavar="TARGET", help="Headless mode target")
    parser.add_argument(
        "--mode",
        metavar="MODE",
        default="web recon",
        help="Headless mode action (default: 'web recon')",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    print_banner()
    check_python_deps()

    if args.reset:
        _handle_reset()
        return

    if args.config:
        open_config_menu()
        return

    if args.target:
        config = ConfigStore()
        orch = Orchestrator(config)
        try:
            orch.run_headless(target=args.target, mode=args.mode)
        except KeyboardInterrupt:
            console.print("\n[cyan]Session ended.[/cyan]")
            sys.exit(0)
        return

    if is_first_run():
        console.print("[cyan]Welcome to Kernox![/cyan] Let's configure it first.\n")
        run_first_time_setup()

    config = ConfigStore()
    orch = Orchestrator(config)

    try:
        orch.run()
    except KeyboardInterrupt:
        console.print("\n[cyan]Session ended. Stay ethical.[/cyan]")
        sys.exit(0)


def _handle_reset() -> None:
    from kernox.config.config_store import ConfigStore
    from kernox.security.key_store import KeyStore

    console.print("\n[bold red]Resetting Kernox...[/bold red]")
    try:
        ConfigStore().reset()
        KeyStore().reset()
        console.print("[green]✓ Done. Run `kernox` to set up again.[/green]")
    except Exception as exc:
        console.print(f"[red]Reset failed: {exc}[/red]")


if __name__ == "__main__":
    main()
