"""Command execution using Executor."""

import shlex
import subprocess
import shutil
import getpass
from typing import Optional
from rich.console import Console
from rich.markdown import Markdown
from rich.prompt import Confirm, Prompt
from rich.syntax import Syntax
from rich.table import Table
from rich import box
import re

from kernox.core.executor import Executor
from kernox.guards.shell_sanitizer import sanitize

console = Console()

_MAX_CHAIN_DEPTH = 3

_HELP_CACHE: dict[str, str] = {}


def _get_tool_help(binary: str) -> str:
    if binary in _HELP_CACHE:
        return _HELP_CACHE[binary]

    path = shutil.which(binary)
    if not path:
        return ""

    for flag in ["--help", "-h", "-help", "help"]:
        try:
            result = subprocess.run(
                [binary, flag],
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = (result.stdout + result.stderr)[:3000]
            if output.strip():
                _HELP_CACHE[binary] = output
                return output
        except Exception:
            continue

    return ""


class CommandExecutor:
    def __init__(self, config, state, ai_analyzer=None):
        self._cfg = config
        self._state = state
        self._executor = Executor(config)
        self._ai_analyzer = ai_analyzer

    def run_shell_step(self, args: dict, reason: str = "", intensity: dict = None,
                       _chain_depth: int = 0) -> Optional[str]:
        raw_cmd = args.get("command", "").strip()
        target = args.get("target", "")

        if not raw_cmd:
            console.print("[red]No command provided[/red]")
            return None

        san = sanitize(raw_cmd, self._cfg)
        if not san.allowed:
            console.print(f"[red]Blocked: {san.reason}[/red]")
            return None

        if not target and san.target:
            target = san.target

        console.print(f"[yellow]\ncommand: {san.command}[/yellow]")

        if not Confirm.ask("  Execute?", default=True):
            console.print("[dim]Skipped[/dim]")
            return None

        sudo_password = None
        needs_sudo = san.binary in ["nmap", "masscan", "tcpdump", "tshark",
                                     "arp-scan", "bettercap", "aireplay-ng",
                                     "reaver", "kismet", "netdiscover", "netstat",
                                     "iptables", "systemctl", "service"]

        if raw_cmd.startswith('sudo ') or raw_cmd.startswith('sudo\t'):
            needs_sudo = True
            san.command = san.command.replace('sudo ', '', 1).lstrip()
            san.binary = san.command.split()[0] if san.command else san.binary

        if needs_sudo:
            sudo_password = getpass.getpass("Sudo password: ")

        timeout = intensity.get("timeout", 60) if intensity else 60
        result = self._executor.run(
            command=san.command,
            tool_name=san.binary,
            target=target,
            timeout=timeout,
            stream_output=True,
            skip_confirm=True,
            use_sudo=needs_sudo,
            sudo_password=sudo_password,
        )

        if result.return_code != 0 and not result.blocked and not result.interrupted:
            console.print(f"[yellow]Command failed (exit {result.return_code})[/yellow]")
            if result.stderr.strip():
                console.print(f"[dim]{result.stderr.strip()[:300]}[/dim]")

            if "sudo: a password is required" in result.stderr or "sudo: 3 incorrect password attempts" in result.stderr:
                console.print("[red]Sudo authentication failed[/red]")
                return None

            help_output = _get_tool_help(san.binary)
            if help_output:
                console.print(f"\n[dim]-- {san.binary} --help --[/dim]")
                console.print(f"[dim]{help_output[:1500]}[/dim]")
                console.print(f"[dim]-- end help --[/dim]\n")
                console.print("[yellow]Tip: Check the help above and re-run with correct flags.[/yellow]")
            else:
                console.print(f"[dim]No --help available for {san.binary}[/dim]")

            self._state.add_tool_result(
                tool=result.tool_name,
                target=target or "unknown",
                parsed={"exit_code": result.return_code, "duration": result.duration_seconds},
                raw_output=result.stdout + result.stderr,
            )
            return None

        if result.stdout.strip():
            from .output_formatter import OutputFormatter
            OutputFormatter.format_output(result.tool_name, result.stdout, target)

        self._state.add_tool_result(
            tool=result.tool_name,
            target=target or "unknown",
            parsed={"exit_code": result.return_code, "duration": result.duration_seconds},
            raw_output=result.stdout + result.stderr,
        )

        if self._ai_analyzer and result.stdout.strip() and _chain_depth < _MAX_CHAIN_DEPTH and result.return_code == 0:
            next_steps = self._ai_analyzer.analyze(
                tool_name=result.tool_name,
                target=target or "unknown",
                raw_output=result.stdout,
            )

            if not next_steps:
                return result.stdout if (not result.blocked and result.return_code >= 0) else None

            table = Table(
                title="Proposed follow-up actions",
                box=box.ROUNDED,
                border_style="yellow",
                title_style="bold yellow",
            )
            table.add_column("#", style="cyan", width=3)
            table.add_column("Prio", style="magenta", width=4)
            table.add_column("Reason", style="white")
            table.add_column("Command", style="green", no_wrap=False)

            for i, step in enumerate(next_steps, 1):
                cmd = step.get("args", {}).get("command", "")
                reason_str = step.get("reason", "No reason")
                priority = step.get("priority", 1)
                table.add_row(
                    str(i),
                    str(priority),
                    reason_str,
                    Syntax(cmd, "bash", theme="monokai", word_wrap=True),
                )

            console.print(table)

            choice = Prompt.ask(
                "\nEnter numbers to run (comma-separated, 'all', or 'none')",
                default="none",
            ).strip().lower()

            if choice == "all":
                selected = next_steps
            elif choice == "none":
                selected = []
            else:
                indices = []
                for part in choice.split(","):
                    part = part.strip()
                    if part.isdigit():
                        indices.append(int(part))
                selected = [next_steps[i-1] for i in indices if 1 <= i <= len(next_steps)]

            for step in selected:
                step_args = step.get("args", {})
                step_reason = step.get("reason", "")
                self.run_shell_step(step_args, step_reason, intensity,
                                    _chain_depth=_chain_depth + 1)

        return result.stdout if (not result.blocked and result.return_code >= 0) else None
