"""
kernox.core.executor  –  Safe subprocess wrapper with graceful interrupt handling.
"""

from __future__ import annotations

import subprocess
import shlex
import shutil
import time
import signal
import sys
from dataclasses import dataclass, field
from typing import Optional

from rich.console import Console
from rich.prompt import Confirm

from kernox.guards.rules import GuardRules
from kernox.config.config_store import ConfigStore

console = Console()

# Map tool names to their binary names
TOOL_BINARIES = {
    "nmap": "nmap",
    "ffuf": "ffuf",
    "gobuster": "gobuster",
    "sqlmap": "sqlmap",
    "nikto": "nikto",
    "enum4linux": "enum4linux",
    "wpscan": "wpscan",
    "smbclient": "smbclient",
    "dnsenum": "dnsenum",
    "curl": "curl",
    "hashcat": "hashcat",
    "whatweb": "whatweb",
    "wafw00f": "wafw00f",
    "sslscan": "sslscan",
    "onesixtyone": "onesixtyone",
    "dnsrecon": "dnsrecon",
    "nuclei": "nuclei",
    "ssh": "ssh",
    "sshpass": "sshpass",
    "msfvenom":      "msfvenom",
    "mail_crawler":  "python3",
    "zapcli":        "zap.sh",
    "hydra":         "hydra",
    "theharvester":  "theHarvester",
}

# Install hints per tool
INSTALL_HINTS = {
    "nmap": "sudo apt install nmap",
    "ffuf": "sudo apt install ffuf",
    "gobuster": "sudo apt install gobuster",
    "sqlmap": "sudo apt install sqlmap",
    "nikto": "sudo apt install nikto",
    "enum4linux": "sudo apt install enum4linux",
    "wpscan": "sudo apt install wpscan  OR  gem install wpscan",
    "smbclient": "sudo apt install smbclient",
    "dnsenum": "sudo apt install dnsenum",
    "curl": "sudo apt install curl",
    "hashcat": "sudo apt install hashcat",
    "whatweb": "sudo apt install whatweb",
    "wafw00f": "pip install wafw00f  OR  sudo apt install wafw00f",
    "sslscan": "sudo apt install sslscan",
    "onesixtyone": "sudo apt install onesixtyone",
    "dnsrecon": "sudo apt install dnsrecon  OR  pip install dnsrecon",
    "nuclei": "sudo apt install nuclei  OR  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "sshpass":        "sudo apt install sshpass",
    "msfvenom":       "sudo apt install metasploit-framework",
    "mail_crawler":   "pip install beautifulsoup4 requests",
    "zapcli":         "sudo apt install zaproxy  OR  docker pull ghcr.io/zaproxy/zaproxy:stable",
    "hydra":          "sudo apt install hydra",
    "theharvester":   "sudo apt install theharvester  OR  pip install theHarvester",
}


def check_tool_installed(binary: str) -> bool:
    """Return True if *binary* is found in PATH."""
    return shutil.which(binary) is not None


def check_and_warn(tool_name: str) -> bool:
    """
    Check if a tool is installed.
    Warns the user and returns False if not found.
    Returns True if installed or if tool not in known list.

    Special case: zapcli can run via Docker even when zap.sh is missing.
    """
    if tool_name == "zapcli":
        import shutil as _shutil
        if _shutil.which("zap.sh") or _shutil.which("zaproxy") or _shutil.which("docker"):
            return True
        hint = INSTALL_HINTS.get(tool_name, "sudo apt install zaproxy")
        console.print(
            f"\n[bold red]⚠ ZAP not found:[/bold red] neither [cyan]zap.sh[/cyan] "
            f"nor [cyan]docker[/cyan] is available.\n"
            f"  [dim]Install with:[/dim] [bold yellow]{hint}[/bold yellow]\n"
        )
        return Confirm.ask("Try running zapcli anyway?", default=False)

    binary = TOOL_BINARIES.get(tool_name)
    if not binary:
        return True

    if check_tool_installed(binary):
        return True

    hint = INSTALL_HINTS.get(tool_name, f"sudo apt install {tool_name}")
    console.print(
        f"\n[bold red]⚠ Tool not installed:[/bold red] [cyan]{binary}[/cyan]\n"
        f"  [dim]Install with:[/dim] [bold yellow]{hint}[/bold yellow]\n"
    )

    if Confirm.ask(f"Try running {tool_name} anyway?", default=False):
        return True

    return False


@dataclass
class ExecutionResult:
    command: str
    stdout: str
    stderr: str
    return_code: int
    duration_seconds: float
    blocked: bool = False
    block_reason: str = ""
    interrupted: bool = False
    extra: dict = field(default_factory=dict)

    @property
    def success(self) -> bool:
        return not self.blocked and not self.interrupted and self.return_code == 0

    def __str__(self) -> str:
        if self.blocked:
            return f"[BLOCKED] {self.block_reason}"
        if self.interrupted:
            return "[INTERRUPTED] Tool stopped by user"
        return self.stdout or self.stderr


class Executor:
    """Executes shell commands produced by tool wrappers."""

    def __init__(self, config: ConfigStore) -> None:
        self._cfg = config
        self._guards = GuardRules(config)

    # ── Public interface ─────────────────────────────────────────────────────

    def run(
        self,
        command: str,
        *,
        tool_name: str = "unknown",
        target: Optional[str] = None,
        timeout: int = 300,
        stream_output: bool = True,
        skip_confirm: bool = False,
    ) -> ExecutionResult:
        """Execute *command* after guard checks and optional confirmation."""

        # 0. Check if tool is installed
        if not check_and_warn(tool_name):
            return ExecutionResult(
                command=command,
                stdout="",
                stderr="",
                return_code=-1,
                duration_seconds=0.0,
                blocked=True,
                block_reason=f"Tool '{tool_name}' is not installed.",
            )

        # 1. Guard check
        allowed, reason = self._guards.check(command, target=target)
        if not allowed:
            console.print(f"[bold red]⛔ Blocked:[/bold red] {reason}")
            return ExecutionResult(
                command=command,
                stdout="",
                stderr="",
                return_code=-1,
                duration_seconds=0.0,
                blocked=True,
                block_reason=reason,
            )

        # 2. Optional confirmation — skip if tool handles its own interaction
        if not skip_confirm and self._cfg.get("confirm_before_exec") == "1":
            console.print(
                f"\n[bold yellow]⚡ About to run:[/bold yellow] {command}...\n"
            )
            if not Confirm.ask("Execute?", default=True):
                console.print("[yellow]Skipped.[/yellow]")
                return ExecutionResult(
                    command=command,
                    stdout="",
                    stderr="",
                    return_code=-1,
                    duration_seconds=0.0,
                    blocked=True,
                    block_reason="User declined execution.",
                )

        # 3. Execute
        if command.startswith("__PRIVESC_SSH_DONE__:"):
            output = command[len("__PRIVESC_SSH_DONE__:") :]
            console.print("[green]✓ SSH privesc completed[/green]")
            return ExecutionResult(
                command="ssh privesc",
                stdout=output,
                stderr="",
                return_code=0,
                duration_seconds=0.0,
            )

        console.print(f"\n[dim]$ {command}[/dim]")
        start = time.monotonic()
        stdout_parts: list[str] = []
        stderr_parts: list[str] = []

        show_raw = self._cfg.get("show_raw_output") == "1"
        interrupted = False

        try:
            proc = subprocess.Popen(
                shlex.split(command),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            if show_raw:
                # Stream stdout live with interrupt handling
                assert proc.stdout is not None
                try:
                    for line in proc.stdout:
                        console.print(line, end="")
                        stdout_parts.append(line)
                    proc.wait(timeout=timeout)
                    assert proc.stderr is not None
                    stderr_out = proc.stderr.read()
                    if stderr_out:
                        stderr_parts.append(stderr_out)
                except KeyboardInterrupt:
                    console.print("\n[yellow]⚠ Interrupt received - stopping tool...[/yellow]")
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                    interrupted = True
            else:
                # Silent mode with spinner and interrupt handling
                from rich.live import Live
                from rich.spinner import Spinner

                tool_label = tool_name.upper()
                try:
                    with Live(
                        Spinner("dots", text=f"[cyan]Running {tool_label}... (Ctrl+C to stop)[/cyan]"),
                        refresh_per_second=10,
                    ):
                        out, err = proc.communicate(timeout=timeout)
                    stdout_parts.append(out)
                    if err:
                        stderr_parts.append(err)
                except KeyboardInterrupt:
                    console.print("\n[yellow]⚠ Interrupt received - stopping tool...[/yellow]")
                    proc.terminate()
                    try:
                        out, err = proc.communicate(timeout=5)
                        stdout_parts.append(out)
                        if err:
                            stderr_parts.append(err)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        out, err = proc.communicate()
                        stdout_parts.append(out)
                        if err:
                            stderr_parts.append(err)
                    interrupted = True

            rc = proc.returncode if not interrupted else -2

        except FileNotFoundError:
            err_msg = (
                f"Tool not found: '{shlex.split(command)[0]}'. "
                "Please install it or add it to PATH."
            )
            console.print(f"[red]{err_msg}[/red]")
            rc = 127
            stderr_parts.append(err_msg)

        except subprocess.TimeoutExpired:
            proc.kill()
            err_msg = f"Command timed out after {timeout}s."
            console.print(f"[red]{err_msg}[/red]")
            rc = -1
            stderr_parts.append(err_msg)

        duration = time.monotonic() - start

        if interrupted:
            console.print(f"\n[yellow]⏹ Tool stopped by user after {duration:.1f}s[/yellow]")
            return ExecutionResult(
                command=command,
                stdout="".join(stdout_parts),
                stderr="".join(stderr_parts),
                return_code=-2,
                duration_seconds=duration,
                interrupted=True,
            )

        result = ExecutionResult(
            command=command,
            stdout="".join(stdout_parts),
            stderr="".join(stderr_parts),
            return_code=rc,
            duration_seconds=duration,
        )

        _status = "[green]✓[/green]" if result.success else "[red]✗[/red]"
        console.print(
            f"\n{_status} [dim]{tool_name} finished in {duration:.1f}s "
            f"(exit {rc})[/dim]\n"
        )
        return result
