"""
kernox.core.executor – Safe subprocess wrapper with graceful interrupt handling.
Uses adaptive timeout that extends while output is still flowing.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import signal
import subprocess
import time
import getpass
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional
import sys

from rich.console import Console
from rich.live import Live
from rich.prompt import Confirm, Prompt
from rich.text import Text

from kernox.config.config_store import ConfigStore
from kernox.guards.shell_sanitizer import sanitize

console = Console()
TMP_OUTPUT_DIR = Path("/tmp/kernox")

ABSOLUTE_MAX_TIMEOUT = 3600
PROGRESS_GRACE = 10
MIN_EXTENSION = 30

SUDO_TOOLS = {
    "nmap": True,
    "masscan": True,
    "tcpdump": True,
    "tshark": True,
    "arp-scan": True,
    "bettercap": True,
    "aireplay-ng": True,
    "reaver": True,
    "kismet": True,
    "netdiscover": True,
    "netstat": True,
    "iptables": True,
    "systemctl": True,
    "service": True,
}


def _ensure_tmp() -> None:
    TMP_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def _save_output(binary: str, target: str, output: str) -> Path:
    _ensure_tmp()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = re.sub(r"[^a-zA-Z0-9._-]", "_", target)[:40]
    filename = f"{binary}_{safe_target}_{ts}.txt"
    path = TMP_OUTPUT_DIR / filename
    path.write_text(output, encoding="utf-8", errors="replace")
    return path


def check_tool_installed(binary: str) -> tuple[bool, Optional[str]]:
    if shutil.which(binary):
        return True, None

    try:
        result = subprocess.run(
            ["dpkg", "-S", binary],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            pkg = result.stdout.split(":")[0]
            return False, f"sudo apt install {pkg}"
    except Exception:
        pass

    try:
        result = subprocess.run(
            ["apt-file", "search", f"bin/{binary}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout:
            pkg = result.stdout.split(":")[0]
            return False, f"sudo apt install {pkg}"
    except Exception:
        pass

    return False, f"Install '{binary}' using your package manager (apt, yum, brew, etc.)"


@dataclass
class ExecutionResult:
    command: str
    stdout: str
    stderr: str
    return_code: int
    duration_seconds: float
    tool_name: str
    target: str = ""
    output_path: Optional[Path] = None
    blocked: bool = False
    block_reason: str = ""
    interrupted: bool = False
    used_sudo: bool = False


class Executor:
    def __init__(self, config: ConfigStore) -> None:
        self._cfg = config

    def run(
        self,
        command: str,
        *,
        tool_name: str = "unknown",
        target: Optional[str] = None,
        timeout: int = 60,
        stream_output: bool = False,
        skip_confirm: bool = False,
        use_sudo: Optional[bool] = None,
        sudo_password: Optional[str] = None,
    ) -> ExecutionResult:
        san_result = sanitize(command, self._cfg)
        if not san_result.allowed:
            return ExecutionResult(
                command=command,
                stdout="",
                stderr=san_result.reason,
                return_code=-1,
                duration_seconds=0.0,
                tool_name=tool_name,
                target=target or san_result.target or "",
                blocked=True,
                block_reason=san_result.reason,
            )

        final_command = san_result.command
        binary = san_result.binary
        detected_target = san_result.target or target or ""

        is_installed, install_hint = check_tool_installed(binary)
        if not is_installed:
            msg = f"Tool '{binary}' not found"
            if install_hint:
                msg += f"\n  Hint: {install_hint}"
            return ExecutionResult(
                command=command,
                stdout="",
                stderr=msg,
                return_code=-1,
                duration_seconds=0.0,
                tool_name=tool_name,
                target=detected_target,
                blocked=True,
                block_reason=f"'{binary}' not installed",
            )

        auto_sudo = SUDO_TOOLS.get(binary, False) if use_sudo is None else use_sudo
        needs_sudo = auto_sudo
        sudo_pass = sudo_password
        actual_command = final_command

        if auto_sudo and sudo_pass is None and not skip_confirm:
            sudo_pass = getpass.getpass("Sudo password: ")

        if not skip_confirm and self._cfg.get("confirm_before_exec") == "1":
            display_cmd = f"sudo {actual_command}" if needs_sudo else actual_command
            if not Confirm.ask(f"  command: {display_cmd} [execute? y/n]", default=True):
                return ExecutionResult(
                    command=command,
                    stdout="",
                    stderr="User declined execution",
                    return_code=-1,
                    duration_seconds=0.0,
                    tool_name=tool_name,
                    target=detected_target,
                    blocked=True,
                    block_reason="User declined",
                )

        console.print(f"\n[dim]$ {'sudo ' if needs_sudo else ''}{actual_command}[/dim]")
        start = time.monotonic()
        stdout_parts: list[str] = []
        stderr_parts: list[str] = []
        interrupted = False
        timed_out = False

        deadline = start + max(timeout, 10)

        try:
            if needs_sudo and sudo_pass:
                cmd_parts = ["sudo", "-S"] + shlex.split(actual_command)
                proc = subprocess.Popen(
                    cmd_parts,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                )
                proc.stdin.write(sudo_pass + "\n")
                proc.stdin.flush()
            else:
                proc = subprocess.Popen(
                    shlex.split(actual_command),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                )

            last_output_time = start

            with Live(Text(""), refresh_per_second=4, console=console) as live:
                try:
                    for line in iter(proc.stdout.readline, ""):
                        now = time.monotonic()
                        elapsed = now - start

                        stdout_parts.append(line)
                        last_output_time = now
                        line_count = len(stdout_parts)

                        if now >= deadline - 5:
                            new_deadline = min(now + MIN_EXTENSION, start + ABSOLUTE_MAX_TIMEOUT)
                            if new_deadline > deadline:
                                deadline = new_deadline

                        remaining = max(0, int(deadline - now))
                        status_text = (
                            f"[cyan]{binary} running...[/cyan] "
                            f"[dim]{int(elapsed)}s elapsed | {line_count} lines | timeout in {remaining}s[/dim]"
                        )
                        live.update(Text.from_markup(status_text))

                        if stream_output:
                            console.print(f"[dim]{line.rstrip()}[/dim]")

                        if elapsed >= ABSOLUTE_MAX_TIMEOUT:
                            live.update(Text.from_markup("[yellow]Reached maximum runtime limit[/yellow]"))
                            time.sleep(1)
                            proc.kill()
                            timed_out = True
                            break

                        if now > deadline:
                            if now - last_output_time > PROGRESS_GRACE:
                                live.update(Text.from_markup("[yellow]Command stalled, terminating[/yellow]"))
                                time.sleep(1)
                                proc.kill()
                                timed_out = True
                                break
                            else:
                                deadline = min(now + MIN_EXTENSION, start + ABSOLUTE_MAX_TIMEOUT)

                    if not timed_out:
                        proc.wait(timeout=10)
                        remaining_err = proc.stderr.read()
                        if remaining_err:
                            stderr_parts.append(remaining_err)

                except KeyboardInterrupt:
                    live.update(Text.from_markup("[yellow]Interrupted by user[/yellow]"))
                    time.sleep(0.5)
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                    interrupted = True

            rc = proc.returncode if not interrupted else -2

        except FileNotFoundError:
            return ExecutionResult(
                command=command,
                stdout="",
                stderr=f"'{binary}' not found in PATH",
                return_code=127,
                duration_seconds=0.0,
                tool_name=tool_name,
                target=detected_target,
                blocked=True,
                block_reason=f"'{binary}' not found",
            )
        except Exception as e:
            return ExecutionResult(
                command=command,
                stdout="",
                stderr=f"Execution error: {str(e)}",
                return_code=-1,
                duration_seconds=0.0,
                tool_name=tool_name,
                target=detected_target,
                blocked=True,
                block_reason=str(e),
            )

        duration = time.monotonic() - start
        full_output = "".join(stdout_parts) + "".join(stderr_parts)

        if timed_out:
            console.print(f"[yellow]{binary} timed out[/yellow]")
            if full_output.strip():
                console.print(f"[dim](partial output saved, {len(full_output)} chars)[/dim]")

        output_path = None
        if full_output.strip():
            output_path = _save_output(binary, detected_target or "unknown", full_output)
            console.print(f"[dim]saved -> {output_path}[/dim]")

        if timed_out:
            console.print(f"[yellow][/yellow] [dim]{binary} timed out ({duration:.1f}s)[/dim]")
        elif interrupted:
            console.print(f"[yellow][/yellow] [dim]{binary} interrupted ({duration:.1f}s)[/dim]")
        elif rc == 0:
            console.print(f"[green][/green] [dim]{binary} finished in {duration:.1f}s[/dim]")
        else:
            console.print(f"[cyan][/cyan] [dim]{binary} finished with exit {rc} ({duration:.1f}s)[/dim]")

        if "sudo: a password is required" in full_output or "sudo: 3 incorrect password attempts" in full_output:
            console.print("[red]Sudo authentication failed[/red]")

        return ExecutionResult(
            command=command,
            stdout="".join(stdout_parts),
            stderr="".join(stderr_parts),
            return_code=-1 if timed_out else rc,
            duration_seconds=duration,
            tool_name=tool_name,
            target=detected_target,
            output_path=output_path,
            used_sudo=needs_sudo,
            interrupted=interrupted,
        )


def _dim(m: str) -> None:
    console.print(f"[dim]{m}[/dim]")
