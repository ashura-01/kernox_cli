"""
kernox.core.executor – Safe subprocess wrapper.

Handles three execution modes:
  1. Normal    – subprocess.Popen with optional spinner
  2. Streaming – live stdout line-by-line (raw on)
  3. PTY       – full pseudo-terminal for interactive tools (msfconsole, etc.)
"""

from __future__ import annotations

import os
import pty
import re
import select
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.live import Live
from rich.prompt import Confirm
from rich.spinner import Spinner

from kernox.config.config_store import ConfigStore
from kernox.guards.shell_sanitizer import sanitize, SUDO_TOOLS

console = Console()
TMP_OUTPUT_DIR = Path("/tmp/kernox")


# ── Helpers ───────────────────────────────────────────────────────────────────

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
    """Check if a binary is in PATH. Returns (found, install_hint)."""
    if shutil.which(binary):
        return True, None

    # Ask apt-cache for the package name
    try:
        r = subprocess.run(
            ["apt-cache", "search", "--names-only", binary],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0 and r.stdout.strip():
            pkg = r.stdout.strip().split("\n")[0].split(" ")[0]
            return False, f"sudo apt install {pkg}"
    except Exception:
        pass

    return False, f"sudo apt install {binary}"


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class ExecutionResult:
    command:          str
    stdout:           str
    stderr:           str
    return_code:      int
    duration_seconds: float
    tool_name:        str
    target:           str = ""
    output_path:      Optional[Path] = None
    blocked:          bool = False
    block_reason:     str = ""
    interrupted:      bool = False
    used_sudo:        bool = False


# ── Executor ──────────────────────────────────────────────────────────────────

class Executor:
    def __init__(self, config: ConfigStore) -> None:
        self._cfg = config

    def run(
        self,
        command:        str,
        *,
        tool_name:      str           = "unknown",
        target:         Optional[str] = None,
        timeout:        int           = 120,
        stream_output:  bool          = False,
        skip_confirm:   bool          = False,
        use_sudo:       Optional[bool] = None,
    ) -> ExecutionResult:

        # ── 1. Sanitize ───────────────────────────────────────────────────────
        san = sanitize(command, self._cfg)
        if not san.allowed:
            console.print(f"[red]✗ Blocked: {san.reason}[/red]")
            return _blocked(command, tool_name, target or "", san.reason)

        final_cmd  = san.command
        binary     = san.binary
        det_target = san.target or target or ""

        # ── 2. Tool installed? ────────────────────────────────────────────────
        # For sudo-prefixed commands, check the inner binary
        check_bin = binary
        if final_cmd.strip().startswith("sudo "):
            parts = shlex.split(final_cmd)
            check_bin = parts[1] if len(parts) > 1 else binary

        installed, hint = check_tool_installed(check_bin)
        if not installed:
            msg = f"[red]✗ '{check_bin}' not found.[/red]"
            if hint:
                msg += f"\n  [dim]Install:[/dim] [cyan]{hint}[/cyan]"
            console.print(msg)
            return _blocked(command, tool_name, det_target,
                            f"'{check_bin}' not installed")

        # ── 3. Sudo handling ──────────────────────────────────────────────────
        needs_sudo = san.needs_sudo if use_sudo is None else use_sudo

        # Don't double-prepend if already has sudo
        already_sudo = final_cmd.strip().startswith("sudo ")

        if needs_sudo and not already_sudo:
            if not skip_confirm:
                console.print(f"\n[bold cyan]⚠  '{binary}' typically needs root.[/bold cyan]")
                if Confirm.ask("  Run with sudo?", default=True):
                    final_cmd = f"sudo {final_cmd}"
                    already_sudo = True
            else:
                final_cmd = f"sudo {final_cmd}"
                already_sudo = True

        # ── 4. Raw output toggle ──────────────────────────────────────────────
        # Always respect the live config value — reads from SQLite each time
        if not stream_output:
            stream_output = self._cfg.get("show_raw_output") == "1"

        # ── 5. Confirmation ───────────────────────────────────────────────────
        console.print(f"\n[dim]$ {final_cmd}[/dim]")

        # ── 6. Execute ────────────────────────────────────────────────────────
        start = time.monotonic()

        if san.needs_pty:
            return self._run_pty(final_cmd, binary, det_target, tool_name, start)
        elif stream_output:
            return self._run_streaming(final_cmd, binary, det_target,
                                       tool_name, timeout, start, already_sudo)
        else:
            return self._run_normal(final_cmd, binary, det_target,
                                    tool_name, timeout, start, already_sudo)

    # ── Execution modes ───────────────────────────────────────────────────────

    def _run_normal(self, cmd, binary, target, tool_name, timeout, start,
                    used_sudo) -> ExecutionResult:
        stdout_buf, stderr_buf = [], []
        interrupted = False
        try:
            proc = subprocess.Popen(
                shlex.split(cmd),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                with Live(
                    Spinner("dots", text=f"[cyan]Running {binary}...[/cyan]"),
                    refresh_per_second=10,
                ):
                    out, err = proc.communicate(timeout=timeout)
                stdout_buf.append(out or "")
                stderr_buf.append(err or "")
            except KeyboardInterrupt:
                proc.terminate()
                try:
                    out, err = proc.communicate(timeout=5)
                    stdout_buf.append(out or "")
                    stderr_buf.append(err or "")
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate()
                interrupted = True
        except FileNotFoundError:
            return _blocked(cmd, tool_name, target, f"'{binary}' not in PATH")
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            return _timeout(cmd, tool_name, target, timeout)

        return self._finish(cmd, binary, target, tool_name, start,
                            "".join(stdout_buf), "".join(stderr_buf),
                            proc.returncode if not interrupted else -2,
                            interrupted, used_sudo)

    def _run_streaming(self, cmd, binary, target, tool_name, timeout, start,
                       used_sudo) -> ExecutionResult:
        stdout_buf, stderr_buf = [], []
        interrupted = False
        try:
            proc = subprocess.Popen(
                shlex.split(cmd),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                for line in proc.stdout:
                    console.print(line, end="")
                    stdout_buf.append(line)
                proc.wait(timeout=timeout)
                err = proc.stderr.read()
                if err:
                    stderr_buf.append(err)
            except KeyboardInterrupt:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                interrupted = True
        except FileNotFoundError:
            return _blocked(cmd, tool_name, target, f"'{binary}' not in PATH")

        return self._finish(cmd, binary, target, tool_name, start,
                            "".join(stdout_buf), "".join(stderr_buf),
                            proc.returncode if not interrupted else -2,
                            interrupted, used_sudo)

    def _run_pty(self, cmd, binary, target, tool_name, start) -> ExecutionResult:
        """Full PTY passthrough for interactive tools (msfconsole, etc.)."""
        console.print(
            f"[bold cyan]⚡ Launching {binary} in interactive mode[/bold cyan]\n"
            "[dim]Press Ctrl+C to exit back to kernox[/dim]\n"
        )
        buf = []
        try:
            master_fd, slave_fd = pty.openpty()
            proc = subprocess.Popen(
                shlex.split(cmd),
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
            )
            os.close(slave_fd)

            # Save terminal settings
            import tty, termios
            old_settings = termios.tcgetattr(sys.stdin.fileno())
            try:
                tty.setraw(sys.stdin.fileno())
                while proc.poll() is None:
                    r, _, _ = select.select([master_fd, sys.stdin], [], [], 0.05)
                    if master_fd in r:
                        try:
                            data = os.read(master_fd, 1024)
                            if data:
                                os.write(sys.stdout.fileno(), data)
                                buf.append(data.decode("utf-8", errors="replace"))
                        except OSError:
                            break
                    if sys.stdin in r:
                        data = os.read(sys.stdin.fileno(), 1024)
                        if data:
                            os.write(master_fd, data)
            finally:
                termios.tcsetattr(sys.stdin.fileno(),
                                  termios.TCSADRAIN, old_settings)
            os.close(master_fd)
        except KeyboardInterrupt:
            try:
                proc.terminate()
            except Exception:
                pass

        output = "".join(buf)
        duration = time.monotonic() - start
        output_path = None
        if output.strip():
            output_path = _save_output(binary, target or "interactive", output)
            console.print(f"\n[dim]saved → {output_path}[/dim]")

        console.print(f"\n[green]✓[/green] [dim]{binary} session ended ({duration:.1f}s)[/dim]")
        return ExecutionResult(
            command=cmd, stdout=output, stderr="",
            return_code=proc.returncode or 0,
            duration_seconds=duration,
            tool_name=tool_name, target=target or "",
            output_path=output_path,
        )

    def _finish(self, cmd, binary, target, tool_name, start,
                stdout, stderr, rc, interrupted, used_sudo) -> ExecutionResult:
        duration = time.monotonic() - start
        full_output = (stdout + stderr).strip()

        output_path = None
        if full_output:
            output_path = _save_output(binary, target or "unknown", full_output)
            console.print(f"[dim]saved → {output_path}[/dim]")

        if interrupted:
            console.print(f"[cyan]⚠[/cyan] [dim]{binary} interrupted ({duration:.1f}s)[/dim]")
        elif rc == 0:
            console.print(f"[green]✓[/green] [dim]{binary} finished in {duration:.1f}s[/dim]")
        else:
            console.print(f"[cyan]⚠[/cyan] [dim]{binary} exited {rc} ({duration:.1f}s)[/dim]")

        return ExecutionResult(
            command=cmd, stdout=stdout, stderr=stderr,
            return_code=rc, duration_seconds=duration,
            tool_name=tool_name, target=target or "",
            output_path=output_path,
            interrupted=interrupted, used_sudo=used_sudo,
        )


# ── Convenience constructors ──────────────────────────────────────────────────

def _blocked(cmd, tool_name, target, reason) -> ExecutionResult:
    return ExecutionResult(
        command=cmd, stdout="", stderr=reason,
        return_code=-1, duration_seconds=0.0,
        tool_name=tool_name, target=target,
        blocked=True, block_reason=reason,
    )


def _timeout(cmd, tool_name, target, timeout) -> ExecutionResult:
    return ExecutionResult(
        command=cmd, stdout="", stderr=f"Timed out after {timeout}s",
        return_code=-1, duration_seconds=float(timeout),
        tool_name=tool_name, target=target,
    )


def _dim(m: str) -> None:
    console.print(f"[dim]{m}[/dim]")
