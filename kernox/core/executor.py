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
        r = subprocess.run(
            ["apt-cache", "search", "--names-only", binary],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if r.returncode == 0 and r.stdout.strip():
            pkg = r.stdout.strip().split("\n")[0].split(" ")[0]
            return False, f"sudo apt install {pkg}"
    except Exception:
        pass

    return False, f"sudo apt install {binary}"


def _prime_sudo() -> bool:
    try:
        if subprocess.run(["sudo", "-n", "-v"], stdin=subprocess.DEVNULL, capture_output=True).returncode == 0:
            return True
    except Exception:
        pass

    if not sys.stdin.isatty():
        console.print("[red]✗ No TTY available — cannot prompt for sudo password.[/red]")
        return False

    console.print("\n[bold cyan] sudo password required[/bold cyan]")

    try:
        result = subprocess.run(
            ["sudo", "-v"],
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
    except Exception:
        return False

    if result.returncode != 0:
        return False

    time.sleep(0.1)

    try:
        verify = subprocess.run(
            ["sudo", "-n", "-v"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
        )
        return verify.returncode == 0
    except Exception:
        return False


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
        timeout: int = 120,
        stream_output: bool = False,
        skip_confirm: bool = False,
        use_sudo: Optional[bool] = None,
    ) -> ExecutionResult:

        san = sanitize(command, self._cfg)
        if not san.allowed:
            console.print(f"[red]✗ Blocked: {san.reason}[/red]")
            return _blocked(command, tool_name, target or "", san.reason)

        final_cmd = san.command
        binary = san.binary
        det_target = san.target or target or ""

        parts = shlex.split(final_cmd) if final_cmd else []
        already_sudo = bool(parts) and parts[0] == "sudo"

        check_bin = parts[1] if already_sudo and len(parts) > 1 else binary

        installed, hint = check_tool_installed(check_bin)
        if not installed:
            return _blocked(command, tool_name, det_target, f"{check_bin} not installed")

        needs_sudo = san.needs_sudo if use_sudo is None else use_sudo

        if needs_sudo and not already_sudo:
            if not skip_confirm:
                console.print(f"\n[bold cyan]⚠  '{binary}' typically needs root.[/bold cyan]")
                if Confirm.ask("  Run with sudo?", default=True):
                    final_cmd = f"sudo {final_cmd}"
                    already_sudo = True
            else:
                final_cmd = f"sudo {final_cmd}"
                already_sudo = True

        if already_sudo and not san.needs_pty:
            if not _prime_sudo():
                return _blocked(command, tool_name, det_target, "sudo authentication failed")

        if not stream_output:
            stream_output = self._cfg.get("show_raw_output") == "1"

        console.print(f"\n[dim]$ {final_cmd}[/dim]")

        start = time.monotonic()

        if san.needs_pty:
            return self._run_pty(final_cmd, binary, det_target, tool_name, start)
        elif stream_output:
            return self._run_streaming(final_cmd, binary, det_target, tool_name, timeout, start, already_sudo)
        else:
            return self._run_normal(final_cmd, binary, det_target, tool_name, timeout, start, already_sudo)

    def _run_normal(self, cmd, binary, target, tool_name, timeout, start, used_sudo):
        stdout_buf, stderr_buf = [], []
        interrupted = False
        proc = None

        try:
            proc = subprocess.Popen(
                shlex.split(cmd),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            out, err = proc.communicate(timeout=timeout)
            stdout_buf.append(out or "")
            stderr_buf.append(err or "")

        except subprocess.TimeoutExpired:
            if proc:
                proc.kill()
                out, err = proc.communicate()
                stdout_buf.append(out or "")
                stderr_buf.append(err or "")
            return _timeout(cmd, tool_name, target, timeout)

        except KeyboardInterrupt:
            if proc:
                proc.terminate()
                out, err = proc.communicate()
                stdout_buf.append(out or "")
                stderr_buf.append(err or "")
            interrupted = True

        rc = proc.returncode if proc else -1

        return self._finish(cmd, binary, target, tool_name, start,
                            "".join(stdout_buf), "".join(stderr_buf),
                            rc, interrupted, used_sudo)

    def _run_streaming(self, cmd, binary, target, tool_name, timeout, start, used_sudo):
        stdout_buf, stderr_buf = [], []
        proc = None
        interrupted = False

        try:
            proc = subprocess.Popen(
                shlex.split(cmd),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            start_t = time.time()

            while True:
                if proc.stdout:
                    line = proc.stdout.readline()
                    if line:
                        console.print(line, end="")
                        stdout_buf.append(line)

                if proc.poll() is not None:
                    break

                if time.time() - start_t > timeout:
                    proc.kill()
                    return _timeout(cmd, tool_name, target, timeout)

        except KeyboardInterrupt:
            if proc:
                proc.terminate()
            interrupted = True

        rc = proc.returncode if proc else -1

        return self._finish(cmd, binary, target, tool_name, start,
                            "".join(stdout_buf), "".join(stderr_buf),
                            rc, interrupted, used_sudo)

    def _run_pty(self, cmd, binary, target, tool_name, start):
        console.print(f"[bold cyan]⚡ Launching {binary} in interactive mode[/bold cyan]\n")
        buf = []
        master_fd, slave_fd = pty.openpty()

        proc = subprocess.Popen(
            shlex.split(cmd),
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
        )
        os.close(slave_fd)

        import tty, termios
        old_settings = termios.tcgetattr(sys.stdin.fileno())

        try:
            tty.setraw(sys.stdin.fileno())

            while proc.poll() is None:
                r, _, _ = select.select([master_fd, sys.stdin], [], [], 0.05)

                if master_fd in r:
                    data = os.read(master_fd, 1024)
                    if data:
                        os.write(sys.stdout.fileno(), data)
                        buf.append(data.decode("utf-8", errors="replace"))

                if sys.stdin in r:
                    data = os.read(sys.stdin.fileno(), 1024)
                    if data:
                        os.write(master_fd, data)

        finally:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old_settings)
            os.close(master_fd)

        output = "".join(buf)

        return ExecutionResult(
            command=cmd,
            stdout=output,
            stderr="",
            return_code=proc.returncode or 0,
            duration_seconds=time.monotonic() - start,
            tool_name=tool_name,
            target=target or "",
        )

    def _finish(self, cmd, binary, target, tool_name, start,
                stdout, stderr, rc, interrupted, used_sudo):

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
            command=cmd,
            stdout=stdout,
            stderr=stderr,
            return_code=rc,
            duration_seconds=duration,
            tool_name=tool_name,
            target=target or "",
            output_path=output_path,
            interrupted=interrupted,
            used_sudo=used_sudo,
        )


def _blocked(cmd, tool_name, target, reason):
    return ExecutionResult(cmd, "", reason, -1, 0.0, tool_name, target, blocked=True, block_reason=reason)


def _timeout(cmd, tool_name, target, timeout):
    return ExecutionResult(cmd, "", f"Timed out after {timeout}s", -1, float(timeout), tool_name, target)
