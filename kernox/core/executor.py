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
import tty  # ADDED: Required for PTY operations
import termios  # ADDED: Required for terminal settings
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
    """Create temp directory with proper error handling."""
    try:
        TMP_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        console.print(f"[red]✗ Failed to create temp directory: {e}[/red]")
        raise


def _save_output(binary: str, target: str, output: str) -> Optional[Path]:
    """Save output to file with comprehensive error handling."""
    try:
        _ensure_tmp()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = re.sub(r"[^a-zA-Z0-9._-]", "_", target)[:40]
        filename = f"{binary}_{safe_target}_{ts}.txt"
        path = TMP_OUTPUT_DIR / filename
        
        # FIXED: Better error handling for encoding issues
        try:
            path.write_text(output, encoding="utf-8", errors="replace")
        except UnicodeEncodeError:
            # Fallback to ascii with replacement
            path.write_text(output, encoding="ascii", errors="replace")
        except OSError as e:
            console.print(f"[red]✗ Failed to write output file: {e}[/red]")
            return None
            
        return path
    except Exception as e:
        console.print(f"[red]✗ Unexpected error saving output: {e}[/red]")
        return None


def check_tool_installed(binary: str) -> tuple[bool, Optional[str]]:
    """Check if tool is installed with better error handling."""
    if not binary or not isinstance(binary, str):
        return False, "Invalid binary name"
        
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
    except subprocess.TimeoutExpired:
        pass
    except FileNotFoundError:
        # apt-cache not available (non-Debian system)
        pass
    except Exception:
        pass

    return False, f"sudo apt install {binary}"


def _prime_sudo() -> bool:
    """Initialize sudo session with better verification."""
    try:
        # Check if already have valid sudo session
        if subprocess.run(["sudo", "-n", "-v"], stdin=subprocess.DEVNULL, capture_output=True).returncode == 0:
            return True
    except Exception:
        pass

    # Not in a TTY
    if not sys.stdin.isatty():
        console.print("[red]✗ No TTY available — cannot prompt for sudo password.[/red]")
        return False

    console.print("\n[bold cyan]sudo password required[/bold cyan]")

    try:
        # Request password
        result = subprocess.run(
            ["sudo", "-v"],
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
        if result.returncode != 0:
            return False
    except Exception:
        return False

    # FIXED: More reliable verification instead of arbitrary sleep
    for _ in range(3):  # Try up to 3 times
        time.sleep(0.2)
        try:
            verify = subprocess.run(
                ["sudo", "-n", "-v"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=1,
            )
            if verify.returncode == 0:
                return True
        except subprocess.TimeoutExpired:
            continue
        except Exception:
            continue

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
        """Execute a command with comprehensive error handling."""
        
        # Validate inputs
        if not command or not isinstance(command, str):
            return _blocked(command, tool_name, target or "", "Invalid command")

        san = sanitize(command, self._cfg)
        if not san.allowed:
            console.print(f"[red]✗ Blocked: {san.reason}[/red]")
            return _blocked(command, tool_name, target or "", san.reason)

        final_cmd = san.command
        binary = san.binary
        det_target = san.target or target or ""

        # Handle potential None or empty binary
        if not binary:
            return _blocked(command, tool_name, det_target, "Could not determine binary name")

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

        try:
            if san.needs_pty:
                return self._run_pty(final_cmd, binary, det_target, tool_name, start)
            elif stream_output:
                return self._run_streaming(final_cmd, binary, det_target, tool_name, timeout, start, already_sudo)
            else:
                return self._run_normal(final_cmd, binary, det_target, tool_name, timeout, start, already_sudo)
        except Exception as e:
            console.print(f"[red]✗ Unexpected execution error: {e}[/red]")
            return ExecutionResult(
                command=final_cmd,
                stdout="",
                stderr=str(e),
                return_code=-1,
                duration_seconds=time.monotonic() - start,
                tool_name=tool_name,
                target=det_target,
                blocked=True,
                block_reason=f"Execution error: {str(e)}"
            )

    def _run_normal(self, cmd: str, binary: str, target: str, tool_name: str, 
                    timeout: int, start: float, used_sudo: bool) -> ExecutionResult:
        """Run command normally with timeout."""
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
                try:
                    proc.kill()
                    out, err = proc.communicate()
                    stdout_buf.append(out or "")
                    stderr_buf.append(err or "")
                except Exception:
                    pass
            return _timeout(cmd, tool_name, target, timeout)

        except KeyboardInterrupt:
            if proc:
                try:
                    proc.terminate()
                    out, err = proc.communicate()
                    stdout_buf.append(out or "")
                    stderr_buf.append(err or "")
                except Exception:
                    pass
            interrupted = True
        except Exception as e:
            return ExecutionResult(
                cmd, "", f"Execution error: {str(e)}", -1, 
                time.monotonic() - start, tool_name, target,
                blocked=True, block_reason=str(e)
            )

        rc = proc.returncode if proc is not None else -1

        return self._finish(cmd, binary, target, tool_name, start,
                            "".join(stdout_buf), "".join(stderr_buf),
                            rc, interrupted, used_sudo)

    def _run_streaming(self, cmd: str, binary: str, target: str, tool_name: str,
                      timeout: int, start: float, used_sudo: bool) -> ExecutionResult:
        """Run command with streaming output."""
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
                try:
                    proc.terminate()
                except Exception:
                    pass
            interrupted = True
        except Exception as e:
            return ExecutionResult(
                cmd, "", f"Streaming error: {str(e)}", -1,
                time.monotonic() - start, tool_name, target,
                blocked=True, block_reason=str(e)
            )

        rc = proc.returncode if proc is not None else -1

        return self._finish(cmd, binary, target, tool_name, start,
                            "".join(stdout_buf), "".join(stderr_buf),
                            rc, interrupted, used_sudo)

    def _run_pty(self, cmd: str, binary: str, target: str, tool_name: str, start: float) -> ExecutionResult:
        """Run command with PTY for interactive sessions."""
        console.print(f"[bold cyan]⚡ Launching {binary} in interactive mode[/bold cyan]\n")
        
        buf = []
        master_fd = -1
        slave_fd = -1
        proc = None
        old_settings = None

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
            slave_fd = -1  # Mark as closed

            # Save terminal settings
            old_settings = termios.tcgetattr(sys.stdin.fileno())
            tty.setraw(sys.stdin.fileno())

            while True:
                if proc.poll() is not None:
                    break
                    
                try:
                    r, _, _ = select.select([master_fd, sys.stdin], [], [], 0.05)

                    if master_fd in r:
                        try:
                            data = os.read(master_fd, 1024)
                            if data:
                                os.write(sys.stdout.fileno(), data)
                                buf.append(data.decode("utf-8", errors="replace"))
                        except (OSError, IOError):
                            break

                    if sys.stdin in r:
                        data = os.read(sys.stdin.fileno(), 1024)
                        if data:
                            os.write(master_fd, data)
                except select.error:
                    break

        except KeyboardInterrupt:
            console.print("\n[dim]Interrupted[/dim]")
        except Exception as e:
            console.print(f"[red]PTY error: {e}[/red]")
            return ExecutionResult(
                cmd, "", f"PTY error: {str(e)}", -1,
                time.monotonic() - start, tool_name, target,
                blocked=True, block_reason=str(e)
            )
        finally:
            # Restore terminal settings
            if old_settings is not None:
                try:
                    termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old_settings)
                except Exception:
                    pass
            
            # Clean up file descriptors
            if master_fd != -1:
                try:
                    os.close(master_fd)
                except Exception:
                    pass
            if slave_fd != -1:
                try:
                    os.close(slave_fd)
                except Exception:
                    pass

        output = "".join(buf)
        rc = proc.returncode if proc is not None else -1

        return ExecutionResult(
            command=cmd,
            stdout=output,
            stderr="",
            return_code=rc,
            duration_seconds=time.monotonic() - start,
            tool_name=tool_name,
            target=target or "",
        )

    def _finish(self, cmd: str, binary: str, target: str, tool_name: str, start: float,
                stdout: str, stderr: str, rc: int, interrupted: bool, used_sudo: bool) -> ExecutionResult:
        """Finish execution and save output."""
        duration = time.monotonic() - start
        full_output = (stdout + stderr).strip()

        output_path = None
        if full_output:
            output_path = _save_output(binary, target or "unknown", full_output)
            if output_path:
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


def _blocked(cmd: str, tool_name: str, target: str, reason: str) -> ExecutionResult:
    """Create blocked execution result."""
    return ExecutionResult(
        cmd if cmd else "", 
        "", 
        reason, 
        -1, 
        0.0, 
        tool_name, 
        target, 
        blocked=True, 
        block_reason=reason
    )


def _timeout(cmd: str, tool_name: str, target: str, timeout: int) -> ExecutionResult:
    """Create timeout execution result."""
    return ExecutionResult(
        cmd if cmd else "", 
        "", 
        f"Timed out after {timeout}s", 
        -1, 
        float(timeout), 
        tool_name, 
        target
    )