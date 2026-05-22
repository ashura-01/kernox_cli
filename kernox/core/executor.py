"""
kernox.core.executor – Safe subprocess wrapper.

Handles three execution modes:
  1. Normal    – subprocess.Popen with optional spinner
  2. Streaming – live stdout line-by-line (raw on)
  3. PTY       – full pseudo-terminal for interactive tools (msfconsole, etc.)
"""


from __future__ import annotations

import errno
import fcntl
import os
import pty
import re
import select
import shlex
import shutil
import signal
import subprocess
import sys
import termios
import time
import tty
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

import psutil
from rich.console import Console
from rich.live import Live
from rich.prompt import Confirm
from rich.spinner import Spinner

from kernox.config.config_store import ConfigStore
from kernox.guards.shell_sanitizer import sanitize

console = Console()
TMP_OUTPUT_DIR = Path("/tmp/kernox")

IDLE_TIMEOUT = 120
HARD_DEADLINE = 7200
PSUTIL_CHECK_INTERVAL = 2.0

TOOL_TIMEOUTS: dict[str, int] = {
    "nmap": 600,
    "masscan": 600,
    "msfconsole": 3600,
    "sqlmap": 900,
    "nikto": 1200,
    "hydra": 1800,
    "john": 3600,
    "hashcat": 3600,
    "aircrack-ng": 3600,
    "gobuster": 600,
    "ffuf": 600,
    "wfuzz": 600,
    "dirb": 600,
    "dirbuster": 600,
    "burpsuite": 3600,
    "metasploit": 3600,
    "setoolkit": 3600,
    "wpscan": 600,
    "enum4linux": 300,
    "smbclient": 300,
    "crackmapexec": 900,
    "impacket": 600,
}


def _ensure_tmp() -> None:
    try:
        TMP_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        console.print(f"[red]✗ Failed to create temp directory: {e}[/red]")
        raise


def _save_output(binary: str, target: str, output: str, tool_name: str = "") -> Optional[Path]:
    try:
        _ensure_tmp()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = re.sub(r"[^a-zA-Z0-9._-]", "_", target)[:40]
        # Use tool_name (the logical name passed by the caller) for the filename
        # so on_demand_analyzer can match it against state's tool_name field.
        # Fall back to binary only when tool_name is absent or generic.
        file_prefix = (tool_name.strip() or binary).lower()
        file_prefix = re.sub(r"[^a-zA-Z0-9._-]", "_", file_prefix)[:30]
        filename = f"{file_prefix}_{safe_target}_{ts}.txt"
        path = TMP_OUTPUT_DIR / filename
        try:
            path.write_text(output, encoding="utf-8", errors="replace")
        except UnicodeEncodeError:
            path.write_text(output, encoding="ascii", errors="replace")
        except OSError as e:
            console.print(f"[red]✗ Failed to write output file: {e}[/red]")
            return None
        return path
    except Exception as e:
        console.print(f"[red]✗ Unexpected error saving output: {e}[/red]")
        return None


def _resolve_binary(binary: str) -> Optional[str]:
    if not binary:
        return None
    candidate = Path(binary)
    if candidate.is_absolute() or binary.startswith("./") or binary.startswith("../"):
        resolved = candidate.resolve()
        if resolved.is_file() and os.access(resolved, os.X_OK):
            return str(resolved)
        return None
    found = shutil.which(binary)
    return found if found else None


def _resolve_idle_timeout(binary: str, cfg: ConfigStore) -> int:
    cfg_val = cfg.get(f"idle_timeout_{binary}")
    if cfg_val:
        try:
            return max(5, int(cfg_val))
        except (ValueError, TypeError):
            pass
    return IDLE_TIMEOUT


def _resolve_hard_deadline(binary: str, cfg: ConfigStore) -> int:
    cfg_val = cfg.get(f"hard_deadline_{binary}")
    if cfg_val:
        try:
            return max(30, int(cfg_val))
        except (ValueError, TypeError):
            pass
    tool_val = TOOL_TIMEOUTS.get(binary)
    if tool_val:
        return tool_val
    global_val = cfg.get("hard_deadline")
    if global_val:
        try:
            return max(30, int(global_val))
        except (ValueError, TypeError):
            pass
    return HARD_DEADLINE


def _is_process_active(pid: int) -> tuple[bool, str]:
    try:
        p = psutil.Process(pid)
        status = p.status()

        if status == psutil.STATUS_ZOMBIE:
            return False, "zombie"
        if status == psutil.STATUS_STOPPED:
            return False, "stopped"
        if status in (psutil.STATUS_RUNNING, psutil.STATUS_DISK_SLEEP):
            return True, status

        cpu = p.cpu_percent(interval=None)
        if cpu > 0.0:
            return True, f"sleeping/cpu={cpu:.1f}%"

        try:
            conns = p.connections()
            if conns:
                return True, f"sleeping/connections={len(conns)}"
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        try:
            children = p.children(recursive=True)
            for child in children:
                try:
                    cs = child.status()
                    if cs in (psutil.STATUS_RUNNING, psutil.STATUS_DISK_SLEEP):
                        return True, f"child_active/pid={child.pid}"
                    cc = child.cpu_percent(interval=None)
                    if cc > 0.0:
                        return True, f"child_cpu={cc:.1f}%"
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        return False, "sleeping/idle"

    except psutil.NoSuchProcess:
        return False, "no_such_process"
    except psutil.AccessDenied:
        return True, "access_denied/assume_active"
    except Exception:
        return True, "unknown/assume_active"


def _kill_process_tree(proc: subprocess.Popen) -> None:
    try:
        parent = psutil.Process(proc.pid)
        children = parent.children(recursive=True)
        for child in children:
            try:
                child.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        proc.kill()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        try:
            proc.kill()
        except Exception:
            pass
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def check_tool_installed(binary: str) -> tuple[bool, Optional[str]]:
    if not binary or not isinstance(binary, str):
        return False, "Invalid binary name"

    if _resolve_binary(binary):
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
        pass
    except Exception:
        pass

    return False, f"sudo apt install {binary}"


def _prime_sudo() -> bool:
    try:
        if subprocess.run(
            ["sudo", "-n", "-v"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
        ).returncode == 0:
            return True
    except Exception:
        pass

    if not sys.stdin.isatty():
        console.print("[red]✗ No TTY available — cannot prompt for sudo password.[/red]")
        return False

    console.print("\n[bold cyan]sudo password required[/bold cyan]")

    try:
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

    for _ in range(3):
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


def _set_nonblocking(fd: int) -> None:
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)


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
        if not command or not isinstance(command, str):
            return _blocked(command, tool_name, target or "", "Invalid command")

        san = sanitize(command, self._cfg)
        if not san.allowed:
            console.print(f"[red]✗ Blocked: {san.reason}[/red]")
            return _blocked(command, tool_name, target or "", san.reason)

        final_cmd = san.command
        binary = san.binary
        det_target = san.target or target or ""

        if not binary:
            return _blocked(command, tool_name, det_target, "Could not determine binary name")

        try:
            parts = shlex.split(final_cmd)
        except ValueError as e:
            return _blocked(command, tool_name, det_target, f"Invalid command syntax: {e}")

        already_sudo = bool(parts) and parts[0] == "sudo"
        check_bin = parts[1] if already_sudo and len(parts) > 1 else binary

        installed, hint = check_tool_installed(check_bin)
        if not installed:
            msg = f"{check_bin} not installed"
            if hint:
                msg += f" — {hint}"
            return _blocked(command, tool_name, det_target, msg)

        resolved = _resolve_binary(check_bin)
        if resolved and resolved != check_bin:
            if already_sudo:
                parts[1] = resolved
            else:
                parts[0] = resolved
            final_cmd = shlex.join(parts)

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

        idle_timeout = _resolve_idle_timeout(binary, self._cfg)
        hard_deadline = _resolve_hard_deadline(binary, self._cfg)

        console.print(f"\n[dim]$ {final_cmd}[/dim]")

        start = time.monotonic()

        try:
            if san.needs_pty:
                return self._run_pty(final_cmd, binary, det_target, tool_name, start, already_sudo, idle_timeout, hard_deadline)
            elif stream_output:
                return self._run_streaming(final_cmd, binary, det_target, tool_name, start, already_sudo, idle_timeout, hard_deadline)
            else:
                return self._run_normal(final_cmd, binary, det_target, tool_name, start, already_sudo, idle_timeout, hard_deadline)
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
                block_reason=f"Execution error: {str(e)}",
            )

    def _run_normal(
        self,
        cmd: str,
        binary: str,
        target: str,
        tool_name: str,
        start: float,
        used_sudo: bool,
        idle_timeout: int,
        hard_deadline: int,
    ) -> ExecutionResult:
        stdout_buf: list[str] = []
        stderr_buf: list[str] = []
        interrupted = False
        proc = None

        try:
            proc = subprocess.Popen(
                shlex.split(cmd),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            assert proc.stdout is not None
            assert proc.stderr is not None

            _set_nonblocking(proc.stdout.fileno())
            _set_nonblocking(proc.stderr.fileno())

            last_output_time = time.monotonic()
            last_psutil_check = time.monotonic()

            try:
                psutil_proc = psutil.Process(proc.pid)
                psutil_proc.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            while True:
                elapsed = time.monotonic() - start
                if elapsed >= hard_deadline:
                    _kill_process_tree(proc)
                    proc.communicate()
                    console.print(f"[red]✗ Hard deadline {hard_deadline}s reached[/red]")
                    return _timeout(cmd, tool_name, target, hard_deadline)

                fds = [proc.stdout, proc.stderr]
                try:
                    readable, _, _ = select.select(fds, [], fds, 0.5)
                except (select.error, ValueError):
                    break

                got_data = False
                for fd in readable:
                    try:
                        chunk = fd.read(65536)
                    except (IOError, OSError):
                        chunk = None
                    if chunk:
                        got_data = True
                        if fd is proc.stdout:
                            stdout_buf.append(chunk)
                        else:
                            stderr_buf.append(chunk)

                if got_data:
                    last_output_time = time.monotonic()

                if proc.poll() is not None:
                    for fd in (proc.stdout, proc.stderr):
                        try:
                            remainder = fd.read()
                            if remainder:
                                if fd is proc.stdout:
                                    stdout_buf.append(remainder)
                                else:
                                    stderr_buf.append(remainder)
                        except Exception:
                            pass
                    break

                idle_secs = time.monotonic() - last_output_time
                if idle_secs >= idle_timeout:
                    now = time.monotonic()
                    if now - last_psutil_check >= PSUTIL_CHECK_INTERVAL:
                        last_psutil_check = now
                        active, reason = _is_process_active(proc.pid)
                        if not active:
                            _kill_process_tree(proc)
                            proc.communicate()
                            console.print(f"[yellow]⚠ {binary} idle {idle_secs:.0f}s ({reason}), killed[/yellow]")
                            return _timeout(cmd, tool_name, target, idle_timeout)

        except KeyboardInterrupt:
            if proc:
                try:
                    proc.terminate()
                    out, err = proc.communicate(timeout=5)
                    stdout_buf.append(out or "")
                    stderr_buf.append(err or "")
                except Exception:
                    pass
            interrupted = True
        except Exception as e:
            return ExecutionResult(
                command=cmd,
                stdout="".join(stdout_buf),
                stderr=f"Execution error: {str(e)}",
                return_code=-1,
                duration_seconds=time.monotonic() - start,
                tool_name=tool_name,
                target=target,
                blocked=True,
                block_reason=str(e),
            )

        rc = proc.returncode if proc is not None else -1

        return self._finish(
            cmd, binary, target, tool_name, start,
            "".join(stdout_buf), "".join(stderr_buf),
            rc, interrupted, used_sudo,
        )

    def _run_streaming(
        self,
        cmd: str,
        binary: str,
        target: str,
        tool_name: str,
        start: float,
        used_sudo: bool,
        idle_timeout: int,
        hard_deadline: int,
    ) -> ExecutionResult:
        stdout_buf: list[str] = []
        stderr_buf: list[str] = []
        interrupted = False
        proc = None

        try:
            proc = subprocess.Popen(
                shlex.split(cmd),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            assert proc.stdout is not None
            assert proc.stderr is not None

            _set_nonblocking(proc.stdout.fileno())
            _set_nonblocking(proc.stderr.fileno())

            last_output_time = time.monotonic()
            last_psutil_check = time.monotonic()

            try:
                psutil_proc = psutil.Process(proc.pid)
                psutil_proc.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            while True:
                elapsed = time.monotonic() - start
                if elapsed >= hard_deadline:
                    _kill_process_tree(proc)
                    proc.communicate()
                    console.print(f"[red]✗ Hard deadline {hard_deadline}s reached[/red]")
                    return _timeout(cmd, tool_name, target, hard_deadline)

                fds = [proc.stdout, proc.stderr]
                try:
                    readable, _, _ = select.select(fds, [], fds, 0.5)
                except (select.error, ValueError):
                    break

                got_data = False
                for fd in readable:
                    try:
                        chunk = fd.read(65536)
                    except (IOError, OSError):
                        chunk = None
                    if chunk:
                        got_data = True
                        if fd is proc.stdout:
                            console.print(chunk, end="")
                            stdout_buf.append(chunk)
                        else:
                            stderr_buf.append(chunk)

                if got_data:
                    last_output_time = time.monotonic()

                if proc.poll() is not None:
                    for fd in (proc.stdout, proc.stderr):
                        try:
                            remainder = fd.read()
                            if remainder:
                                if fd is proc.stdout:
                                    console.print(remainder, end="")
                                    stdout_buf.append(remainder)
                                else:
                                    stderr_buf.append(remainder)
                        except Exception:
                            pass
                    break

                idle_secs = time.monotonic() - last_output_time
                if idle_secs >= idle_timeout:
                    now = time.monotonic()
                    if now - last_psutil_check >= PSUTIL_CHECK_INTERVAL:
                        last_psutil_check = now
                        active, reason = _is_process_active(proc.pid)
                        if not active:
                            _kill_process_tree(proc)
                            proc.communicate()
                            console.print(f"[yellow]⚠ {binary} idle {idle_secs:.0f}s ({reason}), killed[/yellow]")
                            return _timeout(cmd, tool_name, target, idle_timeout)

        except KeyboardInterrupt:
            if proc:
                try:
                    proc.terminate()
                    out, err = proc.communicate(timeout=5)
                    if out:
                        stdout_buf.append(out)
                    if err:
                        stderr_buf.append(err)
                except Exception:
                    pass
            interrupted = True
        except Exception as e:
            return ExecutionResult(
                command=cmd,
                stdout="".join(stdout_buf),
                stderr=f"Streaming error: {str(e)}",
                return_code=-1,
                duration_seconds=time.monotonic() - start,
                tool_name=tool_name,
                target=target,
                blocked=True,
                block_reason=str(e),
            )

        rc = proc.returncode if proc is not None else -1

        return self._finish(
            cmd, binary, target, tool_name, start,
            "".join(stdout_buf), "".join(stderr_buf),
            rc, interrupted, used_sudo,
        )

    def _run_pty(
        self,
        cmd: str,
        binary: str,
        target: str,
        tool_name: str,
        start: float,
        used_sudo: bool,
        idle_timeout: int,
        hard_deadline: int,
    ) -> ExecutionResult:
        console.print(f"[bold cyan]⚡ Launching {binary} in interactive mode[/bold cyan]\n")

        buf: list[str] = []
        master_fd = -1
        slave_fd = -1
        proc = None
        old_settings = None
        stdin_is_tty = sys.stdin.isatty()

        try:
            master_fd, slave_fd = pty.openpty()

            proc = subprocess.Popen(
                shlex.split(cmd),
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
                start_new_session=True,
            )
            os.close(slave_fd)
            slave_fd = -1

            _set_nonblocking(master_fd)

            if stdin_is_tty:
                old_settings = termios.tcgetattr(sys.stdin.fileno())
                tty.setraw(sys.stdin.fileno())

            stdin_fd = sys.stdin.fileno() if stdin_is_tty else -1
            read_fds = [master_fd] + ([stdin_fd] if stdin_is_tty else [])

            last_output_time = time.monotonic()
            last_psutil_check = time.monotonic()

            try:
                psutil_proc = psutil.Process(proc.pid)
                psutil_proc.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            while True:
                elapsed = time.monotonic() - start
                if elapsed >= hard_deadline:
                    _kill_process_tree(proc)
                    console.print(f"\n[red]✗ Hard deadline {hard_deadline}s reached[/red]")
                    break

                if proc.poll() is not None:
                    try:
                        while True:
                            data = os.read(master_fd, 4096)
                            if not data:
                                break
                            os.write(sys.stdout.fileno(), data)
                            buf.append(data.decode("utf-8", errors="replace"))
                    except (OSError, IOError):
                        pass
                    break

                try:
                    r, _, _ = select.select(read_fds, [], [], 0.05)
                except (select.error, ValueError):
                    break

                got_data = False

                if master_fd in r:
                    try:
                        data = os.read(master_fd, 4096)
                        if data:
                            got_data = True
                            os.write(sys.stdout.fileno(), data)
                            buf.append(data.decode("utf-8", errors="replace"))
                    except (OSError, IOError) as e:
                        if e.errno not in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EIO):
                            break

                if stdin_is_tty and stdin_fd in r:
                    try:
                        data = os.read(stdin_fd, 4096)
                        if data:
                            os.write(master_fd, data)
                    except (OSError, IOError) as e:
                        if e.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                            break

                if got_data:
                    last_output_time = time.monotonic()

                idle_secs = time.monotonic() - last_output_time
                if idle_secs >= idle_timeout:
                    now = time.monotonic()
                    if now - last_psutil_check >= PSUTIL_CHECK_INTERVAL:
                        last_psutil_check = now
                        active, reason = _is_process_active(proc.pid)
                        if not active:
                            _kill_process_tree(proc)
                            console.print(f"\n[yellow]⚠ {binary} idle {idle_secs:.0f}s ({reason}), killed[/yellow]")
                            break

        except KeyboardInterrupt:
            console.print("\n[dim]Interrupted[/dim]")
            if proc:
                try:
                    proc.send_signal(signal.SIGINT)
                except Exception:
                    pass
        except Exception as e:
            console.print(f"[red]PTY error: {e}[/red]")
            return ExecutionResult(
                command=cmd,
                stdout="".join(buf),
                stderr=f"PTY error: {str(e)}",
                return_code=-1,
                duration_seconds=time.monotonic() - start,
                tool_name=tool_name,
                target=target,
                blocked=True,
                block_reason=str(e),
            )
        finally:
            if old_settings is not None:
                try:
                    termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old_settings)
                except Exception:
                    pass
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

        if proc is not None:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

        rc = proc.returncode if proc is not None else -1

        return self._finish(
            cmd, binary, target, tool_name, start,
            "".join(buf), "",
            rc, False, used_sudo,
        )

    def _finish(
        self,
        cmd: str,
        binary: str,
        target: str,
        tool_name: str,
        start: float,
        stdout: str,
        stderr: str,
        rc: int,
        interrupted: bool,
        used_sudo: bool,
    ) -> ExecutionResult:
        duration = time.monotonic() - start
        full_output = (stdout + stderr).strip()

        output_path = None
        if full_output:
            output_path = _save_output(binary, target or "unknown", full_output, tool_name=tool_name)
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
    return ExecutionResult(
        command=cmd if cmd else "",
        stdout="",
        stderr=reason,
        return_code=-1,
        duration_seconds=0.0,
        tool_name=tool_name,
        target=target,
        blocked=True,
        block_reason=reason,
    )


def _timeout(cmd: str, tool_name: str, target: str, timeout: int) -> ExecutionResult:
    return ExecutionResult(
        command=cmd if cmd else "",
        stdout="",
        stderr=f"Timed out after {timeout}s",
        return_code=-1,
        duration_seconds=float(timeout),
        tool_name=tool_name,
        target=target,
    )
