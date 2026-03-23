"""
kernox.tools.privesc  –  Linux Privilege Escalation Enumeration.

Runs all checks locally on the target system (SSH session or direct).
All checks are read-only — no exploitation, just enumeration.
"""

from __future__ import annotations

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich import box
from rich.table import Table

from kernox.parsers.privesc_parser import PrivescParser

console = Console()

# GTFOBins — common SUID binaries with known privesc
GTFOBINS = {
    "nmap", "vim", "vi", "nano", "find", "bash", "sh", "more", "less",
    "man", "awk", "gawk", "python", "python3", "ruby", "perl", "lua",
    "php", "node", "tar", "cp", "mv", "cat", "tee", "env", "time",
    "watch", "strace", "ltrace", "dd", "xxd", "base64", "openssl",
    "curl", "wget", "git", "zip", "unzip", "7z", "scp", "rsync",
    "ftp", "ssh", "nc", "netcat", "ncat", "socat", "screen", "tmux",
    "mysql", "sqlite3", "psql", "ftp", "tftp", "aria2c",
    "apt", "apt-get", "pip", "pip3", "gem", "npm",
    "docker", "lxc", "runc", "podman",
    "journalctl", "systemctl", "service",
    "passwd", "chsh", "chfn", "su", "sudo",
    "pkexec", "dbus-send", "gdbus",
    "taskset", "ionice", "nice",
    "xargs", "tclsh", "expect",
    "gcc", "cc", "make",
    "busybox", "ash", "dash", "zsh", "ksh",
}

# All checks bundled into one script to minimize shell calls
PRIVESC_SCRIPT = """
echo "=== KERNEL ==="
uname -a
cat /proc/version 2>/dev/null
cat /etc/issue 2>/dev/null
cat /etc/*release 2>/dev/null | head -5

echo "=== CURRENT USER ==="
id
whoami
sudo -l 2>/dev/null

echo "=== SUID BINARIES ==="
find / -perm -u=s -type f 2>/dev/null

echo "=== SGID BINARIES ==="
find / -perm -g=s -type f 2>/dev/null

echo "=== CAPABILITIES ==="
getcap -r / 2>/dev/null

echo "=== WRITABLE PASSWD ==="
ls -la /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null

echo "=== CRON JOBS ==="
cat /etc/crontab 2>/dev/null
ls -la /etc/cron* 2>/dev/null
crontab -l 2>/dev/null
ls -la /var/spool/cron 2>/dev/null
find /etc/cron* /var/spool/cron -type f 2>/dev/null -exec ls -la {} \\;

echo "=== WRITABLE CRON SCRIPTS ==="
find /etc/cron* /var/spool/cron -type f 2>/dev/null | xargs ls -la 2>/dev/null

echo "=== NFS ==="
cat /etc/exports 2>/dev/null
showmount -e localhost 2>/dev/null

echo "=== PATH ==="
echo $PATH
find / -writable -type d 2>/dev/null | grep -v proc | grep -v sys | head -20

echo "=== WRITABLE FILES IN PATH ==="
echo $PATH | tr ':' '\\n' | while read dir; do find "$dir" -writable -type f 2>/dev/null; done

echo "=== SENSITIVE FILES ==="
find / -name "*.conf" -o -name "*.config" -o -name "*.cfg" 2>/dev/null | xargs grep -l "password\\|passwd\\|secret\\|key\\|token" 2>/dev/null | head -10
find / -name "id_rsa" -o -name "id_dsa" -o -name "*.pem" 2>/dev/null 2>/dev/null | head -10
find / -name ".bash_history" -o -name ".mysql_history" -o -name ".psql_history" 2>/dev/null | head -5

echo "=== INTERESTING FILES ==="
find / -perm -o=w -type f 2>/dev/null | grep -v proc | grep -v sys | head -20
find / -name "flag*" -o -name "*.txt" -perm -o=r 2>/dev/null | grep -v proc | head -10

echo "=== NETWORK ==="
ifconfig 2>/dev/null || ip a 2>/dev/null
netstat -tlnp 2>/dev/null || ss -tlnp 2>/dev/null
cat /etc/hosts 2>/dev/null

echo "=== PROCESSES ==="
ps aux 2>/dev/null

echo "=== INSTALLED TOOLS ==="
which gcc python python3 perl ruby php nc netcat wget curl nmap 2>/dev/null

echo "=== DONE ==="
"""


class PrivescTool:
    name = "privesc"

    def build_command(
        self,
        target: str = "",
        mode: str = "",
        ssh_user: str = "",
        ssh_host: str = "",
        **kwargs,
    ) -> str:
        mode = mode or self._pick_mode()
        return self._build_from_mode(mode, target, ssh_user, ssh_host)

    def _pick_mode(self) -> str:
        console.print("\n[bold cyan]PrivEsc Enumeration Mode[/bold cyan]\n")
        console.print("  [green]1[/green] – quick  (SUID + sudo + caps only, fast)")
        console.print("  [green]2[/green] – full   (all 8 checks, thorough)\n")
        choice = Prompt.ask("Select mode", choices=["1", "2"], default="2")
        return {"1": "quick", "2": "full"}[choice]

    def _build_from_mode(
        self,
        mode: str,
        target: str,
        ssh_user: str,
        ssh_host: str,
    ) -> str:
        import tempfile, os, subprocess, shutil

        script = PRIVESC_SCRIPT if mode != "quick" else """
echo "=== CURRENT USER ===" && id && whoami
echo "=== SUDO ===" && sudo -l 2>/dev/null
echo "=== SUID ===" && find / -perm -u=s -type f 2>/dev/null
echo "=== CAPABILITIES ===" && getcap -r / 2>/dev/null
echo "=== WRITABLE PASSWD ===" && ls -la /etc/passwd /etc/shadow 2>/dev/null
"""
        # Always ask credentials
        ssh_host = ssh_host or Prompt.ask("\n[bold cyan]SSH host/IP[/bold cyan]")
        ssh_user = ssh_user or Prompt.ask("[bold cyan]SSH username[/bold cyan]")

        # Ask auth method
        console.print("\n[bold cyan]Authentication method:[/bold cyan]")
        console.print("  [green]1[/green] – Password")
        console.print("  [green]2[/green] – SSH key file\n")
        auth_choice = Prompt.ask("Select", choices=["1","2"], default="1")

        key_flag = ""
        password = ""

        if auth_choice == "2":
            ssh_key = Prompt.ask("SSH key path", default="~/.ssh/id_rsa")
            key_flag = f"-i {ssh_key}"
        else:
            from kernox.utils.secure_input import secure_prompt
            password = secure_prompt(f"Password for {ssh_user}@{ssh_host}") or ""

        console.print(
            f"\n[dim]Connecting to [cyan]{ssh_user}@{ssh_host}[/cyan]...[/dim]\n"
        )

        # Write script to temp file
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".sh", delete=False, prefix="kernox_privesc_"
        )
        tmp.write(script)
        tmp.close()

        output_file = "/tmp/kernox_privesc_output.txt"

        if auth_choice == "1" and password:
            # Use sshpass if available for non-interactive password auth
            if shutil.which("sshpass"):
                ssh_cmd = (
                    f"sshpass -p '{password}' ssh "
                    f"-o StrictHostKeyChecking=no -o ConnectTimeout=10 "
                    f"{ssh_user}@{ssh_host} 'bash -s' < {tmp.name}"
                )
                console.print("[dim]Using sshpass for authentication...[/dim]")
            else:
                # sshpass not available — use SSH with password via expect-like approach
                console.print(
                    "[yellow]⚠ sshpass not found. Install it for better experience:[/yellow]\n"
                    "[cyan]  sudo apt install sshpass[/cyan]\n\n"
                    "[dim]Falling back to interactive SSH — enter password when prompted:[/dim]\n"
                )
                # Write a temporary expect-like wrapper
                expect_script = f"""#!/usr/bin/expect -f
set timeout 30
spawn ssh -o StrictHostKeyChecking=no {ssh_user}@{ssh_host} bash -s
expect {{
    "password:" {{ send "{password}\\r" }}
    "yes/no"   {{ send "yes\\r"; exp_continue }}
}}
interact
"""
                if shutil.which("expect"):
                    exp_tmp = tempfile.NamedTemporaryFile(
                        mode="w", suffix=".exp", delete=False, prefix="kernox_expect_"
                    )
                    exp_tmp.write(expect_script)
                    exp_tmp.close()
                    os.chmod(exp_tmp.name, 0o700)
                    ssh_cmd = f"{exp_tmp.name} < {tmp.name}"
                else:
                    # Last resort — interactive, password prompt visible
                    console.print("[dim]Enter password at the SSH prompt below:[/dim]\n")
                    os.system(
                        f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "
                        f"{ssh_user}@{ssh_host} 'bash -s' < {tmp.name} "
                        f"> {output_file}"
                    )
                    try:
                        with open(output_file) as f:
                            output = f.read()
                    except Exception:
                        output = ""
                    os.unlink(tmp.name)
                    return f"__PRIVESC_SSH_DONE__:{output}"
        else:
            ssh_cmd = (
                f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "
                f"{key_flag} {ssh_user}@{ssh_host} 'bash -s' < {tmp.name}"
            )

        # Run and capture output
        try:
            result = subprocess.run(
                ssh_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=120,
            )
            output = result.stdout
            if result.returncode != 0 and not output:
                console.print(f"[red]SSH failed: {result.stderr[:200]}[/red]")
                output = result.stderr
        except subprocess.TimeoutExpired:
            console.print("[red]SSH connection timed out[/red]")
            output = ""
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            output = ""

        try:
            os.unlink(tmp.name)
        except Exception:
            pass

        return f"__PRIVESC_SSH_DONE__:{output}"

    def parse(self, output: str) -> dict:
        return PrivescParser().parse(output)
