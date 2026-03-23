"""
kernox.core.analyse_mode  –  Paste & analyse reverse shell / privesc output.

When you have a reverse shell (nc -lnvp 4444) on an authorized CTF/lab target,
you can run commands manually on the target, paste the output here, and Kernox
will analyse it for privilege escalation paths — same as LinPEAS but interactive.
"""

from __future__ import annotations

import sys
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich import box
from rich.table import Table

from kernox.parsers.privesc_parser import PrivescParser
from kernox.utils.privesc_formatter import format_privesc

console = Console()

# Commands to copy-paste into your reverse shell
ENUM_COMMANDS = {
    "quick": """id && whoami && hostname
sudo -l 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
getcap -r / 2>/dev/null
ls -la /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null
cat /etc/crontab 2>/dev/null""",

    "full": """echo "=== KERNEL ===" && uname -a && cat /proc/version 2>/dev/null && cat /etc/issue 2>/dev/null
echo "=== CURRENT USER ===" && id && whoami && sudo -l 2>/dev/null
echo "=== SUID BINARIES ===" && find / -perm -u=s -type f 2>/dev/null
echo "=== SGID BINARIES ===" && find / -perm -g=s -type f 2>/dev/null
echo "=== CAPABILITIES ===" && getcap -r / 2>/dev/null
echo "=== WRITABLE PASSWD ===" && ls -la /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null
echo "=== CRON JOBS ===" && cat /etc/crontab 2>/dev/null && ls -la /etc/cron* 2>/dev/null
echo "=== NFS ===" && cat /etc/exports 2>/dev/null
echo "=== PATH ===" && echo $PATH && find / -writable -type d 2>/dev/null | grep -v proc | grep -v sys | head -20
echo "=== SENSITIVE FILES ===" && find / -name "id_rsa" -o -name "id_dsa" 2>/dev/null | head -5 && find / -name ".bash_history" 2>/dev/null | head -3
echo "=== INSTALLED TOOLS ===" && which gcc python python3 perl ruby php nc wget curl 2>/dev/null
echo "=== NETWORK ===" && ip a 2>/dev/null || ifconfig 2>/dev/null && ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null
echo "=== PROCESSES ===" && ps aux 2>/dev/null
echo "=== DONE ===" """,
}


def run_analyse_mode() -> None:
    """Interactive paste-and-analyse mode for reverse shell output."""
    console.print(Panel(
        "[bold cyan]Reverse Shell PrivEsc Analyser[/bold cyan]\n\n"
        "[dim]You have a reverse shell on an authorized target.\n"
        "Copy the enumeration commands, run them on the target,\n"
        "paste the output here, and Kernox will analyse it.[/dim]",
        border_style="cyan",
        box=box.ROUNDED,
    ))

    # Step 1 — Show commands to run
    console.print("\n[bold]Step 1 — Choose enumeration depth:[/bold]")
    console.print("  [green]1[/green] – Quick  (fast, key checks only)")
    console.print("  [green]2[/green] – Full   (thorough, all checks)\n")
    depth = Prompt.ask("Select", choices=["1","2"], default="2")
    mode = "quick" if depth == "1" else "full"

    console.print(Panel(
        f"[bold yellow]Copy and paste this into your reverse shell:[/bold yellow]\n\n"
        f"[cyan]{ENUM_COMMANDS[mode]}[/cyan]",
        title="[bold]Commands to run on target[/bold]",
        border_style="yellow",
        box=box.ROUNDED,
    ))

    console.print(
        "\n[bold]Step 2 — Paste the output below.[/bold]\n"
        "[dim]Type or paste all output, then type [bold]END[/bold] on a new line and press Enter.[/dim]\n"
    )

    # Collect pasted output
    lines = []
    while True:
        try:
            line = input()
            if line.strip().upper() == "END":
                break
            lines.append(line)
        except EOFError:
            break

    raw_output = "\n".join(lines)

    if not raw_output.strip():
        console.print("[red]No output pasted. Exiting analyse mode.[/red]")
        return

    console.print(f"\n[dim]Received {len(lines)} lines of output. Analysing...[/dim]\n")

    # Parse and display
    parser = PrivescParser()
    parsed = parser.parse(raw_output)

    # Display full analysis
    format_privesc(parsed)

    # Export option
    if parsed.get("juicy_points"):
        if Confirm.ask("\nExport findings to file?", default=False):
            _export_findings(parsed)


def _export_findings(parsed: dict) -> None:
    """Export privesc findings to a text file."""
    import json
    from datetime import datetime

    filename = f"/tmp/kernox_privesc_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    with open(filename, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("KERNOX PRIVESC ANALYSIS REPORT\n")
        f.write("=" * 60 + "\n\n")

        f.write(f"Kernel: {parsed.get('kernel_version','?')}\n")
        f.write(f"Total findings: {parsed.get('total',0)}\n")
        f.write(f"Critical: {parsed.get('critical',0)}\n")
        f.write(f"High: {parsed.get('high',0)}\n\n")

        f.write("JUICY POINTS:\n")
        f.write("-" * 40 + "\n")
        for j in parsed.get("juicy_points", []):
            f.write(f"\n[{j['severity'].upper()}] {j['title']}\n")
            f.write(f"  Category: {j['category']}\n")
            if j.get("path"):
                f.write(f"  Path: {j['path']}\n")
            f.write(f"  Detail: {j['detail']}\n")
            if j.get("exploit_hint"):
                f.write(f"  Hint: {j['exploit_hint']}\n")

        f.write("\n\nALL FINDINGS:\n")
        f.write("-" * 40 + "\n")
        for finding in parsed.get("findings", []):
            f.write(f"\n[{finding['severity'].upper()}] {finding['title']}\n")
            f.write(f"  {finding['detail']}\n")
            if finding.get("juicy_path"):
                f.write(f"  Path: {finding['juicy_path']}\n")
            if finding.get("exploit_hint"):
                f.write(f"  Hint: {finding['exploit_hint']}\n")

    console.print(f"[green]✓ Report saved to:[/green] [cyan]{filename}[/cyan]")
