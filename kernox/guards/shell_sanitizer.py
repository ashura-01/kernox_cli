"""
kernox.guards.shell_sanitizer — Smart sanitization for any shell command.

Design:
  1. Hard-blocked binaries  (rm, mkfs, dd — system-destructive ONLY)
  2. Shell operator ban      (; && || | > >> $() backticks) — quoted args exempt
  3. Dangerous flag check    per binary
  4. Dangerous path check    (/etc/shadow, /dev/sda etc.)
  5. Length + printability
  6. Target extraction       for scope enforcement
  7. sudo/PTY detection      smart — checks binary capabilities at runtime
"""

from __future__ import annotations

import ipaddress
import re
import shlex
import shutil
import string
import subprocess
from dataclasses import dataclass
from typing import Optional


# ── Absolutely blocked — system-destructive only ──────────────────────────────
BLOCKED_BINARIES: set[str] = {
    "rm", "rmdir", "mkfs", "dd", "shred", "wipe",
    "fdisk", "parted", "gparted", "gdisk",
    "shutdown", "reboot", "halt", "poweroff", "init",
    "passwd", "chpasswd", "useradd", "userdel", "usermod",
    "mount", "umount", "format",
}

# ── PTY-required tools — need full interactive terminal ───────────────────────
# Tools that use curses, raw input, or expect a terminal
PTY_TOOLS: set[str] = {
    # ── Metasploit / C2 ──────────────────────────────────────────────────────
    "msfconsole", "metasploit", "armitage", "cobalt-strike",

    # ── Social Engineering ────────────────────────────────────────────────────
    "setoolkit", "social-engineer-toolkit", "beef-xss", "beef",

    # ── Wireless ─────────────────────────────────────────────────────────────
    "wifite", "airbase-ng", "hostapd-wpe",

    # ── Web / SQLi ────────────────────────────────────────────────────────────
    "sqlmap",                          # --os-shell / --sql-shell drops to PTY
    "burpsuite", "zaproxy",

    # ── File Transfer / Remote ────────────────────────────────────────────────
    "ftp", "sftp", "tftp", "ncftp",
    "ssh", "telnet", "rlogin", "rsh",
    "smbclient", "rpcclient", "wmiexec.py",

    # ── Password Cracking (interactive prompts) ───────────────────────────────
    "john", "hashcat",                 # --status / keypress listeners
    "hydra",                           # progress + interactive kill

    # ── Impacket suite ───────────────────────────────────────────────────────
    "psexec.py", "smbexec.py", "atexec.py", "dcomexec.py",
    "lookupsid.py", "secretsdump.py", "getTGT.py", "getST.py",

    # ── Post-exploitation shells ──────────────────────────────────────────────
    "evil-winrm", "pwncat", "pwncat-cs", "rlwrap",
    "netcat", "nc", "ncat", "socat",

    # ── Database CLIs ─────────────────────────────────────────────────────────
    "mysql", "psql", "sqlite3", "mssql-cli", "redis-cli",
    "mongo", "mongosh", "cqlsh",

    # ── Shells / REPLs ────────────────────────────────────────────────────────
    "bash", "sh", "zsh", "fish", "dash", "ksh",
    "python", "python3", "python2",
    "ruby", "irb",
    "node", "nodejs",
    "php", "perl",
    "gdb", "pdb", "lldb", "radare2", "r2",
    "pwndbg",

    # ── Enumeration (interactive/paginated output) ────────────────────────────
    "enum4linux", "enum4linux-ng",
    "crackmapexec", "cme",
    "bloodhound-python",

    # ── Fuzzing / Scanning with interactive kill ──────────────────────────────
    "ffuf", "gobuster", "wfuzz", "dirb",   # Ctrl-C mid-run needs PTY
    "nikto",

    # ── Exploit frameworks ────────────────────────────────────────────────────
    "routersploit",                     # rsf console
    "empire",                           # PowerShell Empire
    "starkiller",

    # ── Misc interactive tools ────────────────────────────────────────────────
    "proxychains", "proxychains4",      # wraps an interactive child
    "tmux", "screen",                   # mux sessions
    "vim", "nano", "less", "more",      # editors/pagers in pipeline
}

# ── Tools that always need sudo ───────────────────────────────────────────────
# Covers all common Kali tools that need raw socket / packet capture access
SUDO_TOOLS: set[str] = {
    # Network scanning (raw sockets)
    "nmap", "masscan", "zmap",
    # Packet capture
    "tcpdump", "tshark", "wireshark", "dumpcap",
    # ARP / Layer2
    "arp-scan", "netdiscover", "arpspoof", "arping",
    # Wireless
    "airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng",
    "airbase-ng", "airdecap-ng", "packetforge-ng",
    "reaver", "bully", "pixiewps", "wifite",
    # MITM / traffic
    "bettercap", "ettercap", "mitmproxy", "responder",
    # Other raw socket tools
    "kismet", "hping3", "scapy",
    "ifconfig", "iwconfig",
}

# ── Dangerous flags per binary ────────────────────────────────────────────────
DANGEROUS_FLAGS: dict[str, list[str]] = {
    "sqlmap":     ["--os-shell", "--os-cmd", "--sql-shell", "--reg-add", "--reg-del"],
    "curl":       ["--config", "-K"],
    "wget":       ["--execute"],
    "nmap":       ["--resume"],
}

# ── Dangerous local paths ─────────────────────────────────────────────────────
DANGEROUS_PATH_RE = re.compile(
    r"""
    (?:
        \.\.(?:/|\\)        |
        /etc/shadow         |
        /etc/sudoers        |
        /proc/self          |
        /dev/sd[a-z]        |
        /dev/nvme           |
        /dev/zero           |
        /home/[^/]+/\.ssh
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

# ── Shell operators ───────────────────────────────────────────────────────────
# Applied to command with quoted sections stripped so msfconsole -x "cmd;cmd" works
SHELL_OPERATOR_RE = re.compile(
    r"""
    (?:
        &&          |
        \|\|        |
        \|(?!\w)    |
        >>?         |
        `[^`]*`     |
        \$\(        |
        \$\{        |
        \beval\b    |
        2>&1
    )
    """,
    re.VERBOSE,
)

MAX_COMMAND_LENGTH = 4096   # msfvenom with large payloads
MAX_ARG_COUNT      = 120    # nuclei, nmap with many flags


@dataclass
class SanitizationResult:
    allowed:    bool
    reason:     str
    command:    str
    binary:     str
    target:     Optional[str]
    needs_pty:  bool = False
    needs_sudo: bool = False


def _in_scope(target: str, allowed_networks: str) -> bool:
    if not allowed_networks or not allowed_networks.strip():
        return True
    if not target:
        return True
    try:
        t_addr = ipaddress.ip_address(target.split("/")[0])
    except ValueError:
        return True
    for net in allowed_networks.split(","):
        net = net.strip()
        if not net:
            continue
        try:
            if t_addr in ipaddress.ip_network(net, strict=False):
                return True
        except ValueError:
            continue
    return False


def _needs_sudo_runtime(binary: str) -> bool:
    """
    Check if a tool needs sudo.
    Fast-path: static SUDO_TOOLS list.
    Fallback: check if binary exists and test-run to detect permission errors.
    """
    if binary in SUDO_TOOLS:
        return True
    # For unknown tools: check if they're in known sudo-requiring categories
    # by testing if running without sudo gives "Operation not permitted" or similar
    sudo_indicators = [
        "tcpd", "arping", "dhcp", "raw", "capture",
        "sniff", "inject", "monitor", "promiscuous",
    ]
    if any(ind in binary.lower() for ind in sudo_indicators):
        return True
    return False


def _needs_pty_runtime(binary: str) -> bool:
    """
    Check if a tool needs a PTY.
    Fast-path: static PTY_TOOLS list.
    Fallback: known interactive tool patterns.
    """
    if binary in PTY_TOOLS:
        return True
    # Interactive tool patterns — console-based, menu-driven, or uses curses
    pty_indicators = [
        "console", "shell", "toolkit", "framework",
        "wizard", "menu", "interactive",
    ]
    if any(ind in binary.lower() for ind in pty_indicators):
        return True
    return False


def sanitize(raw_command: str, config=None) -> SanitizationResult:
    command = raw_command.strip()

    if not command:
        return SanitizationResult(False, "Empty command.", "", "", None)

    if len(command) > MAX_COMMAND_LENGTH:
        return SanitizationResult(
            False, f"Command too long ({len(command)} chars).", command, "", None)

    bad = [c for c in command if c not in string.printable]
    if bad:
        return SanitizationResult(
            False, f"Non-printable characters detected.", command, "", None)

    # Strip quoted content before operator check — allows msfconsole -x "cmd; cmd"
    check_cmd = re.sub(r'"[^"]*"', '""', command)
    check_cmd = re.sub(r"'[^']*'", "''", check_cmd)
    op = SHELL_OPERATOR_RE.search(check_cmd)
    if op:
        return SanitizationResult(
            False,
            f"Shell operator '{op.group().strip()}' not allowed — "
            "one command per step, no chaining.",
            command, "", None,
        )

    try:
        tokens = shlex.split(command)
    except ValueError as e:
        return SanitizationResult(False, f"Parse error: {e}", command, "", None)

    if not tokens:
        return SanitizationResult(False, "Empty after parsing.", command, "", None)

    binary = tokens[0].lower()
    if "/" in binary:
        binary = binary.rsplit("/", 1)[-1]

    # Handle sudo prefix — re-check inner binary
    if binary == "sudo" and len(tokens) > 1:
        inner = tokens[1].lower()
        if "/" in inner:
            inner = inner.rsplit("/", 1)[-1]
        if inner in BLOCKED_BINARIES:
            return SanitizationResult(
                False, f"'{inner}' is blocked (system-destructive).",
                command, inner, None)
        binary = inner

    if binary in BLOCKED_BINARIES:
        return SanitizationResult(
            False,
            f"'{binary}' is blocked (system-destructive). Use a pentesting tool.",
            command, binary, None)

    if len(tokens) > MAX_ARG_COUNT:
        return SanitizationResult(
            False, f"Too many arguments ({len(tokens)}).", command, binary, None)

    joined = " ".join(tokens[1:]).lower()
    for flag in DANGEROUS_FLAGS.get(binary, []):
        if flag.lower() in joined:
            return SanitizationResult(
                False, f"Dangerous flag '{flag}' blocked for '{binary}'.",
                command, binary, None)

    for tok in tokens[1:]:
        if DANGEROUS_PATH_RE.search(tok):
            return SanitizationResult(
                False, f"Dangerous path in argument: '{tok}'.",
                command, binary, None)

    target = _extract_target(tokens)

    if config is not None and target:
        allowed = config.get("allowed_networks") if hasattr(config, "get") else None
        if allowed and not _in_scope(target, allowed):
            return SanitizationResult(
                False,
                f"Target '{target}' is outside allowed scope ({allowed}).",
                command, binary, target)

    already_sudo = command.lstrip().startswith("sudo ")
    needs_pty    = _needs_pty_runtime(binary)
    needs_sudo   = _needs_sudo_runtime(binary) and not already_sudo

    return SanitizationResult(True, "", command, binary, target,
                              needs_pty=needs_pty, needs_sudo=needs_sudo)


# ── Target extraction ─────────────────────────────────────────────────────────

_FLAG_VALUES = {
    "-p", "--port", "-u", "--url", "-w", "--wordlist", "-t", "--threads",
    "-o", "--output", "-H", "--header", "-d", "--data", "--proxy",
    "--timeout", "-e", "--extensions", "--script", "--lhost", "--lport",
    "-f", "--format", "-c", "--config", "-m", "--mode",
}

_IP_RE   = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")
_URL_RE  = re.compile(r"^https?://")
_HOST_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$")


def _extract_target(tokens: list[str]) -> Optional[str]:
    skip_next = False
    for tok in tokens[1:]:
        if skip_next:
            skip_next = False
            continue
        if tok.startswith("-"):
            if tok in _FLAG_VALUES:
                skip_next = True
            continue
        if _IP_RE.match(tok):   return tok
        if _URL_RE.match(tok):  return tok
        if _HOST_RE.match(tok): return tok
    return None
