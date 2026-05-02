"""
kernox.guards.shell_sanitizer  –  Smart sanitization for any shell command.

Design:
  1. Hard-blocked binary list  (rm, mkfs, dd, etc.) — system-destructive only
  2. Shell operator ban        (;  &&  ||  |  >  >>  $()  backticks)
  3. Dangerous flag detection  per binary
  4. Dangerous path detection  (/etc/shadow, /dev/sda, etc.)
  5. Length + printability     anti-padding/injection
  6. Target extraction         for scope enforcement

NOTE: sudo, python, ruby, bash etc. are NOT blocked here — the executor
handles sudo prepending, and interpreters are needed for msfvenom/msf scripts.
Only system-destructive binaries are blocked.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
import string
from dataclasses import dataclass
from typing import Optional


# ── Hard-blocked binaries ─────────────────────────────────────────────────────

BLOCKED_BINARIES: set[str] = {
    # Filesystem destruction
    "rm", "rmdir", "mkfs", "dd", "shred", "wipe",
    "fdisk", "parted", "gparted", "gdisk",
    # System control / shutdown
    "shutdown", "reboot", "halt", "poweroff", "init",
    # User/auth modification
    "passwd", "chpasswd", "useradd", "userdel", "usermod",
    # Device-level
    "mount", "umount",
    # Firewall modification (could lock out)
    "iptables", "ip6tables", "nft",
    # Format / wipe
    "format",
}

# ── Interactive / PTY-required tools ─────────────────────────────────────────

PTY_TOOLS: set[str] = {
    "msfconsole",
    "sqlmap",       
    "beef-xss",
    "setoolkit",
    "social-engineer-toolkit",
}

# ── Tools that need sudo ──────────────────────────────────────────────────────
SUDO_TOOLS: set[str] = {
    "nmap", "masscan", "tcpdump", "tshark",
    "arp-scan", "bettercap", "aireplay-ng",
    "reaver", "kismet", "netdiscover",
    "airmon-ng", "airodump-ng",
}

# ── Shell operator pattern ────────────────────────────────────────────────────
SHELL_OPERATOR_RE = re.compile(
    r"""
    (?:
        ;                   |
        &&                  |
        \|\|                |
        \|(?!\w)            |
        >>?                 |
        <(?!<)              |
        `[^`]*`             |
        \$\(                |
        \$\{                |
        \bexec\b            |
        \beval\b            |
        \bsource\b          |
        2>&1
    )
    """,
    re.VERBOSE,
)

# ── Per-binary dangerous flags ────────────────────────────────────────────────
DANGEROUS_FLAGS: dict[str, list[str]] = {
    "sqlmap": ["--os-shell", "--os-cmd", "--sql-shell",
               "--reg-add", "--reg-del"],
    "curl":   ["--config", "-K"],
    "wget":   ["--execute"],
    "nmap":   ["--resume"],
    "hydra":  ["-x"],
}

# ── Dangerous path patterns ───────────────────────────────────────────────────
DANGEROUS_PATH_RE = re.compile(
    r"""
    (?:
        \.\.(?:/|\\)        |
        /etc/shadow         |
        /etc/sudoers        |
        /root/              |
        /home/[^/]+/\.ssh   |
        /proc/self          |
        /dev/sd[a-z]        |
        /dev/nvme           |
        /dev/zero           |
        /dev/null(?!\s)
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

MAX_COMMAND_LENGTH = 2048   # msfvenom commands can be long
MAX_ARG_COUNT      = 80


@dataclass
class SanitizationResult:
    allowed:  bool
    reason:   str
    command:  str
    binary:   str
    target:   Optional[str]
    needs_pty: bool = False
    needs_sudo: bool = False


def _in_scope(target: str, allowed_networks: str) -> bool:
    """Return True if target is within any allowed network, or if unrestricted."""
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


def sanitize(raw_command: str, config=None) -> SanitizationResult:
    command = raw_command.strip()

    if not command:
        return SanitizationResult(False, "Empty command.", "", "", None)

    # Length guard
    if len(command) > MAX_COMMAND_LENGTH:
        return SanitizationResult(
            False,
            f"Command too long ({len(command)} chars, max {MAX_COMMAND_LENGTH}).",
            command, "", None,
        )

    # Printable only
    bad = [c for c in command if c not in string.printable]
    if bad:
        return SanitizationResult(
            False, f"Non-printable characters: {bad!r}",
            command, "", None,
        )


    check_cmd = re.sub(r'"[^"]*"', '""', command)   
    check_cmd = re.sub(r"'[^']*'", "''", check_cmd) 
    op = SHELL_OPERATOR_RE.search(check_cmd)
    if op:
        return SanitizationResult(
            False,
            f"Shell operator '{op.group().strip()}' not allowed. "
            "One command only — no pipes, redirects, or chaining.",
            command, "", None,
        )

 
    try:
        tokens = shlex.split(command)
    except ValueError as e:
        return SanitizationResult(False, f"Parse error: {e}", command, "", None)

    if not tokens:
        return SanitizationResult(False, "Empty after parsing.", command, "", None)

  
    raw_binary = tokens[0]
    binary = raw_binary.lower()
    if "/" in binary:
        binary = binary.rsplit("/", 1)[-1]


    if binary == "sudo" and len(tokens) > 1:
        inner = tokens[1].lower()
        if "/" in inner:
            inner = inner.rsplit("/", 1)[-1]
        if inner in BLOCKED_BINARIES:
            return SanitizationResult(
                False,
                f"'{inner}' is a blocked binary (system-destructive).",
                command, inner, None,
            )
        binary = inner

    # System-destructive check
    if binary in BLOCKED_BINARIES:
        return SanitizationResult(
            False,
            f"'{binary}' is a blocked binary (system-destructive). "
            "Use a dedicated pentesting tool instead.",
            command, binary, None,
        )

    # Arg count
    if len(tokens) > MAX_ARG_COUNT:
        return SanitizationResult(
            False, f"Too many arguments ({len(tokens)}, max {MAX_ARG_COUNT}).",
            command, binary, None,
        )

    # Dangerous flags per binary
    joined = " ".join(tokens[1:]).lower()
    for flag in DANGEROUS_FLAGS.get(binary, []):
        if flag.lower() in joined:
            return SanitizationResult(
                False, f"Dangerous flag '{flag}' blocked for '{binary}'.",
                command, binary, None,
            )

    # Path traversal / sensitive paths
    for tok in tokens[1:]:
        if DANGEROUS_PATH_RE.search(tok):
            return SanitizationResult(
                False, f"Dangerous path in argument: '{tok}'.",
                command, binary, None,
            )

    target = _extract_target(tokens)

    # Scope enforcement
    if config is not None and target:
        allowed = config.get("allowed_networks") if hasattr(config, "get") else None
        if allowed and not _in_scope(target, allowed):
            return SanitizationResult(
                False,
                f"Target '{target}' is outside allowed scope ({allowed}). "
                "Update scope with `kernox --config`.",
                command, binary, target,
            )

    needs_pty  = binary in PTY_TOOLS
    needs_sudo = binary in SUDO_TOOLS and not command.lstrip().startswith("sudo")

    return SanitizationResult(True, "", command, binary, target,
                              needs_pty=needs_pty, needs_sudo=needs_sudo)


# ── Target extraction ─────────────────────────────────────────────────────────

FLAG_VALUE_PREFIXES = {
    "-p", "--port", "-u", "--url", "-w", "--wordlist",
    "-t", "--threads", "-o", "--output", "-H", "--header",
    "-d", "--data", "--proxy", "--timeout", "-e",
    "--extensions", "-s", "--sources", "--script",
    "--lhost", "--lport", "-f", "--format",
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
            if tok in FLAG_VALUE_PREFIXES:
                skip_next = True
            continue
        if _IP_RE.match(tok):   return tok
        if _URL_RE.match(tok):  return tok
        if _HOST_RE.match(tok): return tok
    return None
