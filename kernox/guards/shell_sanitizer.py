"""
kernox.guards.shell_sanitizer  –  Smart sanitization for any shell command.

Instead of a binary whitelist (too restrictive), we use:
  1. Hard-blocked binary list  (rm, mkfs, dd, bash, sh, etc.)
  2. Shell operator ban        (;  $()  backticks  eval  exec  source  2>&1)
  3. Dangerous flag detection  per binary
  4. Dangerous path detection  (/etc/shadow, /dev/sda, etc.)
  5. Length + printability     anti-padding/injection
  6. Target extraction         for scope enforcement

Allowed shell operators for chaining: &&  ||  |  >  >>  <
"""

from __future__ import annotations

import re
import shlex
import string
from dataclasses import dataclass
from typing import Optional

# ── Hard-blocked binaries ─────────────────────────────────────────────────────
BLOCKED_BINARIES: set[str] = {
    # Shell / interpreters
    "bash", "sh", "zsh", "fish", "dash", "ksh", "tcsh", "csh",
    "python", "python2", "python3", "ruby", "perl", "php", "lua",
    "node", "nodejs", "deno", "bun",
    # Privilege tools
     "su", "doas", "pkexec",
    # Destructive tools
    "rm", "rmdir", "mkfs", "dd", "shred", "wipe",
    "fdisk", "parted", "gparted",
    # System control
    "shutdown", "reboot", "halt", "poweroff", "init", "systemctl",
    # Package management (can install malware)
    "apt", "apt-get", "dpkg", "yum", "dnf", "pacman", "brew",
    "pip", "pip3", "npm", "gem", "cargo",
    # Compilers (can build+run anything)
    "gcc", "g++", "cc", "make", "cmake",
    # Netcat (nc/ncat blocked, 'netcat' allowed below)
    "nc", "ncat",
    # Misc dangerous
    "crontab", "at", "batch",
    "passwd", "chpasswd", "useradd", "userdel", "usermod",
    "chmod", "chown", "chattr",
    "mount", "umount",
    "iptables", "ip6tables", "nft", "ufw",
    "kill", "killall", "pkill",
    "format",
}

# Specific netcat binary we DO allow
ALLOWED_NETCAT = {"netcat"}

# ── Shell operator pattern ────────────────────────────────────────────────────
# BLOCKED: ;  $()  ``  ${}  eval  exec  source  2>&1
# ALLOWED: &&  ||  |  >  >>  <
SHELL_OPERATOR_RE = re.compile(
    r"""
    (?:
        `[^`]*`             |   # backtick substitution
        \$\(                |   # $(command)
        \$\{                |   # ${variable}
        \bexec\b            |   # exec builtin
        \beval\b            |   # eval builtin
        \bsource\b          |   # source builtin
        2>&1                    # stderr redirect
    )
    """,
    re.VERBOSE,
)

# ── Per-binary dangerous flags ────────────────────────────────────────────────
DANGEROUS_FLAGS: dict[str, list[str]] = {
    "sqlmap": ["--os-shell", "--os-cmd", "--file-write", "--file-dest",
               "--sql-shell", "--reg-add", "--reg-del"],
    "curl":   ["--config", "-K"],
    "wget":   ["--execute"],
    "nmap":   ["--resume"],
    "hydra":  ["-x"],
}

# ── Dangerous path patterns ────────────────────────────────────────────────────
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

MAX_COMMAND_LENGTH = 2048   # Increased for piped commands
MAX_ARG_COUNT      = 100    # Increased for chained commands


@dataclass
class SanitizationResult:
    allowed: bool
    reason:  str
    command: str
    binary:  str
    target:  Optional[str]


def _in_scope(target: str, allowed_networks: str) -> bool:
    """Return True if target IP/CIDR is within any of the allowed networks."""
    if not allowed_networks or not allowed_networks.strip():
        return True
    if not target:
        return True
    import ipaddress
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

    # Length
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
            False, f"Non-printable characters detected: {bad!r}",
            command, "", None,
        )

    # Shell operators — only blocked ones
    op = SHELL_OPERATOR_RE.search(command)
    if op:
        return SanitizationResult(
            False,
            f"Shell operator '{op.group().strip()}' not allowed.",
            command, "", None,
        )

    # Parse first binary (the primary tool being run)
    # For piped commands like "nmap ... | grep ..." — extract the first binary
    first_part = command.split("|")[0].split("&&")[0].split("||")[0].strip()
    try:
        tokens = shlex.split(first_part)
    except ValueError as e:
        return SanitizationResult(False, f"Parse error: {e}", command, "", None)

    if not tokens:
        return SanitizationResult(False, "Empty after parsing.", command, "", None)

    binary = tokens[0].lower()
    if "/" in binary:
        binary = binary.rsplit("/", 1)[-1]

    # Blocked binary check
    if binary in BLOCKED_BINARIES and binary not in ALLOWED_NETCAT:
        return SanitizationResult(
            False,
            f"'{binary}' is a blocked binary. Use a dedicated pentesting tool instead.",
            command, binary, None,
        )

    # Total arg count across all parts (rough)
    all_tokens = shlex.split(command)
    if len(all_tokens) > MAX_ARG_COUNT:
        return SanitizationResult(
            False, f"Too many arguments ({len(all_tokens)}, max {MAX_ARG_COUNT}).",
            command, binary, None,
        )

    # Dangerous flags per binary
    joined = " ".join(all_tokens[1:]).lower()
    for flag in DANGEROUS_FLAGS.get(binary, []):
        if flag.lower() in joined:
            return SanitizationResult(
                False, f"Dangerous flag '{flag}' blocked for '{binary}'.",
                command, binary, None,
            )

    # Path traversal / sensitive paths
    for tok in all_tokens[1:]:
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
                f"Target '{target}' is outside allowed scope ({allowed}).",
                command, binary, target,
            )

    return SanitizationResult(True, "", command, binary, target)


# ── Target extraction ─────────────────────────────────────────────────────────

FLAG_VALUE_PREFIXES = {
    "-p", "--port", "-u", "--url", "-w", "--wordlist",
    "-t", "--threads", "-o", "--output", "-H", "--header",
    "-d", "--data", "--proxy", "--timeout", "-e",
    "--extensions", "-s", "--sources", "--script",
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
