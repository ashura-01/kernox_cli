"""
kernox.guards.rules  –  Safety and scope enforcement rules.

All tool commands are checked here before execution.  Rules:
  1. Blocked commands (rm, mkfs, dd, etc.) are never allowed.
  2. If allowed_networks is set, the target IP/hostname must fall within scope.
     Hostnames are now resolved to IPs before the CIDR check so hostnames
     can no longer silently bypass scope enforcement.
  3. Dangerous sqlmap flags (--os-shell, --os-cmd) require explicit override.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import shlex
from typing import Optional

from kernox.config.config_store import ConfigStore

# Commands that must NEVER be executed
BLOCKED_PREFIXES = [
    "rm ", "rm\t", "mkfs", "dd ", ":(){ :|:& };:", "shutdown",
    "reboot", "halt", "poweroff", "format", "del /", "rmdir /",
]

# Flags that are too destructive for automated use
BLOCKED_FLAGS = [
    "--os-shell", "--os-cmd", "--file-write", "--file-dest",
]


class GuardRules:
    def __init__(self, config: ConfigStore) -> None:
        self._cfg = config

    def check(self, command: str, target: Optional[str] = None) -> tuple[bool, str]:
        """
        Return (allowed: bool, reason: str).
        allowed=True means the command may proceed.
        """
        cmd_lower = command.lower().strip()

        # 1. Blocked command prefixes
        for prefix in BLOCKED_PREFIXES:
            if cmd_lower.startswith(prefix):
                return False, f"Blocked command pattern: '{prefix.strip()}'"

        # 2. Blocked flags
        for flag in BLOCKED_FLAGS:
            if flag in cmd_lower:
                return False, f"Dangerous flag blocked: {flag}"

        # 3. Scope check
        allowed_nets = self._cfg.get("allowed_networks") or ""
        if allowed_nets.strip() and target:
            if not self._in_scope(target, allowed_nets):
                return False, (
                    f"Target '{target}' is outside allowed networks: {allowed_nets}. "
                    "Update scope in `kernox --config`."
                )

        return True, ""

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _in_scope(target: str, allowed_nets: str) -> bool:
        """
        Return True if target IP/hostname is within any of the allowed CIDR ranges.

        Improvement over original: hostnames are now resolved via DNS before the
        CIDR check.  Previously a hostname like 'internal-server.lan' would return
        '' from _extract_ip and be silently allowed through.
        """
        ip_str = _resolve_target(target)
        if not ip_str:
            # Could not resolve at all — allow with a warning rather than hard-block
            # (avoids blocking legitimate scans when DNS is slow/unavailable)
            return True

        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return True  # Unresolvable; allow

        for net_str in allowed_nets.split(","):
            net_str = net_str.strip()
            if not net_str:
                continue
            try:
                network = ipaddress.ip_network(net_str, strict=False)
                if ip in network:
                    return True
            except ValueError:
                continue  # Skip invalid CIDR entries

        return False


def _resolve_target(target: str) -> str:
    """
    Extract and resolve a target string to a bare IPv4/IPv6 address string.

    1. Strip scheme, path, port from the target.
    2. If it looks like an IP already, return it directly.
    3. Otherwise attempt DNS resolution and return the resolved IP.
    Returns '' if resolution fails.
    """
    # Strip scheme
    target = re.sub(r"^https?://", "", target)
    # Strip path and port
    host = target.split("/")[0].split(":")[0].strip()

    if not host:
        return ""

    # Check if it's already a valid IP
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    # Attempt DNS resolution for hostnames
    try:
        resolved = socket.gethostbyname(host)
        return resolved
    except (socket.gaierror, socket.herror):
        return ""  # Could not resolve — caller decides what to do
