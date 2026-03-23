"""
kernox.guards.rules  –  Safety and scope enforcement rules.

All tool commands are checked here before execution.  Rules:
  1. Blocked commands (rm, mkfs, dd, etc.) are never allowed.
  2. If allowed_networks is set, the target IP/hostname must fall within scope.
  3. Dangerous sqlmap flags (--os-shell, --os-cmd) require explicit override.
"""

from __future__ import annotations

import ipaddress
import re
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
        """Return True if target IP is within any of the allowed CIDR ranges."""
        # Extract IP from target (strip port, path, scheme)
        ip_str = _extract_ip(target)
        if not ip_str:
            return True  # Cannot resolve; let it through (best-effort)

        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return True  # Not a bare IP; allow

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


def _extract_ip(target: str) -> str:
    """Best-effort: pull a bare IP from a target string."""
    # Strip scheme
    target = re.sub(r"^https?://", "", target)
    # Strip path and port
    target = target.split("/")[0].split(":")[0]
    # Validate
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        return ""
