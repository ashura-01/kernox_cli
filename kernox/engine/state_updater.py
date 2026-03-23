"""
kernox.engine.state_updater  –  Apply parsed tool results to SessionState.
"""

from __future__ import annotations

from kernox.engine.state import SessionState


class StateUpdater:
    """Translates parsed tool output into session state mutations."""

    def __init__(self, state: SessionState) -> None:
        self._state = state

    def apply(self, tool_name: str, parsed: dict, target: str | None = None) -> None:
        """Dispatch to the correct update method based on tool name."""
        dispatch = {
            "nmap": self._apply_nmap,
            "ffuf": self._apply_ffuf,
            "gobuster": self._apply_gobuster,
            "sqlmap": self._apply_sqlmap,
            "nikto": self._apply_nikto,
            "enum4linux": self._apply_enum4linux,
        }
        handler = dispatch.get(tool_name)
        if handler:
            handler(parsed, target or "")

    # ── Per-tool handlers ────────────────────────────────────────────────────

    def _apply_nmap(self, parsed: dict, target: str) -> None:
        for host_data in parsed.get("hosts", []):
            ip = host_data.get("ip", target)
            self._state.upsert_host(
                ip,
                hostname=host_data.get("hostname", ""),
                os=host_data.get("os", ""),
            )
            self._state.add_ports(ip, host_data.get("ports", []))

    def _apply_ffuf(self, parsed: dict, target: str) -> None:
        findings = parsed.get("findings", [])
        if findings:
            self._state.add_paths(target, findings)

    def _apply_gobuster(self, parsed: dict, target: str) -> None:
        raw_paths = parsed.get("paths", [])
        findings = [{"path": p, "status": 200, "size": 0} for p in raw_paths]
        if findings:
            self._state.add_paths(target, findings)

    def _apply_sqlmap(self, parsed: dict, target: str) -> None:
        if parsed.get("vulnerable"):
            vuln = {
                "type": "sql_injection",
                "parameters": parsed.get("parameters", []),
                "dbms": parsed.get("dbms", ""),
                "databases": parsed.get("databases", []),
            }
            self._state.add_vuln(target, vuln)

    def _apply_nikto(self, parsed: dict, target: str) -> None:
        for finding in parsed.get("findings", []):
            self._state.add_vuln(target, {
                "type": "nikto",
                "finding": finding,
            })

    def _apply_enum4linux(self, parsed: dict, target: str) -> None:
        users = parsed.get("users", [])
        shares = parsed.get("shares", [])
        if users or shares:
            self._state.add_vuln(target, {
                "type": "smb_enum",
                "users": users,
                "shares": shares,
                "os": parsed.get("os", ""),
                "domain": parsed.get("domain", ""),
            })
