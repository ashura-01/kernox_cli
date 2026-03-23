"""
kernox.engine.state  –  In-memory session state for a Kernox run.

Stores everything discovered so far: hosts, open ports, found paths,
SQL injection results, etc. Survives across tool invocations within
one session but is intentionally NOT persisted to disk.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass
class HostInfo:
    ip: str
    hostname: str = ""
    os: str = ""
    ports: list[dict] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass
class ToolResult:
    """Store complete tool execution results."""
    tool: str
    target: str
    parsed: dict
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    raw_output: str = ""


@dataclass
class AIInsight:
    """Store AI-generated explanations for vulnerabilities."""
    vulnerability: str
    severity: str
    tool: str
    target: str
    ai_explanation: dict
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class SessionState:
    """Mutable state bag for the current Kernox session."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self._hosts: dict[str, HostInfo] = {}          # ip → HostInfo
        self._paths: dict[str, list[dict]] = {}         # target_url → [path findings]
        self._vulns: dict[str, list[dict]] = {}         # target_url → [vuln dicts]
        self._notes: list[str] = []                      # free-form notes
        self._tool_results: list[ToolResult] = []        # tool execution results
        self._ai_insights: list[AIInsight] = []          # AI vulnerability explanations
        self._session_start: str = datetime.now().isoformat()

    # ── Tool Results ─────────────────────────────────────────────────────────

    def add_tool_result(self, tool: str, target: str, parsed: dict, raw_output: str = "") -> None:
        """Store complete tool result for reporting."""
        self._tool_results.append(ToolResult(
            tool=tool,
            target=target,
            parsed=parsed,
            raw_output=raw_output[:5000]
        ))

    def get_tool_results(self, tool: Optional[str] = None) -> list[ToolResult]:
        """Get tool results, optionally filtered by tool name."""
        if tool:
            return [r for r in self._tool_results if r.tool == tool]
        return self._tool_results

    # ── AI Insights ──────────────────────────────────────────────────────────

    def add_ai_insight(self, vulnerability: str, severity: str, tool: str, 
                       target: str, explanation: dict) -> None:
        """Store AI-generated vulnerability explanation."""
        self._ai_insights.append(AIInsight(
            vulnerability=vulnerability,
            severity=severity,
            tool=tool,
            target=target,
            ai_explanation=explanation
        ))

    def get_ai_insights(self, severity: Optional[str] = None) -> list[AIInsight]:
        """Get AI insights, optionally filtered by severity."""
        if severity:
            return [i for i in self._ai_insights if i.severity.lower() == severity.lower()]
        return self._ai_insights

    # ── Hosts ────────────────────────────────────────────────────────────────

    def upsert_host(self, ip: str, **kwargs: Any) -> HostInfo:
        if ip not in self._hosts:
            self._hosts[ip] = HostInfo(ip=ip)
        host = self._hosts[ip]
        for k, v in kwargs.items():
            if hasattr(host, k):
                setattr(host, k, v)
        return host

    def add_ports(self, ip: str, ports: list[dict]) -> None:
        host = self.upsert_host(ip)
        existing = {(p["port"], p["proto"]) for p in host.ports}
        for p in ports:
            key = (p["port"], p["proto"])
            if key not in existing:
                host.ports.append(p)
                existing.add(key)

    @property
    def hosts(self) -> dict[str, HostInfo]:
        return self._hosts

    # ── Paths ────────────────────────────────────────────────────────────────

    def add_paths(self, target: str, findings: list[dict]) -> None:
        if target not in self._paths:
            self._paths[target] = []
        seen = {f["path"] for f in self._paths[target]}
        for f in findings:
            if f["path"] not in seen:
                self._paths[target].append(f)
                seen.add(f["path"])

    @property
    def paths(self) -> dict[str, list[dict]]:
        return self._paths

    # ── Vulnerabilities ──────────────────────────────────────────────────────

    def add_vuln(self, target: str, vuln: dict) -> None:
        if target not in self._vulns:
            self._vulns[target] = []
        self._vulns[target].append(vuln)

    @property
    def vulns(self) -> dict[str, list[dict]]:
        return self._vulns

    # ── Notes ────────────────────────────────────────────────────────────────

    def add_note(self, note: str) -> None:
        self._notes.append(note)

    # ── Serialisation ────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "session_start": self._session_start,
            "hosts": {
                ip: {
                    "ip": h.ip,
                    "hostname": h.hostname,
                    "os": h.os,
                    "ports": h.ports,
                    "tags": h.tags,
                }
                for ip, h in self._hosts.items()
            },
            "paths": self._paths,
            "vulns": self._vulns,
            "notes": self._notes,
            "tool_results": [
                {
                    "tool": r.tool,
                    "target": r.target,
                    "parsed": r.parsed,
                    "timestamp": r.timestamp,
                }
                for r in self._tool_results
            ],
            "ai_insights": [
                {
                    "vulnerability": i.vulnerability,
                    "severity": i.severity,
                    "tool": i.tool,
                    "target": i.target,
                    "explanation": i.ai_explanation,
                    "timestamp": i.timestamp,
                }
                for i in self._ai_insights
            ],
        }

    def summary(self) -> str:
        lines = [
            f"Hosts: {len(self._hosts)}",
            f"URL targets with paths found: {len(self._paths)}",
            f"Vulnerable targets: {len(self._vulns)}",
            f"Tools run: {len(self._tool_results)}",
            f"AI insights: {len(self._ai_insights)}",
        ]
        return " | ".join(lines)