"""
kernox.engine.state  –  In-memory session state for a Kernox run.

Stores everything discovered so far: hosts, open ports, found paths,
SQL injection results, etc. Survives across tool invocations within
one session but is intentionally NOT persisted to disk.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class HostInfo:
    ip: str
    hostname: str = ""
    os: str = ""
    ports: list[dict] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


class SessionState:
    """Mutable state bag for the current Kernox session."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self._hosts: dict[str, HostInfo] = {}          # ip → HostInfo
        self._paths: dict[str, list[dict]] = {}         # target_url → [path findings]
        self._vulns: dict[str, list[dict]] = {}         # target_url → [vuln dicts]
        self._notes: list[str] = []                      # free-form notes

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
        }

    def summary(self) -> str:
        lines = [
            f"Hosts: {len(self._hosts)}",
            f"URL targets with paths found: {len(self._paths)}",
            f"Vulnerable targets: {len(self._vulns)}",
        ]
        return " | ".join(lines)
