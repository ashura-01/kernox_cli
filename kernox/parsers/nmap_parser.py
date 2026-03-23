"""
kernox.parsers.nmap_parser  –  Parse raw nmap text output into structured data.
"""

from __future__ import annotations

import re


class NmapParser:
    """Extract hosts, ports, services, and OS from nmap output."""

    # Matches lines like: 22/tcp   open  ssh     OpenSSH 8.9
    PORT_RE = re.compile(
        r"(?P<port>\d+)/(?P<proto>tcp|udp)\s+(?P<state>\w+)\s+(?P<service>\S+)(?:\s+(?P<version>.+))?"
    )
    # Matches: Nmap scan report for <host> (<ip>)  OR  Nmap scan report for <ip>
    HOST_RE = re.compile(r"Nmap scan report for (?:(\S+) \()?(\d{1,3}(?:\.\d{1,3}){3})\)?")
    OS_RE = re.compile(r"OS details?:\s*(.+)")

    def parse(self, raw: str) -> dict:
        result: dict = {"hosts": [], "raw": raw}
        current_host: dict | None = None

        filtered_count = raw.lower().count("filtered")

        for line in raw.splitlines():
            # New host block
            host_match = self.HOST_RE.search(line)
            if host_match:
                if current_host:
                    result["hosts"].append(current_host)
                hostname = host_match.group(1) or ""
                ip = host_match.group(2)
                current_host = {"ip": ip, "hostname": hostname, "ports": [], "os": ""}
                continue

            if current_host is None:
                continue

            # Port line
            port_match = self.PORT_RE.search(line)
            if port_match:
                current_host["ports"].append({
                    "port": int(port_match.group("port")),
                    "proto": port_match.group("proto"),
                    "state": port_match.group("state"),
                    "service": port_match.group("service"),
                    "version": (port_match.group("version") or "").strip(),
                })
                continue

            # OS
            os_match = self.OS_RE.search(line)
            if os_match and current_host:
                current_host["os"] = os_match.group(1).strip()

        if current_host:
            result["hosts"].append(current_host)

        # Add metadata
        for host in result["hosts"]:
            host["filtered_ports"] = filtered_count

        return result
