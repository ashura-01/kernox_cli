"""
kernox.parsers.nikto_parser  –  Parse nikto output into structured data.
"""

from __future__ import annotations

import re


class NiktoParser:
    """Extract vulnerabilities and info from nikto output."""

    VULN_RE = re.compile(r"^\+\s+(.+)$", re.MULTILINE)
    TARGET_RE = re.compile(r"Target IP:\s+(\S+)")
    SERVER_RE = re.compile(r"Server:\s+(.+)")
    OSVDB_RE = re.compile(r"OSVDB-(\d+)")

    def parse(self, raw: str) -> dict:
        result: dict = {
            "target": "",
            "server": "",
            "findings": [],
            "osvdb_refs": [],
            "total": 0,
            "raw": raw,
        }

        target_m = self.TARGET_RE.search(raw)
        if target_m:
            result["target"] = target_m.group(1).strip()

        server_m = self.SERVER_RE.search(raw)
        if server_m:
            result["server"] = server_m.group(1).strip()

        for match in self.VULN_RE.finditer(raw):
            finding = match.group(1).strip()
            if finding and not finding.startswith("-"):
                result["findings"].append(finding)

                # Extract OSVDB refs
                for osvdb in self.OSVDB_RE.finditer(finding):
                    ref = osvdb.group(1)
                    if ref not in result["osvdb_refs"]:
                        result["osvdb_refs"].append(ref)

        result["total"] = len(result["findings"])
        return result
