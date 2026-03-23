"""
kernox.parsers.ffuf_parser  –  Parse ffuf text output into structured data.
"""

from __future__ import annotations

import re


class FfufParser:
    """Extract discovered paths and status codes from ffuf output."""

    # Matches lines like: admin                   [Status: 200, Size: 1234, Words: 56, Lines: 78]
    RESULT_RE = re.compile(
        r"(?P<path>\S+)\s+\[Status:\s*(?P<status>\d+),\s*Size:\s*(?P<size>\d+)"
    )

    def parse(self, raw: str) -> dict:
        findings: list[dict] = []
        for line in raw.splitlines():
            m = self.RESULT_RE.search(line)
            if m:
                findings.append({
                    "path": m.group("path"),
                    "status": int(m.group("status")),
                    "size": int(m.group("size")),
                })

        return {
            "findings": findings,
            "total": len(findings),
            "raw": raw,
        }
