"""
kernox.parsers.wpscan_parser  –  Parse wpscan output.
"""

from __future__ import annotations
import re


class WpscanParser:
    VERSION_RE  = re.compile(r"WordPress version (\S+)", re.IGNORECASE)
    VULN_RE     = re.compile(r"\[!\]\s+(.+)")
    PLUGIN_RE   = re.compile(r"\[\+\]\s+(\S+)$", re.MULTILINE)
    USER_RE     = re.compile(r"\[\+\]\s+([a-zA-Z0-9_\-]+)\s+Found", re.IGNORECASE)
    THEME_RE    = re.compile(r"Theme:\s+(\S+)")
    CRED_RE     = re.compile(r"Username:\s+(\S+),\s+Password:\s+(\S+)")

    def parse(self, raw: str) -> dict:
        version_m = self.VERSION_RE.search(raw)
        vulns     = [m.group(1).strip() for m in self.VULN_RE.finditer(raw)]
        plugins   = list(set(m.group(1) for m in self.PLUGIN_RE.finditer(raw)))
        users     = list(set(m.group(1) for m in self.USER_RE.finditer(raw)))
        theme_m   = self.THEME_RE.search(raw)
        creds     = [{"user": m.group(1), "pass": m.group(2)} for m in self.CRED_RE.finditer(raw)]

        return {
            "wp_version": version_m.group(1) if version_m else "",
            "vulnerabilities": vulns,
            "plugins": plugins,
            "users": users,
            "theme": theme_m.group(1) if theme_m else "",
            "credentials": creds,
            "total_vulns": len(vulns),
            "raw": raw,
        }
