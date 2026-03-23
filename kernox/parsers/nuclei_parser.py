"""
kernox.parsers.nuclei_parser  –  Parse nuclei output (text + JSON).
"""

from __future__ import annotations

import json
import re


class NucleiParser:
    """Parse nuclei findings from both text and JSON output."""

    # Text output line format:
    # [CVE-2021-41773] [http] [critical] http://target/cgi-bin/...
    TEXT_RE = re.compile(
        r"\[(?P<template>[^\]]+)\]\s+"
        r"\[(?P<type>[^\]]+)\]\s+"
        r"\[(?P<severity>critical|high|medium|low|info)\]\s+"
        r"(?P<matched>.+)",
        re.IGNORECASE,
    )

    SEVERITY_ORDER = {
        "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4
    }

    def parse(self, raw: str) -> dict:
        findings: list[dict] = []

        # Try JSON file first
        try:
            with open("/tmp/kernox_nuclei.json", "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        findings.append({
                            "template":    entry.get("template-id", ""),
                            "name":        entry.get("info", {}).get("name", ""),
                            "severity":    entry.get("info", {}).get("severity", "info"),
                            "type":        entry.get("type", ""),
                            "matched":     entry.get("matched-at", ""),
                            "description": entry.get("info", {}).get("description", ""),
                            "tags":        entry.get("info", {}).get("tags", []),
                            "reference":   entry.get("info", {}).get("reference", []),
                            "cvss_score":  entry.get("info", {}).get("classification", {}).get("cvss-score", ""),
                            "cve_id":      entry.get("info", {}).get("classification", {}).get("cve-id", []),
                        })
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            pass

        # Fall back to text parsing if JSON empty
        if not findings:
            for line in raw.splitlines():
                m = self.TEXT_RE.search(line)
                if m:
                    findings.append({
                        "template":    m.group("template"),
                        "name":        m.group("template"),
                        "severity":    m.group("severity").lower(),
                        "type":        m.group("type"),
                        "matched":     m.group("matched").strip(),
                        "description": "",
                        "tags":        [],
                        "reference":   [],
                        "cvss_score":  "",
                        "cve_id":      [],
                    })

        # Sort by severity
        findings.sort(key=lambda x: self.SEVERITY_ORDER.get(x["severity"], 99))

        # Count by severity
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1

        return {
            "findings":  findings,
            "total":     len(findings),
            "critical":  counts["critical"],
            "high":      counts["high"],
            "medium":    counts["medium"],
            "low":       counts["low"],
            "info":      counts["info"],
            "raw":       raw,
        }
