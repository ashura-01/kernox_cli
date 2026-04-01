"""
kernox.tools.zapcli  –  OWASP ZAP CLI wrapper.

Runs ZAP in daemon mode and performs active/passive web application scans.
Supports both the native zap.sh CLI and the zaproxy Docker image.
Requires: zap.sh in PATH  OR  docker with ghcr.io/zaproxy/zaproxy image.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
import re


class ZapCliTool:
    """Build ZAP commands and parse their output."""

    # Default ZAP API port (daemon mode)
    ZAP_PORT = 8090

    MODES = {
        "baseline":   "Passive baseline scan — no active attacks",
        "active":     "Full active scan — tests all attack categories",
        "ajax":       "Ajax spider + passive scan — for JS-heavy apps",
        "api":        "API scan using OpenAPI/GraphQL definition",
    }

    def build_command(
        self,
        target: str,
        mode: str = "baseline",
        report_path: str = "/tmp/zap_report.html",
        extra_flags: str = "",
    ) -> str:
        """
        Build the ZAP CLI command.

        Prefers the native zap.sh binary.  Falls back to the Docker image
        if zap.sh is not found.
        """
        zap_bin = shutil.which("zap.sh") or shutil.which("zaproxy")
        use_docker = zap_bin is None

        if use_docker:
            # Docker-based invocation
            base = (
                f"docker run --rm --network host "
                f"ghcr.io/zaproxy/zaproxy:stable"
            )
        else:
            base = zap_bin

        if mode == "baseline":
            cmd = (
                f"{base} zap-baseline.py "
                f"-t {target} "
                f"-r {report_path} "
                f"-I"  # -I = ignore warnings (don't fail on medium+)
            )
        elif mode == "active":
            cmd = (
                f"{base} zap-full-scan.py "
                f"-t {target} "
                f"-r {report_path} "
                f"-I"
            )
        elif mode == "ajax":
            cmd = (
                f"{base} zap-baseline.py "
                f"-t {target} "
                f"-j "          # -j = enable Ajax spider
                f"-r {report_path} "
                f"-I"
            )
        elif mode == "api":
            cmd = (
                f"{base} zap-api-scan.py "
                f"-t {target} "
                f"-f openapi "
                f"-r {report_path} "
                f"-I"
            )
        else:
            # Fallback to baseline
            cmd = (
                f"{base} zap-baseline.py "
                f"-t {target} "
                f"-r {report_path} "
                f"-I"
            )

        if extra_flags:
            cmd += f" {extra_flags}"

        return cmd

    def parse(self, output: str) -> dict:
        """Parse ZAP stdout into a structured dict."""
        return _parse_zap_output(output)


# ── Parser ────────────────────────────────────────────────────────────────────

def _parse_zap_output(raw: str) -> dict:
    """
    Parse ZAP CLI stdout.

    ZAP prints alerts in the format:
      WARN-NEW: <name> [<id>] x N
        URL: <url>
        ...
      FAIL-NEW: ...
      PASS: ...
    """
    result: dict = {
        "alerts": [],
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "pass_count": 0,
        "raw": raw[:2000],
    }

    severity_map = {
        "FAIL-NEW": "high",
        "FAIL-INPROG": "high",
        "WARN-NEW": "medium",
        "WARN-INPROG": "medium",
        "INFO": "info",
        "PASS": "pass",
    }

    current_alert: dict = {}
    for line in raw.splitlines():
        line = line.strip()

        # Alert header line: WARN-NEW: XSS [40012] x 3
        m = re.match(r"^(FAIL-NEW|FAIL-INPROG|WARN-NEW|WARN-INPROG|INFO|PASS):\s+(.+?)(?:\s+\[(\d+)\])?\s*(?:x\s*(\d+))?$", line)
        if m:
            if current_alert:
                result["alerts"].append(current_alert)
            level_key = m.group(1)
            sev = severity_map.get(level_key, "info")
            if sev == "pass":
                result["pass_count"] += 1
                current_alert = {}
                continue
            current_alert = {
                "name": m.group(2).strip(),
                "severity": sev,
                "alert_id": m.group(3) or "",
                "count": int(m.group(4)) if m.group(4) else 1,
                "urls": [],
            }
            # Increment severity counter (only for known keys to avoid pollution)
            if sev in ("critical", "high", "medium", "low", "info"):
                result[sev] += 1
            continue

        # URL line inside an alert block
        if current_alert and line.lower().startswith("url:"):
            url = line[4:].strip()
            if url:
                current_alert["urls"].append(url)

    if current_alert:
        result["alerts"].append(current_alert)

    # Upgrade "high" alerts that look critical (SQL injection, RCE, etc.)
    critical_keywords = {"sql injection", "remote code execution", "rce", "xxe", "deserialization"}
    for alert in result["alerts"]:
        if any(kw in alert["name"].lower() for kw in critical_keywords):
            alert["severity"] = "critical"
            result["critical"] = result.get("critical", 0) + 1
            if result["high"] > 0:
                result["high"] -= 1

    return result
