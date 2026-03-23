"""
kernox.parsers.enum4linux_parser  –  Parse enum4linux output into structured data.
"""

from __future__ import annotations

import re


class Enum4linuxParser:
    """Extract users, shares, groups, OS info from enum4linux output."""

    USER_RE = re.compile(r"user:\[(\S+)\]\s+rid:\[(\S+)\]")
    SHARE_RE = re.compile(r"Sharename\s+Type\s+Comment|^\s+(\S+)\s+(Disk|IPC|Printer)\s*(.*)?$", re.MULTILINE)
    SHARE_LINE_RE = re.compile(r"^\s{1,8}(\S+)\s+(Disk|IPC|Printer)\s*(.*)?$", re.MULTILINE)
    GROUP_RE = re.compile(r"group:\[(.+?)\]\s+rid:\[(\S+)\]")
    OS_RE = re.compile(r"OS=\[(.+?)\]")
    DOMAIN_RE = re.compile(r"Domain=\[(.+?)\]")
    WORKGROUP_RE = re.compile(r"Workgroup=\[(.+?)\]")
    PASSWORD_POLICY_RE = re.compile(r"Minimum password length:\s*(\d+)")

    def parse(self, raw: str) -> dict:
        result: dict = {
            "users": [],
            "shares": [],
            "groups": [],
            "os": "",
            "domain": "",
            "workgroup": "",
            "password_policy": {},
            "raw": raw,
        }

        # Users
        for m in self.USER_RE.finditer(raw):
            result["users"].append({"username": m.group(1), "rid": m.group(2)})

        # Shares
        for m in self.SHARE_LINE_RE.finditer(raw):
            result["shares"].append({
                "name": m.group(1),
                "type": m.group(2),
                "comment": (m.group(3) or "").strip(),
            })

        # Groups
        for m in self.GROUP_RE.finditer(raw):
            result["groups"].append({"group": m.group(1), "rid": m.group(2)})

        # OS / Domain
        os_m = self.OS_RE.search(raw)
        if os_m:
            result["os"] = os_m.group(1)

        domain_m = self.DOMAIN_RE.search(raw)
        if domain_m:
            result["domain"] = domain_m.group(1)

        wg_m = self.WORKGROUP_RE.search(raw)
        if wg_m:
            result["workgroup"] = wg_m.group(1)

        # Password policy
        pw_m = self.PASSWORD_POLICY_RE.search(raw)
        if pw_m:
            result["password_policy"]["min_length"] = int(pw_m.group(1))

        return result
