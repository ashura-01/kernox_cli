"""
kernox.parsers.sqlmap_parser  –  Parse sqlmap output into structured data.
"""

from __future__ import annotations

import re


class SqlmapParser:
    """Extract injection points, databases, and tables from sqlmap output."""

    VULN_RE = re.compile(r"Parameter '(.+?)' is vulnerable", re.IGNORECASE)
    DB_RE = re.compile(r"\[\*\]\s+(.+)", re.IGNORECASE)
    INJECTABLE_RE = re.compile(r"sqlmap identified the following injection point", re.IGNORECASE)
    DBMS_RE = re.compile(r"back-end DBMS:\s*(.+)", re.IGNORECASE)

    def parse(self, raw: str) -> dict:
        result: dict = {
            "vulnerable": False,
            "parameters": [],
            "dbms": "",
            "databases": [],
            "raw": raw,
        }

        if self.INJECTABLE_RE.search(raw):
            result["vulnerable"] = True

        for m in self.VULN_RE.finditer(raw):
            param = m.group(1).strip()
            if param not in result["parameters"]:
                result["parameters"].append(param)

        dbms_m = self.DBMS_RE.search(raw)
        if dbms_m:
            result["dbms"] = dbms_m.group(1).strip()

        # Databases are listed after "available databases [N]:"
        in_db_section = False
        for line in raw.splitlines():
            if "available databases" in line.lower():
                in_db_section = True
                continue
            if in_db_section:
                db_m = self.DB_RE.match(line.strip())
                if db_m:
                    result["databases"].append(db_m.group(1).strip())
                elif line.strip() == "":
                    in_db_section = False

        return result
