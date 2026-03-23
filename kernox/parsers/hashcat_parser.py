"""
kernox.parsers.hashcat_parser  –  Parse hashcat output.
"""

from __future__ import annotations
import re


class HashcatParser:
    CRACKED_RE   = re.compile(r"^([a-fA-F0-9\$\.\:\/\*\+\=]+):([^\n]+)$", re.MULTILINE)
    STATUS_RE    = re.compile(r"Status\.+:\s*(.+)")
    SPEED_RE     = re.compile(r"Speed\.#\*\.+:\s*(.+)|Speed\.#1\.+:\s*(.+)")
    PROGRESS_RE  = re.compile(r"Progress\.+:\s*(.+)")
    RECOVERED_RE = re.compile(r"Recovered\.+:\s*(.+)")
    TIME_RE      = re.compile(r"Time\.Estimated\.+:\s*(.+)")
    HASH_TYPE_RE = re.compile(r"Hash\.+:\s*(.+)")

    def parse(self, raw: str) -> dict:
        cracked = []
        for m in self.CRACKED_RE.finditer(raw):
            plaintext = m.group(2).strip()
            if plaintext and not plaintext.startswith("*") and len(plaintext) < 200:
                cracked.append({
                    "hash": m.group(1).strip(),
                    "plaintext": plaintext,
                })

        # Also check outfile if saved
        try:
            with open("/tmp/kernox_cracked.txt", "r") as f:
                for line in f:
                    line = line.strip()
                    if ":" in line:
                        parts = line.split(":", 1)
                        entry = {"hash": parts[0], "plaintext": parts[1]}
                        if entry not in cracked:
                            cracked.append(entry)
        except Exception:
            pass

        status_m    = self.STATUS_RE.search(raw)
        speed_m     = self.SPEED_RE.search(raw)
        progress_m  = self.PROGRESS_RE.search(raw)
        recovered_m = self.RECOVERED_RE.search(raw)
        time_m      = self.TIME_RE.search(raw)
        hashtype_m  = self.HASH_TYPE_RE.search(raw)

        speed = ""
        if speed_m:
            speed = (speed_m.group(1) or speed_m.group(2) or "").strip()

        return {
            "cracked": cracked,
            "total_cracked": len(cracked),
            "status": status_m.group(1).strip() if status_m else "",
            "speed": speed,
            "progress": progress_m.group(1).strip() if progress_m else "",
            "recovered": recovered_m.group(1).strip() if recovered_m else "",
            "time_estimated": time_m.group(1).strip() if time_m else "",
            "hash_type": hashtype_m.group(1).strip() if hashtype_m else "",
            "raw": raw,
        }
