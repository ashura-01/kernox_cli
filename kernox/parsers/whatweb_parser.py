"""kernox.parsers.whatweb_parser"""
from __future__ import annotations
import re


def _strip_ansi(text: str) -> str:
    return re.sub(r'\x1b\[[0-9;]*[a-zA-Z]|\[[0-9;]*[a-zA-Z]', '', text)


class WhatwebParser:
    PLUGIN_RE = re.compile(r"\[([^\]]+)\]")
    VERSION_RE = re.compile(r"(\w[\w\-\.]+)\s+\[(\d[\d\.]+)\]")
    EMAIL_RE = re.compile(r"[\w\.\-]+@[\w\.\-]+\.\w+")
    IP_RE = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")
    COUNTRY_RE = re.compile(r"Country\[([^\]]+)\]")

    def parse(self, raw: str) -> dict:
        raw = _strip_ansi(raw)
        technologies, versions, emails = [], [], []
        for m in self.PLUGIN_RE.finditer(raw):
            val = m.group(1).strip()
            if val and len(val) < 100:
                technologies.append(val)
        for m in self.VERSION_RE.finditer(raw):
            versions.append({"tech": m.group(1), "version": m.group(2)})
        emails = list(set(self.EMAIL_RE.findall(raw)))
        ips = list(set(self.IP_RE.findall(raw)))
        country_m = self.COUNTRY_RE.search(raw)
        return {
            "technologies": list(set(technologies)),
            "versions": versions,
            "emails": emails,
            "ips": ips,
            "country": country_m.group(1) if country_m else "",
            "raw": raw,
        }