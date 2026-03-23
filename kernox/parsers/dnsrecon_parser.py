"""kernox.parsers.dnsrecon_parser"""
from __future__ import annotations
import re

class DnsreconParser:
    A_RE     = re.compile(r"\[\*\]\s+A\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)")
    MX_RE    = re.compile(r"\[\*\]\s+MX\s+(\S+)\s+(\S+)")
    NS_RE    = re.compile(r"\[\*\]\s+NS\s+(\S+)\s+(\S+)")
    TXT_RE   = re.compile(r"\[\*\]\s+TXT\s+\S+\s+(.+)")
    AXFR_RE  = re.compile(r"Zone Transfer", re.IGNORECASE)
    SUB_RE   = re.compile(r"\[\+\]\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)")

    def parse(self, raw: str) -> dict:
        a_records, mx_records, ns_records, txt_records, subdomains = [], [], [], [], []

        for m in self.A_RE.finditer(raw):
            a_records.append({"host": m.group(1), "ip": m.group(2)})
        for m in self.MX_RE.finditer(raw):
            mx_records.append({"host": m.group(1), "ip": m.group(2)})
        for m in self.NS_RE.finditer(raw):
            ns_records.append({"host": m.group(1), "ip": m.group(2)})
        for m in self.TXT_RE.finditer(raw):
            txt_records.append(m.group(1).strip())
        for m in self.SUB_RE.finditer(raw):
            subdomains.append({"subdomain": m.group(1), "ip": m.group(2)})

        zone_transfer = bool(self.AXFR_RE.search(raw))

        return {
            "a_records": a_records,
            "mx_records": mx_records,
            "ns_records": ns_records,
            "txt_records": txt_records,
            "subdomains": subdomains,
            "zone_transfer_possible": zone_transfer,
            "total_subdomains": len(subdomains),
            "raw": raw,
        }
