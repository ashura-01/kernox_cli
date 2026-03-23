"""kernox.parsers.sslscan_parser"""
from __future__ import annotations
import re

class SslscanParser:
    PROTOCOL_RE  = re.compile(r"(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|TLSv1\.2|TLSv1\.3)\s+(enabled|disabled)", re.IGNORECASE)
    CIPHER_RE    = re.compile(r"(Accepted|Preferred)\s+(\S+)\s+\d+\s+bits\s+(\S+)")
    HEARTBLEED_RE= re.compile(r"heartbleed", re.IGNORECASE)
    CERT_CN_RE   = re.compile(r"Subject:\s+.+?CN\s*=\s*([^\,\n]+)")
    CERT_EXP_RE  = re.compile(r"Not valid after:\s+(.+)")
    SELF_SIGNED_RE = re.compile(r"self.signed", re.IGNORECASE)

    def parse(self, raw: str) -> dict:
        protocols, weak_protocols = [], []
        for m in self.PROTOCOL_RE.finditer(raw):
            proto, state = m.group(1), m.group(2).lower()
            protocols.append({"protocol": proto, "state": state})
            if state == "enabled" and proto in ("SSLv2","SSLv3","TLSv1.0","TLSv1.1"):
                weak_protocols.append(proto)

        ciphers = []
        for m in self.CIPHER_RE.finditer(raw):
            ciphers.append({"status": m.group(1), "protocol": m.group(2), "cipher": m.group(3)})

        weak_ciphers = [c for c in ciphers if any(x in c["cipher"].upper() for x in
                        ["RC4","DES","3DES","NULL","EXPORT","ANON","MD5"])]

        cn_m = self.CERT_CN_RE.search(raw)
        exp_m = self.CERT_EXP_RE.search(raw)

        issues = []
        if self.HEARTBLEED_RE.search(raw): issues.append("Heartbleed vulnerable")
        if self.SELF_SIGNED_RE.search(raw): issues.append("Self-signed certificate")
        if weak_protocols: issues.append(f"Weak protocols: {', '.join(weak_protocols)}")
        if weak_ciphers: issues.append(f"Weak ciphers: {len(weak_ciphers)} found")

        return {
            "protocols": protocols,
            "weak_protocols": weak_protocols,
            "ciphers": ciphers,
            "weak_ciphers": weak_ciphers,
            "cert_cn": cn_m.group(1).strip() if cn_m else "",
            "cert_expiry": exp_m.group(1).strip() if exp_m else "",
            "issues": issues,
            "total_issues": len(issues),
            "raw": raw,
        }
