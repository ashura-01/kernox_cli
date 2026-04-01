"""
kernox.tools.theharvester  –  theHarvester OSINT wrapper.

Harvests emails, subdomains, IPs, and employee names from public sources.
Binary: theHarvester  (sudo apt install theharvester  OR  pip install theHarvester)
"""

from __future__ import annotations

import re


class TheHarvesterTool:
    """Build theHarvester commands and parse their output."""

    SOURCES = [
        "anubis", "baidu", "bevigil", "binaryedge", "bing",
        "certspotter", "crtsh", "dnsdumpster", "duckduckgo",
        "fullhunt", "google", "hackertarget", "hunter",
        "intelx", "otx", "rapiddns", "sublist3r",
        "threatminer", "urlscan", "virustotal", "yahoo",
    ]

    def build_command(
        self,
        target: str,
        sources: str = "google,bing,crtsh,certspotter,dnsdumpster,hackertarget",
        limit: int = 500,
        flags: str = "",
    ) -> str:
        """
        Build the theHarvester command.

        Parameters
        ----------
        target:   Domain to harvest (e.g. example.com).
        sources:  Comma-separated data sources.
        limit:    Max results per source.
        flags:    Extra raw flags.
        """
        # Strip scheme/path
        domain = re.sub(r"^https?://", "", target).split("/")[0].strip()

        parts = [
            "theHarvester",
            f"-d {domain}",
            f"-b {sources}",
            f"-l {limit}",
        ]
        if flags:
            parts.append(flags)

        return " ".join(parts)

    def parse(self, output: str) -> dict:
        """Parse theHarvester output into a structured dict."""
        return _parse_harvester_output(output)


# ── Parser ────────────────────────────────────────────────────────────────────

_EMAIL_RE  = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_DOMAIN_RE = re.compile(r"(?:^|\s)((?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,})(?:\s|$)")
_IP_RE     = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _parse_harvester_output(raw: str) -> dict:
    result: dict = {
        "emails": [],
        "subdomains": [],
        "ips": [],
        "raw": raw[:3000],
    }

    emails_seen: set = set()
    subs_seen: set   = set()
    ips_seen: set    = set()

    in_emails    = False
    in_hosts     = False

    for line in raw.splitlines():
        stripped = line.strip()

        # Section start headers — explicit named markers only
        if re.search(r"\[\*\]\s*Emails found", stripped, re.IGNORECASE):
            in_emails = True; in_hosts = False; continue
        if re.search(r"\[\*\]\s*(Hosts|IPs|Interesting|Subdomains) found", stripped, re.IGNORECASE):
            in_hosts = True; in_emails = False; continue
        # Section END: a [*] header for a *different* known section resets state
        if stripped.startswith("[*]") and not stripped.startswith("[*] Found") and not re.search(r"\[\*\]\s*(Email|Host|IP|Sub)", stripped, re.IGNORECASE):
            # Only reset if we hit a clearly different top-level section marker
            if re.search(r"\[\*\]\s+\w", stripped) and ":" not in stripped[:30]:
                in_emails = False
                in_hosts  = False

        # Extract emails
        for email in _EMAIL_RE.findall(stripped):
            if email not in emails_seen:
                emails_seen.add(email)
                result["emails"].append(email)

        # Extract subdomains / IPs from host lines
        if in_hosts or "." in stripped:
            for ip in _IP_RE.findall(stripped):
                if ip not in ips_seen:
                    ips_seen.add(ip)
                    result["ips"].append(ip)
            for domain in _DOMAIN_RE.findall(stripped):
                if domain not in subs_seen and len(domain) > 4:
                    subs_seen.add(domain)
                    result["subdomains"].append(domain)

    result["total_emails"]     = len(result["emails"])
    result["total_subdomains"] = len(result["subdomains"])
    result["total_ips"]        = len(result["ips"])
    return result
