"""
kernox.features.cve_lookup — NIST NVD API integration.

Automatically enriches AI findings with CVE data.
API key stored in KeyStore under 'nvd_api_key'.
Without a key: 5 requests/30s limit (still works, just slower).
With a key:    50 requests/30s limit.
"""

from __future__ import annotations

import time
import urllib.request
import urllib.parse
import json
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from kernox.security.key_store import KeyStore

console = Console()

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_last_request_time: float = 0.0
_RATE_LIMIT_DELAY = 6.5   # seconds between requests (no-key tier safe)


def _get_api_key() -> Optional[str]:
    try:
        return KeyStore().retrieve("nvd_api_key")
    except Exception:
        return None


def _rate_limit() -> None:
    global _last_request_time
    elapsed = time.monotonic() - _last_request_time
    if elapsed < _RATE_LIMIT_DELAY:
        time.sleep(_RATE_LIMIT_DELAY - elapsed)
    _last_request_time = time.monotonic()


def search_cve(keyword: str, max_results: int = 5) -> list[dict]:
    """Search NVD for CVEs matching keyword. Returns list of CVE dicts."""
    _rate_limit()
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
    }
    url = f"{NVD_BASE}?{urllib.parse.urlencode(params)}"
    headers = {"Accept": "application/json"}
    api_key = _get_api_key()
    if api_key:
        headers["apiKey"] = api_key

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        return _parse_cves(data.get("vulnerabilities", []))
    except Exception as exc:
        console.print(f"[dim]⚠ CVE lookup failed: {exc}[/dim]")
        return []


def lookup_cve_id(cve_id: str) -> Optional[dict]:
    """Look up a specific CVE by ID like CVE-2021-44228."""
    _rate_limit()
    url = f"{NVD_BASE}?cveId={cve_id.upper()}"
    headers = {"Accept": "application/json"}
    api_key = _get_api_key()
    if api_key:
        headers["apiKey"] = api_key

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        vulns = _parse_cves(data.get("vulnerabilities", []))
        return vulns[0] if vulns else None
    except Exception:
        return None


def _parse_cves(raw: list[dict]) -> list[dict]:
    results = []
    for item in raw:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        desc_list = cve.get("descriptions", [])
        desc = next((d["value"] for d in desc_list if d.get("lang") == "en"), "")

        # CVSS v3 score
        metrics = cve.get("metrics", {})
        cvss_score = None
        cvss_vector = ""
        cvss_severity = ""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                if "cvssData" in m:
                    cvss_score    = m["cvssData"].get("baseScore")
                    cvss_vector   = m["cvssData"].get("vectorString", "")
                    cvss_severity = m["cvssData"].get("baseSeverity", "")
                break

        refs = [r["url"] for r in cve.get("references", [])[:3]]
        published = cve.get("published", "")[:10]

        results.append({
            "id":           cve_id,
            "description":  desc[:400],
            "cvss_score":   cvss_score,
            "cvss_severity":cvss_severity,
            "cvss_vector":  cvss_vector,
            "published":    published,
            "references":   refs,
        })
    return results


def enrich_finding(vuln_name: str, tool_name: str) -> None:
    """
    Called automatically from ai_analyzer after each finding.
    Shows top CVEs if found, graceful fallback message if not.
    """
    search = vuln_name.replace(" ", "+")[:60]
    cves   = search_cve(search, max_results=3)

    if cves:
        display_cves(cves, title=f"CVEs — {vuln_name[:50]}")
    else:
        # No match — show honest fallback, never silent nothing
        console.print(
            f"  [dim]No NVD match for '{vuln_name[:50]}' — "
            f"search manually: https://nvd.nist.gov/vuln/search?query="
            f"{urllib.parse.quote(vuln_name[:40])}[/dim]"
        )


def display_cves(cves: list[dict], title: str = "CVE Results") -> None:
    """Render CVEs as a clean table."""
    if not cves:
        console.print("[dim]No CVEs found.[/dim]")
        return

    t = Table(
        title=title,
        box=box.MINIMAL,
        show_header=True,
        header_style="bold cyan",
        border_style="dim cyan",
        padding=(0, 1),
    )
    t.add_column("CVE ID",    style="cyan",  width=18)
    t.add_column("CVSS",      width=6)
    t.add_column("SEV",       width=10)
    t.add_column("Published", style="dim", width=12)
    t.add_column("Description")

    for c in cves:
        score = c.get("cvss_score")
        sev   = c.get("cvss_severity", "").upper()
        col   = _sev_color(sev)
        t.add_row(
            f"[cyan]{c['id']}[/cyan]",
            f"[{col}]{score or '—'}[/{col}]",
            f"[{col}]{sev or '—'}[/{col}]",
            c.get("published", ""),
            c.get("description", "")[:80],
        )
    console.print(t)


def interactive_cve_lookup() -> None:
    """Command: `cve <query>` or `cve CVE-XXXX-XXXXX`."""
    from rich.prompt import Prompt
    query = Prompt.ask("  CVE search / CVE-ID")
    if not query.strip():
        return
    if query.upper().startswith("CVE-"):
        result = lookup_cve_id(query)
        if result:
            display_cves([result], title=query.upper())
        else:
            console.print("[dim]Not found.[/dim]")
    else:
        cves = search_cve(query, max_results=8)
        display_cves(cves, title=f"CVEs: {query}")


def _sev_color(sev: str) -> str:
    return {
        "CRITICAL": "#ff6b6b",
        "HIGH":     "red",
        "MEDIUM":   "#00b894",
        "LOW":      "cyan",
    }.get(sev, "dim white")
