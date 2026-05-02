"""
kernox.engine.state_parser — Auto-parse tool output into structured state.

Called after every tool run. Extracts hosts, ports, paths, vulns
from raw output and feeds them into SessionState so context_builder
always has real structured data — not just counts.

This is what makes agent memory actually useful.
"""

from __future__ import annotations

import re
from kernox.engine.state import SessionState


# ── nmap port line ─────────────────────────────────────────────────────────────
_NMAP_PORT_RE = re.compile(
    r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)(?:\s+(.*))?$"
)
# nmap OS detection
_NMAP_OS_RE = re.compile(r"OS details?:\s+(.+)$", re.IGNORECASE)
# nmap hostname
_NMAP_HOST_RE = re.compile(r"Nmap scan report for (?:([^\s(]+)\s+)?\(?([\d.]+)\)?")

# ffuf/gobuster path line
_PATH_RE = re.compile(
    r"(?:/[^\s]+)\s+(?:\(Status:\s*(\d+)\))?|"
    r'"url":\s*"([^"]+)"',
)
_GOBUSTER_RE = re.compile(r"(/[^\s]+)\s+\(Status:\s*(\d+)\)")
_FFUF_LINE_RE = re.compile(r"\*\s+\w+\s+\[Status:\s*(\d+)[^\]]*\]\s+\*\s+\S+\s+(/.+)")

# hydra credential
_HYDRA_CRED_RE = re.compile(
    r"\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)"
)

# searchsploit
_SPLOIT_RE = re.compile(r"(.{30,})\s+\|\s+(\S+\.(?:py|rb|c|sh|txt|php))", re.IGNORECASE)


def auto_parse(tool_name: str, target: str, raw_output: str,
               state: SessionState) -> None:
    """
    Parse raw_output for tool_name and update state with structured data.
    Always safe — exceptions are swallowed so core flow never breaks.
    """
    if not raw_output.strip():
        return
    try:
        fn = _PARSERS.get(tool_name.lower().split()[0])
        if fn:
            fn(target, raw_output, state)
        # Run generic path parser for any web tool
        if tool_name.lower() in ("ffuf","gobuster","dirb","feroxbuster","dirsearch"):
            _parse_paths(target, raw_output, state)
    except Exception:
        pass


# ── Per-tool parsers ──────────────────────────────────────────────────────────

def _parse_nmap(target: str, raw: str, state: SessionState) -> None:
    current_ip   = target
    current_host = ""

    for line in raw.splitlines():
        # Scan report line → extract IP + hostname
        hm = _NMAP_HOST_RE.search(line)
        if hm:
            current_host = hm.group(1) or ""
            current_ip   = hm.group(2) or target
            state.upsert_host(current_ip, hostname=current_host)
            continue

        # OS detection
        om = _NMAP_OS_RE.search(line)
        if om and current_ip:
            state.upsert_host(current_ip, os=om.group(1).strip()[:80])
            continue

        # Port line
        pm = _NMAP_PORT_RE.match(line.strip())
        if pm and pm.group(3) == "open" and current_ip:
            port    = int(pm.group(1))
            proto   = pm.group(2)
            service = pm.group(4)
            version = (pm.group(5) or "").strip()[:80]
            state.add_ports(current_ip, [{
                "port": port, "proto": proto,
                "service": service, "version": version,
            }])


def _parse_ffuf(target: str, raw: str, state: SessionState) -> None:
    # JSON output
    if '"results"' in raw:
        import json as _j
        try:
            data = _j.loads(raw)
            findings = [
                {"path": r.get("url",""), "status": r.get("status",0),
                 "size": r.get("length",0)}
                for r in data.get("results", [])
            ]
            if findings:
                state.add_paths(target, findings)
            return
        except Exception:
            pass
    # Text output
    findings = []
    for line in raw.splitlines():
        m = _FFUF_LINE_RE.search(line)
        if m:
            findings.append({"path": m.group(2).strip(), "status": int(m.group(1))})
    if findings:
        state.add_paths(target, findings)


def _parse_gobuster(target: str, raw: str, state: SessionState) -> None:
    findings = []
    for line in raw.splitlines():
        m = _GOBUSTER_RE.search(line)
        if m:
            findings.append({"path": m.group(1), "status": int(m.group(2))})
    if findings:
        state.add_paths(target, findings)


def _parse_paths(target: str, raw: str, state: SessionState) -> None:
    """Generic path parser for dirb, feroxbuster etc."""
    findings = []
    for line in raw.splitlines():
        # Lines starting with a path
        m = re.search(r'(GET|POST)?\s+(/[^\s"]+)', line)
        if m:
            path = m.group(2)
            if len(path) > 1 and not path.endswith(".map"):
                findings.append({"path": path, "status": 0})
    if findings:
        state.add_paths(target, findings)


def _parse_hydra(target: str, raw: str, state: SessionState) -> None:
    for line in raw.splitlines():
        m = _HYDRA_CRED_RE.search(line)
        if m:
            state.add_vuln(target, {
                "type":     "credential",
                "port":     m.group(1),
                "service":  m.group(2),
                "login":    m.group(4),
                "password": m.group(5),
            })


def _parse_searchsploit(target: str, raw: str, state: SessionState) -> None:
    for line in raw.splitlines():
        m = _SPLOIT_RE.search(line)
        if m:
            state.add_vuln(target, {
                "type":  "exploit",
                "title": m.group(1).strip()[:100],
                "path":  m.group(2).strip(),
            })


def _parse_nikto(target: str, raw: str, state: SessionState) -> None:
    for line in raw.splitlines():
        if line.strip().startswith("+ ") and len(line) > 10:
            state.add_vuln(target, {
                "type":   "web_finding",
                "detail": line.strip()[2:200],
            })


def _parse_sqlmap(target: str, raw: str, state: SessionState) -> None:
    if "is vulnerable" in raw.lower() or "parameter" in raw.lower():
        state.add_vuln(target, {
            "type":   "sqli",
            "detail": "SQLMap identified injection point",
        })


_PARSERS: dict = {
    "nmap":          _parse_nmap,
    "masscan":       _parse_nmap,   # similar output format
    "ffuf":          _parse_ffuf,
    "gobuster":      _parse_gobuster,
    "dirb":          _parse_paths,
    "feroxbuster":   _parse_paths,
    "dirsearch":     _parse_paths,
    "hydra":         _parse_hydra,
    "medusa":        _parse_hydra,
    "searchsploit":  _parse_searchsploit,
    "nikto":         _parse_nikto,
    "sqlmap":        _parse_sqlmap,
}
