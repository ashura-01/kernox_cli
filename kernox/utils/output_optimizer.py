"""
kernox.core.output_cleaner
Cleans raw Kali tool output into plain minimal text for AI analysis.
Covers: nmap, masscan, whatweb, gobuster, ffuf, nikto, sqlmap,
        metasploit, hydra, john, hashcat, enum4linux, dirb, wpscan.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class CleanOutput:
    text: str            
    tool: str
    target: str
    findings: List[str]
    truncated: int       

    def __str__(self) -> str:
        return self.text


class OutputCleaner:

    # ── Tool fingerprints ──────────────────────────────────────────────
    _TOOLS: List[Tuple[str, str]] = [
        (r'Nmap \d+\.\d+',                       'nmap'),
        (r'masscan V\d+|MASSCAN',                 'masscan'),
        (r'WhatWeb',                              'whatweb'),
        (r'Gobuster v\d+|by OJ Reeves',           'gobuster'),
        (r'Nikto v\d+',                           'nikto'),
        (r'ffuf v\d+|Fuzz Faster',                'ffuf'),
        (r'sqlmap/\d+|sqlmap identified',         'sqlmap'),
        (r'Metasploit Framework|msf\d*\s*>',      'metasploit'),
        (r'\[hydra\]|Hydra v\d+',                 'hydra'),
        (r'John the Ripper|john\s+\d+\.\d+',      'john'),
        (r'hashcat \(v\d+|Hashcat',               'hashcat'),
        (r'enum4linux|Enum4linux',                'enum4linux'),
        (r'DIRB v\d+',                            'dirb'),
        (r'WPScan v\d+',                          'wpscan'),
        (r'nuclei v\d+',                          'nuclei'),
    ]

    # ── Inline noise to strip (regex, replacement) ─────────────────────
    _STRIP: List[Tuple[str, str]] = [
        (r'\x1b\[[0-9;]*[mGKHFABCDsuJT]', ''),   # ANSI color/cursor
        (r'\x1b[=>]', ''),                         # ANSI misc
        (r'\r[^\n]*', ''),                         # carriage-return overwrite
        (r'[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏►◄▸▹●○✓✗]', ''),          # spinners / symbols
        (r'\[[=#\-\s]+\]\s*\d+%', ''),             # progress bars [====] 45%
        (r'\[\d{2}:\d{2}:\d{2}\]', ''),            # [HH:MM:SS] timestamps
        (r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?', ''),
        (r'^\s*\[(DEBUG|TRACE|VERBOSE|INFO|V)\]\s*', ''),
        (r'[ \t]+$', ''),                           # trailing spaces
    ]

    _DROP: List[str] = [
        r'^\s*$',
        r'^[=\-\*#~_]{6,}\s*$',
        r'^\s*\.{3,}\s*$',
        r'^Loading\b|^Please wait|^Initializing',
        r'^Starting\s+\w+.*\d{4}$',
        r'^\[.*\]\s*$',
    ]

    _SIGNAL: List[str] = [
        r'\d{1,5}/(tcp|udp)',
        r'\b(open|closed|filtered)\b',
        r'(\d{1,3}\.){3}\d{1,3}',
        r'CVE-\d{4}-\d{4,}',
        r'MS\d{2}-\d{3}',
        r'\b(vuln|vulnerable|exploit|RCE|LFI|XSS|SQLi|IDOR)\b',
        r'\[(CRITICAL|HIGH|MEDIUM|LOW)\]',
        r'CVSS',
        r'\b(password|passwd|credential|hash|token|secret)\b',
        r'login.*success|session.*opened|shell.*opened',
        r'\b(admin|root)\b.*(access|shell|session)',
        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
        r'https?://\S+',
        r'\b(found|discovered|identified|detected)\b',
        r'(200|301|302|401|403|500)\s',
        r'ERROR|Exception|Failed|Timeout',
        r'\b(username|user):\s*\S+',
    ]

    _FINDING_PATTERNS: List[Tuple[str, str]] = [
        (r'(\d{1,5}/(tcp|udp)\s+open\s+\S+.*)',   'port'),
        (r'(CVE-\d{4}-\d{4,}.*)',                  'cve'),
        (r'(MS\d{2}-\d{3}.*)',                     'patch'),
        (r'(login.*success.*|session.*opened.*)',   'auth'),
        (r'(password.*found.*|hash.*cracked.*)',    'cred'),
        (r'(VULNERABLE.*)',                         'vuln'),
        (r'(\[CRITICAL\].*|\[HIGH\].*)',            'severity'),
        (r'(https?://\S+)',                         'url'),
    ]

    # ──────────────────────────────────────────────────────────────────
    #  Public API
    # ──────────────────────────────────────────────────────────────────

    @classmethod
    def clean(cls, raw: str, max_lines: int = 80) -> CleanOutput:
        """
        Clean raw tool output for AI consumption.

        Args:
            raw:       Raw stdout/stderr from any Kali tool.
            max_lines: Max lines passed to the AI (default 80).

        Returns:
            CleanOutput — use str() or .text for the AI-ready string.
        """
        if not raw or not raw.strip():
            return CleanOutput("no output", "unknown", "", [], 0)

        text = cls._strip_noise(raw)

        lines = []
        for line in text.splitlines():
            line = re.sub(r'\s+', ' ', line).strip()
            if not line:
                continue
            if cls._is_signal(line) or not cls._is_drop(line):
                lines.append(line)

        lines = cls._dedup(lines)

        tool   = cls._detect_tool(raw)
        target = cls._detect_target(raw)

        findings = cls._extract_findings(lines)

        truncated = 0
        if len(lines) > max_lines:
            truncated = len(lines) - max_lines
            head = int(max_lines * 0.65)
            tail = max_lines - head
            lines = (
                lines[:head]
                + [f"... {truncated} lines removed ..."]
                + lines[-tail:]
            )

        text = cls._build(tool, target, lines, findings, truncated)
        return CleanOutput(text, tool, target, findings, truncated)


    @classmethod
    def _strip_noise(cls, text: str) -> str:
        for pattern, replacement in cls._STRIP:
            text = re.sub(pattern, replacement, text, flags=re.MULTILINE)
        return text

    @classmethod
    def _is_signal(cls, line: str) -> bool:
        return any(re.search(p, line, re.IGNORECASE) for p in cls._SIGNAL)

    @classmethod
    def _is_drop(cls, line: str) -> bool:
        return any(re.search(p, line, re.IGNORECASE) for p in cls._DROP)

    @classmethod
    def _dedup(cls, lines: List[str], max_run: int = 2) -> List[str]:
        out, prev, run = [], None, 0
        for line in lines:
            if line == prev:
                run += 1
                if run <= max_run:
                    out.append(line)
                elif run == max_run + 1:
                    out.append(f"[{run} identical lines collapsed]")
            else:
                run = 0
                prev = line
                out.append(line)
        return out

    @classmethod
    def _detect_tool(cls, raw: str) -> str:
        for pattern, name in cls._TOOLS:
            if re.search(pattern, raw, re.IGNORECASE):
                return name
        return "unknown"

    @classmethod
    def _detect_target(cls, raw: str) -> str:
        m = re.search(r'scan report for ([\w.\-]+)', raw)
        if m:
            return m.group(1)
        m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', raw)
        if m:
            return m.group(1)
        m = re.search(r'https?://([\w.\-]+)', raw)
        if m:
            return m.group(1)
        return ""

    @classmethod
    def _extract_findings(cls, lines: List[str]) -> List[str]:
        seen, findings = set(), []
        for line in lines:
            for pattern, _ in cls._FINDING_PATTERNS:
                m = re.search(pattern, line, re.IGNORECASE)
                if m:
                    val = m.group(1).strip()
                    if val not in seen:
                        seen.add(val)
                        findings.append(val)
                    break
        return findings[:20]

    @classmethod
    def _build(
        cls,
        tool: str,
        target: str,
        lines: List[str],
        findings: List[str],
        truncated: int,
    ) -> str:
        parts = []

        parts.append(f"TOOL: {tool}")
        if target:
            parts.append(f"TARGET: {target}")
        parts.append("")
        parts.extend(lines)

        if findings:
            parts.append("")
            parts.append("FINDINGS:")
            for f in findings:
                parts.append(f"- {f}")

        if truncated:
            parts.append("")
            parts.append(f"NOTE: {truncated} low-signal lines removed.")

        return "\n".join(parts)



def clean(raw: str, max_lines: int = 80) -> str:
    """Returns the AI-ready string directly."""
    return OutputCleaner.clean(raw, max_lines).text



# if __name__ == "__main__":
#     sample = """
# \x1b[1;32mStarting Nmap 7.94\x1b[0m
# ⠙ Scanning 192.168.1.1...
# [DEBUG] raw socket ok
# [INFO] resolving host
# Nmap scan report for 192.168.1.1
# Host is up (0.0023s latency).

# PORT     STATE    SERVICE  VERSION
# 22/tcp   open     ssh      OpenSSH 8.9
# 80/tcp   open     http     Apache 2.4.52
# 443/tcp  open     https    Apache 2.4.52
# 3306/tcp closed   mysql
# 8080/tcp filtered http-proxy

# |_CVE-2023-38408: VULNERABLE OpenSSH pre-auth RCE [CRITICAL]
# |_smb-vuln-ms17-010: VULNERABLE (MS17-010 EternalBlue) [HIGH]

# Host script results:
# | smb-security-mode:
# |   account_used: guest

# ============================================
# ============================================
# Nmap done: 1 IP address scanned in 12.34 seconds
# """
#     result = OutputCleaner.clean(sample)
#     print(result.text)
#     print(f"\ntool={result.tool}  target={result.target}  findings={len(result.findings)}")