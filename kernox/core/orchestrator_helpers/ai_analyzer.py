"""
ai_analyzer.py — Post-execution AI analysis.

ONE AI call per chunk. Reflection + structured extraction in same response.
Full output chunked at 10k chars. Anti-hallucination prompts with real examples.
NEVER suggests patching or remediation.

Fixes applied:
  1. Rate limiting  — enforced sleep between chunk API calls (configurable)
  2. Generic prompt — no hardcoded vsftpd example; uses neutral placeholder
  3. Input validation — early return on empty/invalid tool_name or target
  4. JSON repair    — only attempted on fragments long enough to be truncated
  5. NVD dedup      — class-level set tracks enriched vulns; never enriches twice
"""

from __future__ import annotations

import json
import re
import time
from typing import TYPE_CHECKING
from rich.console import Console
from rich.live import Live
from rich.spinner import Spinner

from kernox.guards.shell_sanitizer import sanitize
from .output_formatter import OutputFormatter
from rich.prompt import Prompt

if TYPE_CHECKING:
    from .reflection_engine import ReflectionEngine

console = Console()

CHUNK_SIZE = 100_000

# Minimum seconds to wait between consecutive AI calls within one analyze() run.
# Groq free tier: ~30 req/min → 2 s gives comfortable headroom.
# Set to 0 to disable (e.g. when using a provider without rate limits).
INTER_CHUNK_DELAY: float = 1.5

# Only attempt JSON repair on fragments at least this long.
# Short fragments that fail to parse are almost certainly garbage, not truncation.
MIN_REPAIR_LENGTH = 500

ANALYSIS_SYSTEM = (
    "You are an offensive security AI. "
    "Find exploitable vulnerabilities and extract all structured data from tool output. "
    "NEVER mention patching, hardening, or remediation. "
    "Return ONLY valid JSON. No markdown fences."
)


def _build_prompt(
    tool: str, target: str, mode: str, chunk_info: str, output: str
) -> str:
    return (
        f"Tool: {tool}\nTarget: {target}\nMode: {mode}\n"
        f"{chunk_info}"
        f"\nOUTPUT:\n{output}\n\n"
        "Analyze the output above. Return this JSON schema filled with real data "
        "(use empty arrays [] for sections with no findings):\n\n"
        "CRITICAL: Extract EXACT software names and versions from the output (e.g., 'vsftpd 2.3.4', 'OpenSSH 7.2p2'). "
        "Do NOT use placeholders like 'EXACT_SOFTWARE_VERSION'.\n\n"
        "{\n"
        '  "summary": "one sentence describing what was found",\n'
        '  "hosts": [{"ip": "192.168.1.1", "hostname": "host01", "os": "Linux"}],\n'
        '  "ports": [{"ip": "192.168.1.1", "port": 80, "proto": "tcp", '
        '"service": "http", "version": "Apache 2.4"}],\n'
        '  "credentials": [{"host": "192.168.1.1", "service": "ftp", '
        '"login": "admin", "password": "secret"}],\n'
        '  "paths": [{"path": "/admin", "status": 200}],\n'
        '  "vulnerabilities": [{"name": "vsftpd 2.3.4 Backdoor", '
        '"severity": "critical", '
        '"description": "vsftpd 2.3.4 has a deliberate backdoor", '
        '"impact": "unauthenticated root shell", '
        f'"exploit": "msfconsole -q -x \'use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS {target}; run\'"}}],\n'
        '  "next_steps": [{"tool": "shell", '
        f'"args": {{"command": "searchsploit vsftpd 2.3.4", "target": "{target}"}}, '
        '"reason": "find additional exploits for discovered service"}],\n'
        '  "reflection": "high-value service found — exploit directly before broader scanning"\n'
        "}\n"
        f"Apply {mode} timing to all suggested commands. "
        "Exploit-focused only. No remediation advice."
    )


def extract_json(text: str) -> dict | None:
    text = text.strip()
    if text.startswith("```"):
        text = "\n".join(
            line for line in text.split("\n") if not line.strip().startswith("```")
        ).strip()

    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return None

    fragment = m.group()

    # Fast path: valid as-is
    try:
        return json.loads(fragment)
    except json.JSONDecodeError:
        pass

    # Repair only makes sense for fragments long enough to be truncated JSON.
    # Short failures are almost always garbage or schema echoes — don't waste
    # time trying to patch them; return None and let the caller handle it.
    if len(fragment) < MIN_REPAIR_LENGTH:
        return None

    fragment = fragment.rstrip()
    for suffix in ["]}", "]}]}", "}]}", "}}"]:
        try:
            return json.loads(fragment + suffix)
        except json.JSONDecodeError:
            continue

    return None


def _chunk_output(text: str, size: int) -> list[str]:
    if len(text) <= size:
        return [text]
    chunks, buf, count = [], [], 0
    for line in text.splitlines(keepends=True):
        if count + len(line) > size and buf:
            chunks.append("".join(buf))
            buf, count = [], 0
        buf.append(line)
        count += len(line)
    if buf:
        chunks.append("".join(buf))
    return chunks


class AIAnalyzer:
    # Class-level set so enrichment dedup survives across multiple analyze() calls
    # within the same session (e.g. analyze all → many chunks all hitting enrich).
    _enriched_vulns: set[str] = set()

    def __init__(self, ai_client, state, intensity):
        self._ai = ai_client
        self._state = state
        self._intensity = intensity
        self._reflection: "ReflectionEngine | None" = None

    def set_reflection_engine(self, engine) -> None:
        self._reflection = engine

    @classmethod
    def reset_enrichment_cache(cls) -> None:
        """Call this on session clear so a fresh session re-enriches everything."""
        cls._enriched_vulns.clear()

    def analyze(self, tool_name: str, target: str, raw_output: str) -> list[dict]:
        """
        Analyze full tool output in chunks.
        Each chunk: extract vulns + hosts/ports/creds/paths + reflection.
        No separate AI calls for state parsing.
        Returns validated next_steps.
        """
        # ── Input validation ──────────────────────────────────────────────────
        if not raw_output or not raw_output.strip():
            return []

        tool_name = (tool_name or "unknown").strip()
        target = (target or "unknown").strip()

        if not tool_name:
            tool_name = "unknown"
        if not target:
            target = "unknown"

        # ── Chunk + iterate ───────────────────────────────────────────────────
        mode = self._intensity.get("name", "NORMAL")
        chunks = _chunk_output(raw_output, CHUNK_SIZE)
        total = len(chunks)

        all_vulns, all_steps, all_summaries = [], [], []

        for idx, chunk in enumerate(chunks, 1):
            # Rate limiting: sleep before every call except the very first
            if idx > 1 and INTER_CHUNK_DELAY > 0:
                time.sleep(INTER_CHUNK_DELAY)

            chunk_info = f"[Part {idx} of {total}]\n" if total > 1 else ""
            prompt = _build_prompt(
                tool=tool_name,
                target=target,
                mode=mode,
                chunk_info=chunk_info,
                output=chunk,
            )
            spinner_txt = (
                f"[cyan]Analyzing part {idx}/{total}...[/cyan]"
                if total > 1
                else "[cyan]Analyzing...[/cyan]"
            )

            try:
                with Live(Spinner("dots", text=spinner_txt), refresh_per_second=10):
                    response = self._ai.chat(
                        messages=[{"role": "user", "content": prompt}],
                        system=ANALYSIS_SYSTEM,
                        max_tokens=2000,
                    )

                data = extract_json(response)
                if not data:
                    if total == 1:
                        console.print("[dim]⚠ No structured analysis returned[/dim]")
                    continue

                if data.get("summary"):
                    all_summaries.append(data["summary"])
                all_vulns.extend(data.get("vulnerabilities", []))
                all_steps.extend(data.get("next_steps", []))

                # Feed structured data to state — no extra AI call
                try:
                    from kernox.engine.state_parser import auto_parse

                    auto_parse(tool_name, target, "", self._state, parsed_data=data)
                except Exception:
                    pass

                # Store reflection
                if data.get("reflection") and self._reflection:
                    self._state.add_note(
                        f"[REFLECTION after {tool_name}] {data['reflection']}"
                    )
                    console.print(f"\n[dim cyan]⟳ {data['reflection']}[/dim cyan]")

            except Exception as exc:
                console.print(f"[red]✗ Analysis error: {exc}[/red]")

        if not all_summaries and not all_vulns:
            return []

        # ── Deduplicate vulns by name ─────────────────────────────────────────
        unique_vulns: list[dict] = []
        seen_names: set[str] = set()
        for v in all_vulns:
            n = v.get("name", "").lower().strip()
            if n and n not in seen_names:
                seen_names.add(n)
                unique_vulns.append(v)

        # ── Deduplicate steps by command ──────────────────────────────────────
        unique_steps: list[dict] = []
        seen_cmds: set[str] = set()
        for s in all_steps:
            c = s.get("args", {}).get("command", "")
            if c and c not in seen_cmds:
                seen_cmds.add(c)
                unique_steps.append(s)

        summary = " | ".join(all_summaries) if all_summaries else ""
        OutputFormatter.format_analysis_summary(summary, unique_steps[:3])

        for vuln in unique_vulns[:10]:
            if not vuln.get("name"):
                continue

            OutputFormatter.format_vulnerability(vuln)
            self._state.add_ai_insight(
                vulnerability=vuln.get("name", ""),
                severity=vuln.get("severity", "info"),
                tool=tool_name,
                target=target,
                explanation=vuln,
            )

            try:
                from kernox.features.attack_log import log_finding
                from kernox.features.exploit_score import render_score_from_finding

                log_finding(
                    vuln.get("name", ""),
                    vuln.get("severity", "info"),
                    tool_name,
                    target,
                    vuln.get("exploit", ""),
                )
                render_score_from_finding(vuln)

                # NVD enrichment — only for critical/high, and only once per
                # unique vuln name across the entire session.
                if vuln.get("severity", "").lower() in ("critical", "high"):
                    vuln_key = vuln.get("name", "").lower().strip()
                    if vuln_key and vuln_key not in AIAnalyzer._enriched_vulns:
                        AIAnalyzer._enriched_vulns.add(vuln_key)
                        from kernox.features.cve_lookup import enrich_finding

                        enrich_finding(vuln.get("name", ""), tool_name)

            except Exception:
                pass

        # ── Validate + sanitize next steps ────────────────────────────────────
        valid: list[dict] = []
        for step in unique_steps[:3]:
            cmd = step.get("args", {}).get("command", "")
            if not cmd:
                continue
            san = sanitize(cmd, None)
            if san.allowed:
                valid.append(step)
            else:
                console.print(f"[dim]⚠ Suggested step blocked: {san.reason}[/dim]")

        return valid
