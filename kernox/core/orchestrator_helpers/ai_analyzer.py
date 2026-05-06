"""
ai_analyzer.py — Post-execution AI analysis.

ONE AI call per chunk. Reflection + structured extraction in same response.
Full output chunked at 10k chars. Anti-hallucination prompts with real examples.
NEVER suggests patching or remediation.
"""

from __future__ import annotations

import json
import re
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

CHUNK_SIZE = 10000

ANALYSIS_SYSTEM = (
    "You are an offensive security AI. "
    "Find exploitable vulnerabilities and extract all structured data from tool output. "
    "NEVER mention patching, hardening, or remediation. "
    "Return ONLY valid JSON. No markdown fences."
)


def _build_prompt(tool: str, target: str, mode: str,
                  chunk_info: str, output: str) -> str:
    """
    Build analysis prompt with real concrete examples — not placeholder strings.
    Real examples prevent the AI from echoing the schema back as its answer.
    """
    return (
        f"Tool: {tool}\nTarget: {target}\nMode: {mode}\n"
        f"{chunk_info}"
        f"\nOUTPUT:\n{output}\n\n"
        "Analyze the output above. Return this JSON schema filled with real data "
        "(use empty arrays [] for sections with no findings):\n"
        "{\n"
        '  "summary": "one sentence describing what was found",\n'
        '  "hosts": [{"ip": "192.168.1.1", "hostname": "web01", "os": "Linux 4.x"}],\n'
        '  "ports": [{"ip": "192.168.1.1", "port": 80, "proto": "tcp", '
        '"service": "http", "version": "Apache 2.4"}],\n'
        '  "credentials": [{"host": "192.168.1.1", "service": "ftp", '
        '"login": "admin", "password": "password123"}],\n'
        '  "paths": [{"path": "/admin", "status": 200}],\n'
        '  "vulnerabilities": [{"name": "vsftpd 2.3.4 Backdoor", '
        '"severity": "critical", '
        '"description": "vsftpd 2.3.4 has a deliberate backdoor", '
        '"impact": "unauthenticated root shell", '
        f'"exploit": "msfconsole -q -x \'use exploit/unix/ftp/vsftpd_234_backdoor; '
        f'set RHOSTS {target}; run\'"}},\n'
        '  "next_steps": [{"tool": "shell", '
        f'"args": {{"command": "searchsploit vsftpd 2.3.4", "target": "{target}"}}, '
        '"reason": "find additional exploits"}],\n'
        '  "reflection": "vsftpd backdoor found — exploit directly before scanning further"\n'
        "}\n"
        f"Apply {mode} timing to all suggested commands. "
        "Exploit-focused only. No remediation advice."
    )


def extract_json(text: str) -> dict | None:
    text = text.strip()
    if text.startswith("```"):
        text = "\n".join(
            l for l in text.split("\n") if not l.strip().startswith("```")
        ).strip()
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group())
    except json.JSONDecodeError:
        # Try to fix truncated JSON by closing open structures
        fragment = m.group().rstrip()
        for suffix in [']}', ']}]}', '}]}', '}}']:
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
    def __init__(self, ai_client, state, intensity):
        self._ai        = ai_client
        self._state     = state
        self._intensity = intensity
        self._reflection: "ReflectionEngine | None" = None

    def set_reflection_engine(self, engine) -> None:
        self._reflection = engine

    def analyze(self, tool_name: str, target: str, raw_output: str) -> list[dict]:
        """
        Analyze full tool output in chunks.
        Each chunk: extract vulns + hosts/ports/creds/paths + reflection.
        No separate AI calls for state parsing.
        Returns validated next_steps.
        """
        if not raw_output.strip():
            return []

        mode   = self._intensity.get("name", "NORMAL")
        chunks = _chunk_output(raw_output, CHUNK_SIZE)
        total  = len(chunks)

        all_vulns, all_steps, all_summaries = [], [], []

        for idx, chunk in enumerate(chunks, 1):
            chunk_info = f"[Part {idx} of {total}]\n" if total > 1 else ""
            prompt     = _build_prompt(
                tool=tool_name, target=target, mode=mode,
                chunk_info=chunk_info, output=chunk,
            )
            spinner_txt = (
                f"[cyan]Analyzing part {idx}/{total}...[/cyan]"
                if total > 1 else "[cyan]Analyzing...[/cyan]"
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
                    auto_parse(tool_name, target, "", self._state,
                               parsed_data=data)
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

        # Deduplicate vulns by name (single clean pass)
        unique_vulns = []
        seen_names   = set()
        for v in all_vulns:
            n = v.get("name", "").lower()
            if n and n not in seen_names:
                seen_names.add(n)
                unique_vulns.append(v)

        unique_steps = []
        seen_cmds    = set()
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
                log_finding(vuln.get("name",""), vuln.get("severity","info"),
                            tool_name, target, vuln.get("exploit",""))
                render_score_from_finding(vuln)
                if vuln.get("severity","").lower() in ("critical","high"):
                    from kernox.features.cve_lookup import enrich_finding
                    enrich_finding(vuln.get("name",""), tool_name)
            except Exception:
                pass

        valid = []
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
