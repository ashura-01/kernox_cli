"""
ai_analyzer.py — Post-execution AI analysis.

ONE AI call per chunk. Reflection folded in — no separate round-trip.
Full output chunked at 10k chars, sent completely to AI.
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

if TYPE_CHECKING:
    from .reflection_engine import ReflectionEngine

console = Console()

CHUNK_SIZE = 10000   # larger chunks = fewer AI calls

# Tight system prompt — attacker only, no patching
ANALYSIS_SYSTEM = (
    "You are an offensive security AI. "
    "Find exploitable vulnerabilities and suggest attack commands. "
    "NEVER mention patching, hardening, or remediation. "
    "Return ONLY valid JSON. No markdown."
)

# Tight analysis prompt — folded reflection + next steps in ONE call
_PROMPT_TEMPLATE = (
    "Tool:{tool} Target:{target} Mode:{mode}\n"
    "{chunk_info}"
    "OUTPUT:\n{output}\n\n"
    "Return JSON:\n"
    '{{"summary":"one line","vulnerabilities":[{{"name":"","severity":"critical|high|medium|low|info","description":"","impact":"","exploit":"exact_runnable_cmd_for_{target}"}}],"next_steps":[{{"tool":"shell","args":{{"command":"exact_cmd_mode_{mode}","target":"{target}"}},"reason":"why"}}],"reflection":"what changed, best attack path now"}}\n'
    "Rules: exploit commands only — no patch advice. "
    "next_steps: 1-3 highest-impact attacks not yet run. "
    "Empty arrays OK if nothing found."
)


def extract_json(text: str) -> dict | None:
    text = text.strip()
    if text.startswith("```"):
        text = "\n".join(l for l in text.split("\n") if not l.strip().startswith("```")).strip()
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group())
    except json.JSONDecodeError:
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
        Analyze full tool output.
        Reflection folded into same call — no separate round-trip.
        Returns validated next_steps.
        """
        if not raw_output.strip():
            return []

        mode   = self._intensity.get("name", "NORMAL")
        chunks = _chunk_output(raw_output, CHUNK_SIZE)
        total  = len(chunks)

        all_vulns, all_steps, all_summaries = [], [], []

        for idx, chunk in enumerate(chunks, 1):
            chunk_info = f"[chunk {idx}/{total}]\n" if total > 1 else ""
            prompt = _PROMPT_TEMPLATE.format(
                tool=tool_name, target=target, mode=mode,
                chunk_info=chunk_info, output=chunk,
            )

            spinner_txt = (
                f"[cyan]Analyzing {idx}/{total}...[/cyan]"
                if total > 1 else "[cyan]Analyzing...[/cyan]"
            )

            try:
                with Live(Spinner("dots", text=spinner_txt), refresh_per_second=10):
                    response = self._ai.chat(
                        messages=[{"role": "user", "content": prompt}],
                        system=ANALYSIS_SYSTEM,
                        max_tokens=1200,
                    )

                data = extract_json(response)
                if not data:
                    if total == 1:
                        console.print("[dim]⚠ No analysis returned[/dim]")
                    continue

                if data.get("summary"):
                    all_summaries.append(data["summary"])
                all_vulns.extend(data.get("vulnerabilities", []))
                all_steps.extend(data.get("next_steps", []))

                # Store reflection from THIS call — no extra round-trip
                if data.get("reflection") and self._reflection:
                    self._state.add_note(
                        f"[REFLECTION after {tool_name}] {data['reflection']}"
                    )
                    console.print(f"\n[dim cyan]⟳ {data['reflection']}[/dim cyan]")

            except Exception as exc:
                console.print(f"[red]✗ Analysis error: {exc}[/red]")

        if not all_summaries and not all_vulns:
            return []

        # Deduplicate
        seen_v, seen_s = set(), set()
        unique_vulns = [v for v in all_vulns
                        if v.get("name") and not (seen_v.add(v["name"].lower()) or
                           v["name"].lower() in seen_v - {v["name"].lower()})]
        # simpler dedup
        unique_vulns = []
        seen_names = set()
        for v in all_vulns:
            n = v.get("name","").lower()
            if n and n not in seen_names:
                seen_names.add(n)
                unique_vulns.append(v)

        unique_steps = []
        seen_cmds = set()
        for s in all_steps:
            c = s.get("args",{}).get("command","")
            if c and c not in seen_cmds:
                seen_cmds.add(c)
                unique_steps.append(s)

        # Display
        summary = " | ".join(all_summaries) if all_summaries else ""
        OutputFormatter.format_analysis_summary(summary, unique_steps[:3])

        for vuln in unique_vulns[:10]:
            if not vuln.get("name"):
                continue
            OutputFormatter.format_vulnerability(vuln)
            self._state.add_ai_insight(
                vulnerability=vuln.get("name",""),
                severity=vuln.get("severity","info"),
                tool=tool_name, target=target,
                explanation=vuln,
            )
            # Enrichment — additive, never breaks flow
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

        # Validate next steps
        valid = []
        for step in unique_steps[:3]:
            cmd = step.get("args",{}).get("command","")
            if not cmd:
                continue
            san = sanitize(cmd, None)
            if san.allowed:
                valid.append(step)
            else:
                console.print(f"[dim]⚠ Blocked: {san.reason}[/dim]")

        return valid
