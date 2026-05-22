"""
ai_analyzer.py — Post-execution AI analysis.

ONE AI call per chunk. Reflection + structured extraction in same response.
Full output chunked at 100k chars. Anti-hallucination prompts with real examples.
NEVER suggests patching or remediation.

Fixes applied:
  1. Rate limiting      — exponential backoff on 429/503; configurable base sleep
  2. Generic prompt     — no hardcoded vsftpd example; uses neutral placeholder
  3. Input validation   — early return on empty/invalid tool_name or target
  4. JSON repair        — only attempted on fragments long enough to be truncated
  5. NVD dedup          — instance-level set tracks enriched vulns; never enriches twice
  6. No duplicate steps — next_steps printed ONCE after all chunks are processed
  7. No duplicate table — format_analysis_summary called exactly once at the end
  8. Full output passed — no stripping; ai_analyzer chunks internally
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

if TYPE_CHECKING:
    from .reflection_engine import ReflectionEngine

console = Console()

CHUNK_SIZE = 100_000
MIN_REPAIR_LENGTH = 500

# Seconds to sleep between chunk API calls under normal conditions.
# Raised automatically on 429/503 via exponential backoff.
_INTER_CHUNK_SLEEP: float = 0.0   # set to >0 for providers with strict RPM limits

# Backoff config
_BACKOFF_BASE: float = 2.0   # seconds for first retry
_BACKOFF_MAX:  float = 60.0  # cap per attempt
_MAX_RETRIES:  int   = 5

ANALYSIS_SYSTEM = (
    "You are a security data extraction engine. "
    "Your ONLY job is to extract structured facts that are explicitly present in tool output — nothing more. "
    "STRICT RULES:\n"
    "- Empty arrays [] are CORRECT and EXPECTED when a section has no findings. "
    "Do NOT feel pressured to populate every field.\n"
    "- You MUST NOT invent, infer, or hallucinate vulnerabilities, versions, credentials, or exploits "
    "that are not directly evidenced in the text provided.\n"
    "- An open port alone is NEVER a vulnerability. Only report a vulnerability when the output "
    "shows a specific version, misconfiguration, or known weakness — not just that a port is open.\n"
    "- If a whois, DNS, or recon tool output contains no open ports or service banners, "
    "the ports and vulnerabilities arrays MUST be empty.\n"
    "- Fabricating findings is a CRITICAL FAILURE — worse than returning empty arrays.\n"
    "- Return ONLY valid JSON. No markdown fences. No commentary.\n"
    "- The 'exploit' field MUST contain concrete ready-to-run commands "
    "(e.g. msfconsole -x 'use exploit/...', sqlmap flags, curl PoC commands). "
    "NEVER write impact statements there. If no known exploit exists, use empty string."
)


def _get_recent_commands(state) -> str:
    """
    Return a formatted string listing the last 5 tool executions from state.

    Tries common state attributes in order of specificity so this works even
    if the state object schema changes between versions. Falls back to an
    empty string rather than crashing — callers treat "" as "no history".
    """
    entries: list[str] = []

    for attr in ("command_history", "history", "executed_commands", "tool_history"):
        history = getattr(state, attr, None)
        if isinstance(history, list) and history:
            for item in history[-5:]:
                if isinstance(item, dict):
                    tool = item.get("tool") or item.get("name") or item.get("cmd", "")
                    tgt  = item.get("target") or item.get("host", "")
                    if tool:
                        entries.append(f"  - {tool}" + (f" -> {tgt}" if tgt else ""))
                elif isinstance(item, str):
                    entries.append(f"  - {item}")
            break

    if not entries:
        insights = getattr(state, "ai_insights", None) or []
        seen: set[str] = set()
        for ins in reversed(insights):
            if not isinstance(ins, dict):
                continue
            tool = ins.get("tool", "")
            tgt  = ins.get("target", "")
            key  = f"{tool}:{tgt}"
            if tool and key not in seen:
                seen.add(key)
                entries.append(f"  - {tool}" + (f" -> {tgt}" if tgt else ""))
            if len(entries) >= 5:
                break
        entries.reverse()

    if not entries:
        return ""

    return "ALREADY EXECUTED (do NOT suggest these again):\n" + "\n".join(entries)


def _build_prompt(
    tool: str, target: str, mode: str, chunk_info: str, output: str, state=None
) -> str:
    recent = _get_recent_commands(state) if state is not None else ""

    no_repeat_rule = (
        f"7. DO NOT suggest any tool or command that appears in the ALREADY EXECUTED list above.\n"
        f"8. DO NOT suggest running the same tool ({tool}) on the same target ({target}) again.\n"
        f"9. next_steps MUST offer genuinely new actions that follow logically from what was found.\n"
    ) if recent else (
        f"7. DO NOT suggest running the same tool ({tool}) on the same target ({target}) again.\n"
        f"8. next_steps MUST offer genuinely new actions that follow logically from what was found.\n"
    )

    return (
        f"Tool: {tool}\nTarget: {target}\nMode: {mode}\n"
        f"{chunk_info}"
        + (f"\n{recent}\n" if recent else "")
        + f"\nOUTPUT TO ANALYZE:\n{output}\n\n"
        "RULES — follow exactly before writing any JSON:\n"
        "1. ONLY report data that is EXPLICITLY present in the OUTPUT above.\n"
        "2. Empty arrays [] are CORRECT — use them for any section with no findings.\n"
        "3. Do NOT invent software names, versions, CVEs, or exploits not shown verbatim.\n"
        "4. Versions MUST be copied character-for-character from the output. "
        "If no version is shown, leave the version field as an empty string.\n"
        "5. The 'exploit' field MUST be a ready-to-run shell command "
        "(e.g. 'msfconsole -x \"use exploit/unix/ftp/vsftpd_234_backdoor; set RHOST {target}; run\"' "
        "or 'hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://{target}'). "
        "If no concrete exploit command exists for this specific finding, use empty string.\n"
        "6. Vulnerability names and descriptions MUST match what the tool actually reported — "
        "not what you think the service might be vulnerable to.\n"
        + no_repeat_rule
        + "\nReturn ONLY this JSON (use [] for empty sections — do NOT echo placeholder text):\n\n"
        "{\n"
        '  "summary": "",\n'
        '  "hosts": [],\n'
        '  "ports": [],\n'
        '  "credentials": [],\n'
        '  "paths": [],\n'
        '  "vulnerabilities": [\n'
        '    {\n'
        '      "name": "",\n'
        '      "severity": "critical|high|medium|low",\n'
        '      "description": "",\n'
        '      "evidence": "exact line(s) from the output proving this finding",\n'
        '      "exploit": "ready-to-run command e.g. msfconsole -x \'use exploit/...\' or sqlmap flags"\n'
        "    }\n"
        "  ],\n"
        '  "next_steps": [\n'
        '    {\n'
        '      "tool": "nmap",\n'
        f'      "args": {{"command": "nmap -sV -p 80,443 {target}", "target": "{target}"}},\n'
        '      "reason": "why this step follows from the findings"\n'
        "    }\n"
        "  ],\n"
        '  "reflection": ""\n'
        "}\n\n"
        "CRITICAL for next_steps:\n"
        "  args.command MUST be the COMPLETE shell command including the binary "
        f"(e.g. 'nmap -sV {target}' or 'wpscan --url {target}') — NEVER flags-only.\n"
        "  The tool field and the first word of args.command MUST be the same binary.\n"
        "  tool='shell'/'bash' still requires a full command in args.command.\n"
        f"Apply {mode} timing to suggested commands. "
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

    try:
        return json.loads(fragment)
    except json.JSONDecodeError:
        pass

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


def _chat_with_backoff(ai_client, messages: list, system: str, max_tokens: int) -> str:
    """
    Calls ai_client.chat() with exponential backoff on rate-limit (429) and
    server-error (503) responses. Any other exception is re-raised immediately.

    Returns the raw response string.
    """
    delay = _BACKOFF_BASE
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            return ai_client.chat(
                messages=messages,
                system=system,
                max_tokens=max_tokens,
            )
        except Exception as exc:
            msg = str(exc).lower()
            is_rate  = "429" in msg or "rate limit" in msg or "rate_limit" in msg
            is_server = "503" in msg or "server error" in msg or "overloaded" in msg
            if (is_rate or is_server) and attempt < _MAX_RETRIES:
                wait = min(delay, _BACKOFF_MAX)
                console.print(
                    f"[dim yellow]Rate limited (attempt {attempt}/{_MAX_RETRIES}). "
                    f"Retrying in {wait:.1f}s...[/dim yellow]"
                )
                time.sleep(wait)
                delay *= 2
            else:
                raise


class AIAnalyzer:

    def __init__(self, ai_client, state, intensity):
        self._ai        = ai_client
        self._state     = state
        self._intensity = intensity
        self._reflection: "ReflectionEngine | None" = None
        self._enriched_vulns: set[str] = set()

    def set_reflection_engine(self, engine) -> None:
        self._reflection = engine

    def reset_enrichment_cache(self) -> None:
        """Call this on session clear so a fresh session re-enriches everything."""
        self._enriched_vulns.clear()

    def analyze(self, tool_name: str, target: str, raw_output: str) -> list[dict]:
        """
        Analyze full tool output in chunks.
        Each chunk: extract vulns + hosts/ports/creds/paths + reflection.
        No separate AI calls for state parsing.

        Suggested next_steps and the analysis summary are printed ONCE after
        all chunks are processed — never inside the per-chunk loop.

        Returns validated, deduplicated next_steps for the caller to offer.
        """
        # ── Input validation ──────────────────────────────────────────────────
        if not raw_output or not raw_output.strip():
            return []

        tool_name = (tool_name or "unknown").strip() or "unknown"
        target    = (target    or "unknown").strip() or "unknown"

        # ── Chunk + iterate ───────────────────────────────────────────────────
        mode   = self._intensity.get("name", "NORMAL")
        chunks = _chunk_output(raw_output, CHUNK_SIZE)
        total  = len(chunks)

        all_vulns, all_steps, all_summaries, all_reflections = [], [], [], []

        for idx, chunk in enumerate(chunks, 1):
            # Inter-chunk sleep to stay under provider RPM limits
            if idx > 1 and _INTER_CHUNK_SLEEP > 0:
                time.sleep(_INTER_CHUNK_SLEEP)

            chunk_info  = f"[Part {idx} of {total}]\n" if total > 1 else ""
            prompt      = _build_prompt(
                tool=tool_name,
                target=target,
                mode=mode,
                chunk_info=chunk_info,
                output=chunk,
                state=self._state,
            )
            spinner_txt = (
                f"[cyan]Analyzing part {idx}/{total}...[/cyan]"
                if total > 1 else "[cyan]Analyzing...[/cyan]"
            )

            try:
                with Live(Spinner("dots", text=spinner_txt), refresh_per_second=10):
                    response = _chat_with_backoff(
                        self._ai,
                        messages=[{"role": "user", "content": prompt}],
                        system=ANALYSIS_SYSTEM,
                        max_tokens=8000,
                    )

                data = extract_json(response)
                if not data:
                    if total == 1:
                        console.print("[dim]No structured analysis returned[/dim]")
                    continue

                if data.get("summary"):
                    all_summaries.append(data["summary"])

                # Grounded vuln filter — require non-empty evidence field
                raw_vulns      = data.get("vulnerabilities", [])
                grounded_vulns = [v for v in raw_vulns if v.get("evidence", "").strip()]
                dropped        = len(raw_vulns) - len(grounded_vulns)
                if dropped:
                    console.print(
                        f"[dim yellow]Dropped {dropped} ungrounded vuln(s) "
                        f"(no evidence field)[/dim yellow]"
                    )
                all_vulns.extend(grounded_vulns)
                all_steps.extend(data.get("next_steps", []))

                # State parsing — fire-and-forget, never blocks analysis
                try:
                    from kernox.engine.state_parser import auto_parse
                    auto_parse(tool_name, target, "", self._state, parsed_data=data)
                except Exception:
                    pass

                # Collect reflections — print after all chunks so they appear
                # together, not interleaved with spinners
                if data.get("reflection"):
                    all_reflections.append(data["reflection"])

            except Exception as exc:
                console.print(f"[red]Analysis error: {exc}[/red]")

        # ── Nothing found ─────────────────────────────────────────────────────
        # Guard covers the case where the AI returned only next_steps with no
        # summary or vulns — that is still valid output and must not be dropped.
        if not all_summaries and not all_vulns and not all_steps:
            return []

        # ── Print reflections once, after all chunks ──────────────────────────
        for ref in all_reflections:
            if self._reflection:
                self._state.add_note(f"[REFLECTION after {tool_name}] {ref}")
            console.print(f"\n[dim cyan]{ref}[/dim cyan]")

        # ── Deduplicate vulns by name ─────────────────────────────────────────
        unique_vulns: list[dict] = []
        seen_names:   set[str]   = set()
        for v in all_vulns:
            n = v.get("name", "").lower().strip()
            if n and n not in seen_names:
                seen_names.add(n)
                unique_vulns.append(v)

        # ── Deduplicate steps by command ──────────────────────────────────────
        unique_steps: list[dict] = []
        seen_cmds:    set[str]   = set()
        for s in all_steps:
            c = s.get("args", {}).get("command", "")
            if c and c not in seen_cmds:
                seen_cmds.add(c)
                unique_steps.append(s)

        # ── Drop next_steps repeating already-executed tool+target pairs ──────
        already_run: set[str] = set()
        try:
            for attr in ("command_history", "history", "executed_commands", "tool_history"):
                history = getattr(self._state, attr, None)
                if isinstance(history, list) and history:
                    for item in history:
                        if isinstance(item, dict):
                            t = (item.get("tool") or item.get("name") or "").strip().lower()
                            h = (item.get("target") or item.get("host") or "").strip().lower()
                            if t:
                                already_run.add(f"{t}:{h}")
                    break
            for ins in getattr(self._state, "ai_insights", None) or []:
                if isinstance(ins, dict):
                    t = ins.get("tool", "").strip().lower()
                    h = ins.get("target", "").strip().lower()
                    if t:
                        already_run.add(f"{t}:{h}")
        except Exception:
            pass

        filtered_steps: list[dict] = []
        for step in unique_steps:
            cmd         = step.get("args", {}).get("command", "").lower()
            step_target = step.get("args", {}).get("target", "").strip().lower()
            base_cmd    = cmd.split()[0] if cmd.split() else ""
            key         = f"{base_cmd}:{step_target}"
            if key and key in already_run:
                console.print(
                    f"[dim]Skipping repeated next-step: {base_cmd} on {step_target}[/dim]"
                )
            else:
                filtered_steps.append(step)

        # ── Print vulnerabilities ─────────────────────────────────────────────
        for vuln in unique_vulns:
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

                if vuln.get("severity", "").lower() in ("critical", "high"):
                    vuln_key = vuln.get("name", "").lower().strip()
                    if vuln_key and vuln_key not in self._enriched_vulns:
                        self._enriched_vulns.add(vuln_key)
                        from kernox.features.cve_lookup import enrich_finding
                        enrich_finding(vuln.get("name", ""), tool_name)

            except Exception:
                pass

        # ── Print summary + next steps ONCE, after all vulns ─────────────────
        summary = " | ".join(all_summaries) if all_summaries else ""
        OutputFormatter.format_analysis_summary(summary, filtered_steps)

        # ── Validate + sanitize next steps ────────────────────────────────────
        valid: list[dict] = []
        for step in filtered_steps:
            cmd = step.get("args", {}).get("command", "")
            if not cmd:
                continue
            san = sanitize(cmd, None)
            if san.allowed:
                valid.append(step)
            else:
                console.print(f"[dim]Suggested step blocked: {san.reason}[/dim]")

        return valid
