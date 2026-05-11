"""
orchestrator_helpers.reflection_engine — AI self-reflection after tool output.

After every tool run, the AI reflects on:
  1. What did this tool reveal?
  2. Does this change the attack strategy?
  3. What is the single highest-value next action?

The reflection is stored in state and injected into the next planning call.
This gives Kernox the "reflect before acting" property of real agent tools.

Also handles autonomous multi-step mode — AI can run a full recon chain
without user typing each step, while user still confirms each execution.

Phase enforcement
─────────────────
All autonomous actions are gated through a 4-phase model:

  Phase 1 — Reconnaissance  : whois, dig, dnsrecon, host, curl -I
  Phase 2 — Scanning        : nmap, rustscan, masscan
  Phase 3 — Enumeration     : whatweb, nikto, gobuster, dirb, enum4linux,
                              smbclient, searchsploit
  Phase 4 — Exploitation    : sqlmap, msfconsole, msfvenom, hydra, medusa

Phases advance when the previous phase has produced useful output.
Exploitation (phase 4) is never suggested until phases 1-3 are complete.
"""

from __future__ import annotations

import json
import re
from rich.console import Console
from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel
from rich.spinner import Spinner
from rich.prompt import Confirm
from rich import box

console = Console()

# ── Phase definitions ─────────────────────────────────────────────────────────

_PHASE_NAMES = {
    1: "Reconnaissance",
    2: "Scanning",
    3: "Enumeration",
    4: "Exploitation",
}

_PHASE_TOOLS = {
    1: "whois, dig, dnsrecon, host, curl -I, ping",
    2: "nmap, rustscan, masscan",
    3: "whatweb, nikto, gobuster, dirb, enum4linux, smbclient, searchsploit, wpscan",
    4: "sqlmap, msfconsole, msfvenom, hydra, medusa, john, hashcat",
}

_MIN_OUTPUT_FOR_ADVANCE = 200

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

_REFLECTION_SYSTEM = (
    "You are an offensive security agent executing a structured attack chain. "
    "Follow the phase rules in the user prompt STRICTLY. "
    "NEVER suggest patching, hardening, or remediation. "
    "NEVER suggest exploitation before reconnaissance and scanning are complete. "
    "Return ONLY valid JSON, no markdown, no extra text."
)

_REFLECT_PROMPT = """\
Tool just run  : {tool}
Target         : {target}
Bare hostname  : {bare_target}
Mode           : {mode}
Current phase  : {phase_num} — {phase_name}
Allowed tools  : {phase_tools}
Already ran    : {completed}
{vuln_summary}
Session context:
{context}

Tool output:
{output}

Return EXACTLY this JSON and nothing else:
{{
  "reflection": "one sentence: what did this output reveal?",
  "next_step": {{
    "tool": "shell",
    "args": {{"command": "exact full command including all flags and target", "target": "{target}"}},
    "reason": "one sentence why this is the best next action"
  }}
}}

RULES — follow every one, no exceptions:
1. "tool" field MUST be "shell" — never put a binary name there
2. "command" must be complete and runnable: binary + all flags + correct target form
3. Pick ONE tool from the "Allowed tools" list — nothing else
4. NEVER pick a tool listed under "Already ran"
5. Use the correct target form per tool:
   - nmap, whois, dig, host, ping → use bare hostname "{bare_target}" (no http/https)
   - nikto, gobuster, dirb, curl, whatweb, wpscan, sqlmap → use full URL with protocol if available
   - When the original target is an IP, always use the IP directly
6. NEVER suggest: msfconsole, reverse shell, privilege escalation, payload, msfvenom
7. If every allowed tool has already run, set next_step to null
8. No patching, hardening, or remediation advice
9. "target" in args must match whatever form you used in "command"

Good command examples (adapt to actual target — do NOT copy verbatim):
  nmap -sV -T4 --open {bare_target}
  nikto -h https://{bare_target}
  gobuster dir -u https://{bare_target} -w /usr/share/wordlists/dirb/common.txt
  whatweb https://{bare_target}
  wpscan --url https://{bare_target}
  dig {bare_target}
  whois {bare_target}
"""


def _extract_json(text: str) -> dict | None:
    text = text.strip()
    if text.startswith("```"):
        text = "\n".join(
            line for line in text.split("\n")
            if not line.strip().startswith("```")
        ).strip()
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group())
    except json.JSONDecodeError:
        fragment = m.group().rstrip()
        for suffix in ["}", "}}", "}]}", "]}}}"]:
            try:
                return json.loads(fragment + suffix)
            except json.JSONDecodeError:
                continue
        return None


def _is_ip(text: str) -> bool:
    return bool(_IP_RE.match(text.strip()))


def _is_url(text: str) -> bool:
    return text.strip().startswith(("http://", "https://"))


def _strip_url(url: str) -> str:
    """Strip protocol and trailing slash — gives bare hostname for nmap/dig/whois."""
    return re.sub(r"^https?://", "", url).rstrip("/").split("/")[0]


def _bootstrap_command(tool_name: str, target: str) -> dict | None:
    """
    Deterministic first command — no AI involved.

    Web URL  → whatweb with full URL  (preserves https:// for accurate scan)
    IP       → nmap -sV               (open services, feeds enumeration phase)
    Domain   → whois bare hostname    (ownership info, phase 1 recon)
    """
    t = target.strip()

    if _is_url(t):
        bare = _strip_url(t)
        return {
            "tool": "shell",
            # Keep full URL so whatweb follows the correct protocol
            "args": {"command": f"whatweb {t}", "target": t},
            "reason": "identify web technologies and CMS before scanning",
        }

    if _is_ip(t):
        return {
            "tool": "shell",
            "args": {"command": f"nmap -sV -T4 --open {t}", "target": t},
            "reason": "version scan to identify open services before enumeration",
        }

    # Domain / hostname — no protocol, whois/dig use bare name
    return {
        "tool": "shell",
        "args": {"command": f"whois {t}", "target": t},
        "reason": "domain ownership and registrar info — first recon step",
    }


class ReflectionEngine:
    """
    Gives Kernox autonomous reasoning between steps.

    Phase tracking
    ──────────────
    _phase advances from 1 → 4 based on how many distinct tools have
    produced meaningful output in the current phase.  The AI does NOT
    control phase advancement — Kernox does, based on objective counts.

    _phase_tools_run   : set of binaries that produced output per phase
    _completed_combos  : "binary|target" pairs that already ran (dedup)
    """

    def __init__(self, ai_client, state, intensity: dict):
        self._ai        = ai_client
        self._state     = state
        self._intensity = intensity
        self._phase: int = 1
        self._phase_tools_run: dict[int, set[str]] = {1: set(), 2: set(), 3: set(), 4: set()}
        self._completed_combos: set[str] = set()

    def reset_phase(self) -> None:
        """Call when switching to a new target so phase resets to 1."""
        self._phase = 1
        self._phase_tools_run = {1: set(), 2: set(), 3: set(), 4: set()}
        self._completed_combos.clear()

    def _record_tool_ran(self, binary: str, output: str) -> None:
        """
        Record that a tool produced meaningful output in the current phase.
        Advances phase when enough distinct tools have run.
        Phase 1 → 2 : after 1 recon tool
        Phase 2 → 3 : after 1 scanning tool
        Phase 3 → 4 : after 2 enumeration tools
        """
        if len(output.strip()) < _MIN_OUTPUT_FOR_ADVANCE:
            return

        self._phase_tools_run[self._phase].add(binary)

        thresholds = {1: 1, 2: 1, 3: 2, 4: 99}
        needed = thresholds.get(self._phase, 99)

        if (self._phase < 4
                and len(self._phase_tools_run[self._phase]) >= needed):
            old = self._phase
            self._phase += 1
            console.print(
                f"\n[dim cyan]⟳ Phase {old} complete "
                f"({len(self._phase_tools_run[old])} tool(s) run) → "
                f"entering Phase {self._phase}: "
                f"{_PHASE_NAMES[self._phase]}[/dim cyan]"
            )

    def _completed_summary(self) -> str:
        if not self._completed_combos:
            return "none"
        return ", ".join(sorted(self._completed_combos))

    def reflect(
        self,
        tool_name:   str,
        target:      str,
        raw_output:  str,
        vulns_found: list[dict] | None = None,
    ) -> dict | None:
        """
        Reflect on tool output and return a single best next_step dict (or None).
        Stores the reflection text as a state note for context_builder.
        """
        if not raw_output.strip():
            return None

        if vulns_found is None:
            vulns_found = []

        from kernox.core.orchestrator_helpers.context_builder import build_agent_context
        session_context = build_agent_context(self._state)
        mode = self._intensity.get("name", "NORMAL")

        # bare_target is passed to the prompt as a HINT for tools that need it
        # (nmap, whois, dig). The AI chooses which form to use per tool.
        bare_target = _strip_url(target) if _is_url(target) else target

        vuln_summary = ""
        if vulns_found:
            vuln_summary = "Vulnerabilities found so far:\n" + "\n".join(
                f"  [{v.get('severity', '?').upper()}] {v.get('name', '?')}: "
                f"{v.get('exploit', '')[:100]}"
                for v in vulns_found[:5]
            )

        phase = self._phase

        prompt = _REFLECT_PROMPT.format(
            tool=tool_name,
            target=target,          # full original target (may include https://)
            bare_target=bare_target,
            mode=mode,
            phase_num=phase,
            phase_name=_PHASE_NAMES[phase],
            phase_tools=_PHASE_TOOLS[phase],
            completed=self._completed_summary(),
            vuln_summary=vuln_summary,
            context=(session_context or "")[:400],
            output=raw_output[:3000],
        )

        try:
            with Live(Spinner("dots", text="[cyan]Reflecting...[/cyan]"),
                      refresh_per_second=10):
                response = self._ai.chat(
                    messages=[{"role": "user", "content": prompt}],
                    system=_REFLECTION_SYSTEM,
                    max_tokens=400,
                )

            data = _extract_json(response)
            if not data:
                return None

            reflection_text = data.get("reflection", "")
            if reflection_text:
                self._state.add_note(
                    f"[REFLECTION after {tool_name}] {reflection_text}"
                )
                console.print(f"\n[dim cyan]⟳ {reflection_text}[/dim cyan]")

            return data.get("next_step")

        except Exception as exc:
            console.print(f"[dim]⚠ Reflection error: {exc}[/dim]")
            return None

    def autonomous_chain(
        self,
        initial_output: str,
        tool_name:      str,
        target:         str,
        intensity:      dict,
        executor,
        max_steps:      int = 5,
    ) -> None:
        """
        Autonomous multi-step attack chain.

        Flow per step:
          1. If first step with no output → bootstrap with deterministic command
          2. Otherwise → reflect() to get AI's best next step
          3. Sanitize + dedup check (skip silently if duplicate, reflect again)
          4. Show + ask user to confirm
          5. Execute, record tool ran → maybe advance phase
          6. Loop
        """
        from kernox.guards.shell_sanitizer import sanitize
        from kernox.features.attack_log import log_tool_run
        from .output_formatter import OutputFormatter

        self._intensity = intensity

        console.print(
            f"\n[bold cyan]⟳ Autonomous chain — "
            f"{_PHASE_NAMES[self._phase]} phase[/bold cyan] "
            f"[dim](max {max_steps} steps, confirm each)[/dim]"
        )

        is_bootstrap = (tool_name == "init")
        has_output   = bool(initial_output and initial_output.strip())

        current_output = initial_output
        current_tool   = tool_name
        current_target = target
        vulns_found: list[dict] = []

        consecutive_dupes = 0
        MAX_CONSECUTIVE_DUPES = 3

        step_num = 0
        while step_num < max_steps:

            # ── Determine next step ───────────────────────────────────────────
            if is_bootstrap and not has_output:
                next_step    = _bootstrap_command(tool_name, current_target)
                is_bootstrap = False
            else:
                next_step = self.reflect(
                    tool_name   = current_tool,
                    target      = current_target,
                    raw_output  = current_output,
                    vulns_found = vulns_found,
                )

            if not next_step:
                console.print("[dim cyan]⟳ Agent: nothing more to do.[/dim cyan]")
                break

            cmd    = next_step.get("args", {}).get("command", "")
            reason = next_step.get("reason", "")

            if not cmd:
                break

            # ── Sanitize ──────────────────────────────────────────────────────
            san = sanitize(cmd, None)
            if not san.allowed:
                console.print(f"[dim]⚠ Agent proposed blocked command: {san.reason}[/dim]")
                break

            # ── Dedup check ───────────────────────────────────────────────────
            combo_key = f"{san.binary}|{san.target or current_target}"
            if combo_key in self._completed_combos:
                consecutive_dupes += 1
                console.print(
                    f"[dim]⟳ Already ran: {san.binary} on "
                    f"{san.target or current_target} — asking for alternative...[/dim]"
                )
                if consecutive_dupes >= MAX_CONSECUTIVE_DUPES:
                    console.print(
                        f"[dim]⟳ Agent stuck after {MAX_CONSECUTIVE_DUPES} "
                        f"duplicate suggestions — stopping chain.[/dim]"
                    )
                    break
                current_output = (
                    f"[SYSTEM: {san.binary} already ran on "
                    f"{san.target or current_target}. "
                    f"Pick a DIFFERENT tool from the allowed list.]"
                )
                current_tool = san.binary
                continue

            consecutive_dupes = 0
            step_num += 1

            # ── Show step + confirm ───────────────────────────────────────────
            console.print(
                f"\n[cyan]⟳ Step {step_num}/{max_steps}[/cyan]  "
                f"[dim]Phase {self._phase}: {_PHASE_NAMES[self._phase]}[/dim]"
            )
            if reason:
                console.print(f"[dim cyan]{reason}[/dim cyan]")
            console.print(Panel(
                Markdown(f"```bash\n{cmd}\n```"),
                width=80,
                border_style="dim",
                box=box.MINIMAL,
            ))

            if not Confirm.ask("  Run this step?", default=True):
                console.print("[dim]Chain stopped by user.[/dim]")
                break

            # ── Execute ───────────────────────────────────────────────────────
            step_target = next_step.get("args", {}).get("target") or san.target or current_target
            result = executor.run(
                command      = cmd,
                tool_name    = san.binary,
                target       = step_target,
                timeout      = intensity.get("timeout", 120),
                skip_confirm = True,
            )

            self._completed_combos.add(combo_key)

            output_text = result.stdout + result.stderr

            if result.stdout.strip():
                OutputFormatter.format_output(san.binary, result.stdout, step_target)

            if output_text.strip():
                self._state.add_tool_result(
                    tool       = san.binary,
                    target     = step_target,
                    parsed     = {"exit_code": result.return_code,
                                  "duration":  result.duration_seconds},
                    raw_output = output_text,
                )

            self._record_tool_ran(san.binary, output_text)

            try:
                log_tool_run(
                    tool        = san.binary,
                    command     = cmd,
                    target      = step_target,
                    duration    = result.duration_seconds,
                    return_code = result.return_code,
                    output_path = str(result.output_path or ""),
                )
            except Exception:
                pass

            current_output = output_text
            current_tool   = san.binary
            current_target = step_target
            has_output     = True
            vulns_found    = []

            if result.blocked or result.return_code < 0:
                console.print("[dim]Step failed — stopping chain.[/dim]")
                break

        console.print(
            f"[dim cyan]⟳ Autonomous chain complete "
            f"(reached phase {self._phase}: {_PHASE_NAMES[self._phase]}).[/dim cyan]"
        )
