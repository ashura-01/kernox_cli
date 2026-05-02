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
"""

from __future__ import annotations

import json
import re
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.spinner import Spinner
from rich.prompt import Confirm

console = Console()

# Tight system — attacker only, no patch advice, used only for autonomous chain
REFLECTION_SYSTEM = (
    "You are an offensive security agent. "
    "Given tool output and session state, decide the single best next attack. "
    "NEVER suggest patching or remediation. "
    "Return ONLY valid JSON."
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
        return None


class ReflectionEngine:
    """
    Gives Kernox autonomous reasoning between steps.

    After each tool run:
      - Sends output + full session context to AI
      - AI reflects: what changed? what's highest priority now?
      - Reflection stored in state._notes for context_builder to include
      - Returns the AI's top recommended next step
    """

    def __init__(self, ai_client, state, intensity: dict):
        self._ai        = ai_client
        self._state     = state
        self._intensity = intensity

    def reflect(
        self,
        tool_name:  str,
        target:     str,
        raw_output: str,
        vulns_found: list[dict],
    ) -> dict | None:
        """
        Reflect on tool output. Returns a single best next_step dict or None.
        Stores reflection as a note in state for future context.
        """
        if not raw_output.strip():
            return None

        from kernox.core.orchestrator_helpers.context_builder import build_agent_context
        session_context = build_agent_context(self._state)
        intensity_name  = self._intensity.get("name", "NORMAL")
        preview         = raw_output[:6000]

        vuln_summary = ""
        if vulns_found:
            vuln_summary = "\nVulnerabilities just found:\n" + "\n".join(
                f"  [{v.get('severity','?').upper()}] {v.get('name','?')}: "
                f"{v.get('exploit','')[:100]}"
                for v in vulns_found[:5]
            )

        # Tight prompt — context capped, no bloat
        ctx_short = session_context[:400] if session_context else ""
        prompt = (
            f"Done:{tool_name} Target:{target} Mode:{intensity_name}\n"
            f"{vuln_summary}\n{ctx_short}\n"
            f"Output:\n{preview[:3000]}\n\n"
            f'Return JSON:{{"reflection":"1 sentence","next_step":{{"tool":"shell","args":{{"command":"exact_{intensity_name}_cmd","target":"{target}"}},"reason":"why"}}}}\n'
            "next_step=null if nothing left. No patch advice. Don't repeat completed tool+target."
        )

        try:
            with Live(Spinner("dots", text="[cyan]Reflecting...[/cyan]"),
                      refresh_per_second=10):
                response = self._ai.chat(
                    messages=[{"role": "user", "content": prompt}],
                    system=REFLECTION_SYSTEM,
                    max_tokens=400,  # reflection is short JSON
                )

            data = extract_json(response)
            if not data:
                return None

            # Store reflection as a note — context_builder picks it up
            reflection_text = data.get("reflection", "")
            if reflection_text:
                self._state.add_note(
                    f"[REFLECTION after {tool_name}] {reflection_text}"
                )

            # Show reflection inline
            priority = data.get("priority_target", "")
            reasoning = data.get("reasoning", "")
            if reflection_text:
                console.print(
                    f"\n[dim cyan]⟳ Reflection:[/dim cyan] {reflection_text}"
                )
            if priority:
                console.print(
                    f"[dim cyan]⟳ Priority target:[/dim cyan] {priority}"
                    + (f" — {reasoning}" if reasoning else "")
                )

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
        Autonomous multi-step mode.
        AI reflects → proposes next step → user confirms → executes → repeats.
        Stops when AI says nothing left or max_steps reached.
        User confirms EVERY execution — never runs blind.
        """
        from kernox.guards.shell_sanitizer import sanitize
        from kernox.features.attack_log import log_tool_run
        from .output_formatter import OutputFormatter

        console.print(
            f"\n[bold cyan]⟳ Autonomous chain mode[/bold cyan] "
            f"[dim](max {max_steps} steps, you confirm each)[/dim]"
        )

        current_output = initial_output
        current_tool   = tool_name
        current_target = target
        vulns_found: list[dict] = []

        for step_num in range(1, max_steps + 1):
            next_step = self.reflect(
                tool_name   = current_tool,
                target      = current_target,
                raw_output  = current_output,
                vulns_found = vulns_found,
            )

            if not next_step:
                console.print("[dim cyan]⟳ Agent: no further actions needed.[/dim cyan]")
                break

            cmd    = next_step.get("args", {}).get("command", "")
            reason = next_step.get("reason", "")

            if not cmd:
                break

            # Sanitize before showing
            san = sanitize(cmd, None)
            if not san.allowed:
                console.print(f"[dim]⚠ Agent proposed blocked command: {san.reason}[/dim]")
                break

            console.print(
                f"\n[cyan]⟳ Step {step_num}/{max_steps}[/cyan] "
                f"[dim]{reason}[/dim]"
            )

            from rich.markdown import Markdown
            console.print(Markdown(f"```bash\n{cmd}\n```"))

            if not Confirm.ask("  Run this step?", default=True):
                console.print("[dim]Chain stopped by user.[/dim]")
                break

            result = executor.run(
                command    = cmd,
                tool_name  = san.binary,
                target     = san.target or current_target,
                timeout    = intensity.get("timeout", 120),
                skip_confirm = True,
            )

            if result.stdout.strip():
                OutputFormatter.format_output(san.binary, result.stdout,
                                              san.target or current_target)

            # Update state
            if result.stdout.strip() or result.stderr.strip():
                self._state.add_tool_result(
                    tool       = san.binary,
                    target     = san.target or current_target,
                    parsed     = {"exit_code": result.return_code,
                                  "duration":  result.duration_seconds},
                    raw_output = result.stdout + result.stderr,
                )

            # Parse structured state
            try:
                from kernox.engine.state_parser import auto_parse
                auto_parse(san.binary, san.target or current_target,
                           result.stdout, self._state)
            except Exception:
                pass

            # Log
            try:
                log_tool_run(
                    tool=san.binary, command=cmd,
                    target=san.target or current_target,
                    duration=result.duration_seconds,
                    return_code=result.return_code,
                    output_path=str(result.output_path or ""),
                )
            except Exception:
                pass

            current_output = result.stdout
            current_tool   = san.binary
            current_target = san.target or current_target
            vulns_found    = []

            if result.blocked or result.return_code < 0:
                console.print("[dim]Step failed — stopping chain.[/dim]")
                break

        console.print("[dim cyan]⟳ Autonomous chain complete.[/dim cyan]")
