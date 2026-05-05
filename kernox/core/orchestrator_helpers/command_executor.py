"""
Command execution — runs tools, shows output, triggers AI analysis + chaining.

Flow:
  1. Sanitize command
  2. Show as markdown, user confirms
  3. Execute via Executor
  4. Show output (table if structured, raw lines otherwise)
  5. Save to state
  6. Log to attack timeline
  7. AI analyzes output → extracts vulns + structured state (hosts/ports/etc.)
     (state_parser is called FROM ai_analyzer — no separate AI call)
  8. Chain next steps with user confirmation (up to 3 levels)
"""

from __future__ import annotations

from typing import Optional
from rich.console import Console
from rich.markdown import Markdown
from rich.prompt import Confirm
from rich.panel import Panel
from rich import box

from kernox.core.executor import Executor
from kernox.guards.shell_sanitizer import sanitize

console = Console()

_MAX_CHAIN_DEPTH = 3


class CommandExecutor:
    def __init__(self, config, state, ai_analyzer=None):
        self._cfg         = config
        self._state       = state
        self._executor    = Executor(config)
        self._ai_analyzer = ai_analyzer   # injected by Orchestrator
        self._reflection  = None          # injected by Orchestrator

    def run_shell_step(
        self,
        args:         dict,
        reason:       str  = "",
        intensity:    dict = None,
        _chain_depth: int  = 0,
    ) -> Optional[str]:

        raw_cmd = args.get("command", "").strip()
        target  = args.get("target", "")

        if not raw_cmd:
            console.print("[red]✗ No command to execute[/red]")
            return None

        san = sanitize(raw_cmd, self._cfg)
        if not san.allowed:
            console.print(f"[red]✗ Blocked: {san.reason}[/red]")
            return None

        if not target and san.target:
            target = san.target

        # Show command as markdown — no boxes
        console.print()
        if reason:
            console.print(f"[dim cyan]{reason}[/dim cyan]")
        # console.print(Markdown(f"```bash\n{san.command}\n```"))
        console.print(Panel(Markdown(f"```bash\n{san.command}\n```"), width=80,border_style="dim", box=box.MINIMAL))

        if not Confirm.ask("  Execute?", default=True):
            console.print("[dim]Skipped.[/dim]")
            return None

        timeout = intensity.get("timeout", 300) if intensity else 300

        result = self._executor.run(
            command      = san.command,
            tool_name    = san.binary,
            target       = target,
            timeout      = timeout,
            skip_confirm = True,
        )

        # Show output immediately — table or raw lines, never truncated
        if result.stdout.strip() and not san.needs_pty:
            from .output_formatter import OutputFormatter
            OutputFormatter.format_output(result.tool_name, result.stdout, target)

        # Save raw output to state (no truncation)
        if result.stdout.strip() or result.stderr.strip():
            self._state.add_tool_result(
                tool       = result.tool_name,
                target     = target or "unknown",
                parsed     = {"exit_code": result.return_code,
                              "duration":  result.duration_seconds},
                raw_output = result.stdout + result.stderr,
            )

        # Log to attack timeline
        try:
            from kernox.features.attack_log import log_tool_run
            log_tool_run(
                tool        = result.tool_name,
                command     = san.command,
                target      = target or "unknown",
                duration    = result.duration_seconds,
                return_code = result.return_code,
                output_path = str(result.output_path or ""),
            )
        except Exception:
            pass

        # PTY tools: analyze captured session output after they exit
        if san.needs_pty and result.stdout.strip() and self._ai_analyzer:
            console.print("\n[dim cyan]Analyzing session output...[/dim cyan]")
            next_steps = self._ai_analyzer.analyze(
                tool_name  = result.tool_name,
                target     = target or "unknown",
                raw_output = result.stdout,
            )
            self._offer_chain(next_steps, intensity, _chain_depth)
            return result.stdout

        # AI analysis — extracts vulns AND structured state in ONE call
        if (self._ai_analyzer
                and result.stdout.strip()
                and not result.blocked
                and _chain_depth < _MAX_CHAIN_DEPTH):
            next_steps = self._ai_analyzer.analyze(
                tool_name  = result.tool_name,
                target     = target or "unknown",
                raw_output = result.stdout,
            )
            self._offer_chain(next_steps, intensity, _chain_depth)

        return result.stdout if (not result.blocked and result.return_code >= 0) else None

    def _offer_chain(self, next_steps: list, intensity: dict, depth: int) -> None:
        """Offer each AI-suggested next step to the user."""
        for step in next_steps:
            cmd    = step.get("args", {}).get("command", "")
            reason = step.get("reason", "")
            if not cmd:
                continue
            preview = cmd[:80]
            if Confirm.ask(
                f"\n  [cyan]⚡ Chain:[/cyan] `{preview}` — run?",
                default=False,
            ):
                self.run_shell_step(
                    step.get("args", {}),
                    reason,
                    intensity,
                    _chain_depth=depth + 1,
                )
