"""Command execution — delegates to Executor with AI chaining."""

from __future__ import annotations

from typing import Optional
from rich.console import Console
from rich.markdown import Markdown
from rich.prompt import Confirm

from kernox.core.executor import Executor
from kernox.guards.shell_sanitizer import sanitize

console = Console()

_MAX_CHAIN_DEPTH = 3


class CommandExecutor:
    def __init__(self, config, state, ai_analyzer=None):
        self._cfg      = config
        self._state    = state
        self._executor = Executor(config)
        self._ai_analyzer = ai_analyzer   # injected by Orchestrator

    def run_shell_step(
        self,
        args: dict,
        reason: str = "",
        intensity: dict = None,
        _chain_depth: int = 0,
    ) -> Optional[str]:
        raw_cmd = args.get("command", "").strip()
        target  = args.get("target", "")

        if not raw_cmd:
            console.print("[red]✗ No command to execute[/red]")
            return None

        # Pre-check with sanitizer for early UI feedback
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
        console.print(Markdown(f"```bash\n{san.command}\n```"))

        if not Confirm.ask("  Execute?", default=True):
            console.print("[dim]Skipped.[/dim]")
            return None

        timeout = intensity.get("timeout", 120) if intensity else 120

        result = self._executor.run(
            command=san.command,
            tool_name=san.binary,
            target=target,
            timeout=timeout,
            skip_confirm=True,   # user already confirmed above
        )

        # Format output as table where possible
        if result.stdout.strip() and not san.needs_pty:
            from .output_formatter import OutputFormatter
            OutputFormatter.format_output(result.tool_name, result.stdout, target)

        # Persist to state
        if result.stdout.strip() or result.stderr.strip():
            self._state.add_tool_result(
                tool=result.tool_name,
                target=target or "unknown",
                parsed={
                    "exit_code": result.return_code,
                    "duration":  result.duration_seconds,
                },
                raw_output=result.stdout + result.stderr,
            )

        # Auto-parse into structured state (hosts, ports, paths, vulns)
        try:
            from kernox.engine.state_parser import auto_parse
            auto_parse(result.tool_name, target or "unknown",
                       result.stdout, self._state)
        except Exception:
            pass

        # Log to attack timeline
        try:
            from kernox.features.attack_log import log_tool_run
            log_tool_run(
                tool=result.tool_name,
                command=san.command,
                target=target or "unknown",
                duration=result.duration_seconds,
                return_code=result.return_code,
                output_path=str(result.output_path or ""),
            )
        except Exception:
            pass  # additive — never break core flow

        # AI analysis + up to 3-level chaining
        if (
            self._ai_analyzer
            and result.stdout.strip()
            and not result.blocked
            and _chain_depth < _MAX_CHAIN_DEPTH
        ):
            next_steps = self._ai_analyzer.analyze(
                tool_name=result.tool_name,
                target=target or "unknown",
                raw_output=result.stdout,
            )
            for step in next_steps:
                step_cmd    = step.get("args", {}).get("command", "")[:70]
                step_reason = step.get("reason", "")
                if Confirm.ask(
                    f"\n  [cyan]⚡ Chain step:[/cyan] `{step_cmd}` — run?",
                    default=False,
                ):
                    self.run_shell_step(
                        step.get("args", {}),
                        step_reason,
                        intensity,
                        _chain_depth=_chain_depth + 1,
                    )

        return result.stdout if (not result.blocked and result.return_code >= 0) else None
