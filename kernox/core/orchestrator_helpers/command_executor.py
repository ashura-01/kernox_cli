"""
Command execution — runs tools, shows output, triggers AI analysis + chaining.

Flow:
  1. Sanitize command
  2. Show as markdown, user confirms
  3. Execute via Executor
  4. Show output (table if structured, raw lines otherwise)
  5. Save to state
  6. Log to attack timeline
  7. AI analyzes output (only when auto-analyze is ON) → extracts vulns + structured state
     (state_parser is called FROM ai_analyzer — no separate AI call)
  8. Chain next steps with user confirmation (up to max_chain_depth levels)

Design contract
───────────────
• _offer_chain is the SINGLE source of truth for interactive step selection.
  OnDemandAnalyzer delegates to it — never duplicates the logic.
• _offer_chain(next_steps, intensity, depth) is called exactly once per
  analyze() return; never inside the chunk loop.
• format_analysis_summary is owned by ai_analyzer/OutputFormatter — not here.
"""

from __future__ import annotations

import copy
import glob
import os
import threading
from typing import Optional

from rich.console import Console
from rich.markdown import Markdown
from rich.prompt import Confirm
from rich.panel import Panel
from rich import box

from kernox.core.executor import Executor
from kernox.guards.shell_sanitizer import sanitize
from kernox.features.attack_log import log_tool_run
from .output_formatter import OutputFormatter

console = Console()


class CommandExecutor:
    def __init__(self, config, state, ai_analyzer=None):
        self._cfg          = config
        self._state        = state
        self._executor     = Executor(config)
        self._ai_analyzer  = ai_analyzer
        self._reflection   = None
        self._chat_handler = None
        self._auto_analyze: bool = True
        self._tg_send:      bool = False

        self.max_chain_depth: int = int(config.get("max_chain_depth") or 3)

    # ── Private helpers ───────────────────────────────────────────────────────

    def _merge_tool_into_command(self, step: dict) -> dict:
        """
        Enforce that args.command starts with the binary named in step["tool"].

        The AI prompt instructs this, but this method is the hard safety net.
        Returns a deep copy of args with the binary prepended only when missing.
        """
        args = copy.deepcopy(step.get("args", {}))
        tool = step.get("tool", "").strip().lower()
        cmd  = args.get("command", "").strip()

        if not tool or tool in ("shell", "bash"):
            return args

        cmd_parts  = cmd.split()
        cmd_binary = cmd_parts[0].lower() if cmd_parts else ""
        if cmd_binary == tool or cmd_binary.endswith(f"/{tool}"):
            return args

        args["command"] = f"{tool} {cmd}".strip() if cmd else tool
        return args

    # ── Public interface ──────────────────────────────────────────────────────

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
            console.print("[red]No command to execute[/red]")
            return None

        san = sanitize(raw_cmd, self._cfg)
        if not san.allowed:
            console.print(f"[red]Blocked: {san.reason}[/red]")
            return None

        if not target and san.target:
            target = san.target

        console.print()
        if reason:
            console.print(f"[dim cyan]{reason}[/dim cyan]")
        console.print(Panel(
            Markdown(f"```bash\n{san.command}\n```"),
            width=80,
            border_style="dim",
            box=box.MINIMAL,
        ))

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

        # Record output path for chat handler
        if self._chat_handler:
            if result.output_path:
                self._chat_handler.record_command(san.command, str(result.output_path))
            else:
                out_files = glob.glob(os.path.join("/tmp/kernox", "*.txt"))
                if out_files:
                    self._chat_handler.record_command(
                        san.command, max(out_files, key=os.path.getctime)
                    )

        # Auto-send to Telegram (non-blocking)
        if self._tg_send and result.output_path and result.stdout.strip():
            _op, _tool, _tgt = str(result.output_path), result.tool_name, target or "unknown"
            def _do_send():
                try:
                    from kernox.utils.telegram_sender import get_telegram
                    get_telegram().auto_send_output(_tool, _tgt, _op)
                except Exception:
                    pass
            threading.Thread(target=_do_send, daemon=True).start()

        # PTY tools: analyze captured session output after they exit
        if san.needs_pty and result.stdout.strip() and self._ai_analyzer:
            if self._auto_analyze:
                console.print("\n[dim cyan]Analyzing session output...[/dim cyan]")
                next_steps = self._ai_analyzer.analyze(
                    tool_name  = result.tool_name,
                    target     = target or "unknown",
                    raw_output = result.stdout,
                )
                self._offer_chain(next_steps, intensity, depth=_chain_depth)
            return result.stdout

        # AI analysis — extracts vulns + structured state in ONE call per chunk
        if (self._ai_analyzer
                and self._auto_analyze
                and result.stdout.strip()
                and not result.blocked
                and _chain_depth < self.max_chain_depth):
            next_steps = self._ai_analyzer.analyze(
                tool_name  = result.tool_name,
                target     = target or "unknown",
                raw_output = result.stdout,
            )
            # _offer_chain called ONCE after analyze() completes
            self._offer_chain(next_steps, intensity, depth=_chain_depth)
        elif not self._auto_analyze and result.stdout.strip():
            console.print(
                "[dim]Auto-analysis off — run [cyan]analyze last[/cyan] "
                "to analyze this output.[/dim]"
            )

        return result.stdout if (not result.blocked and result.return_code >= 0) else None

    def _offer_chain(
        self,
        next_steps: list,
        intensity:  dict | None,
        depth:      int = 0,
    ) -> None:
        """
        Offer AI-suggested next steps to the user — user picks by number.

        This method is the SINGLE source of truth for interactive step selection.
        It is called:
          • by run_shell_step() after every auto-analysis, and
          • by OnDemandAnalyzer._offer_chain() after on-demand analysis.

        It is NEVER called from inside ai_analyzer.py.

        Uses plain input() instead of Rich Prompt.ask(choices=) to avoid
        Rich's strict re-prompt loop swallowing input on some terminal configs.

        Parameters
        ----------
        next_steps : list
            Validated step dicts returned by ai_analyzer.analyze().
        intensity : dict | None
            Current intensity settings; None → default 300 s timeout.
        depth : int
            Current chain depth; incremented for each recursive step.
        """
        if not next_steps:
            return
        if depth >= self.max_chain_depth:
            console.print(
                f"[dim]Max chain depth ({self.max_chain_depth}) reached — "
                "stopping automatic chaining.[/dim]"
            )
            return

        valid_choices = [str(i) for i in range(1, len(next_steps) + 1)] + ["all", "none"]
        hint          = "/".join(valid_choices)

        while True:
            try:
                raw = input(f"  Run which? [{hint}] (none): ").strip().lower() or "none"
            except (EOFError, KeyboardInterrupt):
                console.print()
                return

            if raw in valid_choices:
                choice = raw
                break
            console.print(f"  [dim]Enter one of: {hint}[/dim]")

        if choice == "none":
            return

        selected = next_steps if choice == "all" else [next_steps[int(choice) - 1]]

        for step in selected:
            merged_args = self._merge_tool_into_command(step)
            reason      = step.get("reason", "")
            if merged_args.get("command"):
                self.run_shell_step(
                    merged_args,
                    reason,
                    intensity,
                    _chain_depth=depth + 1,
                )
