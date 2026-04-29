"""
kernox.core.orchestrator – Main agent loop.
No mode system — intensity is detected from natural language.
Supports chaining: "nmap on X, nikto on X, ffuf on X" → 3 sequential steps.
"""

from __future__ import annotations

from typing import Optional

from prompt_toolkit import PromptSession
from prompt_toolkit.styles import Style
from rich.console import Console
from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.spinner import Spinner
from rich.table import Table
from rich import box

from kernox.ai.factory import build_ai_client
from kernox.config.config_store import ConfigStore
from kernox.engine.state import SessionState
from kernox.engine.state_updater import StateUpdater
from kernox.tools.mail_crawler import MailCrawlerTool


from kernox.core.orchestrator_helpers import (
    ChatHandler,
    CommandExecutor,
    OutputFormatter,
    AIAnalyzer,
    StateManager,
    SessionManager,
    ReportHandler,
)

console = Console()
PROMPT_STYLE = Style.from_dict({"prompt": "bold #00d787"})

INTENSITY_LEVELS = {
    "STEALTH":    {"name": "STEALTH",    "timeout": 60},
    "NORMAL":     {"name": "NORMAL",     "timeout": 30},
    "AGGRESSIVE": {"name": "AGGRESSIVE", "timeout": 15},
    "FULL":       {"name": "FULL",       "timeout": 5},
}

INTENSITY_KEYWORDS = {
    "stealth": "STEALTH", "slow": "STEALTH", "quiet": "STEALTH", "sneaky": "STEALTH",
    "normal": "NORMAL", "standard": "NORMAL", "default": "NORMAL",
    "aggressive": "AGGRESSIVE", "fast": "AGGRESSIVE", "quick": "AGGRESSIVE", "speed": "AGGRESSIVE",
    "full": "FULL", "maximum": "FULL", "max": "FULL", "blast": "FULL", "noisy": "FULL",
}

INTENSITY_FLAG_HINTS = {
    "STEALTH": (
        "STEALTH: Slowest possible timing. Workers/threads=1. Delays 2-5s between requests. "
        "Rate limit 5-10/sec. TCP connect (not SYN). No aggressive templates. "
        "Reference: nmap=-T0/--scan-delay, ffuf/gobuster/dirb/wfuzz=-t 1 -delay, "
        "hydra/medusa=-t 1 -W 5, sqlmap=--delay=3 --threads=1, nikto=-T 1"
    ),
    "NORMAL": (
        "NORMAL: Default timing. No special restrictions."
    ),
    "AGGRESSIVE": (
        "AGGRESSIVE: Fast timing. Increase workers. Reduce delays. "
        "Reference: nmap=-T4, ffuf/wfuzz/gobuster=-t 100, hydra=-t 16, sqlmap=--threads=10"
    ),
    "FULL": (
        "FULL SPEED: Maximum threads. No delays. Fastest possible. "
        "Reference: nmap=-T5 --min-rate 5000, ffuf/wfuzz=-t 200, hydra=-t 64, sqlmap=--threads=10 --delay=0"
    ),
}

BASE_SYSTEM_PROMPT = """You are Kernox, an autonomous penetration testing AI.
You operate strictly within Kali Linux environments and use real, verified tools only.

Current intensity: {intensity_name}
{timing_rule}

YOUR JOB:
1. Precisely understand the user's objective
2. Select the MOST appropriate Kali Linux tool for that task
3. Construct a VALID command using ONLY real flags and syntax
4. Apply {intensity_name} timing rules to every command
5. If multiple objectives exist, break into multiple logical steps

STRICT TOOL SELECTION RULES:
- Never default to nmap unless it is clearly the best tool
- Always prefer specialized tools over general-purpose ones

ANTI-HALLUCINATION RULES:
- NEVER invent flags, arguments, or tool capabilities
- ONLY use flags that are officially supported by the tool
- If unsure about a flag, DO NOT include it
- Prefer minimal valid commands over complex uncertain ones
- Do NOT assume tool behavior — stick to known usage patterns
- If input is ambiguous, make the safest reasonable assumption

COMMAND SAFETY RULES:
- NO shell operators:  ` $ ( ) & < >
- NO chaining commands
- ONE command per step
- Commands must be directly executable in Kali Linux

OUTPUT FORMAT (STRICT JSON ONLY):
{{
  "analysis": "clear reasoning for tool selection based on task",
  "steps": [
    {{
      "tool": "shell",
      "args": {{
        "command": "exact, valid Kali command with correct flags and {intensity_name} timing",
        "target": "target IP or URL"
      }},
      "reason": "what this step achieves"
    }}
  ],
  "message": "concise summary of execution plan"
}}

QUALITY CONTROL:
Before responding, internally verify:
- Is the tool correct for the task?
- Are all flags real and valid?
- Would this command run successfully in Kali Linux?

If any answer is "no", FIX it before output.

DO NOT explain outside JSON.
DO NOT include extra text.
ONLY return valid JSON.
"""


class Orchestrator:
    def __init__(self, config: ConfigStore) -> None:
        self._cfg = config
        self._ai = build_ai_client(config)
        self._state = SessionState()
        self._updater = StateUpdater(self._state)
        self._history: list[dict] = []
        self._intensity = INTENSITY_LEVELS["NORMAL"]
        self._mail_crawler = MailCrawlerTool()

        self._chat_handler = ChatHandler(self._ai, self._state, self._history)
        self._cmd_executor = CommandExecutor(config, self._state)
        self._ai_analyzer = AIAnalyzer(self._ai, self._state, self._intensity)
        self._cmd_executor._ai_analyzer = self._ai_analyzer
        self._state_manager = StateManager(self._state, self._intensity)
        self._session_manager = SessionManager(self._state, self._updater)
        self._report_handler = ReportHandler(self._state)




    def _store_network_state(self) -> None:
        """Store network info in session state - COMPLETELY SILENT."""
        # Store default IP
        if self._network_state.default_ip:
            self._state.set_metadata("local_ip", self._network_state.default_ip)
            self._state.set_metadata("local_interface", self._network_state.default_interface)

        # Store all IPs
        all_ips = self._network_state.get_ips()
        self._state.set_metadata("all_local_ips", all_ips)

        # Store per-interface IPs
        for iface in self._network_state.interfaces:
            if iface.ipv4:
                self._state.set_metadata(f"ip_{iface.name}", iface.ipv4)

        # NO print statements - completely silent

    def run(self) -> None:
        console.print("\n[bold #00d787]kernox[/bold #00d787] [dim]ready[/dim]\n")

        session = PromptSession(style=PROMPT_STYLE)
        while True:
            try:
                user_input = session.prompt("\nkernox ❯ ")
            except (EOFError, KeyboardInterrupt):
                break

            user_input = user_input.strip()
            if not user_input:
                continue

            cmd = user_input.lower()

            if cmd in ("exit", "quit"):
                console.print("\n[dim]Goodbye[/dim]\n")
                break
            elif cmd == "help":
                self._print_help()
                continue
            elif cmd == "state":
                self._state_manager.print_state()
                continue
            elif cmd == "clear":
                self._state_manager.clear_all(self._history)
                continue
            elif cmd == "report" or cmd.startswith("report "):
                self._report_handler.ask_report()
                continue
            elif cmd == "save":
                self._session_manager.save()
                continue
            elif cmd == "load":
                self._session_manager.load()
                continue
            elif cmd == "sessions":
                self._session_manager.list_sessions()
                continue
            elif cmd in ("raw on", "raw off"):
                val = "1" if cmd == "raw on" else "0"
                self._cfg.set("show_raw_output", val)
                state_text = "[#55efc4]ON[/#55efc4]" if val == "1" else "[dim]OFF[/dim]"
                console.print(f"[#00d787]✓ Raw output {state_text}[/#00d787]")
                continue

            self._detect_intensity(user_input)

            from kernox.core.orchestrator_helpers.chat_handler import is_chat
            from kernox.core.orchestrator_helpers.ai_analyzer import extract_json

            if is_chat(user_input):
                response = self._chat_handler.chat(user_input)
                self._history.append({"role": "user", "content": user_input})
                self._history.append({"role": "assistant", "content": response})
                plan = extract_json(response)
                if plan and plan.get("steps"):
                    normalized = self._normalize_steps(plan["steps"])
                    if normalized:
                        self._print_plan(normalized)
                        self._execute_steps(normalized)
                    else:
                        console.print(Panel(Markdown(response), border_style="dim"))
                else:
                    console.print(Panel(Markdown(response), border_style="dim"))
            else:
                self._process(user_input)

    def _normalize_steps(self, steps: list) -> list[dict]:
        normalized = []
        for s in steps:
            if isinstance(s, str):
                normalized.append({
                    "tool": "shell",
                    "args": {"command": s, "target": ""},
                    "reason": "",
                })
            elif isinstance(s, dict):
                cmd = s.get("command") or s.get("args", {}).get("command", "")
                if cmd:
                    normalized.append({
                        "tool": s.get("tool", "shell"),
                        "args": {
                            "command": cmd,
                            "target": s.get("target") or s.get("args", {}).get("target", ""),
                        },
                        "reason": s.get("reason") or s.get("description", ""),
                    })
        return normalized

    def _process(self, user_input: str) -> None:
        self._history.append({"role": "user", "content": user_input})

        intensity_name = self._intensity["name"]
        timing_rule = INTENSITY_FLAG_HINTS.get(intensity_name, INTENSITY_FLAG_HINTS["NORMAL"])
        system_prompt = BASE_SYSTEM_PROMPT.format(
            intensity_name=intensity_name,
            timing_rule=timing_rule,
        )

        with Live(Spinner("dots", text="[#00d787]thinking...[/#00d787]"), refresh_per_second=10):
            ai_resp = self._ai.chat(
                messages=self._history[-20:],
                system=system_prompt,
            )
        self._history.append({"role": "assistant", "content": ai_resp})

        from kernox.core.orchestrator_helpers.ai_analyzer import extract_json
        plan = extract_json(ai_resp)

        if not plan:
            console.print("[red]✗ Invalid response[/red]")
            return

        steps = plan.get("steps", [])
        if not steps:
            console.print("[dim]Nothing to run[/dim]")
            return

        # self._print_plan(steps)
        self._execute_steps(steps)

    def _execute_steps(self, steps: list[dict]) -> None:
        for i, step in enumerate(steps, 1):
            tool = step.get("tool", "").lower()
            args = step.get("args", {})
            reason = step.get("reason", "")

            if len(steps) > 1:
                console.print(f"\n[dim]── Step {i}/{len(steps)} ──[/dim]")

            if tool == "mail_crawler":
                self._run_mail_crawler(args)
            else:
                self._cmd_executor.run_shell_step(args, reason, self._intensity)

    def _run_mail_crawler(self, args: dict) -> None:
        target = args.get("target", "")
        if not target:
            console.print("[red]✗ No target[/red]")
            return
        if not Confirm.ask(f"Run mail_crawler on {target}?", default=True):
            return
        result = self._mail_crawler.run_direct(target=target, max_pages=200)
        if result.get("emails"):
            console.print(f"[green]✓ {len(result['emails'])} emails[/green]")
            for email in result["emails"][:10]:
                console.print(f"  [cyan]{email}[/cyan]")

    def _print_plan(self, steps: list[dict]) -> None:
        if not steps:
            return
        table = Table(title="Plan", box=box.ROUNDED, border_style="#00d787")
        table.add_column("#", style="cyan", width=3)
        table.add_column("Tool", style="#00d787", width=15)
        table.add_column("Target", style="white", width=20)
        table.add_column("Command", style="dim", no_wrap=False)
        for i, s in enumerate(steps, 1):
            args = s.get("args", {})
            table.add_row(
                str(i),
                args.get("command", "").split()[0] if args.get("command") else "?",
                args.get("target", "-"),
                args.get("command", "")[:70],
            )
        console.print(table)

    def _detect_intensity(self, user_input: str) -> None:
        lower = user_input.lower()
        for keyword, level_name in INTENSITY_KEYWORDS.items():
            if keyword in lower:
                new = INTENSITY_LEVELS[level_name]
                if new["name"] != self._intensity["name"]:
                    self._intensity = new
                    self._ai_analyzer._intensity = new
                    self._cmd_executor._ai_analyzer._intensity = new
                    console.print(f"[dim]⚡ {new['name']} mode[/dim]")
                break

    def run_headless(self, target: str, mode: str = "web recon") -> None:
        console.print(f"\n[bold #00d787]Headless:[/bold #00d787] {mode} → {target}\n")
        self._process(f"{mode} {target}")

    def _print_help(self) -> None:
        help_text = """
**Commands:**
- Type a target or instruction — the AI plans and executes
- Use keywords like *stealth*, *fast*, or *aggressive* to control speed
- Ask for multiple tools: *"nmap, nikto, and ffuf on 192.168.1.1"*
- `state` — show findings
- `report` — generate PDF report
- `save` / `load` / `sessions` — session management
- `raw on` / `raw off` — toggle live tool output
- `clear` — reset session
- `exit` — quit
        """
        console.print(Panel(Markdown(help_text), title="Help", border_style="#00d787"))
