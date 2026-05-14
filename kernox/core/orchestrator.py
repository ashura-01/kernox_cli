"""
kernox.core.orchestrator – Main agent loop.
"""

from __future__ import annotations

import json
import re
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
from kernox.utils.network_ips import get_ip_context
from kernox.core.orchestrator_helpers import (
    ChatHandler,
    CommandExecutor,
    OutputFormatter,
    AIAnalyzer,
    StateManager,
    SessionManager,
    ReportHandler,
    FeatureHandler,
)
from kernox.core.orchestrator_helpers.chat_handler import detect_builtin
# ── NEW: on-demand analyzer ──────────────────────────────────────────────────
from kernox.core.orchestrator_helpers.on_demand_analyzer import OnDemandAnalyzer

console = Console()
PROMPT_STYLE = Style.from_dict({"prompt": "bold cyan"})

# ── Intensity levels ──────────────────────────────────────────────────────────
INTENSITY_LEVELS = {
    "1": {"name": "STEALTH",    "timeout": 600},
    "2": {"name": "NORMAL",     "timeout": 300},
    "3": {"name": "AGGRESSIVE", "timeout": 180},
    "4": {"name": "FULL",       "timeout": 120},
}

MODE_NUMBERS = {
    "STEALTH": "1",
    "NORMAL": "2",
    "AGGRESSIVE": "3",
    "FULL": "4",
}

INTENSITY_KEYWORDS = {
    "stealth": "1", "slow": "1", "quiet": "1", "passive": "1", "evasive": "1",
    "normal": "2", "standard": "2", "default": "2",
    "aggressive": "3", "fast": "3", "quick": "3",
    "full": "4", "maximum": "4", "max": "4", "insane": "4",
}

INTENSITY_TIMING = {
    "STEALTH":    "T0,delay=2s,maxrate=5,passive",
    "NORMAL":     "T3,defaults",
    "AGGRESSIVE": "T4,threads=high",
    "FULL":       "T5,minrate=5000,all-scripts",
}

BASE_SYSTEM_PROMPT = """You are Kernox — autonomous offensive security agent on Kali Linux.
MODE NUMBER:{mode_number} MODE NAME:{intensity_name} TIMING:{timing}
{memory}
Return ONLY this JSON (no markdown, no extra text):
{{"is_chat":false,"analysis":"one sentence","steps":[{{"tool":"shell","args":{{"command":"full exact command","target":"ip or hostname"}},"reason":"why"}}],"message":"one sentence"}}

RULES:
- "tool" MUST always be "shell" — never put a binary name there
- "command" = complete runnable command e.g. "nmap -sV -p- 192.168.0.1"
- For URLs strip protocol: https://example.com → target=example.com
- For web recon chain steps: whois, dig, nmap, whatweb, nikto
- Multiple steps allowed — return all in steps array
- msfconsole: "msfconsole -q -x 'use exploit/X; set RHOSTS T; run'"
- msfvenom: output to /tmp/kernox/
- NO shell operators ; && || | > >> (except inside single-quoted -x args)
- NO sudo prefix — kernox adds it automatically
- NEVER suggest patching, hardening, or remediation
- is_chat:true + steps:[] for greetings or pure questions only
- Do NOT suggest report/pdf/export — that is handled by the user separately
- When user asks for code/snippet without "execute/run/save/create file": set is_chat:true and put code in message field with no steps"""

ip_context = get_ip_context()


class Orchestrator:
    def __init__(self, config: ConfigStore) -> None:
        self._cfg = config
        self._ai  = build_ai_client(config)
        self._state   = SessionState()
        self._updater = StateUpdater(self._state)
        self._history: list[dict] = []
        self._intensity = INTENSITY_LEVELS["2"]

        self._mail_crawler = MailCrawlerTool()

        self._chat_handler   = ChatHandler(self._ai, self._state, self._history)
        self._cmd_executor   = CommandExecutor(config, self._state)
        self._ai_analyzer    = AIAnalyzer(self._ai, self._state, self._intensity)
        self._cmd_executor._ai_analyzer = self._ai_analyzer

        from kernox.core.orchestrator_helpers.reflection_engine import ReflectionEngine
        self._reflection = ReflectionEngine(self._ai, self._state, self._intensity)
        self._ai_analyzer.set_reflection_engine(self._reflection)
        self._cmd_executor._reflection = self._reflection
        self._state_manager  = StateManager(self._state, self._intensity)
        self._session_manager = SessionManager(self._state, self._updater)
        self._report_handler  = ReportHandler(self._state)
        self._feature_handler = FeatureHandler(self._state, self._cmd_executor._executor)
        self._cmd_executor._chat_handler = self._chat_handler  # Link for recording

        # ── On-demand analysis (shares the same AIAnalyzer — identical output) ──
        self._on_demand_analyzer = OnDemandAnalyzer(
            state=self._state,
            ai_analyzer=self._ai_analyzer,
        )
        # Auto-analyze flag — True by default, toggled with `analyze on/off`
        # Propagated to _cmd_executor so it skips the post-execution AI call.
        self._auto_analyze: bool = True

    def _check_result_question(self, user_input: str) -> bool:
        """Intercept questions about command results before normal processing"""
        result_patterns = [
            r"what.*found",
            r"what.*output",
            r"what.*file",
            r"show.*result",
            r"tool output",
            r"output of the tool",
            r"extracted",
            r"hidden.*message",
            r"did you find",
            r"cat.*\.out",
            r"what.*in the file",
            r"what did you find",
            r"output please",
            r"file you found",
            r"check.*output",
            r"show output",
            r"what is the output",
            r"where.*file.*saved",
            r"output of the tool\?",
        ]

        pattern = re.compile('|'.join(result_patterns), re.I)
        if pattern.search(user_input):
            print(f"[DEBUG] Intercepted: {user_input}")
            response = self._chat_handler.chat(user_input)
            console.print(Panel(Markdown(response), border_style="dim cyan", title="[dim]Response[/dim]", width=80))
            return True
        return False

    def run(self) -> None:
        session = PromptSession(style=PROMPT_STYLE)

        while True:
            try:
                mode = self._intensity["name"]
                mode_num = MODE_NUMBERS.get(mode, "2")
                label = f":{mode_num}.{mode.lower()}" if mode != "NORMAL" else ":2.normal"
                raw = session.prompt(f"\nkernox⮞⮞ ")
            except (EOFError, KeyboardInterrupt):
                break

            user_input = raw.strip()
            if not user_input:
                continue

            cmd = user_input.lower()

            if cmd in ("exit", "quit"):
                console.print("\n[dim]Stay ethical.[/dim]\n")
                break
            elif cmd == "help":
                self._print_help(); continue
            elif cmd == "state":
                self._state_manager.print_state(); continue
            elif cmd == "clear":
                self._state_manager.clear_all(self._history); continue
            elif cmd == "report":
                self._report_handler.ask_report(); continue
            elif cmd == "save":
                self._session_manager.save(); continue
            elif cmd == "load":
                self._session_manager.load(); continue
            elif cmd == "sessions":
                self._session_manager.list_sessions(); continue
            elif cmd == "mode":
                self._show_mode_picker(); continue
            elif cmd.startswith("cve"):
                self._feature_handler.cve(user_input[3:].strip()); continue
            elif cmd == "payload":
                self._feature_handler.payload(); continue
            elif cmd in ("log", "log clear"):
                self._feature_handler.log(user_input[3:].strip()); continue
            elif cmd == "score":
                self._feature_handler.score(); continue
            elif cmd.startswith("auto"):
                self._run_autonomous(user_input[4:].strip()); continue
            elif cmd in ("raw on", "raw off"):
                val = "1" if cmd == "raw on" else "0"
                self._cfg.set("show_raw_output", val)
                label_s = "[#55efc4]ON[/#55efc4]" if val == "1" else "[dim]OFF[/dim]"
                console.print(f"[cyan]✓ Raw output {label_s}[/cyan]")
                continue
            # ── analyze commands ──────────────────────────────────────────────
            elif cmd.startswith("analyze"):
                rest = user_input[len("analyze"):].strip()
                if rest.lower() == "on":
                    self._toggle_auto_analyze(True); continue
                elif rest.lower() == "off":
                    self._toggle_auto_analyze(False); continue
                else:
                    self._on_demand_analyzer.run(rest); continue

            builtin = detect_builtin(user_input)
            if builtin == "report":
                self._report_handler.ask_report(); continue
            elif builtin == "state":
                self._state_manager.print_state(); continue
            elif builtin == "score":
                self._feature_handler.score(); continue
            elif builtin == "log":
                self._feature_handler.log(); continue
            elif builtin == "save":
                self._session_manager.save(); continue
            elif builtin == "sessions":
                self._session_manager.list_sessions(); continue
            elif builtin == "payload":
                self._feature_handler.payload(); continue
            elif builtin == "cve":
                self._feature_handler.cve(); continue
            elif builtin == "mode":
                self._show_mode_picker(); continue

            self._auto_detect_intensity(user_input)
            self._process(user_input)

    def _process(self, user_input: str) -> None:
        self._history.append({"role": "user", "content": user_input})
        if len(self._history) > 30:
            self._history = self._history

        intensity_name = self._intensity["name"]
        mode_number = MODE_NUMBERS.get(intensity_name, "2")
        timing = INTENSITY_TIMING.get(intensity_name, "T3,defaults")

        from kernox.core.orchestrator_helpers.context_builder import build_agent_context
        raw_memory = build_agent_context(self._state)
        memory = raw_memory[:2000] if raw_memory else ""
        if ip_context and ip_context != "No active network interfaces found.":
            memory = f"{memory}\n\n{ip_context}"

        system_prompt = BASE_SYSTEM_PROMPT.format(
            mode_number=mode_number,
            intensity_name=intensity_name,
            timing=timing,
            memory=memory,
        )

        try:
            with Live(Spinner("dots", text="[cyan]Thinking...[/cyan]"),
                      refresh_per_second=10):
                ai_resp = self._ai.chat(
                    messages=self._history[-10:],
                    system=system_prompt,
                    max_tokens=800,
                )
        except Exception as exc:
            console.print(f"[red]✗ AI error: {exc}[/red]")
            return

        self._history.append({"role": "assistant", "content": ai_resp})

        plan = _extract_json(ai_resp)
        if not plan:
            console.print(Panel(Markdown(ai_resp), border_style="dim", width=80))
            return

        if plan.get("is_chat"):
            msg = plan.get("message") or ai_resp
            console.print(Panel(Markdown(msg), border_style="dim", width=80))
            return

        if plan.get("analysis"):
            console.print(f"\n[dim cyan]{plan['analysis']}[/dim cyan]")

        steps = plan.get("steps", [])
        if not steps:
            if plan.get("message"):
                console.print(Panel(Markdown(plan["message"]), border_style="dim", width=80))
            return

        self._print_plan(steps)
        self._execute_steps(steps)

    def _execute_steps(self, steps: list[dict]) -> None:
        for step in steps:
            tool = step.get("tool", "").lower()
            args = step.get("args", {})
            reason = step.get("reason", "")

            if tool == "mail_crawler":
                self._run_mail_crawler(args)
                continue

            if not args.get("command") and tool not in ("shell", "mail_crawler", ""):
                target = args.get("target", "")
                flags = args.get("flags", args.get("args", ""))
                args = {"command": f"{tool} {flags} {target}".strip(),
                        "target": target}

            if args.get("command"):
                self._cmd_executor.run_shell_step(args, reason, self._intensity)
            else:
                console.print(f"[red]✗ No command in step: {step}[/red]")

    def _run_mail_crawler(self, args: dict) -> None:
        target = args.get("target", "")
        if not target:
            console.print("[red]✗ No target for mail_crawler[/red]")
            return
        if not Confirm.ask(f"Run mail crawler on {target}?", default=True):
            return
        result = self._mail_crawler.run_direct(target=target, max_pages=200)
        emails = result.get("emails", [])
        if emails:
            console.print(f"[green]✓ Found {len(emails)} email(s)[/green]")
            for e in emails[:20]:
                console.print(f"  [cyan]{e}[/cyan]")
        else:
            console.print("[dim]No emails found.[/dim]")

    def _print_plan(self, steps: list[dict]) -> None:
        if not steps:
            return
        t = Table(title="Execution Plan", box=box.MINIMAL,
                  border_style="dim cyan", header_style="none", padding=(0, 1))
        t.add_column("#",       style="bold cyan", width=3)
        t.add_column("Command", style="white", no_wrap=False)
        t.add_column("Reason",  style="dim",  no_wrap=False)
        for i, s in enumerate(steps, 1):
            cmd = s.get("args", {}).get("command", "")
            reason = s.get("reason", "")
            t.add_row(str(i), cmd, reason)
        console.print(t)

    def _show_mode_picker(self) -> None:
        console.print()
        t = Table(title="Intensity Mode", box=box.MINIMAL,
                  border_style="bold cyan", padding=(0, 2))
        t.add_column("#",    style="cyan",  width=3)
        t.add_column("Mode", style="white", width=12)
        t.add_column("Timeout", style="dim", width=10)
        t.add_column("Description", style="dim")
        descs = {
            "STEALTH":    "Slow, quiet — avoid IDS detection",
            "NORMAL":     "Standard speed and noise level",
            "AGGRESSIVE": "Fast scans, full enumeration",
            "FULL":       "Maximum speed, all techniques",
        }
        for k, v in INTENSITY_LEVELS.items():
            marker = "▸ " if self._intensity["name"] == v["name"] else "  "
            t.add_row(
                f"{marker}{k}",
                v["name"],
                f"{v['timeout']}s",
                descs.get(v["name"], ""),
            )
        console.print(t)
        choice = Prompt.ask("Choose", choices=["1", "2", "3", "4"], default="2")
        self._intensity = INTENSITY_LEVELS[choice]
        self._ai_analyzer._intensity = self._intensity
        self._reflection._intensity = self._intensity
        console.print(f"[green]✓ Mode → {self._intensity['name']}[/green]")

    def _toggle_auto_analyze(self, enable: bool) -> None:
        """Enable or disable automatic post-execution AI analysis."""
        self._auto_analyze = enable
        # Propagate to command executor so it guards the AIAnalyzer call
        self._cmd_executor._auto_analyze = enable
        state = "[#55efc4]ON[/#55efc4]" if enable else "[dim]OFF[/dim]"
        console.print(f"[cyan]✓ Auto-analysis {state}[/cyan]")

    def _auto_detect_intensity(self, text: str) -> None:
        lower = text.lower()
        for kw, lvl in INTENSITY_KEYWORDS.items():
            if kw in lower:
                new = INTENSITY_LEVELS[lvl]
                if new["name"] != self._intensity["name"]:
                    self._intensity = new
                    self._ai_analyzer._intensity = new
                    self._reflection._intensity = new
                    console.print(f"[cyan]⚡ Intensity → {new['name']}[/cyan]")
                break

    def _run_autonomous(self, target_hint: str = "") -> None:
        results = self._state.get_tool_results()
        if not results and not target_hint:
            console.print(
                "[dim]No tool output in session yet. "
                "Run a scan first, or: auto 192.168.0.1[/dim]"
            )
            return

        if results:
            last = results[-1]
            seed_output = last.raw_output or last.tool
            seed_tool = last.tool
            seed_target = last.target
        else:
            seed_output = f"Starting reconnaissance on {target_hint}"
            seed_tool = "init"
            seed_target = target_hint

        self._reflection.autonomous_chain(
            initial_output = seed_output,
            tool_name = seed_tool,
            target = seed_target,
            intensity = self._intensity,
            executor = self._cmd_executor._executor,
            max_steps = 5,
        )

    def run_headless(self, target: str, mode: str = "web recon") -> None:
        console.print(f"\n[bold cyan]Headless:[/bold cyan] {mode} → {target}\n")
        self._process(f"{mode} {target}")

    def _print_help(self) -> None:
        t = Table(box=box.SIMPLE, show_header=False,
                  border_style="dim cyan", padding=(0, 2))
        t.add_column(style="bold cyan",  width=28, no_wrap=True)
        t.add_column(style="dim white",  no_wrap=False)

        rows = [
            ("help",                            "show this menu"),
            ("exit / quit",                     "exit kernox"),
            ("clear",                           "reset session state and history"),
            ("mode",                            "pick intensity: STEALTH / NORMAL / AGGRESSIVE / FULL"),
            ("raw on / raw off",                "toggle live streaming of tool output"),
            ("auto [target]",                   "autonomous agent chain — AI plans & runs up to 5 steps"),
            ("state",                           "show hosts, findings, web paths, tools run"),
            ("score",                           "CVSS risk summary for all session findings"),
            ("cve <query>",                     "search NIST NVD — keyword or exact CVE-ID"),
            ("payload",                         "interactive msfvenom payload builder"),
            ("log",                             "attack timeline  |  log clear — wipe it"),
            ("report",                          "export findings to PDF"),
            ("save",                            "save session to disk"),
            ("load",                            "restore a saved session"),
            ("sessions",                        "list all saved sessions"),
            ("analyze",                         "analyze entire session (all saved outputs)"),
            ("analyze last",                    "analyze most recent tool output"),
            ("analyze <toolname>",              "analyze all outputs from a specific tool"),
            ("analyze <ip>",                    "analyze all findings for a host IP"),
            ("analyze on / analyze off",        "toggle auto-analysis after each tool run"),
        ]
        for cmd, desc in rows:
            t.add_row(cmd, desc)

        console.print(Panel(
            t,
            title="[bold cyan] Kernox Commands [/bold cyan]",
            border_style="cyan",
            box=box.MINIMAL,
            padding=(0, 1),
        ))
        console.print(
            "  [dim]Any natural language works: "
            "[cyan]\"scan 192.168.0.1\"[/cyan]  "
            "[cyan]\"enumerate web server at target.com\"[/cyan]  "
            "[cyan]\"exploit vsftpd on 192.168.0.5\"[/cyan][/dim]\n"
        )


def _extract_json(text: str) -> Optional[dict]:
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
