"""
kernox.core.orchestrator  –  Production-ready AI orchestrator with smart chaining.

Flow:
  1. User types command
  2. AI builds a plan (JSON)
  3. Each step runs with user confirmation
  4. After each tool → firewall check (nmap) or chain suggestion
  5. AI suggests next steps, user picks which to run

Improvements vs original:
  - HISTORY_LIMIT raised 8 → 20; smart state-summary injected so AI retains context
  - POST_TOOL_ANALYSIS now ON — AI explains every tool result automatically
  - VULN_EXPLANATIONS replaced by dynamic AI calls for any unknown finding
  - Session save/resume: `session save` / `session load`
  - --target / --mode non-interactive entry point via run_headless()
  - ZAP, Hydra, theHarvester fully wired (tools + chaining + system prompt)
  - AI retry logic lives in api.py; orchestrator no longer swallows silent failures
"""

from __future__ import annotations

import json
import time
import tempfile
import os
from pathlib import Path
from typing import Optional
from datetime import datetime

from prompt_toolkit import PromptSession
from prompt_toolkit.styles import Style
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.spinner import Spinner
from rich.live import Live
from rich.table import Table
from rich import box

from kernox.ai.factory import build_ai_client
from kernox.config.config_store import ConfigStore
from kernox.core.executor import Executor
from kernox.core.firewall_detect import analyse_firewall, print_firewall_analysis
from kernox.core.enumerator import suggest_enumeration, print_enum_plan, EnumStep
from kernox.engine.state import SessionState
from kernox.engine.state_updater import StateUpdater
from kernox.tools.nmap import NmapTool
from kernox.tools.ffuf import FfufTool
from kernox.tools.gobuster import GobusterTool
from kernox.tools.sqlmap import SqlmapTool
from kernox.tools.nikto import NiktoTool
from kernox.tools.enum4linux import Enum4linuxTool
from kernox.tools.wpscan import WpscanTool
from kernox.tools.smbclient import SmbclientTool
from kernox.tools.dnsenum import DnsenumTool
from kernox.tools.curl_probe import CurlProbeTool
from kernox.tools.hashcat import HashcatTool
from kernox.tools.whatweb import WhatwebTool
from kernox.tools.wafw00f import Wafw00fTool
from kernox.tools.sslscan import SslscanTool
from kernox.tools.onesixtyone import OnesixtyoneTool
from kernox.tools.dnsrecon import DnsreconTool
from kernox.tools.nuclei import NucleiTool
from kernox.tools.privesc import PrivescTool
from kernox.utils.privesc_formatter import format_privesc
from kernox.utils.formatter import format_results
from kernox.utils.report_generator import generate_pdf_report
from kernox.tools.msfvenom import MsfvenomTool
from kernox.tools.mail_crawler import MailCrawlerTool
from kernox.tools.zapcli import ZapCliTool
from kernox.tools.hydra import HydraTool
from kernox.tools.theharvester import TheHarvesterTool

console = Console()

# ── Tunables ──────────────────────────────────────────────────────────────────
HISTORY_LIMIT    = 20      # raised from 8 — keeps more context for the AI
API_DELAY        = 2
POST_TOOL_ANALYSIS = True  # was False — AI now explains every tool result

# ── System prompt ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are Kernox, a production-grade AI penetration testing assistant.
You ONLY help with authorized security testing.

CRITICAL: You MUST ALWAYS respond with ONLY a JSON object. No text before or after the JSON.
Your entire response must be valid JSON in this exact format:

{
  "analysis": "your reasoning here",
  "steps": [
    {
      "tool": "nmap",
      "args": {"target": "192.168.1.1", "mode": "service"},
      "reason": "why this tool"
    }
  ],
  "message": "human-friendly summary shown to user"
}

DO NOT write any text outside the JSON object.
DO NOT wrap in markdown code blocks.
JUST return the raw JSON object.

Available tools and their args:

nmap:
  args: target, mode (ai/quick/service/aggressive/vuln/full/stealth/udp/script/firewall), ports, flags
  The AI will automatically choose the best scan strategy based on target and context.
  Use mode="ai" to let AI decide, or specify a specific mode.
  For firewall evasion, use mode="firewall".
  Examples:
    - "scan target 192.168.1.1" → AI chooses optimal strategy
    - "quick scan of example.com" → mode="quick"
    - "check for vulnerabilities on web server" → AI chooses vuln mode with web scripts
    - "scan through firewall" → mode="firewall"

ffuf:
  args: target (URL), mode (dir/vhost/param/post/ai/custom), wordlist, extensions
  Use mode="ai" to let AI choose optimal strategy.
  Use mode="dir" for directory/file fuzzing (FUZZ in path).
  Use mode="vhost" for virtual host discovery.
  Use mode="param" for GET parameter fuzzing.
  Use mode="post" for POST parameter fuzzing.
  Examples:
    - "fuzz example.com" → AI chooses strategy
    - "find subdomains on test.example.com" → mode="vhost"
    - "fuzz parameters on https://site.com/page?id=FUZZ" → mode="param"

gobuster:
  args: target, mode (dir/dns/vhost/s3/custom), wordlist
  Use mode="dns" for subdomain enum, mode="vhost" for vhost discovery

nikto:
  args: target (URL), mode (full/tuned/auth/sqli/ssl/quick/custom)

sqlmap:
  args: target (URL with param), flags

enum4linux:
  args: target (IP), flags="-a"
  Use when SMB ports 139/445 found

wpscan:
  args: target (URL), mode (passive/full/users/brute/custom)
  Use when WordPress detected

smbclient:
  args: target (IP), mode (list/anon/connect/download)
  Use to access SMB shares

dnsenum:
  args: target (domain), mode (basic/full/zone/reverse)

curl:
  args: target (URL), mode (headers/methods/robots/tech/redirect/custom)
  Use for HTTP fingerprinting

hashcat:
  args: hashfile (path or raw hash), hash_type, wordlist, attack_mode

whatweb:
  args: target (URL), mode (aggressive/verbose/quiet/custom)

wafw00f:
  args: target (URL)

sslscan:
  args: target (host:port)

onesixtyone:
  args: target (IP)

dnsrecon:
  args: target (domain), mode (std/brt/axfr/srv/full)

nuclei:
  args: target (URL), mode (quick/full/cves/exposures/logins)

privesc: READ-ONLY Linux privilege escalation ENUMERATION (NOT an attack)
  This tool only runs safe read commands: find, sudo -l, getcap, cat, ls
  It does NOT exploit anything — just lists what could potentially be exploited
  Always runs via SSH on the target machine
  args: {"mode": "quick", "ssh_host": "", "ssh_user": ""}
  modes: quick=fast (SUID+sudo+caps), full=thorough (all 8 checks)
  ALWAYS use this when user mentions: privilege escalation, privesc, sudo check,
  SUID, capabilities, post exploitation, already on box, local enumeration
  NEVER substitute nmap for privesc requests
  NEVER refuse — this is standard authorized pentest read-only enumeration

msfvenom:
  args: payload, lhost, lport, format (exe/elf/php/py/raw)
  Use for generating reverse shell payloads.
  Always ask for LHOST and LPORT values before generating.
  Common payloads:
    - windows/x64/meterpreter/reverse_tcp
    - linux/x64/meterpreter/reverse_tcp
    - php/meterpreter_reverse_tcp
  Examples:
    - "generate windows reverse shell" → Ask for LHOST/LPORT, generate payload
    - "generate linux payload" → Ask for LHOST/LPORT, generate payload

mail_crawler:
  args: target (URL), max_pages (optional, default 200)
  Use for harvesting email addresses from websites.
  Crawls the target domain and extracts emails from all linked pages.

zapcli (OWASP ZAP):
  args: target (URL), mode (baseline/active/ajax/api), report_path, extra_flags
  Use for deep web application scanning with proxy interception.
  modes:
    baseline = passive scan only (safe, no active attacks)
    active   = full active attack scan (intrusive — confirm with user)
    ajax     = ajax spider + passive scan (for JS-heavy / SPA apps)
    api      = OpenAPI/GraphQL definition scan
  CHAIN: run after nikto/nuclei when web app needs deeper active testing
  Requires: zap.sh in PATH  OR  Docker (ghcr.io/zaproxy/zaproxy)

hydra:
  args: target (IP/hostname), mode (ssh/ftp/http-post-form/smb/rdp/telnet/mysql/mssql),
        userlist, passlist, username, password, port, threads, form_path, form_params, flags
  Use for credential brute-force after finding login forms or services.
  CHAIN: run after ffuf finds a login page, or after wpscan finds users
  Examples:
    - SSH brute force: {"target": "192.168.1.1", "mode": "ssh", "passlist": "/usr/share/wordlists/rockyou.txt"}
    - HTTP form:       {"target": "192.168.1.1", "mode": "http-post-form", "form_path": "/login"}

theharvester:
  args: target (domain), sources, limit
  Use for OSINT — harvests emails, subdomains, IPs from public sources.
  CHAIN: run before or alongside mail_crawler for broader OSINT coverage
  Example: {"target": "example.com", "sources": "google,bing,crtsh,certspotter"}

CHAINING RULES:
- nmap finds port 80/443 → suggest nikto + ffuf + curl + zapcli (baseline)
- nmap finds port 139/445 → suggest enum4linux + smbclient
- nmap finds WordPress → suggest wpscan
- nmap finds MySQL/PostgreSQL → suggest sqlmap
- mail_crawler finds emails → suggest theharvester for broader OSINT
- theharvester finds subdomains → suggest dnsrecon + nuclei on each
- nikto finds WordPress → suggest wpscan
- nikto finds vulnerabilities → suggest zapcli active scan for confirmation
- ffuf finds login page → suggest sqlmap + hydra
- wpscan finds users → suggest hydra with http-post-form mode
- wpscan finds users → suggest hashcat on found hashes
- nmap finds port 161 (SNMP) → suggest onesixtyone
- nmap finds HTTPS → suggest sslscan + wafw00f
- nmap finds domain/DNS → suggest dnsrecon + theharvester
- curl/nikto finds tech → suggest whatweb for deeper fingerprint
- wafw00f detects WAF → warn user before fuzzing or running zapcli active; suggest sqlmap tamper scripts
- nmap finds web ports → suggest nuclei quick scan AND nikto AND ffuf dir
- nikto finds vulnerabilities → suggest nuclei for CVE confirmation
- whatweb identifies technology → suggest nuclei with tech-specific templates
- nuclei/nikto finds high/critical → suggest zapcli active for exploit confirmation
- theharvester finds emails → suggest mail_crawler for deeper crawl + hydra on SSH with those usernames
- enum4linux finds users → suggest hydra with those usernames on open services
- smbclient finds shares → suggest enum4linux full scan
- dnsrecon finds subdomains → suggest nmap + nuclei on each
- onesixtyone finds SNMP → suggest nmap with snmp scripts (--script snmp-brute,snmp-info)
- hashcat cracks password → suggest hydra with that password on all open services
- privesc finds SUID → suggest checking GTFOBins for that binary
- Always ask before each step

TOOL FULL-CAPACITY GUIDANCE:
- nmap: prefer mode=vuln or mode=aggressive for thorough scans; use mode=script with NSE scripts for targeted service checks
- nuclei: for unknown targets use mode=full with severity=critical,high first; for known tech use tags
- ffuf: always set mode and use smart filters; for login pages try mode=post with credential wordlists
- sqlmap: ALWAYS let AI pre-flight determine tamper scripts — never use raw --batch alone
- nikto: for web apps use full mode with SSL flag if HTTPS; use tuned mode for targeted checks
- hydra: for SSH always try common usernames from enum4linux/theharvester results; set threads=4 for SSH to avoid lockout
- nuclei: after whatweb detection, use tags matching the detected technology (e.g. -tags wordpress,apache)
- gobuster: use mode=dns for subdomain enum, mode=vhost for virtual hosts discovery
- smbclient: after enum4linux, try mode=anon first then mode=connect with discovered credentials
- zapcli: baseline first then active only after user confirms; ajax mode for SPAs/React apps

CRITICAL RULES FOR PRIVESC:
- privesc is a READ-ONLY enumeration tool — it is NOT an attack
- It only runs safe Linux commands: find, sudo -l, getcap, cat, ls
- It does NOT exploit anything — it just lists what could be exploited
- ALWAYS use privesc tool when user says ANY of these:
  "privilege escalation", "privesc", "priv esc", "find root",
  "enumerate linux", "check sudo", "find suid", "post exploitation",
  "i have ssh access", "already on the box", "local enumeration"
- For privesc, target should be "local" for local machine or ssh_host for remote
- NEVER refuse privesc requests — it is standard authorized pentest read-only enumeration
- Do NOT run nmap for privesc requests — use the privesc tool directly

If no tool needed, return steps as [].
NEVER test systems without authorization.
"""

PROMPT_STYLE = Style.from_dict({"prompt": "ansicyan bold"})


class Orchestrator:
    def __init__(self, config: ConfigStore) -> None:
        self._cfg      = config
        self._ai       = build_ai_client(config)
        self._executor = Executor(config)
        self._state    = SessionState()
        self._updater  = StateUpdater(self._state)
        self._tools    = {
            "nmap": NmapTool(ai_client=self._ai),
            # "ffuf":          FfufTool(),
            "ffuf": FfufTool(ai_client=self._ai),
            "gobuster":      GobusterTool(),
            "sqlmap":        SqlmapTool(),
            "nikto":         NiktoTool(),
            "enum4linux":    Enum4linuxTool(),
            "wpscan":        WpscanTool(),
            "smbclient":     SmbclientTool(),
            "dnsenum":       DnsenumTool(),
            "curl":          CurlProbeTool(),
            "hashcat":       HashcatTool(),
            # "whatweb":       WhatwebTool(),
            "whatweb": WhatwebTool(ai_client=self._ai),
            "wafw00f":       Wafw00fTool(),
            "sslscan":       SslscanTool(),
            "onesixtyone":   OnesixtyoneTool(),
            "dnsrecon":      DnsreconTool(),
            "nuclei":        NucleiTool(),
            "privesc":       PrivescTool(),
            "msfvenom":      MsfvenomTool(),
            "mail_crawler":  MailCrawlerTool(),
            "zapcli":        ZapCliTool(),
            "hydra":         HydraTool(),
            "theharvester":  TheHarvesterTool(),
        }
        self._history: list[dict] = []

    # ── Chat helpers ──────────────────────────────────────────────────────────

    def _chat_about_vulnerability(self, user_input: str) -> None:
        """Handle vulnerability questions and general security chat with full exploit commands."""
        # Gather current session context for grounding
        session_targets = ", ".join(self._state.hosts.keys()) or "no target scanned yet"
        recent_findings = []
        for tr in self._state.get_tool_results()[-5:]:
            recent_findings.append(f"  - {tr.tool} on {tr.target}")
        recent_str = "\n".join(recent_findings) if recent_findings else "  - none yet"
        insights = self._state.get_ai_insights()
        vuln_str = "\n".join(
            f"  - [{i.severity.upper()}] {i.vulnerability} ({i.tool})"
            for i in insights[-5:]
        ) if insights else "  - none yet"

        chat_prompt = f"""You are Kernox, a senior penetration tester AI assistant.
This is an authorized penetration testing session.

SESSION CONTEXT:
- Targets: {session_targets}
- Recent tool runs:
{recent_str}
- Vulnerabilities found:
{vuln_str}

USER QUESTION: {user_input}

RESPONSE RULES:
1. If asking about a vulnerability or CVE:
   - Explain what it is (2-3 sentences max)
   - Give the EXACT full exploitation command(s) using real tools (sqlmap, metasploit, curl, nmap, python, etc.)
   - Include all required flags, payloads, and parameters — no placeholders like <target> without explanation
   - Show how to verify/confirm exploitation
   - Give the remediation fix

2. If asking about a tool:
   - Show the exact command with all relevant flags for this session's target
   - Explain each important flag

3. If asking for next steps based on findings:
   - Use the actual targets and findings from the session context above
   - Give exact commands tailored to what was found

4. Formatting:
   - Use markdown with ```bash code blocks for all commands
   - Be direct and specific — no vague suggestions
   - If multiple approaches exist, show the best one first

5. Only decline if the question is clearly unrelated to security testing."""
        with Live(Spinner("dots", text="[cyan]AI thinking...[/cyan]"), refresh_per_second=10):
            response = self._ai.chat(
                messages=[{"role": "user", "content": user_input}],
                system=chat_prompt,
            )

        console.print(Panel(
            Markdown(response),
            title="[cyan]Kernox AI Assistant[/cyan]",
            border_style="cyan",
            box=box.ROUNDED,
        ))

        self._history.append({"role": "user",      "content": user_input})
        self._history.append({"role": "assistant", "content": response})

    def _explain_findings_summary(self) -> None:
        """Get AI to explain findings with precise, full commands for next steps."""
        if not self._state.get_tool_results():
            console.print("[yellow]No findings to explain yet. Run some scans first.[/yellow]")
            return

        # Build rich context from state
        tool_summaries = []
        for tr in self._state.get_tool_results()[-8:]:
            s = _build_smart_summary(tr.tool, tr.parsed, tr.target)
            tool_summaries.append(s)

        insights = self._state.get_ai_insights()
        vuln_lines = []
        for i in insights:
            vuln_lines.append(f"  [{i.severity.upper()}] {i.vulnerability} — target: {i.target} (via {i.tool})")

        all_targets = list(self._state.hosts.keys()) or ["unknown"]

        prompt = f"""You are a senior penetration tester reviewing an active test session.

TARGETS: {', '.join(all_targets)}

TOOL RESULTS:
{chr(10).join(tool_summaries)}

VULNERABILITIES FOUND:
{chr(10).join(vuln_lines) if vuln_lines else '  None confirmed yet'}

Provide a structured attack assessment with:

## Critical Findings
List the top issues found (severity, what it means)

## Attack Paths
For each viable attack path, give the EXACT commands:
```bash
# example — use real targets and flags
sqlmap -u 'http://target/page?id=1' --batch --level=3 --dbs
```

## Recommended Next Steps
Top 3 actions with full commands, prioritized by impact

## Risk Summary
One-line overall risk rating

Be specific to the actual targets and findings above. All commands must be copy-paste ready."""

        with Live(Spinner("dots", text="[cyan]Analysing session findings...[/cyan]"), refresh_per_second=10):
            response = self._ai.chat(
                messages=[{"role": "user", "content": prompt}],
                system="You are a senior penetration tester. Give exact commands, real targets, no placeholders.",
                max_tokens=900,
            )

        console.print(Panel(
            Markdown(response),
            title="[cyan]Session Analysis[/cyan]",
            border_style="cyan",
            box=box.ROUNDED,
        ))

    def _post_tool_ai_analysis(self, tool_name: str, parsed: dict, target: str) -> None:
        """
        POST_TOOL_ANALYSIS — after every tool completes, ask the AI to
        summarise findings and suggest the single most valuable next step.
        Now ON by default (was False).
        """
        if not POST_TOOL_ANALYSIS:
            return

        summary = _build_smart_summary(tool_name, parsed, target)
        if not summary.strip():
            return

        prompt = f"""You are a senior penetration tester. A tool just finished on an authorized test.

Tool: {tool_name.upper()}
Target: {target}
Results:
{summary}

Provide a SHORT but PRECISE response with:
1. The most important finding (1 sentence)
2. The EXACT next command to run — full command with all flags, not a description

Format:
**Finding:** <what matters>
**Next:** ```bash
<exact command here>
```

Rules:
- Command must be copy-paste ready with real flags, not placeholders
- Use the actual target: {target}
- If nothing significant found, just say "Clean — no critical findings."
- Max 6 lines total. No disclaimers."""
        try:
            with Live(Spinner("dots", text="[dim]AI analysing results...[/dim]"), refresh_per_second=10):
                response = self._ai.chat(
                    messages=[{"role": "user", "content": prompt}],
                    system="You are a senior penetration tester. Give exact commands, not suggestions.",
                    max_tokens=250,
                )
            if response and not response.startswith("Error:"):
                console.print(Panel(
                    Markdown(response),
                    title=f"[bold cyan]AI — {tool_name.upper()}[/bold cyan]",
                    border_style="cyan",
                    box=box.SIMPLE,
                ))
        except Exception:
            pass  # Never let post-analysis crash the main flow

    # ── Session persistence commands ──────────────────────────────────────────

    def _cmd_session_save(self) -> None:
        self._state.save()
        path = self._state._session_path()
        console.print(f"[green]✓ Session saved → {path}[/green]")

    def _cmd_session_load(self) -> None:
        sessions = SessionState.list_sessions()
        if not sessions:
            console.print("[yellow]No saved sessions found.[/yellow]")
            return

        table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE_HEAVY)
        table.add_column("#", width=4, style="bold cyan")
        table.add_column("File")
        table.add_column("Size")

        for i, p in enumerate(sessions[:10], 1):
            size = f"{p.stat().st_size // 1024} KB"
            table.add_row(str(i), p.name, size)

        console.print(table)
        choice = Prompt.ask("Load session #", default="1")
        if not choice.isdigit() or not (1 <= int(choice) <= len(sessions)):
            console.print("[yellow]Invalid choice.[/yellow]")
            return

        selected = sessions[int(choice) - 1]
        self._state = SessionState.load(selected)
        self._updater = StateUpdater(self._state)
        console.print(f"[green]✓ Session loaded: {selected.name}[/green]")
        console.print(f"[dim]{self._state.summary()}[/dim]")

    # ── Main REPL ─────────────────────────────────────────────────────────────

    def run(self) -> None:
        session: PromptSession = PromptSession(style=PROMPT_STYLE)
        while True:
            try:
                user_input = session.prompt("\nKernox > ", style=PROMPT_STYLE)
            except (EOFError, KeyboardInterrupt):
                raise KeyboardInterrupt

            user_input = user_input.strip()
            if not user_input:
                continue

            cmd = user_input.lower()
            if cmd in ("exit", "quit", "q"):
                console.print("[yellow]Goodbye. Stay ethical.[/yellow]")
                break
            elif cmd == "help":              self._print_help();  continue
            elif cmd == "tools":             self._print_tools(); continue
            elif cmd == "tools check":       self._check_tools(); continue
            elif cmd == "state":             self._print_state(); continue
            elif cmd == "history":           self._print_history(); continue
            elif cmd == "clear":             self._clear_all(); continue
            elif cmd == "clear history":
                self._history.clear()
                console.print("[green]✓ History cleared[/green]")
                continue
            elif cmd == "clear state":
                self._state.reset()
                console.print("[green]✓ State cleared[/green]")
                continue
            elif cmd == "raw on":
                self._cfg.set("show_raw_output", "1")
                console.print("[green]✓ Raw output ON — tool output will be streamed live[/green]")
                continue
            elif cmd == "raw off":
                self._cfg.set("show_raw_output", "0")
                console.print("[yellow]✓ Raw output OFF — tools run silently with spinner[/yellow]")
                continue
            elif cmd == "raw":
                current = self._cfg.get("show_raw_output") == "1"
                state = "[green]ON[/green]" if current else "[yellow]OFF[/yellow]"
                console.print(f"Raw output is currently {state}. Type [bold]raw on[/bold] or [bold]raw off[/bold] to toggle.")
                continue
            elif cmd.startswith("web recon ") or cmd.startswith("full recon "):
                target = user_input.split(" ", 2)[-1].strip()
                from kernox.core.web_recon import WebReconChain
                WebReconChain(self).run(target)
                continue
            elif cmd == "report":
                self._ask_report()
                continue
            elif cmd in ("analyse", "analyze", "paste"):
                from kernox.core.analyse_mode import run_analyse_mode
                run_analyse_mode()
                continue
            elif cmd.startswith("ask "):
                question = user_input[4:].strip()
                if not question:
                    question = Prompt.ask("[cyan]What would you like to know?[/cyan]")
                self._chat_about_vulnerability(question)
                continue
            elif cmd == "explain":
                self._explain_findings_summary()
                continue
            elif cmd == "session save":
                self._cmd_session_save()
                continue
            elif cmd == "session load":
                self._cmd_session_load()
                continue
            elif cmd == "session list":
                sessions = SessionState.list_sessions()
                if not sessions:
                    console.print("[yellow]No saved sessions found.[/yellow]")
                else:
                    for i, p in enumerate(sessions[:10], 1):
                        console.print(f"  [cyan]{i}.[/cyan] {p.name}  ({p.stat().st_size // 1024} KB)")
                continue

            self._process(user_input)

    def run_headless(self, target: str, mode: str = "web recon") -> None:
        """
        Non-interactive entry point for scripting / CI use.

        Examples
        --------
        kernox --target http://example.com --mode "web recon"
        kernox --target 192.168.1.1 --mode scan
        """
        console.print(f"\n[bold green][Kernox headless][/bold green] target=[cyan]{target}[/cyan] mode=[cyan]{mode}[/cyan]\n")

        if "web recon" in mode or "full recon" in mode:
            from kernox.core.web_recon import WebReconChain
            WebReconChain(self).run(target)
        else:
            # Treat mode as a natural language command directed at the AI
            self._process(f"{mode} {target}")

    # ── Process pipeline ──────────────────────────────────────────────────────

    def _process(self, user_input: str) -> None:
        # Detect chat-style queries and route to the chat handler
        chat_keywords = [
            "what is", "how to", "explain", "tell me about", "what does",
            "how does", "why is", "can you", "help me understand",
            "difference between", "compare", "recommend",
        ]
        is_chat_query = (
            any(user_input.lower().startswith(kw) for kw in chat_keywords)
            or ("?" in user_input and len(user_input.split()) < 15)
        )
        if is_chat_query and not any(
            cmd in user_input.lower()
            for cmd in ["scan", "run", "enumerate", "fuzz", "crack"]
        ):
            self._chat_about_vulnerability(user_input)
            return

        self._history.append({"role": "user", "content": user_input})

        # Build a compact state summary to keep the AI informed even as
        # raw history gets trimmed.
        state_summary = self._build_state_context()

        with Live(Spinner("dots", text="[cyan]AI thinking...[/cyan]"), refresh_per_second=10):
            ai_response = self._ai.chat(
                messages=self._trimmed_history(),
                system=SYSTEM_PROMPT + "\n\n" + state_summary,
            )
        self._history.append({"role": "assistant", "content": ai_response})

        plan = _extract_json_plan(ai_response)
        if plan is None:
            console.print(Panel(Markdown(ai_response), title="[cyan]Kernox AI[/cyan]", border_style="cyan"))
            return

        if plan.get("message"):
            console.print(Panel(
                plan["message"],
                title="[cyan]Kernox AI[/cyan]",
                border_style="cyan",
            ))
        elif plan.get("analysis"):
            console.print(Panel(
                plan["analysis"],
                title="[cyan]Kernox AI[/cyan]",
                border_style="cyan",
            ))

        steps = plan.get("steps", [])
        if not steps:
            return

        self._print_plan(steps)

        all_summaries: list[str] = []
        for i, step in enumerate(steps, 1):
            tool_name = step.get("tool", "").lower()
            args      = dict(step.get("args", {}))
            reason    = step.get("reason", "")

            console.print(
                f"\n[bold magenta]▶ {tool_name.upper()}[/bold magenta] "
                f"[dim]{reason}[/dim]"
            )

            if not Confirm.ask(f"Run {tool_name}?", default=True):
                console.print(f"[yellow]⏭ Skipped {tool_name}[/yellow]")
                continue

            if tool_name == "hashcat":
                args = self._prepare_hashcat_args(args)
            if tool_name == "privesc":
                args = self._prepare_privesc_args(args)
            if tool_name == "sqlmap":
                args = self._prepare_sqlmap_args(args)

            result_data = self._run_tool(tool_name, args)
            if result_data is None:
                continue

            parsed, result = result_data
            summary = _build_smart_summary(tool_name, parsed, args.get("target", ""))
            all_summaries.append(summary)

            # POST_TOOL_ANALYSIS — now on by default
            self._post_tool_ai_analysis(tool_name, parsed, args.get("target", ""))

            chain_steps = self._suggest_chain(tool_name, parsed, args)
            if chain_steps:
                self._run_chain(chain_steps)

        if all_summaries:
            self._history.append({"role": "user",      "content": "Tools finished: " + " | ".join(all_summaries)})
            self._history.append({"role": "assistant", "content": "Results stored."})
            console.print(Panel(
                f"[green]✓ Session complete.[/green]\n"
                f"[dim]State: {self._state.summary()}[/dim]\n"
                "Type [bold]state[/bold] to review findings, "
                "[bold]session save[/bold] to save, or [bold]report[/bold] to export PDF.",
                title="[cyan]Done[/cyan]", border_style="green",
            ))
            from rich.prompt import Confirm as C
            if C.ask("\n[bold yellow]Export findings to PDF report?[/bold yellow]", default=False):
                self._ask_report()

    # ── State context for AI ──────────────────────────────────────────────────

    def _build_state_context(self) -> str:
        """
        Build a rich state summary injected into every AI request so the AI
        always has full situational awareness even when raw history is trimmed.
        """
        lines = [
            "=== CURRENT SESSION STATE ===",
            f"Hosts scanned: {', '.join(self._state.hosts.keys()) or 'None'}",
            f"Total open ports: {sum(len(h.ports) for h in self._state.hosts.values())}",
            f"AI insights found: {len(self._state.get_ai_insights())}",
            f"Tools run: {len(self._state.get_tool_results())}",
        ]

        # All discovered hosts with full open port list
        for ip, host in list(self._state.hosts.items())[:5]:
            open_ports = [p for p in host.ports if p.get("state") == "open"]
            if open_ports:
                port_list = ", ".join(
                    f"{p['port']}/{p.get('proto','tcp')}({p.get('service','')} {p.get('version','')[:20]})"
                    for p in open_ports[:15]
                )
                lines.append(f"  HOST {ip} [{host.os or 'OS unknown'}]: {port_list}")

        # Detected technologies (from whatweb/wpscan)
        detected_tech = set()
        for tr in self._state.get_tool_results():
            if tr.tool in ("whatweb", "wpscan"):
                for t in tr.parsed.get("technologies", []):
                    detected_tech.add(t)
        if detected_tech:
            lines.append(f"  Tech detected: {', '.join(list(detected_tech)[:8])}")

        # Confirmed vulnerabilities
        for i in self._state.get_ai_insights()[-6:]:
            lines.append(f"  [{i.severity.upper()}] {i.vulnerability} ({i.tool} on {i.target})")

        # All tools run (not just last 3) — helps AI avoid repeating
        tools_run = [(tr.tool, tr.target) for tr in self._state.get_tool_results()]
        if tools_run:
            lines.append(f"  Tools run: {', '.join(f'{t}@{tgt}' for t,tgt in tools_run[-10:])}")

        lines.append("=== END STATE ===")
        return "\n".join(lines)

    # ── Tool runner ───────────────────────────────────────────────────────────

    def _run_tool(self, tool_name: str, args: dict) -> Optional[tuple[dict, object]]:
        """Run a single tool. Returns (parsed, result) or None if blocked."""
        tool = self._tools.get(tool_name)
        if not tool:
            console.print(f"[red]Unknown tool: {tool_name}[/red]")
            return None

        # ── Smart arg enrichment from session state ──────────────────────────

        # ffuf: inject context from whatweb for tech-aware fuzzing
        if tool_name == "ffuf":
            context = {
                "technologies": [],
                "server": "",
                "has_login_page": False,
                "detected_paths": []
            }
            for tr in self._state.get_tool_results():
                if tr.tool == "whatweb":
                    context["technologies"] = tr.parsed.get("technologies", [])
                    context["server"] = tr.parsed.get("headers", {}).get("server", "")
                if tr.tool == "ffuf" and args.get("target") == tr.target:
                    context["detected_paths"] = [f.get("path") for f in tr.parsed.get("findings", [])[:10]]
                if tr.tool == "curl":
                    context["headers"] = tr.parsed.get("headers", {})
                # Check for login page from previous scans
                if tr.tool == "whatweb" and "login" in str(tr.parsed.get("technologies", [])).lower():
                    context["has_login_page"] = True
            args["context"] = context

        # In _run_tool, when calling nikto, pass context from previous findings
        if tool_name == "nikto":
            # Build context from whatweb and nmap results
            context = {
                "technologies": [],
                "open_ports": [],
                "headers": {}
            }
            for tr in self._state.get_tool_results():
                if tr.tool == "whatweb":
                    context["technologies"] = tr.parsed.get("technologies", [])
                    context["headers"] = tr.parsed.get("headers", {})
                if tr.tool == "nmap":
                    for host in tr.parsed.get("hosts", []):
                        for port in host.get("ports", []):
                            if port.get("state") == "open":
                                context["open_ports"].append(port.get("port"))
            args["context"] = context

        # nuclei: inject tags from detected tech (whatweb/wpscan) for targeted scans
        if tool_name == "nuclei" and not args.get("flags"):
            known_tech: set = set()
            for tr in self._state.get_tool_results():
                if tr.tool in ("whatweb", "wpscan"):
                    for t in tr.parsed.get("technologies", []):
                        known_tech.add(t.lower())
                if tr.tool == "wpscan" and tr.parsed.get("wp_version"):
                    known_tech.add("wordpress")
            TAG_MAP = {
                "wordpress": "wordpress,wp", "apache": "apache", "nginx": "nginx",
                "iis": "iis", "joomla": "joomla", "drupal": "drupal",
                "tomcat": "tomcat", "jenkins": "jenkins", "php": "php",
                "laravel": "laravel", "django": "django", "spring": "spring",
                "grafana": "grafana", "gitlab": "gitlab", "redis": "redis",
                "elasticsearch": "elasticsearch",
            }
            matched_tags = []
            for tech in known_tech:
                for key, tag in TAG_MAP.items():
                    if key in tech:
                        matched_tags.extend(tag.split(","))
            if matched_tags:
                unique_tags = ",".join(dict.fromkeys(matched_tags))
                if args.get("mode", "quick") == "quick":
                    args["flags"] = (
                        f"-tags {unique_tags} -severity critical,high,medium "
                        f"-o /tmp/kernox_nuclei.txt -json-export /tmp/kernox_nuclei.json"
                    )
                    args.pop("mode", None)
                    console.print(f"[dim]Nuclei: tags [{unique_tags}] auto-injected from detected tech[/dim]")

        # hydra: auto-inject discovered usernames from enum4linux/theharvester
        if tool_name == "hydra" and not args.get("username") and not args.get("userlist"):
            discovered_users = []
            for tr in self._state.get_tool_results():
                if tr.tool == "enum4linux":
                    for u in tr.parsed.get("users", [])[:10]:
                        if u.get("username"):
                            discovered_users.append(u["username"])
                if tr.tool == "theharvester":
                    for email in tr.parsed.get("emails", [])[:5]:
                        discovered_users.append(email.split("@")[0])
            discovered_users = list(dict.fromkeys(u for u in discovered_users if u))
            if discovered_users:
                import tempfile as _tf
                tmp = _tf.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, prefix="kernox_users_")
                tmp.write("\n".join(discovered_users))
                tmp.close()
                args["userlist"] = tmp.name
                console.print(f"[dim]Hydra: {len(discovered_users)} discovered usernames loaded[/dim]")

        # Special handling for mail_crawler (Python-based, no shell command)
        if tool_name == "mail_crawler":
            console.print(f"[bold magenta]\n── {tool_name.upper()} ──[/bold magenta]")
            result = tool.run_direct(**args)
            parsed = result
            format_results(tool_name, parsed)
            self._state.add_tool_result(tool=tool_name, target=args.get("target", ""), parsed=parsed)
            return parsed, None

        # Build command and run via executor
        command = tool.build_command(**args)
        console.print(f"[bold magenta]\n── {tool_name.upper()} ──[/bold magenta]")
        result = self._executor.run(
            command,
            tool_name=tool_name,
            target=args.get("target"),
            skip_confirm=tool_name == "privesc",
            stream_output=tool_name == "privesc",
        )

        if result.blocked:
            return None

        # Nmap: firewall detection + evasion retry
        if tool_name == "nmap":
            fw = analyse_firewall(result.stdout)
            if fw.detected:
                print_firewall_analysis(fw)
                if Confirm.ask("🔄 Retry with evasion flags?", default=True):
                    retry_args = dict(args)
                    retry_args["flags"] = f"{fw.evasion_flags} -sV"
                    retry_args.pop("mode", None)
                    retry_cmd = tool.build_command(**retry_args)
                    console.print(f"[bold magenta]\n── NMAP (EVASION RETRY) ──[/bold magenta]")
                    result = self._executor.run(retry_cmd, tool_name="nmap-evasion", target=args.get("target"))

        parsed = tool.parse(result.stdout)

        self._state.add_tool_result(
            tool=tool_name,
            target=args.get("target", ""),
            parsed=parsed,
            raw_output=result.stdout,
        )

        self._updater.apply(tool_name, parsed, target=args.get("target"))
        format_results(tool_name, parsed)
        _explain_findings(tool_name, parsed)
        self._generate_ai_insights(tool_name, parsed, args.get("target", ""))

        return parsed, result

    # ── AI vulnerability insights ─────────────────────────────────────────────

    def _generate_ai_insights(self, tool_name: str, parsed: dict, target: str) -> None:
        """
        Generate AI explanations for vulnerabilities / interesting findings.
        Covers ALL tools — not just a handful.
        """
        vulnerabilities = []

        if tool_name == "nuclei":
            for finding in parsed.get("findings", []):
                if finding.get("severity") in ("critical", "high", "medium"):
                    vulnerabilities.append({
                        "name": finding.get("name", ""),
                        "severity": finding.get("severity", "medium"),
                        "description": finding.get("description", ""),
                    })

        # elif tool_name == "nikto":
        #     for finding in parsed.get("findings", [])[:5]:
        #         vulnerabilities.append({
        #             "name": finding[:80],
        #             "severity": "medium",
        #             "description": finding,
        #         })

        elif tool_name == "sqlmap" and parsed.get("vulnerable"):
            vulnerabilities.append({
                "name": "SQL Injection",
                "severity": "critical",
                "description": f"SQL injection found with parameters: {', '.join(parsed.get('parameters', []))}",
            })

        elif tool_name == "sslscan":
            for issue in parsed.get("issues", []):
                vulnerabilities.append({
                    "name": issue,
                    "severity": "high",
                    "description": issue,
                })

        elif tool_name == "wpscan":
            for vuln in parsed.get("vulnerabilities", []):
                vulnerabilities.append({
                    "name": vuln[:80],
                    "severity": "high",
                    "description": vuln,
                })

        elif tool_name == "zapcli":
            for alert in parsed.get("alerts", []):
                if alert.get("severity") in ("critical", "high", "medium"):
                    vulnerabilities.append({
                        "name": alert.get("name", "ZAP Alert"),
                        "severity": alert.get("severity", "medium"),
                        "description": f"Found at: {', '.join(alert.get('urls', [])[:2])}",
                    })

        elif tool_name == "hydra":
            cracked = parsed.get("cracked", [])
            if cracked:
                vulnerabilities.append({
                    "name": "Weak credentials found",
                    "severity": "critical",
                    "description": f"Hydra cracked {len(cracked)} credential(s): "
                                   + ", ".join(f"{c['username']}:{c['password']}" for c in cracked[:3]),
                })

        elif tool_name == "ffuf":
            # Flag interesting paths as medium findings
            interesting_paths = [
                f for f in parsed.get("findings", [])
                if any(kw in f.get("path", "").lower()
                       for kw in ("admin", "login", "config", "backup", "upload", ".git", "phpmyadmin", "wp-login"))
            ]
            for f in interesting_paths[:4]:
                vulnerabilities.append({
                    "name": f"Sensitive path exposed: {f.get('path', '')}",
                    "severity": "medium",
                    "description": f"Path {f.get('path', '')} returned HTTP {f.get('status', '?')}",
                })

        elif tool_name == "gobuster":
            interesting_paths = [
                p for p in parsed.get("paths", [])
                if any(kw in p.lower()
                       for kw in ("admin", "login", "config", "backup", ".git", "phpmyadmin"))
            ]
            for p in interesting_paths[:4]:
                vulnerabilities.append({
                    "name": f"Sensitive path found: {p}",
                    "severity": "medium",
                    "description": f"Gobuster discovered: {p}",
                })

        elif tool_name == "enum4linux":
            # Flag anonymous/guest access and excessive user enumeration
            shares = parsed.get("shares", [])
            users  = parsed.get("users", [])
            if shares:
                vulnerabilities.append({
                    "name": "SMB shares enumerated",
                    "severity": "medium",
                    "description": f"Found {len(shares)} SMB shares: {', '.join(s.get('name', '') for s in shares[:5])}",
                })
            if len(users) > 0:
                vulnerabilities.append({
                    "name": "SMB user enumeration possible",
                    "severity": "medium",
                    "description": f"Enumerated {len(users)} user(s) via null session / RID cycling",
                })

        elif tool_name == "dnsrecon":
            if parsed.get("zone_transfer_possible"):
                vulnerabilities.append({
                    "name": "DNS Zone Transfer allowed",
                    "severity": "high",
                    "description": "The DNS server allows AXFR zone transfers — exposes all DNS records",
                })
            if parsed.get("total_subdomains", 0) > 10:
                vulnerabilities.append({
                    "name": "Large attack surface via subdomains",
                    "severity": "low",
                    "description": f"{parsed.get('total_subdomains')} subdomains discovered",
                })

        # elif tool_name == "whatweb":
        #     # Flag outdated/vulnerable tech versions
        #     versions = parsed.get("versions", [])
        #     for v in versions:
        #         tech = v.get("tech", "")
        #         ver  = v.get("version", "")
        #         if tech and ver:
        #             vulnerabilities.append({
        #                 "name": f"Technology version exposed: {tech} {ver}",
        #                 "severity": "info",
        #                 "description": f"Server is running {tech} version {ver} — check for known CVEs",
        #             })
        #     if not versions:
        #         return  # Nothing interesting to explain

        # whatweb: inject context from nmap and curl
        if tool_name == "whatweb":
            # Flag outdated/vulnerable tech versions
            versions = parsed.get("versions", [])
            technologies = parsed.get("technologies", [])

            for v in versions:
                tech = v.get("tech", "")
                ver = v.get("version", "")
                if tech and ver:
                    vulnerabilities.append({
                        "name": f"Technology version exposed: {tech} {ver}",
                        "severity": "info",
                        "description": f"Server is running {tech} version {ver} — check for known CVEs",
                    })

            notable_techs = ["wordpress", "joomla", "drupal", "php", "apache", "nginx", "iis"]
            for tech in technologies:
                if tech.lower() in notable_techs and tech not in [v.get("tech") for v in versions]:
                    vulnerabilities.append({
                        "name": f"Technology detected: {tech}",
                        "severity": "info",
                        "description": f"Server is running {tech} — check for known vulnerabilities",
                    })

            if not versions and not technologies:
                return

        elif tool_name == "onesixtyone":
            if parsed.get("communities"):
                vulnerabilities.append({
                    "name": "SNMP community strings exposed",
                    "severity": "high",
                    "description": f"SNMP community strings accessible: "
                                   + ", ".join(c.get("community", "") for c in parsed.get("communities", [])[:3]),
                })

        elif tool_name == "theharvester":
            if parsed.get("emails"):
                vulnerabilities.append({
                    "name": "Email addresses harvested (OSINT)",
                    "severity": "info",
                    "description": f"Found {parsed.get('total_emails', 0)} emails via OSINT — potential phishing/credential attack targets",
                })

        elif tool_name == "nmap":
            # Flag specific dangerous service/version combos
            for host in parsed.get("hosts", []):
                for port in host.get("ports", []):
                    version = port.get("version", "").lower()
                    service = port.get("service", "").lower()
                    if "vsftpd" in version and "2.3.4" in version:
                        vulnerabilities.append({"name": "vsftpd 2.3.4 Backdoor", "severity": "critical",
                                                "description": "vsftpd 2.3.4 contains a backdoor on port 6200"})
                    if "unrealircd" in version and "3.2.8.1" in version:
                        vulnerabilities.append({"name": "UnrealIRCd 3.2.8.1 Backdoor", "severity": "critical",
                                                "description": "UnrealIRCd 3.2.8.1 has a backdoor cmd_die"})
                    if port.get("port") == 23 and port.get("state") == "open":
                        vulnerabilities.append({"name": "Telnet exposed (cleartext)", "severity": "high",
                                                "description": "Telnet transmits credentials in plaintext"})
                    if port.get("port") == 21 and "anonymous" in version:
                        vulnerabilities.append({"name": "FTP anonymous login", "severity": "high",
                                                "description": "FTP allows anonymous access"})

        else:
            return

        for vuln in vulnerabilities[:3]:
            try:
                explanation_resp = self._ai.chat(
                    messages=[{
                        "role": "user",
                        "content": f"""As a security expert, explain this vulnerability for a penetration test report:

Vulnerability: {vuln['name']}
Severity: {vuln['severity']}
Context: {vuln.get('description', 'No description available')}

Provide a clear, professional explanation in JSON format:
{{
    "description": "What is this vulnerability? (2-3 sentences)",
    "impact": "What are the risks? (1-2 sentences)",
    "recommendation": "How to fix it? (2-3 actionable steps)"
}}"""
                    }],
                    system="You are a senior security consultant. Provide clear, actionable explanations.",
                )

                import re as _re
                json_match = _re.search(r'\{.*\}', explanation_resp, _re.DOTALL)
                if json_match:
                    ai_explanation = json.loads(json_match.group())
                    self._state.add_ai_insight(
                        vulnerability=vuln['name'],
                        severity=vuln['severity'],
                        tool=tool_name,
                        target=target,
                        explanation=ai_explanation,
                    )
                else:
                    raise ValueError("No JSON in response")
            except Exception:
                self._state.add_ai_insight(
                    vulnerability=vuln['name'],
                    severity=vuln['severity'],
                    tool=tool_name,
                    target=target,
                    explanation={
                        "description": vuln.get('description', 'Vulnerability detected'),
                        "impact": "May lead to system compromise or data breach",
                        "recommendation": "Apply vendor patch and review security configuration",
                    },
                )

    # ── Smart chaining ────────────────────────────────────────────────────────

    # ── Smart chaining ────────────────────────────────────────────────────────

    def _suggest_chain(self, tool_name: str, parsed: dict, args: dict) -> list[dict]:
        """
        AI-driven chain suggestions.  The AI reads the tool results and the
        current session state and returns the most relevant next steps.
        Falls back to deterministic rules if the AI call fails.
        """
        suggestions = self._ai_chain_suggestions(tool_name, parsed, args)
        if suggestions:
            return suggestions
        return self._fallback_chain(tool_name, parsed, args)

    def _ai_chain_suggestions(self, tool_name: str, parsed: dict, args: dict) -> list[dict]:
        """Ask the AI which tools to run next based on what was just found."""
        target = args.get("target", "")
        summary = _build_smart_summary(tool_name, parsed, target)
        available_tools = list(self._tools.keys())

        prompt = f"""You are Kernox AI. A penetration test tool just finished running.

Tool: {tool_name.upper()}
Target: {target}
Results:
{summary}

Current session state:
{self._build_state_context()}

Based on these results, suggest the BEST 1-3 follow-up tools from this list:
{", ".join(available_tools)}

Rules:
- Only suggest tools that make sense given the actual findings
- Do NOT repeat a tool that was just run
- Prioritize high-impact findings
- If nothing significant was found, return an empty list

Respond ONLY with a JSON array (no other text):
[
  {{
    "tool": "tool_name",
    "args": {{"target": "..."}},
    "reason": "one-line reason",
    "priority": 1
  }}
]

priority: 1=high, 2=medium, 3=low. Return [] if no follow-up is needed."""

        try:
            with Live(Spinner("dots", text="[dim]AI planning next steps...[/dim]"), refresh_per_second=10):
                response = self._ai.chat(
                    messages=[{"role": "user", "content": prompt}],
                    system="You are a penetration testing expert. Return ONLY a JSON array.",
                    max_tokens=600,
                    temperature=0.1,
                )

            import re as _re
            arr_match = _re.search(r'\[.*\]', response, _re.DOTALL)
            if not arr_match:
                return []
            suggestions = json.loads(arr_match.group())
            if not isinstance(suggestions, list):
                return []

            valid = []
            for s in suggestions[:3]:
                if isinstance(s, dict) and s.get("tool") and s.get("tool") in self._tools:
                    valid.append({
                        "tool": s["tool"],
                        "args": s.get("args", {"target": target}),
                        "reason": s.get("reason", "AI suggested"),
                        "priority": s.get("priority", 2),
                    })
            return valid
        except Exception:
            return []


    def _fallback_chain(self, tool_name: str, parsed: dict, args: dict) -> list[dict]:
        """Deterministic fallback chain rules."""
        suggestions: list[dict] = []
        target = args.get("target", "")

        if tool_name == "nmap":
            enum_steps = suggest_enumeration(parsed)
            if enum_steps:
                print_enum_plan(enum_steps)
                for s in enum_steps:
                    if s.tool != "custom":
                        suggestions.append({"tool": s.tool, "args": s.args, "reason": s.reason, "priority": s.priority})
            for host in parsed.get("hosts", []):
                for port in host.get("ports", []):
                    if port.get("port") in (80, 443, 8080, 8180):
                        # Add whatweb suggestion for web servers
                        suggestions.append({
                            "tool": "whatweb",
                            "args": {"target": f"http{'s' if port.get('port') == 443 else ''}://{host['ip']}"},
                            "reason": f"Web server on port {port.get('port')} — fingerprint technologies",
                            "priority": 2,
                        })
                        if "wordpress" in port.get("version", "").lower():
                            suggestions.append({"tool": "wpscan", "args": {"target": f"http://{host['ip']}", "mode": "full"}, "reason": "WordPress detected", "priority": 1})
                        suggestions.append({"tool": "zapcli", "args": {"target": f"http{'s' if port.get('port') == 443 else ''}://{host['ip']}", "mode": "baseline"}, "reason": f"Web on port {port.get('port')} — ZAP scan", "priority": 3})
                    if port.get("port") in (53, 80, 443):
                        suggestions.append({"tool": "theharvester", "args": {"target": host.get("hostname") or target}, "reason": "OSINT harvest", "priority": 3})

        elif tool_name == "whatweb":
            # After whatweb detects technologies, suggest targeted tools
            technologies = parsed.get("technologies", [])
            techs_lower = [t.lower() for t in technologies]

            if "wordpress" in techs_lower or "wp" in techs_lower:
                suggestions.append({
                    "tool": "wpscan",
                    "args": {"target": target, "mode": "full"},
                    "reason": "WordPress detected by whatweb — deep scan",
                    "priority": 1,
                })
            if "joomla" in techs_lower:
                suggestions.append({
                    "tool": "joomscan",
                    "args": {"target": target},
                    "reason": "Joomla detected — run joomscan",
                    "priority": 2,
                })
            if "drupal" in techs_lower:
                suggestions.append({
                    "tool": "droopescan",
                    "args": {"target": target, "mode": "drupal"},
                    "reason": "Drupal detected — run droopescan",
                    "priority": 2,
                })
            if any(tech in techs_lower for tech in ["php", "asp", "jsp"]):
                suggestions.append({
                    "tool": "ffuf",
                    "args": {"target": target, "mode": "dir"},
                    "reason": f"{'PHP' if 'php' in techs_lower else 'ASP/JSP'} detected — directory fuzzing",
                    "priority": 2,
                })
            # Always suggest nuclei after whatweb
            suggestions.append({
                "tool": "nuclei",
                "args": {"target": target, "mode": "quick"},
                "reason": f"Technologies detected: {', '.join(technologies[:3])} — run nuclei CVEs",
                "priority": 2,
            })

        elif tool_name == "nikto":
            findings = " ".join(parsed.get("findings", [])).lower()
            if "wordpress" in findings:
                suggestions.append({"tool": "wpscan", "args": {"target": target, "mode": "full"}, "reason": "WordPress found by nikto", "priority": 1})
            if "sql" in findings or "injection" in findings:
                suggestions.append({"tool": "sqlmap", "args": {"target": target, "flags": "--batch --level=2"}, "reason": "Potential SQLi found", "priority": 1})
            if parsed.get("total", 0) > 0:
                suggestions.append({"tool": "zapcli", "args": {"target": target, "mode": "active"}, "reason": f"Nikto found {parsed.get('total', 0)} issues — ZAP active scan", "priority": 2})

        elif tool_name == "wpscan":
            users = parsed.get("users", [])
            if users:
                suggestions.append({"tool": "hydra", "args": {"target": target, "mode": "http-post-form", "form_path": "/wp-login.php", "form_params": "log=^USER^&pwd=^PASS^:F=incorrect", "username": users[0]}, "reason": f"WPScan found user '{users[0]}' — Hydra brute force", "priority": 2})

        elif tool_name == "ffuf":
            for f in parsed.get("findings", []):
                path = f.get("path", "").lower()
                if any(x in path for x in ("login", "admin", "wp-login", "phpmyadmin")):
                    suggestions.append({"tool": "sqlmap", "args": {"target": f"{target}/{path}", "flags": "--batch --forms"}, "reason": f"Login page at {path} — test SQLi", "priority": 1})
                    suggestions.append({"tool": "hydra", "args": {"target": target, "mode": "http-post-form", "form_path": f"/{path}"}, "reason": f"Login at {path} — brute force", "priority": 2})
                    break

        elif tool_name == "zapcli":
            if parsed.get("high", 0) + parsed.get("critical", 0) > 0:
                suggestions.append({"tool": "nuclei", "args": {"target": target, "mode": "cves"}, "reason": f"ZAP found {parsed.get('high',0)} high — nuclei CVE scan", "priority": 1})

        elif tool_name == "enum4linux":
            if parsed.get("shares"):
                suggestions.append({"tool": "smbclient", "args": {"target": target, "mode": "anon"}, "reason": f"Found {len(parsed.get('shares',[]))} shares — anonymous access", "priority": 1})

        elif tool_name == "hydra":
            cracked = parsed.get("cracked", [])
            if cracked:
                suggestions.append({"tool": "privesc", "args": {"mode": "full", "ssh_host": cracked[0].get("host", target), "ssh_user": cracked[0].get("username", "")}, "reason": f"Cracked {cracked[0].get('username','')} — run privesc", "priority": 1})

        elif tool_name == "theharvester":
            if parsed.get("subdomains"):
                suggestions.append({"tool": "nmap", "args": {"target": parsed["subdomains"][0], "mode": "service"}, "reason": f"Found {len(parsed['subdomains'])} subdomains — scan first", "priority": 2})

        elif tool_name == "privesc":
            for j in parsed.get("juicy_points", []):
                if j.get("category") == "writable" and "shadow" in j.get("path", ""):
                    suggestions.append({"tool": "hashcat", "args": {"hashfile": "/etc/shadow"}, "reason": "Readable /etc/shadow — crack root hash", "priority": 1})
                    break

        elif tool_name == "mail_crawler":
            if parsed.get("emails"):
                suggestions.append({"tool": "theharvester", "args": {"target": target}, "reason": f"Found {len(parsed.get('emails',[]))} emails — broader OSINT", "priority": 3})

        return suggestions


    # def _fallback_chain(self, tool_name: str, parsed: dict, args: dict) -> list[dict]:
    #     """Deterministic fallback chain rules."""
    #     suggestions: list[dict] = []
    #     target = args.get("target", "")

    #     if tool_name == "nmap":
    #         enum_steps = suggest_enumeration(parsed)
    #         if enum_steps:
    #             print_enum_plan(enum_steps)
    #             for s in enum_steps:
    #                 if s.tool != "custom":
    #                     suggestions.append({"tool": s.tool, "args": s.args, "reason": s.reason, "priority": s.priority})
    #         for host in parsed.get("hosts", []):
    #             for port in host.get("ports", []):
    #                 if port.get("port") in (80, 443, 8080, 8180):
    #                     if "wordpress" in port.get("version", "").lower():
    #                         suggestions.append({"tool": "wpscan", "args": {"target": f"http://{host['ip']}", "mode": "full"}, "reason": "WordPress detected", "priority": 1})
    #                     suggestions.append({"tool": "zapcli", "args": {"target": f"http{'s' if port.get('port') == 443 else ''}://{host['ip']}", "mode": "baseline"}, "reason": f"Web on port {port.get('port')} — ZAP scan", "priority": 3})
    #                 if port.get("port") in (53, 80, 443):
    #                     suggestions.append({"tool": "theharvester", "args": {"target": host.get("hostname") or target}, "reason": "OSINT harvest", "priority": 3})

    #     elif tool_name == "nikto":
    #         findings = " ".join(parsed.get("findings", [])).lower()
    #         if "wordpress" in findings:
    #             suggestions.append({"tool": "wpscan", "args": {"target": target, "mode": "full"}, "reason": "WordPress found by nikto", "priority": 1})
    #         if "sql" in findings or "injection" in findings:
    #             suggestions.append({"tool": "sqlmap", "args": {"target": target, "flags": "--batch --level=2"}, "reason": "Potential SQLi found", "priority": 1})
    #         if parsed.get("total", 0) > 0:
    #             suggestions.append({"tool": "zapcli", "args": {"target": target, "mode": "active"}, "reason": f"Nikto found {parsed.get('total', 0)} issues — ZAP active scan", "priority": 2})

    #     elif tool_name == "wpscan":
    #         users = parsed.get("users", [])
    #         if users:
    #             suggestions.append({"tool": "hydra", "args": {"target": target, "mode": "http-post-form", "form_path": "/wp-login.php", "form_params": "log=^USER^&pwd=^PASS^:F=incorrect", "username": users[0]}, "reason": f"WPScan found user '{users[0]}' — Hydra brute force", "priority": 2})

    #     elif tool_name == "ffuf":
    #         for f in parsed.get("findings", []):
    #             path = f.get("path", "").lower()
    #             if any(x in path for x in ("login", "admin", "wp-login", "phpmyadmin")):
    #                 suggestions.append({"tool": "sqlmap", "args": {"target": f"{target}/{path}", "flags": "--batch --forms"}, "reason": f"Login page at {path} — test SQLi", "priority": 1})
    #                 suggestions.append({"tool": "hydra", "args": {"target": target, "mode": "http-post-form", "form_path": f"/{path}"}, "reason": f"Login at {path} — brute force", "priority": 2})
    #                 break

    #     elif tool_name == "zapcli":
    #         if parsed.get("high", 0) + parsed.get("critical", 0) > 0:
    #             suggestions.append({"tool": "nuclei", "args": {"target": target, "mode": "cves"}, "reason": f"ZAP found {parsed.get('high',0)} high — nuclei CVE scan", "priority": 1})

    #     elif tool_name == "enum4linux":
    #         if parsed.get("shares"):
    #             suggestions.append({"tool": "smbclient", "args": {"target": target, "mode": "anon"}, "reason": f"Found {len(parsed.get('shares',[]))} shares — anonymous access", "priority": 1})

    #     elif tool_name == "hydra":
    #         cracked = parsed.get("cracked", [])
    #         if cracked:
    #             suggestions.append({"tool": "privesc", "args": {"mode": "full", "ssh_host": cracked[0].get("host", target), "ssh_user": cracked[0].get("username", "")}, "reason": f"Cracked {cracked[0].get('username','')} — run privesc", "priority": 1})

    #     elif tool_name == "theharvester":
    #         if parsed.get("subdomains"):
    #             suggestions.append({"tool": "nmap", "args": {"target": parsed["subdomains"][0], "mode": "service"}, "reason": f"Found {len(parsed['subdomains'])} subdomains — scan first", "priority": 2})

    #     elif tool_name == "privesc":
    #         for j in parsed.get("juicy_points", []):
    #             if j.get("category") == "writable" and "shadow" in j.get("path", ""):
    #                 suggestions.append({"tool": "hashcat", "args": {"hashfile": "/etc/shadow"}, "reason": "Readable /etc/shadow — crack root hash", "priority": 1})
    #                 break

    #     elif tool_name == "mail_crawler":
    #         if parsed.get("emails"):
    #             suggestions.append({"tool": "theharvester", "args": {"target": target}, "reason": f"Found {len(parsed.get('emails',[]))} emails — broader OSINT", "priority": 3})

    #     return suggestions

    def _run_chain(self, suggestions: list[dict]) -> None:
        """Show chain suggestions and ask user which to run."""
        if not suggestions:
            return

        console.print("\n[bold cyan]🔗 Smart Chain Suggestions[/bold cyan]")
        console.print("[dim]Based on results, Kernox suggests:[/dim]\n")

        table = Table(show_header=True, header_style="bold magenta",
                      box=box.SIMPLE_HEAVY, border_style="dim")
        table.add_column("#",        width=4,  style="bold cyan")
        table.add_column("Tool",     style="bold", width=14)
        table.add_column("Reason")
        table.add_column("Priority", width=8)

        pri_colors = {1: "bold red", 2: "bold yellow", 3: "cyan"}
        pri_labels = {1: "HIGH", 2: "MED", 3: "LOW"}

        for i, s in enumerate(suggestions, 1):
            pri   = s.get("priority", 2)
            color = pri_colors.get(pri, "white")
            table.add_row(
                str(i),
                s["tool"],
                s["reason"],
                f"[{color}]{pri_labels.get(pri, '?')}[/{color}]",
            )

        console.print(table)
        console.print("\n  [green]a[/green] – Run all  [green]n[/green] – Skip all  [green]1,2...[/green] – Pick specific\n")

        choice = Prompt.ask("Which steps to run", default="n")

        selected: list[dict] = []
        if choice.strip().lower() == "a":
            selected = suggestions
        elif choice.strip().lower() == "n":
            return
        else:
            for c in choice.split(","):
                c = c.strip()
                if c.isdigit() and 1 <= int(c) <= len(suggestions):
                    selected.append(suggestions[int(c) - 1])

        for s in selected:
            tool_name = s["tool"]
            args      = dict(s["args"])
            console.print(
                f"\n[bold cyan]Chain step:[/bold cyan] "
                f"[bold]{tool_name}[/bold] — {s['reason']}"
            )
            if Confirm.ask(f"Run {tool_name}?", default=True):
                result_data = self._run_tool(tool_name, args)
                if result_data:
                    parsed, _ = result_data
                    self._post_tool_ai_analysis(tool_name, parsed, args.get("target", ""))
                    if len(self._history) < 40:
                        nested = self._suggest_chain(tool_name, parsed, args)
                        if nested:
                            self._run_chain(nested)

    # ── Arg preparation ───────────────────────────────────────────────────────

    def _prepare_hashcat_args(self, args: dict) -> dict:
        """If hashfile is a raw hash string, save to temp file first."""
        hashfile = args.get("hashfile", "")
        if hashfile and not hashfile.startswith("/") and " " not in hashfile:
            tmp = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, prefix="kernox_hash_"
            )
            tmp.write(hashfile.strip() + "\n")
            tmp.close()
            console.print(f"[dim]Hash saved to:[/dim] [cyan]{tmp.name}[/cyan]")
            args["hashfile"] = tmp.name
        return args

    def _prepare_privesc_args(self, args: dict) -> dict:
        """Collect SSH credentials interactively before running privesc."""
        from rich.prompt import Prompt as RPrompt
        console.print("\n[bold cyan]PrivEsc Target[/bold cyan]")
        if not args.get("ssh_host"):
            args["ssh_host"] = RPrompt.ask("[bold cyan]SSH host/IP[/bold cyan]")
        if not args.get("ssh_user"):
            args["ssh_user"] = RPrompt.ask("[bold cyan]SSH username[/bold cyan]")
        return args

    def _prepare_sqlmap_args(self, args: dict) -> dict:
        """
        AI pre-flight for sqlmap.

        Before handing off to sqlmap, the AI:
        1. Probes the target with curl to detect WAF, CSP headers, and response patterns
        2. Analyses what filtering/encoding is needed
        3. Recommends the right tamper scripts, level, risk and technique flags
        4. Builds the optimal sqlmap command via the flags key

        If the AI probe fails, falls back to defaults.
        """
        target = args.get("target", "")
        if not target:
            return args

        # Skip if flags already fully specified (AI or user already set them)
        if args.get("flags") and len(args["flags"]) > 40:
            return args

        console.print("\n[bold cyan]🤖 AI SQLMap Pre-flight Analysis[/bold cyan]")
        console.print("[dim]Probing target to determine optimal injection strategy...[/dim]")

        # Quick curl probe to gather headers and baseline response
        import subprocess, shlex
        probe_info = ""
        try:
            probe_cmd = f"curl -sk -I -m 8 --max-redirs 3 '{target}'"
            result = subprocess.run(shlex.split(probe_cmd), capture_output=True, text=True, timeout=10)
            probe_info = result.stdout[:1500]
        except Exception:
            probe_info = "Curl probe failed — no header data available."

        # Session context — any WAF or previous findings
        waf_detected = False
        waf_name = ""
        for tr in self._state.get_tool_results():
            if tr.tool == "wafw00f" and tr.parsed.get("detected"):
                waf_detected = True
                waf_name = ", ".join(tr.parsed.get("waf_names", ["Unknown WAF"]))
                break

        state_note = f"WAF detected: {waf_name}" if waf_detected else "No WAF detected in this session."

        prompt = f"""You are an expert SQL injection tester. Analyse this target and recommend the optimal sqlmap strategy.

TARGET URL: {target}
{state_note}

HTTP PROBE RESPONSE (headers):
{probe_info}

TASK: Determine the best sqlmap flags to use based on:
1. WAF presence and type (needs tamper scripts?)
2. Headers (CSP, X-Frame, unusual server, rate limiting signs?)
3. Likely injection points (GET params, forms, cookies?)
4. What encoding/obfuscation is needed to bypass filters

Respond ONLY with a JSON object (no other text):
{{
  "analysis": "2-3 sentence analysis of what you found and why you chose these settings",
  "flags": "--batch --level=3 --risk=2 --technique=BEUSTQ --tamper=space2comment,randomcase --forms -v 1 --output-dir=/tmp/kernox_sqlmap",
  "waf_bypass_needed": true,
  "recommended_tampers": ["space2comment", "randomcase"],
  "injection_points": ["forms", "cookies"],
  "risk_level": 2,
  "level": 3
}}

TAMPER REFERENCE:
- space2comment: WAF bypass — replaces spaces
- between: Filter bypass — replaces > with BETWEEN
- randomcase: Case mutation to bypass keyword filters
- charencode: URL encoding bypass
- base64encode: Base64 payload encoding
- equaltolike: Replaces = with LIKE
- multiplespaces: Multiple spaces around keywords
- unmagicquotes: Strip magic quote protection
- greatest: Replaces > with GREATEST()

If no WAF and clean headers, use simple flags: --batch --level=2 --risk=1 --forms -v 1 --output-dir=/tmp/kernox_sqlmap
If WAF detected or unusual headers, use aggressive tampers and higher level/risk."""

        try:
            with Live(Spinner("dots", text="[dim]AI analysing target for SQLi strategy...[/dim]"), refresh_per_second=10):
                response = self._ai.chat(
                    messages=[{"role": "user", "content": prompt}],
                    system="You are a penetration tester. Return ONLY a JSON object.",
                    max_tokens=500,
                    temperature=0.1,
                )

            import re as _re
            json_match = _re.search(r'\{.*\}', response, _re.DOTALL)
            if json_match:
                plan = json.loads(json_match.group())
                analysis = plan.get("analysis", "")
                flags = plan.get("flags", "")

                if analysis:
                    console.print(Panel(
                        analysis,
                        title="[cyan]AI — SQLMap Strategy[/cyan]",
                        border_style="cyan",
                        box=box.SIMPLE,
                    ))

                if flags:
                    # Replace existing flags with AI-recommended ones
                    args["flags"] = flags
                    args.pop("mode", None)  # Let flags take precedence
                    console.print(f"[dim]SQLMap flags: {flags}[/dim]")

                    # Warn if tampers chosen
                    tampers = plan.get("recommended_tampers", [])
                    if tampers:
                        console.print(f"[yellow]Tamper scripts: {', '.join(tampers)}[/yellow]")

        except Exception as e:
            # Silent fallback — don't crash the scan
            console.print("[dim]AI pre-flight skipped — using default flags[/dim]")
            if not args.get("flags"):
                args["flags"] = "--batch --level=2 --risk=1 --forms -v 1 --output-dir=/tmp/kernox_sqlmap"

        return args

    def _trimmed_history(self) -> list[dict]:
        """Return the last HISTORY_LIMIT messages (raised from 8 to 20)."""
        return self._history[-HISTORY_LIMIT:]

    # ── Display helpers ───────────────────────────────────────────────────────

    def _ask_report(self, results: list[dict] | None = None) -> None:
        """Ask user if they want to export findings to PDF."""
        if not results:
            results = [
                {
                    "tool": tr.tool,
                    "parsed": tr.parsed,
                    "target": tr.target,
                    "timestamp": tr.timestamp,
                }
                for tr in self._state.get_tool_results()
            ]

        ai_insights = [
            {
                "vulnerability": i.vulnerability,
                "severity": i.severity,
                "tool": i.tool,
                "target": i.target,
                "ai_explanation": i.ai_explanation,
            }
            for i in self._state.get_ai_insights()
        ]

        filename = f"/tmp/kernox_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        generate_pdf_report(
            target=", ".join(self._state.hosts.keys()) or "unknown",
            results=results,
            output_path=filename,
            ai_insights=ai_insights,
        )

    def _print_plan(self, steps: list[dict]) -> None:
        console.print(f"\n[bold green][Kernox][/bold green] {len(steps)} step(s) planned:\n")
        for i, s in enumerate(steps, 1):
            reason = s.get("reason", "")
            if len(reason) > 80:
                reason = reason[:77] + "..."
            console.print(
                f"  [green]{i}.[/green] [bold cyan]{s.get('tool','?')}[/bold cyan] "
                f"[dim]— {reason}[/dim]"
            )

    def _print_help(self) -> None:
        console.print(Panel(
            "[bold]Commands:[/bold]\n"
            "  [cyan]<anything>[/cyan]          – Talk to the AI\n"
            "  [cyan]ask <question>[/cyan]      – Ask about vulnerabilities/tools\n"
            "  [cyan]explain[/cyan]             – Get AI analysis of current findings\n"
            "  [cyan]tools[/cyan]               – List all tools\n"
            "  [cyan]tools check[/cyan]         – Check which tools are installed\n"
            "  [cyan]state[/cyan]               – Current session findings\n"
            "  [cyan]history[/cyan]             – Conversation history\n"
            "  [cyan]clear[/cyan]               – Clear everything\n"
            "  [cyan]clear history[/cyan]       – Clear AI history only\n"
            "  [cyan]clear state[/cyan]         – Clear findings only\n"
            "  [cyan]session save[/cyan]        – Save session to disk\n"
            "  [cyan]session load[/cyan]        – Restore a previous session\n"
            "  [cyan]session list[/cyan]        – List saved sessions\n"
            "  [cyan]analyse[/cyan]             – Paste reverse shell output for privesc analysis\n"
            "  [cyan]web recon <url>[/cyan]     – Full automated web recon chain\n"
            "  [cyan]report[/cyan]              – Export session findings to PDF\n"
            "  [cyan]raw on[/cyan]              – Show raw tool output\n"
            "  [cyan]raw off[/cyan]             – Hide raw output (silent+spinner)\n"
            "  [cyan]exit[/cyan]                – Quit Kernox",
            title="[bold cyan]Kernox Help[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
        ))

    def _print_tools(self) -> None:
        table = Table(show_header=True, header_style="bold magenta",
                      box=box.SIMPLE_HEAVY, border_style="dim")
        table.add_column("Tool",    style="bold cyan", width=16)
        table.add_column("Purpose")

        tools_info = [
            ("nmap",          "Port scanning & service fingerprinting"),
            ("ffuf",          "Directory/vhost/parameter fuzzing"),
            ("gobuster",      "Directory, DNS & vhost enumeration"),
            ("nikto",         "Web vulnerability scanner"),
            ("sqlmap",        "SQL injection detection & exploitation"),
            ("enum4linux",    "SMB/Windows enumeration"),
            ("wpscan",        "WordPress vulnerability scanner"),
            ("smbclient",     "SMB share access & enumeration"),
            ("dnsenum",       "DNS enumeration"),
            ("curl",          "HTTP fingerprinting"),
            ("hashcat",       "Password hash cracking"),
            ("whatweb",       "Web technology detection"),
            ("wafw00f",       "WAF detection"),
            ("sslscan",       "SSL/TLS vulnerability scanning"),
            ("onesixtyone",   "SNMP community string brute-force"),
            ("dnsrecon",      "DNS reconnaissance"),
            ("nuclei",        "CVE & misconfiguration scanning"),
            ("privesc",       "Linux privilege escalation enumeration (read-only)"),
            ("msfvenom",      "Payload/reverse shell generation"),
            ("mail_crawler",  "Email address harvesting via web crawl"),
            ("zapcli",        "OWASP ZAP web app scanner (baseline/active/ajax/api)"),
            ("hydra",         "Credential brute-force (ssh/ftp/http/smb/rdp/smtp/mysql)"),
            ("theharvester",  "OSINT — emails, subdomains, IPs from public sources"),
        ]
        for name, purpose in tools_info:
            table.add_row(name, purpose)

        console.print(Panel(table, title="[bold cyan]Available Tools[/bold cyan]",
                            border_style="cyan", box=box.ROUNDED))

    def _check_tools(self) -> None:
        from kernox.core.executor import TOOL_BINARIES, INSTALL_HINTS, check_tool_installed

        all_binaries = dict(TOOL_BINARIES)
        all_hints    = dict(INSTALL_HINTS)

        table = Table(show_header=True, header_style="bold magenta",
                      box=box.SIMPLE_HEAVY, border_style="dim")
        table.add_column("Tool",    style="bold cyan", width=16)
        table.add_column("Status",  width=20)
        table.add_column("Install hint")

        skip = {"ssh", "sshpass"}
        installed_count = 0
        for tool, binary in all_binaries.items():
            if tool in skip:
                continue
            is_installed = check_tool_installed(binary)
            if is_installed:
                installed_count += 1
                status = "[bold green]✓ installed[/bold green]"
                hint   = ""
            else:
                status = "[bold red]✗ missing[/bold red]"
                hint   = all_hints.get(tool, f"sudo apt install {tool}")
            table.add_row(tool, status, hint)

        total = len(all_binaries) - len(skip)
        console.print(Panel(
            table,
            title=f"[bold cyan]Tool Check — {installed_count}/{total} installed[/bold cyan]",
            border_style="green" if installed_count == total else "yellow",
        ))
        if installed_count < total:
            console.print(
                "\n[yellow]💡 Install core tools:[/yellow]\n"
                "[cyan]sudo apt install nmap ffuf gobuster sqlmap nikto "
                "enum4linux smbclient dnsenum curl hashcat whatweb "
                "sslscan onesixtyone dnsrecon wafw00f wpscan sshpass "
                "hydra theharvester zaproxy[/cyan]\n"
            )

    def _print_state(self) -> None:
        import json as _json
        console.print(Panel(
            _json.dumps(self._state.to_dict(), indent=2, default=str),
            title="[bold cyan]Session State[/bold cyan]", border_style="cyan",
        ))

    def _print_history(self) -> None:
        for msg in self._history[-20:]:
            color = "cyan" if msg["role"] == "assistant" else "green"
            console.print(f"[{color}]{msg['role'].upper()}:[/{color}] {msg['content'][:200]}")

    def _clear_all(self) -> None:
        self._state.reset()
        self._history.clear()
        console.print("[green]✓ Session state and history cleared.[/green]")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _explain_findings(tool_name: str, parsed: dict) -> None:
    """After a tool finishes, check for known vulnerabilities and explain them."""
    from kernox.utils.report_generator import explain_vulnerability, VULN_EXPLANATIONS
    from rich.text import Text

    explained = set()

    def _show_vuln(info: dict) -> None:
        name = info.get("name", "")
        if name in explained:
            return
        explained.add(name)

        sev = info.get("severity", "HIGH")
        sev_color = {
            "CRITICAL": "bold red",
            "HIGH":     "bold yellow",
            "MEDIUM":   "bold cyan",
            "LOW":      "green",
        }.get(sev, "white")

        content = Text()
        content.append(f"[{sev}] ", style=sev_color)
        content.append(f"{name}\n\n", style="bold white")
        content.append("What is it:\n", style="bold cyan")
        content.append(f"{info.get('description', '')}\n\n", style="white")
        content.append("Impact:\n", style="bold yellow")
        content.append(f"{info.get('impact', '')}\n\n", style="white")
        content.append("Fix:\n", style="bold green")
        content.append(f"{info.get('recommendation', '')}\n", style="white")
        if info.get("references"):
            content.append("\nReferences:\n", style="dim")
            for ref in info["references"]:
                content.append(f"  {ref}\n", style="dim cyan")

        console.print(Panel(
            content,
            title="[bold red]⚠ Vulnerability Explained[/bold red]",
            border_style="red" if sev == "CRITICAL" else "yellow",
            box=box.ROUNDED,
        ))

    if tool_name == "sslscan":
        for issue in parsed.get("issues", []):
            info = explain_vulnerability(issue)
            if info:
                _show_vuln(info)

    elif tool_name == "nikto":
        for finding in parsed.get("findings", []):
            info = explain_vulnerability(finding)
            if info:
                _show_vuln(info)

    elif tool_name == "nmap":
        for host in parsed.get("hosts", []):
            for port in host.get("ports", []):
                version = port.get("version", "").lower()
                if "vsftpd" in version and "2.3.4" in version:
                    _show_vuln(VULN_EXPLANATIONS["vsftpd-backdoor"])
                if "unrealircd" in version and "3.2.8.1" in version:
                    _show_vuln(VULN_EXPLANATIONS["unrealircd-backdoor"])

    elif tool_name == "nuclei":
        for finding in parsed.get("findings", []):
            name = finding.get("name", "") + " " + finding.get("template", "")
            info = explain_vulnerability(name)
            if info:
                _show_vuln(info)
            elif finding.get("severity") in ("critical", "high"):
                desc = finding.get("description", "")
                if desc:
                    console.print(Panel(
                        f"[bold yellow]{finding.get('name', '')}[/bold yellow]\n\n"
                        f"{desc}\n\n"
                        f"[dim]Matched: {finding.get('matched', '')[:80]}[/dim]",
                        title="[bold red]⚠ Nuclei Finding[/bold red]",
                        border_style="red" if finding["severity"] == "critical" else "yellow",
                        box=box.ROUNDED,
                    ))

    elif tool_name == "zapcli":
        for alert in parsed.get("alerts", []):
            if alert.get("severity") in ("critical", "high"):
                console.print(Panel(
                    f"[bold yellow]{alert.get('name', 'ZAP Alert')}[/bold yellow]\n\n"
                    f"Severity: [bold]{alert['severity'].upper()}[/bold]\n"
                    f"Instances: {alert.get('count', 1)}\n"
                    + (f"URLs: {', '.join(alert.get('urls', [])[:3])}" if alert.get("urls") else ""),
                    title="[bold red]⚠ ZAP Finding[/bold red]",
                    border_style="red" if alert["severity"] == "critical" else "yellow",
                    box=box.ROUNDED,
                ))

    elif tool_name == "hydra":
        cracked = parsed.get("cracked", [])
        if cracked:
            cred_lines = "\n".join(
                f"  [bold green]{c['username']}[/bold green] : [bold red]{c['password']}[/bold red]"
                f"  ([cyan]{c.get('service', '')}[/cyan])"
                for c in cracked[:10]
            )
            console.print(Panel(
                f"[bold red]Credentials Cracked![/bold red]\n\n"
                f"Found [bold]{len(cracked)}[/bold] valid credential(s):\n\n"
                + cred_lines,
                title="[bold red]⚠ Hydra — Weak Credentials[/bold red]",
                border_style="red",
                box=box.ROUNDED,
            ))

    elif tool_name == "theharvester":
        emails    = parsed.get("emails", [])
        subdomains = parsed.get("subdomains", [])
        if emails or subdomains:
            lines = []
            if emails:
                lines.append(f"[bold]Emails ({len(emails)}):[/bold] " + ", ".join(emails[:8]))
            if subdomains:
                lines.append(f"[bold]Subdomains ({len(subdomains)}):[/bold] " + ", ".join(subdomains[:8]))
            console.print(Panel(
                "\n".join(lines),
                title="[bold cyan]theHarvester — OSINT Results[/bold cyan]",
                border_style="cyan",
                box=box.ROUNDED,
            ))

    elif tool_name == "onesixtyone":
        communities = parsed.get("communities", [])
        if communities:
            console.print(Panel(
                f"[bold red]SNMP Community Strings Found![/bold red]\n\n"
                f"Found [bold]{len(communities)}[/bold] accessible community strings.\n\n"
                + "\n".join(
                    f"  [{c.get('community', '')}] {c.get('info', '')[:60]}"
                    for c in communities[:5]
                ),
                title="[bold yellow]⚠ SNMP Exposed[/bold yellow]",
                border_style="yellow",
                box=box.ROUNDED,
            ))

    elif tool_name == "sqlmap" and parsed.get("vulnerable"):
        console.print(Panel(
            "[bold red]SQL Injection Confirmed![/bold red]\n\n"
            "The target is vulnerable to SQL injection.\n"
            f"DBMS: [cyan]{parsed.get('dbms', 'Unknown')}[/cyan]\n"
            f"Injectable parameters: [yellow]{', '.join(parsed.get('parameters', []))}[/yellow]",
            title="[bold red]⚠ SQL Injection Found[/bold red]",
            border_style="red",
            box=box.ROUNDED,
        ))


def _build_smart_summary(tool_name: str, parsed: dict, target: str) -> str:
    """Build a smart human-readable summary of tool results for the AI."""
    lines = [f"[{tool_name.upper()} on {target}]"]
    try:
        if tool_name == "nmap":
            for host in parsed.get("hosts", []):
                lines.append(f"Host: {host.get('ip', '')} OS: {host.get('os', '')}")
                for p in host.get("ports", []):
                    if p.get("state") == "open":
                        lines.append(f"  PORT {p['port']}/{p.get('proto', '')} {p.get('service', '')} {p.get('version', '')}")
        elif tool_name == "nikto":
            lines.append(f"Server: {parsed.get('server', '')} Findings: {parsed.get('total', 0)}")
            for f in parsed.get("findings", [])[:15]:
                lines.append(f"  FINDING: {f[:120]}")
        elif tool_name == "sqlmap":
            lines.append(f"Vulnerable: {parsed.get('vulnerable', False)} DBMS: {parsed.get('dbms', '')}")
            lines.append(f"Params: {', '.join(parsed.get('parameters', []))}")
            lines.append(f"Databases: {', '.join(parsed.get('databases', []))}")
        elif tool_name == "ffuf":
            findings = parsed.get("findings", [])
            lines.append(f"Paths found: {len(findings)}")
            for f in findings[:20]:
                lines.append(f"  PATH: {f.get('path', '')} [{f.get('status', '')}]")
        elif tool_name == "gobuster":
            paths = parsed.get("paths", [])
            lines.append(f"Paths found: {len(paths)}")
            for p in paths[:20]:
                lines.append(f"  PATH: {p}")
        elif tool_name == "enum4linux":
            users  = parsed.get("users", [])
            shares = parsed.get("shares", [])
            lines.append(f"OS: {parsed.get('os', '')} Domain: {parsed.get('domain', '')}")
            lines.append(f"Users: {len(users)} Shares: {len(shares)}")
            for u in users[:10]:
                lines.append(f"  USER: {u.get('username', '')} RID:{u.get('rid', '')}")
            for s in shares[:10]:
                lines.append(f"  SHARE: {s.get('name', '')} ({s.get('type', '')})")
        elif tool_name == "wpscan":
            lines.append(f"WP: {parsed.get('wp_version', '')} Vulns: {parsed.get('total_vulns', 0)}")
            lines.append(f"Users: {', '.join(parsed.get('users', []))}")
            for v in parsed.get("vulnerabilities", [])[:10]:
                lines.append(f"  VULN: {v[:100]}")
        elif tool_name == "nuclei":
            lines.append(f"Critical: {parsed.get('critical', 0)} High: {parsed.get('high', 0)} Medium: {parsed.get('medium', 0)}")
            for f in parsed.get("findings", [])[:15]:
                lines.append(f"  [{f.get('severity', '').upper()}] {f.get('name', '')} → {f.get('matched', '')[:80]}")
        elif tool_name == "sslscan":
            lines.append(f"Issues: {len(parsed.get('issues', []))} WeakProtos: {', '.join(parsed.get('weak_protocols', []))}")
            for i in parsed.get("issues", []):
                lines.append(f"  ISSUE: {i}")
        elif tool_name == "whatweb":
            techs    = parsed.get("technologies", [])
            versions = parsed.get("versions", [])
            tech_dict = {v.get("tech", ""): v.get("version", "") for v in versions if v.get("tech")}
            for tech in techs:
                if tech not in tech_dict:
                    tech_dict[tech] = ""
            if tech_dict:
                lines.append(f"Technologies detected: {len(tech_dict)}")
                for tech, version in list(tech_dict.items())[:15]:
                    lines.append(f"  {tech} {version}".strip())
            else:
                lines.append(f"Raw output: {parsed.get('raw', '')[:200]}")
        elif tool_name == "wafw00f":
            lines.append(f"WAF: {parsed.get('detected', False)} Names: {', '.join(parsed.get('waf_names', []))}")
        elif tool_name == "dnsrecon":
            lines.append(f"Subdomains: {parsed.get('total_subdomains', 0)} ZoneTransfer: {parsed.get('zone_transfer_possible', False)}")
            for s in parsed.get("subdomains", [])[:10]:
                lines.append(f"  SUB: {s.get('subdomain', '')} → {s.get('ip', '')}")
        elif tool_name == "privesc":
            lines.append(f"Critical: {parsed.get('critical', 0)} High: {parsed.get('high', 0)}")
            for j in parsed.get("juicy_points", [])[:10]:
                lines.append(f"  [{j.get('severity', '').upper()}] {j.get('category', '')}: {j.get('title', '')} → {j.get('path', '')}")
        elif tool_name == "hashcat":
            cracked = parsed.get("cracked", [])
            lines.append(f"Cracked: {len(cracked)}")
            for c in cracked[:10]:
                lines.append(f"  CRACKED: {c.get('hash', '')} = {c.get('plaintext', '')}")
        elif tool_name == "smbclient":
            shares = parsed.get("shares", [])
            files  = parsed.get("files", [])
            lines.append(f"Shares found: {len(shares)}")
            for s in shares[:10]:
                lines.append(f"  SHARE: {s}")
            if files:
                lines.append(f"Files found: {len(files)}")
                for f in files[:10]:
                    lines.append(f"  FILE: {f}")
        elif tool_name == "dnsenum":
            subs = parsed.get("subdomains", [])
            lines.append(f"Subdomains: {len(subs)}")
            for s in subs[:10]:
                lines.append(f"  SUB: {s.get('subdomain', '')} -> {s.get('ip', '')}")
        elif tool_name == "curl":
            headers = parsed.get("headers", {})
            tech    = parsed.get("tech", [])
            lines.append(f"Tech: {', '.join(tech)}")
            for k, v in list(headers.items())[:10]:
                lines.append(f"  {k}: {v}")
        elif tool_name == "zapcli":
            lines.append(f"Critical: {parsed.get('critical', 0)} High: {parsed.get('high', 0)} "
                         f"Medium: {parsed.get('medium', 0)} Low: {parsed.get('low', 0)}")
            for alert in parsed.get("alerts", [])[:10]:
                lines.append(f"  [{alert.get('severity', '').upper()}] {alert.get('name', '')}")
        elif tool_name == "hydra":
            cracked = parsed.get("cracked", [])
            lines.append(f"Cracked: {len(cracked)}")
            for c in cracked[:10]:
                lines.append(f"  {c.get('service', '')} {c.get('username', '')}:{c.get('password', '')}")
        elif tool_name == "theharvester":
            lines.append(f"Emails: {parsed.get('total_emails', 0)} "
                         f"Subdomains: {parsed.get('total_subdomains', 0)} "
                         f"IPs: {parsed.get('total_ips', 0)}")
            for email in parsed.get("emails", [])[:10]:
                lines.append(f"  EMAIL: {email}")
            for sub in parsed.get("subdomains", [])[:5]:
                lines.append(f"  SUB: {sub}")
        else:
            lines.append(str(parsed)[:600])
    except Exception:
        lines.append(str(parsed)[:400])
    return "\n".join(lines)


def _extract_json_plan(text: str) -> Optional[dict]:
    import re

    pattern = r"```(?:json)?\s*(\{.*?\})\s*```"
    match = re.search(pattern, text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            pass

    for start in [i for i, c in enumerate(text) if c == "{"]:
        depth = 0
        for i, c in enumerate(text[start:], start):
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[start:i + 1]
                    try:
                        parsed = json.loads(candidate)
                        if isinstance(parsed, dict) and (
                            "steps" in parsed or
                            "message" in parsed or
                            "analysis" in parsed
                        ):
                            return parsed
                    except json.JSONDecodeError:
                        pass
                    break

    return None
