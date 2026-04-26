"""
kernox.core.orchestrator  –  Production-ready AI orchestrator with smart chaining.

Flow:
  1. User types command
  2. AI builds a plan (JSON)
  3. Each step runs with user confirmation
  4. After each tool → single unified AI call (vulns + chain + summary)
  5. AI suggests next steps, user picks which to run
"""
from __future__ import annotations
import shlex
import json
import time
import tempfile
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
from rich.text import Text
from rich.rule import Rule
from rich.align import Align

from kernox.ai.factory import build_ai_client
from kernox.config.config_store import ConfigStore
from kernox.core.executor import Executor
from kernox.core.firewall_detect import analyse_firewall, print_firewall_analysis
from kernox.core.enumerator import suggest_enumeration, print_enum_plan
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
from kernox.utils.formatter import format_results
from kernox.utils.report_generator import generate_pdf_report
from kernox.tools.msfvenom import MsfvenomTool
from kernox.tools.mail_crawler import MailCrawlerTool
from kernox.tools.zapcli import ZapCliTool
from kernox.tools.hydra import HydraTool
from kernox.tools.theharvester import TheHarvesterTool
from kernox.tools.live_discovery import LiveDiscoveryTool
from kernox.tools.recon import ReconTool


console = Console()

# ── Tunables ──────────────────────────────────────────────────────────────────
HISTORY_LIMIT      = 20
API_DELAY          = 2
POST_TOOL_ANALYSIS = True

# ── Severity palette ──────────────────────────────────────────────────────────
SEV_STYLE = {
    "critical": ("red",          "◆ CRITICAL"),
    "high":     ("bright_red",   "▲ HIGH"),
    "medium":   ("yellow",       "● MEDIUM"),
    "low":      ("bright_green", "○ LOW"),
    "info":     ("cyan",         "ℹ INFO"),
}

# ── Priority palette ──────────────────────────────────────────────────────────
PRI_STYLE = {
    1: ("bright_red",   "● HIGH"),
    2: ("yellow",       "◆ MED"),
    3: ("bright_cyan",  "○ LOW"),
}

# ── Output helpers ────────────────────────────────────────────────────────────




def _sep() -> None:
    console.print(Rule(style="white"))


def _header(text: str, icon: str = "▸") -> None:
    console.print(f"\n[bold cyan]{icon}  {text}[/bold cyan]")


def _ok(text: str) -> None:
    console.print(f"[bold green]  ✔  {text}[/bold green]")


def _err(text: str) -> None:
    console.print(f"[bold red]  ✘  {text}[/bold red]")


def _dim(text: str) -> None:
    console.print(f"[dim]  {text}[/dim]")


def _info(text: str) -> None:
    console.print(f"[cyan]  ▸  {text}[/cyan]")


def _warn(text: str) -> None:
    console.print(f"[yellow]  ⚠  {text}[/yellow]")


def _tool_header(tool_name: str, command: str) -> None:
    """Print tool name as a dim label then the command in a grey markdown code block."""
    console.print()
    console.print(f"[bold cyan]{tool_name.upper()}[/bold cyan]  [dim]running…[/dim]")
    console.print(Markdown(f"```bash\n   {command}\n```"))


def _sev_badge(severity: str) -> str:
    sev = severity.lower()
    color, label = SEV_STYLE.get(sev, ("white", severity.upper()))
    return f"[{color}]{label}[/{color}]"


# ── System prompt ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are Kernox, AI penetration testing assistant.
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
    - "scan target 192.168.1.1" -> AI chooses optimal strategy
    - "quick scan of example.com" -> mode="quick"
    - "check for vulnerabilities on web server" -> AI chooses vuln mode with web scripts
    - "scan through firewall" -> mode="firewall"

ffuf:
  args: target (URL), mode (dir/vhost/param/post/ai/custom), wordlist, extensions
  Use mode="ai" to let AI choose optimal strategy.
  Use mode="dir" for directory/file fuzzing (FUZZ in path).
  Use mode="vhost" for virtual host discovery.
  Use mode="param" for GET parameter fuzzing.
  Use mode="post" for POST parameter fuzzing.
  Examples:
    - "fuzz example.com" -> AI chooses strategy
    - "find subdomains on test.example.com" -> mode="vhost"
    - "fuzz parameters on https://site.com/page?id=FUZZ" -> mode="param"

recon:
  args: target (domain or IP), mode (full/quick)
  Use for complete reconnaissance on a target.
  Runs: whois, nslookup, dig, ping, traceroute, HTTP headers
  Then analyzes results with AI and suggests next steps.
  Example: {"target": "example.com", "mode": "full"}

gobuster:
  args: target, mode (dir/dns/vhost/s3/custom), wordlist
  Use mode="dns" for subdomain enum, mode="vhost" for vhost discovery

nikto:
  args: target (URL), mode (full/tuned/auth/sqli/ssl/quick/custom)

live_discovery:
  args: target (CIDR like 192.168.1.0/24 or "auto"), vendor_lookup (true/false), icmp_fallback (true/false)
  Use for discovering live hosts on a network.
  Finds all devices via ARP scan, adds MAC vendor lookup and TTL-based OS fingerprinting.
  Examples:
    - "discover network" -> Auto-detects local subnet
    - "discover 192.168.0.0/24" -> Scans that range

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

msfvenom:
  args: payload, lhost, lport, format (exe/elf/php/py/raw)
  Use for generating reverse shell payloads.
  Always ask for LHOST and LPORT values before generating.
  Common payloads:
    - windows/x64/meterpreter/reverse_tcp
    - linux/x64/meterpreter/reverse_tcp
    - php/meterpreter_reverse_tcp
  Examples:
    - "generate windows reverse shell" -> Ask for LHOST/LPORT, generate payload
    - "generate linux payload" -> Ask for LHOST/LPORT, generate payload

mail_crawler:
  args: target (URL), max_pages (optional, default 200)
  Use for harvesting email addresses from websites.
  Crawls the target domain and extracts emails from all linked pages.

zapcli (OWASP ZAP):
  args: target (URL), mode (baseline/active/ajax/api), report_path, extra_flags
  Use for deep web application scanning with proxy interception.
  modes:
    baseline = passive scan only (safe, no active attacks)
    active   = full active attack scan (intrusive -- confirm with user)
    ajax     = ajax spider + passive scan (for JS-heavy / SPA apps)
    api      = OpenAPI/GraphQL definition scan
  CHAIN: run after nikto/nuclei when web app needs deeper active testing
  Requires: zap.sh in PATH  OR  Docker (ghcr.io/zaproxy/zaproxy)

hydra:
  args: target (IP/hostname), service (REQUIRED - use exact service name from nmap: ssh, telnet, ftp, smb, http-post-form, etc.),
        userlist, passlist, username, password, port, threads, form_path, form_params, flags
  Use for credential brute-force after finding login forms or services.
  **CRITICAL: You MUST include the 'service' field with the exact service name from nmap results**
  **CRITICAL: Do NOT use 'mode' - use 'service' instead**
  Examples:
    - SSH: {"target": "192.168.1.1", "service": "ssh"}
    - Telnet: {"target": "192.168.1.1", "service": "telnet", "port": 23}
    - FTP: {"target": "192.168.1.1", "service": "ftp", "port": 21}

theharvester:
  args: target (domain), sources, limit
  Use for OSINT -- harvests emails, subdomains, IPs from public sources.
  CHAIN: run before or alongside mail_crawler for broader OSINT coverage
  Example: {"target": "example.com", "sources": "google,bing,crtsh,certspotter"}

CHAINING RULES:
- nmap finds port 80/443 -> suggest nikto + ffuf + curl + zapcli (baseline)
- nmap finds port 139/445 -> suggest enum4linux + smbclient
- nmap finds WordPress -> suggest wpscan
- nmap finds MySQL/PostgreSQL -> suggest sqlmap
- mail_crawler finds emails -> suggest theharvester for broader OSINT
- theharvester finds subdomains -> suggest dnsrecon + nuclei on each
- nikto finds WordPress -> suggest wpscan
- nikto finds vulnerabilities -> suggest zapcli active scan for confirmation
- ffuf finds login page -> suggest sqlmap + hydra
- wpscan finds users -> suggest hydra with http-post-form mode
- wpscan finds users -> suggest hashcat on found hashes
- nmap finds port 161 (SNMP) -> suggest onesixtyone
- nmap finds HTTPS -> suggest sslscan + wafw00f
- nmap finds domain/DNS -> suggest dnsrecon + theharvester
- curl/nikto finds tech -> suggest whatweb for deeper fingerprint
- wafw00f detects WAF -> warn user before fuzzing or running zapcli active; suggest sqlmap tamper scripts
- nmap finds web ports -> suggest nuclei quick scan AND nikto AND ffuf dir
- nikto finds vulnerabilities -> suggest nuclei for CVE confirmation
- whatweb identifies technology -> suggest nuclei with tech-specific templates
- nuclei/nikto finds high/critical -> suggest zapcli active for exploit confirmation
- theharvester finds emails -> suggest mail_crawler for deeper crawl + hydra on SSH with those usernames
- enum4linux finds users -> suggest hydra with those usernames on open services
- smbclient finds shares -> suggest enum4linux full scan
- dnsrecon finds subdomains -> suggest nmap + nuclei on each
- onesixtyone finds SNMP -> suggest nmap with snmp scripts (--script snmp-brute,snmp-info)
- hashcat cracks password -> suggest hydra with that password on all open services
- Always ask before each step

If no tool needed, return steps as [].
NEVER test systems without authorization.
"""

PROMPT_STYLE = Style.from_dict({
    "prompt": "bold cyan",
})


class Orchestrator:
    def __init__(self, config: ConfigStore) -> None:
        self._cfg      = config
        self._ai       = build_ai_client(config)
        self._executor = Executor(config)
        self._state    = SessionState()
        self._updater  = StateUpdater(self._state)
        self._tools    = {
            "nmap":           NmapTool(ai_client=self._ai),
            "ffuf":           FfufTool(ai_client=self._ai),
            "gobuster":       GobusterTool(),
            "sqlmap":         SqlmapTool(),
            "nikto":          NiktoTool(),
            "enum4linux":     Enum4linuxTool(),
            "wpscan":         WpscanTool(),
            "smbclient":      SmbclientTool(),
            "dnsenum":        DnsenumTool(),
            "curl":           CurlProbeTool(),
            "hashcat":        HashcatTool(),
            "whatweb":        WhatwebTool(ai_client=self._ai),
            "wafw00f":        Wafw00fTool(),
            "sslscan":        SslscanTool(),
            "onesixtyone":    OnesixtyoneTool(),
            "dnsrecon":       DnsreconTool(),
            "nuclei":         NucleiTool(),
            "msfvenom":       MsfvenomTool(),
            "mail_crawler":   MailCrawlerTool(),
            "zapcli":         ZapCliTool(),
            "hydra":          HydraTool(),
            "theharvester":   TheHarvesterTool(),
            "live_discovery": LiveDiscoveryTool(ai_client=self._ai, session_state=self._state),
            "recon":          ReconTool(ai_client=self._ai),
        }
        self._history: list[dict] = []

    # ── Chat helpers ──────────────────────────────────────────────────────────

    def _chat_about_vulnerability(self, user_input: str) -> None:
        """Handle vulnerability questions and general security chat."""
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
   - Give the EXACT full exploitation command(s) using real tools
   - Include all required flags, payloads, and parameters
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
   - Be direct and specific

5. Only decline if the question is clearly unrelated to security testing."""

        with Live(Spinner("dots", text="[cyan]AI thinking…[/cyan]"), refresh_per_second=10, console=console):
            response = self._ai.chat(
                messages=[{"role": "user", "content": user_input}],
                system=chat_prompt,
            )

        console.print()
        console.print(
            Panel(
                Markdown(response),
                title="[bold cyan]  Kernox AI Assistant  [/bold cyan]",
                border_style="cyan",
                box=box.ROUNDED,
                padding=(1, 2),
            )
        )

        self._add_to_history("user", user_input)
        self._add_to_history("assistant", response)

    def _explain_findings_summary(self) -> None:
        """Get AI to explain findings with precise commands for next steps."""
        if not self._state.get_tool_results():
            _err("No findings to explain yet. Run some scans first.")
            return

        tool_summaries = []
        for tr in self._state.get_tool_results()[-8:]:
            s = _build_smart_summary(tr.tool, tr.parsed, tr.target)
            tool_summaries.append(s)

        insights = self._state.get_ai_insights()
        vuln_lines = []
        for i in insights:
            vuln_lines.append(f"  [{i.severity.upper()}] {i.vulnerability} -- target: {i.target} (via {i.tool})")

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
# example -- use real targets and flags
sqlmap -u 'http://target/page?id=1' --batch --level=3 --dbs
```

## Recommended Next Steps
Top 3 actions with full commands, prioritized by impact

## Risk Summary
One-line overall risk rating

Be specific to the actual targets and findings above. All commands must be copy-paste ready."""

        with Live(Spinner("dots", text="[cyan]Analysing session findings…[/cyan]"), refresh_per_second=10, console=console):
            response = self._ai.chat(
                messages=[{"role": "user", "content": prompt}],
                system="You are a senior penetration tester. Give exact commands, real targets, no placeholders.",
                max_tokens=900,
            )

        console.print()
        console.print(
            Panel(
                Markdown(response),
                title="[bold cyan]  Session Analysis  [/bold cyan]",
                border_style="cyan",
                box=box.ROUNDED,
                padding=(1, 2),
            )
        )

    # ── ★  UNIFIED AI PROCESSING  ★ ───────────────────────────────────────────

    def _ai_process_results(
        self,
        tool_name: str,
        parsed: dict,
        target: str,
    ) -> list[dict]:
        """
        Single AI call that replaces the old three-method pattern:
          • _post_tool_ai_analysis   → one-line user summary (printed in panel)
          • _generate_ai_insights    → vulnerability objects saved to state
          • _ai_chain_suggestions    → next-step tool list (returned)

        Returns a list of chain-step dicts (may be empty).
        """
        # Tools that emit their own inline AI output — skip to avoid duplication
        if tool_name in ("recon", "live_discovery"):
            return []

        summary = _build_smart_summary(tool_name, parsed, target)
        if not summary.strip():
            return []

        available_tools = list(self._tools.keys())

        prompt = f"""You are a senior penetration tester.
A tool just finished on an AUTHORIZED engagement.

Tool : {tool_name.upper()}
Target : {target}
Results:
{summary}

Respond with ONLY a single valid JSON object — no markdown, no prose, nothing else:

{{
  "summary": "One sentence — the single most important finding for the operator.",
  "vulnerabilities": [
    {{
      "name": "Short vulnerability name",
      "severity": "critical|high|medium|low|info",
      "description": "What was found and why it matters (2 sentences).",
      "impact": "What an attacker can do with this.",
      "exploit": "EXACT command to exploit this vulnerability (full command with real targets, no placeholders)."
    }}
  ],
  "next_steps": [
    {{
      "tool": "<tool from available list>",
      "args": {{"target": "{target}"}},
      "reason": "Why this tool next",
      "priority": 1
    }}
  ]
}}

Rules:
- vulnerabilities: only real issues found; empty list [] if nothing notable.
- next_steps: max 3 items; tools must be from this list: {", ".join(available_tools)}.
- priority: 1=high, 2=medium, 3=low.
- Return ONLY the JSON object."""

        try:
            with Live(
                Spinner("dots", text="[cyan]Analysing results…[/cyan]"),
                refresh_per_second=10,
                console=console,
            ):
                response = self._ai.chat(
                    messages=[{"role": "user", "content": prompt}],
                    system=(
                        "You are a senior penetration tester. "
                        "Return ONLY a valid JSON object. No markdown. No backticks. No prose."
                    ),
                    max_tokens=600,
                )

            # ── Parse ──────────────────────────────────────────────────────
            import re as _re
            response = response.strip()
            if response.startswith("```"):
                lines = response.split("\n")
                lines = [l for l in lines if not l.strip().startswith("```")]
                response = "\n".join(lines).strip()

            json_match = _re.search(r'\{.*\}', response, _re.DOTALL)
            if not json_match:
                return []

            data = json.loads(json_match.group())

            # ── Print summary panel ────────────────────────────────────────
            summary_text = data.get("summary", "")
            if summary_text:
                console.print()
                console.print(
                    Panel(
                        f"[white]{summary_text}[/white]",
                        title=f"[bold cyan]  {tool_name.upper()} · Analysis  [/bold cyan]",
                        border_style="cyan",
                        box=box.ROUNDED,
                        padding=(0, 2),
                    )
                )

            # ── Save vulnerabilities to state ──────────────────────────────
            for vuln in data.get("vulnerabilities", [])[:5]:
                name     = vuln.get("name", "")
                severity = vuln.get("severity", "info")
                if not name:
                    continue

                # Pretty-print each vuln
                color, badge = SEV_STYLE.get(severity.lower(), ("white", severity.upper()))
                console.print()
                console.print(
                    Panel(
                        (
                            f"[white]{vuln.get('description', '')}[/white]\n\n"
                            f"[dim]Impact :[/dim]  {vuln.get('impact', '')}\n"
                            f"[dim]Exploit    :[/dim]  {vuln.get('exploit', '')}"
                        ),
                        title=f"[{color}]{badge}[/{color}]  [bold white]{name}[/bold white]",
                        border_style=color,
                        box=box.ROUNDED,
                        padding=(0, 2),
                    )
                )

                self._state.add_ai_insight(
                    vulnerability=name,
                    severity=severity,
                    tool=tool_name,
                    target=target,
                    explanation={
                        "description": vuln.get("description", ""),
                        "impact":      vuln.get("impact", ""),
                        "recommendation": vuln.get("exploit", ""),
                    },
                )

            # ── Build and validate next-step list ─────────────────────────
            valid_steps: list[dict] = []
            for step in data.get("next_steps", [])[:3]:
                t = step.get("tool", "")
                if t not in self._tools:
                    continue
                args_dict = step.get("args", {"target": target})
                if not isinstance(args_dict, dict):
                    args_dict = {"target": target}
                if not args_dict.get("target"):
                    args_dict["target"] = target
                valid_steps.append({
                    "tool":     t,
                    "args":     args_dict,
                    "reason":   step.get("reason", "AI suggested"),
                    "priority": int(step.get("priority", 2)),
                })

            return valid_steps

        except (json.JSONDecodeError, Exception):
            return []

    # ── Session persistence ───────────────────────────────────────────────────

    def _cmd_session_save(self) -> None:
        self._state.save()
        path = self._state._session_path()
        _ok(f"Session saved → [dim]{path}[/dim]")

    def _cmd_session_load(self) -> None:
        sessions = SessionState.list_sessions()
        if not sessions:
            _err("No saved sessions found.")
            return

        _header("Saved Sessions", "▸")
        table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
        table.add_column("#",    style="cyan",  width=4)
        table.add_column("Name", style="white")
        table.add_column("Size", style="dim",   justify="right")
        for i, p in enumerate(sessions[:10], 1):
            table.add_row(str(i), p.name, f"{p.stat().st_size // 1024} KB")
        console.print(table)

        choice = Prompt.ask("[cyan]Load session #[/cyan]", default="1")
        if not choice.isdigit() or not (1 <= int(choice) <= len(sessions)):
            _err("Invalid choice.")
            return

        selected = sessions[int(choice) - 1]
        self._state = SessionState.load(selected)
        self._updater = StateUpdater(self._state)
        _ok(f"Session loaded: [bold]{selected.name}[/bold]")
        _dim(self._state.summary())

    # ── Main REPL ─────────────────────────────────────────────────────────────

    def run(self) -> None:
        # _banner()
        session: PromptSession = PromptSession(style=PROMPT_STYLE)
        while True:
            try:
                user_input = session.prompt("\n[kernox]❯ ", style=PROMPT_STYLE)
            except (EOFError, KeyboardInterrupt):
                raise KeyboardInterrupt

            user_input = user_input.strip()
            if not user_input:
                continue

            cmd = user_input.lower()
            if cmd in ("exit", "quit", "q"):
                console.print("\n[dim]Goodbye. Stay ethical.[/dim]\n")
                break
            elif cmd == "help":              self._print_help();  continue
            elif cmd == "tools":             self._print_tools(); continue
            elif cmd == "tools check":       self._check_tools(); continue
            elif cmd == "state":             self._print_state(); continue
            elif cmd == "history":           self._print_history(); continue
            elif cmd == "clear":             self._clear_all(); continue
            elif cmd == "clear history":
                self._history.clear()
                _ok("History cleared")
                continue
            elif cmd == "clear state":
                self._state.reset()
                _ok("State cleared")
                continue
            elif cmd == "raw on":
                self._cfg.set("show_raw_output", "1")
                _ok("Raw output [bold green]ON[/bold green]")
                continue
            elif cmd == "raw off":
                self._cfg.set("show_raw_output", "0")
                _dim("Raw output [bold red]OFF[/bold red]")
                continue
            elif cmd == "raw":
                current = self._cfg.get("show_raw_output") == "1"
                state_str = "[bold green]ON[/bold green]" if current else "[bold red]OFF[/bold red]"
                _dim(f"Raw output is {state_str}  (type [cyan]raw on[/cyan] / [cyan]raw off[/cyan])")
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
                    _err("No saved sessions found.")
                else:
                    _header("Saved Sessions")
                    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
                    table.add_column("#",    style="cyan", width=4)
                    table.add_column("Name", style="white")
                    table.add_column("Size", style="dim", justify="right")
                    for i, p in enumerate(sessions[:10], 1):
                        table.add_row(str(i), p.name, f"{p.stat().st_size // 1024} KB")
                    console.print(table)
                continue

            self._process(user_input)

    def run_headless(self, target: str, mode: str = "web recon") -> None:
        """Non-interactive entry point for scripting / CI use."""
        console.print(f"\n[bold cyan]kernox headless[/bold cyan]  [dim]target={target}  mode={mode}[/dim]\n")
        if "web recon" in mode or "full recon" in mode:
            from kernox.core.web_recon import WebReconChain
            WebReconChain(self).run(target)
        else:
            self._process(f"{mode} {target}")

    # ── Process pipeline ──────────────────────────────────────────────────────

    def _process(self, user_input: str) -> None:
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

        self._add_to_history("user", user_input)

        state_summary = self._build_state_context()

        with Live(Spinner("dots", text="[cyan]Planning…[/cyan]"), refresh_per_second=10, console=console):
            ai_response = self._ai.chat(
                messages=self._trimmed_history(),
                system=SYSTEM_PROMPT + "\n\n" + state_summary,
            )
        self._add_to_history("assistant", ai_response)

        plan = _extract_json_plan(ai_response)
        if plan is None:
            _err("Parse error: AI returned non-JSON response")
            _dim(ai_response[:300])
            return

        msg = plan.get("message") or plan.get("analysis", "")
        if msg:
            _dim(msg)

        steps = plan.get("steps", [])
        if not steps:
            return

        self._print_plan(steps)

        all_summaries: list[str] = []
        for i, step in enumerate(steps, 1):
            tool_name = step.get("tool", "").lower()
            args      = dict(step.get("args", {}))
            reason    = step.get("reason", "")

            # Confirm prompt with styled markup
            console.print()
            confirmed = Confirm.ask(
                f"  [bold cyan]{tool_name.upper()}[/bold cyan]  [dim]{reason[:60]}[/dim]  — run?",
                default=True,
            )
            if not confirmed:
                _dim(f"Skipped {tool_name}")
                continue

            if tool_name == "hashcat":
                args = self._prepare_hashcat_args(args)
            if tool_name == "sqlmap":
                args = self._prepare_sqlmap_args(args)

            t_start = time.monotonic()
            result_data = self._run_tool(tool_name, args)
            elapsed = time.monotonic() - t_start

            if result_data is None:
                continue

            parsed, result = result_data
            summary = _build_smart_summary(tool_name, parsed, args.get("target", ""))
            all_summaries.append(summary)

            _ok(f"Completed in {elapsed:.1f}s")

            # ── UNIFIED AI CALL (replaces 3 old methods) ──────────────────
            chain_steps = self._ai_process_results(tool_name, parsed, args.get("target", ""))

            if chain_steps:
                self._run_chain(chain_steps)

        if all_summaries:
            self._add_to_history("user", "Tools finished: " + " | ".join(all_summaries))
            self._add_to_history("assistant", "Results stored.")
            console.print()
            _sep()
            _dim(f"Done  ·  {self._state.summary()}  ·  type [cyan]state[/cyan] to review  ·  [cyan]report[/cyan] to export")

            if Confirm.ask("\n  [dim]Export findings to PDF report?[/dim]", default=False):
                self._ask_report()

    # ── State context ─────────────────────────────────────────────────────────

    def _build_state_context(self) -> str:
        lines = [
            "=== CURRENT SESSION STATE ===",
            f"Hosts scanned: {', '.join(self._state.hosts.keys()) or 'None'}",
            f"Total open ports: {sum(len(h.ports) for h in self._state.hosts.values())}",
            f"AI insights found: {len(self._state.get_ai_insights())}",
            f"Tools run: {len(self._state.get_tool_results())}",
        ]

        for ip, host in list(self._state.hosts.items())[:5]:
            open_ports = [p for p in host.ports if p.get("state") == "open"]
            if open_ports:
                port_list = ", ".join(
                    f"{p['port']}/{p.get('proto','tcp')}({p.get('service','')} {p.get('version','')[:20]})"
                    for p in open_ports[:15]
                )
                lines.append(f"  HOST {ip} [{host.os or 'OS unknown'}]: {port_list}")

        detected_tech = set()
        for tr in self._state.get_tool_results():
            if tr.tool in ("whatweb", "wpscan"):
                for t in tr.parsed.get("technologies", []):
                    detected_tech.add(t)
        if detected_tech:
            lines.append(f"  Tech detected: {', '.join(list(detected_tech)[:8])}")

        for i in self._state.get_ai_insights()[-6:]:
            lines.append(f"  [{i.severity.upper()}] {i.vulnerability} ({i.tool} on {i.target})")

        tools_run = [(tr.tool, tr.target) for tr in self._state.get_tool_results()]
        if tools_run:
            lines.append(f"  Tools run: {', '.join(f'{t}@{tgt}' for t,tgt in tools_run[-10:])}")

        lines.append("=== END STATE ===")
        return "\n".join(lines)

    # ── Tool runner ───────────────────────────────────────────────────────────

    def _run_tool(self, tool_name: str, args: dict) -> Optional[tuple[dict, object]]:
        """Run a single tool. Returns (parsed, result) or None if blocked."""

        if tool_name == "recon":
            recon_tool = self._tools.get("recon")
            if recon_tool and hasattr(recon_tool, "run_direct"):
                parsed = recon_tool.run_direct(**args)
                self._state.add_tool_result(
                    tool=tool_name,
                    target=args.get("target", ""),
                    parsed=parsed,
                    raw_output=str(parsed),
                )
                self._updater.apply(tool_name, parsed, target=args.get("target"))
                return parsed, None

        tool = self._tools.get(tool_name)
        if not tool:
            _err(f"Unknown tool: [bold]{tool_name}[/bold]")
            return None

        # ── Smart arg enrichment from session state ───────────────────────────

        if tool_name == "ffuf":
            context = {
                "technologies": [], "server": "",
                "has_login_page": False, "detected_paths": [],
            }
            for tr in self._state.get_tool_results():
                if tr.tool == "whatweb":
                    context["technologies"] = tr.parsed.get("technologies", [])
                    context["server"] = tr.parsed.get("headers", {}).get("server", "")
                if tr.tool == "ffuf" and args.get("target") == tr.target:
                    context["detected_paths"] = [f.get("path") for f in tr.parsed.get("findings", [])[:10]]
                if tr.tool == "curl":
                    context["headers"] = tr.parsed.get("headers", {})
                if tr.tool == "whatweb" and "login" in str(tr.parsed.get("technologies", [])).lower():
                    context["has_login_page"] = True
            args["context"] = context

        if tool_name == "nikto":
            context = {"technologies": [], "open_ports": [], "headers": {}}
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
                    _dim(f"nuclei: tags [{unique_tags}] auto-injected")

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
                _dim(f"hydra: {len(discovered_users)} discovered usernames loaded")

        # Python-based tools (no shell command)
        if tool_name in ("mail_crawler", "live_discovery"):
            console.print()
            console.print(f"[bold cyan]{tool_name.upper()}[/bold cyan]  [dim]running…[/dim]")
            result = tool.run_direct(**args)
            parsed = result
            if tool_name == "mail_crawler":
                format_results(tool_name, parsed)
            self._state.add_tool_result(tool=tool_name, target=args.get("target", ""), parsed=parsed)
            return parsed, None

        # Build command and run via executor
        try:
            command = tool.build_command(**args)
        except Exception as e:
            _err(f"Failed to build command: {e}")
            return None
        _tool_header(tool_name, command)

        result = self._executor.run(
            command,
            tool_name=tool_name,
            target=args.get("target"),
        )

        if result.blocked:
            return None

        if tool_name == "nmap":
            fw = analyse_firewall(result.stdout)
            if fw.detected:
                print_firewall_analysis(fw)
                if Confirm.ask(
                    "  [yellow]⚠[/yellow]  Retry with [bold]evasion flags[/bold]?",
                    default=True,
                ):
                    retry_args = dict(args)
                    retry_args["flags"] = f"{fw.evasion_flags} -sV"
                    retry_args.pop("mode", None)
                    retry_cmd = tool.build_command(**retry_args)
                    _tool_header("nmap (evasion retry)", retry_cmd)
                    result = self._executor.run(retry_cmd, tool_name="nmap-evasion", target=args.get("target"))

        try:
            parsed = tool.parse(result.stdout)
        except Exception as exc:
            _err(f"Parse error: {exc}")
            parsed = {}

        self._state.add_tool_result(
            tool=tool_name,
            target=args.get("target", ""),
            parsed=parsed,
            raw_output=result.stdout,
        )

        self._updater.apply(tool_name, parsed, target=args.get("target"))
        format_results(tool_name, parsed)
        _explain_findings(tool_name, parsed)

        return parsed, result

    # ── Smart chaining ────────────────────────────────────────────────────────

    def _suggest_chain(self, tool_name: str, parsed: dict, args: dict) -> list[dict]:
        """Deterministic fallback chain rules (used only in WebReconChain etc.)."""
        return self._fallback_chain(tool_name, parsed, args)

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
                        proto = "https" if port.get("port") == 443 else "http"
                        suggestions.append({
                            "tool": "whatweb",
                            "args": {"target": f"{proto}://{host['ip']}"},
                            "reason": f"web server on port {port.get('port')} — fingerprint technologies",
                            "priority": 2,
                        })
                        if "wordpress" in port.get("version", "").lower():
                            suggestions.append({"tool": "wpscan", "args": {"target": f"http://{host['ip']}", "mode": "full"}, "reason": "WordPress detected", "priority": 1})
                        suggestions.append({"tool": "zapcli", "args": {"target": f"{proto}://{host['ip']}", "mode": "baseline"}, "reason": f"web on port {port.get('port')} — ZAP baseline", "priority": 3})
                    if port.get("port") in (53, 80, 443):
                        suggestions.append({"tool": "theharvester", "args": {"target": host.get("hostname") or target}, "reason": "OSINT harvest", "priority": 3})

        elif tool_name == "whatweb":
            technologies = parsed.get("technologies", [])
            techs_lower = [t.lower() for t in technologies]
            if "wordpress" in techs_lower or "wp" in techs_lower:
                suggestions.append({"tool": "wpscan", "args": {"target": target, "mode": "full"}, "reason": "WordPress detected — deep scan", "priority": 1})
            if any(tech in techs_lower for tech in ["php", "asp", "jsp"]):
                suggestions.append({"tool": "ffuf", "args": {"target": target, "mode": "dir"}, "reason": "dynamic backend detected — directory fuzzing", "priority": 2})
            suggestions.append({"tool": "nuclei", "args": {"target": target, "mode": "quick"}, "reason": "technologies detected — nuclei CVE scan", "priority": 2})

        elif tool_name == "nikto":
            findings = " ".join(parsed.get("findings", [])).lower()
            if "wordpress" in findings:
                suggestions.append({"tool": "wpscan", "args": {"target": target, "mode": "full"}, "reason": "WordPress found by nikto", "priority": 1})
            if "sql" in findings or "injection" in findings:
                suggestions.append({"tool": "sqlmap", "args": {"target": target, "flags": "--batch --level=2"}, "reason": "potential SQLi found", "priority": 1})
            if parsed.get("total", 0) > 0:
                suggestions.append({"tool": "zapcli", "args": {"target": target, "mode": "active"}, "reason": f"nikto found {parsed.get('total', 0)} issues — ZAP active scan", "priority": 2})

        elif tool_name == "wpscan":
            users = parsed.get("users", [])
            if users:
                suggestions.append({"tool": "hydra", "args": {"target": target, "service": "http-post-form", "form_path": "/wp-login.php", "form_params": "log=^USER^&pwd=^PASS^:F=incorrect", "username": users[0]}, "reason": f"user '{users[0]}' found — brute force", "priority": 2})

        elif tool_name == "ffuf":
            for f in parsed.get("findings", []):
                path = f.get("path", "").lower()
                if any(x in path for x in ("login", "admin", "wp-login", "phpmyadmin")):
                    suggestions.append({"tool": "sqlmap", "args": {"target": f"{target}/{path}", "flags": "--batch --forms"}, "reason": f"login page at {path} — SQLi test", "priority": 1})
                    suggestions.append({"tool": "hydra", "args": {"target": target, "service": "http-post-form", "form_path": f"/{path}"}, "reason": f"login at {path} — brute force", "priority": 2})
                    break

        elif tool_name == "zapcli":
            if parsed.get("high", 0) + parsed.get("critical", 0) > 0:
                suggestions.append({"tool": "nuclei", "args": {"target": target, "mode": "cves"}, "reason": f"ZAP found {parsed.get('high',0)} high-severity — nuclei CVE confirmation", "priority": 1})

        elif tool_name == "enum4linux":
            if parsed.get("shares"):
                suggestions.append({"tool": "smbclient", "args": {"target": target, "mode": "anon"}, "reason": f"found {len(parsed.get('shares',[]))} shares — anonymous access test", "priority": 1})

        elif tool_name == "hydra":
            cracked = parsed.get("cracked", [])
            if cracked:
                suggestions.append({"tool": "nmap", "args": {"target": cracked[0].get("host", target), "mode": "aggressive"}, "reason": "credentials cracked — deeper scan", "priority": 1})

        elif tool_name == "theharvester":
            if parsed.get("subdomains"):
                suggestions.append({"tool": "nmap", "args": {"target": parsed["subdomains"][0], "mode": "service"}, "reason": f"found {len(parsed['subdomains'])} subdomains — scan first", "priority": 2})

        elif tool_name == "mail_crawler":
            if parsed.get("emails"):
                suggestions.append({"tool": "theharvester", "args": {"target": target}, "reason": f"found {len(parsed.get('emails',[]))} emails — broader OSINT", "priority": 3})

        return suggestions

    def _run_chain(self, suggestions: list[dict], depth: int = 0) -> None:
        """Show chain suggestions (styled table) and ask user which to run."""
        MAX_CHAIN_DEPTH = 3
        if depth >= MAX_CHAIN_DEPTH:
            _warn(f"Max chain depth ({MAX_CHAIN_DEPTH}) reached — stopping auto-chain")
            return
        if not suggestions:
            return

        console.print()
        _sep()
        _header("Suggested Next Steps", "⬡")

        table = Table(
            box=box.SIMPLE,
            show_header=True,
            header_style="bold cyan",
            padding=(0, 1),
        )
        table.add_column("#",       style="bold cyan", width=3,  justify="right")
        table.add_column("Tool",    style="bold white", width=16)
        table.add_column("Reason",  style="white")
        table.add_column("Priority", width=10, justify="center")

        for i, s in enumerate(suggestions, 1):
            pri   = s.get("priority", 2)
            color, label = PRI_STYLE.get(pri, ("white", "?"))
            table.add_row(
                str(i),
                s["tool"],
                s["reason"],
                f"[{color}]{label}[/{color}]",
            )

        console.print(table)
        console.print(
            "  [dim]Enter:[/dim]  "
            "[cyan]a[/cyan] run all  "
            "[cyan]n[/cyan] skip  "
            "[cyan]1,2…[/cyan] pick specific"
        )
        choice = Prompt.ask("  [bold cyan]>[/bold cyan]", default="n")

        selected: list[dict] = []
        if choice.strip().lower() == "a":
            selected = suggestions
        elif choice.strip().lower() == "n":
            _sep()
            return
        else:
            for c in choice.split(","):
                c = c.strip()
                if c.isdigit() and 1 <= int(c) <= len(suggestions):
                    selected.append(suggestions[int(c) - 1])

        for s in selected:
            tool_name = s["tool"]
            args      = dict(s["args"])
            _dim(f"chain: {tool_name} — {s['reason']}")
            if Confirm.ask(f"  Run [bold cyan]{tool_name}[/bold cyan]?", default=True):
                t_start = time.monotonic()
                result_data = self._run_tool(tool_name, args)
                if result_data:
                    elapsed = time.monotonic() - t_start
                    parsed, _ = result_data
                    _ok(f"Completed in {elapsed:.1f}s")
                    # ── Unified AI call for chain tool ──────────────────
                    chain_steps = self._ai_process_results(tool_name, parsed, args.get("target", ""))
                    if chain_steps:
                        self._run_chain(chain_steps, depth + 1)

        _sep()

    # ── Arg preparation ───────────────────────────────────────────────────────

    def _prepare_hashcat_args(self, args: dict) -> dict:
        hashfile = args.get("hashfile", "")
        if hashfile and not hashfile.startswith("/") and " " not in hashfile:
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, prefix="kernox_hash_")
            tmp.write(hashfile.strip() + "\n")
            tmp.close()
            _dim(f"Hash saved → [dim]{tmp.name}[/dim]")
            args["hashfile"] = tmp.name
        return args

    def _prepare_sqlmap_args(self, args: dict) -> dict:
        target = args.get("target", "")
        if not target:
            return args
        if args.get("flags") and len(args["flags"]) > 40:
            return args

        console.print()
        console.print(
            Panel(
                "[dim]Probing target for injection strategy…[/dim]",
                title="[bold cyan]  SQLMap Pre-flight  [/bold cyan]",
                border_style="cyan",
                box=box.ROUNDED,
                padding=(0, 2),
            )
        )

        import subprocess
        probe_info = ""
        try:
            probe_cmd = f"curl -sk -I -m 8 --max-redirs 3 '{target}'"
            result = subprocess.run(shlex.split(probe_cmd), capture_output=True, text=True, timeout=10)
            probe_info = result.stdout[:1500]
        except Exception:
            probe_info = "Curl probe failed — no header data available."

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

Respond ONLY with a JSON object (no other text):
{{
  "analysis": "2-3 sentence analysis",
  "flags": "--batch --level=3 --risk=2 --technique=BEUSTQ --tamper=space2comment,randomcase --forms -v 1 --output-dir=/tmp/kernox_sqlmap",
  "waf_bypass_needed": true,
  "recommended_tampers": ["space2comment", "randomcase"]
}}

If no WAF and clean headers: --batch --level=2 --risk=1 --forms -v 1 --output-dir=/tmp/kernox_sqlmap"""

        try:
            with Live(Spinner("dots", text="[cyan]Analysing target…[/cyan]"), refresh_per_second=10, console=console):
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
                flags    = plan.get("flags", "")

                if analysis:
                    _dim(analysis)
                if flags:
                    args["flags"] = flags
                    args.pop("mode", None)
                    _dim(f"Flags: [dim]{flags}[/dim]")
                    tampers = plan.get("recommended_tampers", [])
                    if tampers:
                        _warn(f"Tampers: {', '.join(tampers)}")

        except Exception:
            _dim("AI pre-flight skipped — using default flags")
            if not args.get("flags"):
                args["flags"] = f"--batch --level=2 --risk=1 --forms -v 1 --output-dir=/tmp/kernox_sqlmap_{int(time.time())}"

        return args

    def _add_to_history(self, role: str, content: str) -> None:
        self._history.append({"role": role, "content": content})
        if len(self._history) > 40:
            self._history = self._history[-20:]

    def _trimmed_history(self) -> list[dict]:
        return self._history[-HISTORY_LIMIT:]

    # ── Display helpers ───────────────────────────────────────────────────────

    def _ask_report(self, results: list[dict] | None = None) -> None:
        if not results:
            results = [
                {"tool": tr.tool, "parsed": tr.parsed, "target": tr.target, "timestamp": tr.timestamp}
                for tr in self._state.get_tool_results()
            ]

        ai_insights = [
            {"vulnerability": i.vulnerability, "severity": i.severity, "tool": i.tool,
             "target": i.target, "ai_explanation": i.ai_explanation}
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
        if not steps:
            return

        console.print()
        table = Table(
            title=f"[bold cyan]Execution Plan[/bold cyan]  [dim]({len(steps)} step{'s' if len(steps) != 1 else ''})[/dim]",
            box=box.ROUNDED,
            border_style="cyan",
            show_header=True,
            header_style="bold cyan",
            padding=(0, 1),
        )
        table.add_column("#",      style="bold cyan", width=3, justify="right")
        table.add_column("Tool",   style="bold white", width=16)
        table.add_column("Reason", style="dim white")

        for i, s in enumerate(steps, 1):
            reason = s.get("reason", "")
            if len(reason) > 70:
                reason = reason[:67] + "…"
            table.add_row(str(i), s.get("tool", "?").upper(), reason)

        console.print(table)

    def _print_help(self) -> None:
        console.print()
        rows = [
            ("[cyan]<command>[/cyan]",        "talk to the AI / run a scan"),
            ("[cyan]ask <question>[/cyan]",   "ask about vulnerabilities or tools"),
            ("[cyan]explain[/cyan]",          "AI analysis of current session findings"),
            ("[cyan]tools[/cyan]",            "list all available tools"),
            ("[cyan]tools check[/cyan]",      "check which tools are installed"),
            ("[cyan]state[/cyan]",            "show current session findings"),
            ("[cyan]history[/cyan]",          "show conversation history"),
            ("[cyan]clear[/cyan]",            "clear state and history"),
            ("[cyan]clear history[/cyan]",    "clear AI history only"),
            ("[cyan]clear state[/cyan]",      "clear findings only"),
            ("[cyan]session save[/cyan]",     "save session to disk"),
            ("[cyan]session load[/cyan]",     "restore a previous session"),
            ("[cyan]session list[/cyan]",     "list saved sessions"),
            ("[cyan]analyse[/cyan]",          "paste reverse shell output for analysis"),
            ("[cyan]web recon <url>[/cyan]",  "full automated web recon chain"),
            ("[cyan]report[/cyan]",           "export session findings to PDF"),
            ("[cyan]raw on/off[/cyan]",       "toggle raw tool output"),
            ("[cyan]exit[/cyan]",             "quit Kernox"),
        ]
        table = Table(
            title="[bold cyan]Kernox Commands[/bold cyan]",
            box=box.ROUNDED,
            border_style="cyan",
            show_header=False,
            padding=(0, 1),
        )
        table.add_column("Command", no_wrap=True, width=28)
        table.add_column("Description", style="dim white")
        for cmd, desc in rows:
            table.add_row(cmd, desc)
        console.print(table)

    def _print_tools(self) -> None:
        tools_info = [
            ("nmap",          "port scanning and service fingerprinting"),
            ("ffuf",          "directory / vhost / parameter fuzzing"),
            ("gobuster",      "directory, DNS and vhost enumeration"),
            ("nikto",         "web vulnerability scanner"),
            ("sqlmap",        "SQL injection detection and exploitation"),
            ("enum4linux",    "SMB / Windows enumeration"),
            ("wpscan",        "WordPress vulnerability scanner"),
            ("smbclient",     "SMB share access and enumeration"),
            ("dnsenum",       "DNS enumeration"),
            ("curl",          "HTTP fingerprinting"),
            ("hashcat",       "password hash cracking"),
            ("whatweb",       "web technology detection"),
            ("wafw00f",       "WAF detection"),
            ("sslscan",       "SSL / TLS vulnerability scanning"),
            ("onesixtyone",   "SNMP community string brute-force"),
            ("dnsrecon",      "DNS reconnaissance"),
            ("nuclei",        "CVE and misconfiguration scanning"),
            ("msfvenom",      "payload / reverse shell generation"),
            ("mail_crawler",  "email address harvesting via web crawl"),
            ("zapcli",        "OWASP ZAP web app scanner"),
            ("hydra",         "credential brute-force"),
            ("theharvester",  "OSINT — emails, subdomains, IPs"),
        ]
        console.print()
        table = Table(
            title="[bold cyan]Available Tools[/bold cyan]",
            box=box.ROUNDED,
            border_style="cyan",
            show_header=True,
            header_style="bold cyan",
            padding=(0, 1),
        )
        table.add_column("Tool",        style="bold cyan",  width=18)
        table.add_column("Description", style="dim white")
        for name, purpose in tools_info:
            table.add_row(name, purpose)
        console.print(table)

    def _check_tools(self) -> None:
        from kernox.core.executor import TOOL_BINARIES, INSTALL_HINTS, check_tool_installed

        all_binaries = dict(TOOL_BINARIES)
        all_hints    = dict(INSTALL_HINTS)
        skip = {"ssh", "sshpass"}

        installed_count = 0
        total = len(all_binaries) - len(skip)

        console.print()
        table = Table(
            title="[bold cyan]Tool Status[/bold cyan]",
            box=box.ROUNDED,
            border_style="cyan",
            show_header=True,
            header_style="bold cyan",
            padding=(0, 1),
        )
        table.add_column("Status", width=8,  justify="center")
        table.add_column("Tool",   style="bold cyan", width=18)
        table.add_column("Install hint", style="dim white")

        for tool, binary in all_binaries.items():
            if tool in skip:
                continue
            is_installed = check_tool_installed(binary)
            if is_installed:
                installed_count += 1
                table.add_row("[bold green]✔[/bold green]", tool, "")
            else:
                hint = all_hints.get(tool, f"sudo apt install {tool}")
                table.add_row("[bold red]✘[/bold red]", tool, hint)

        console.print(table)
        console.print(f"\n  [dim]{installed_count}/{total} tools installed[/dim]")

    def _print_state(self) -> None:
        import json as _json
        console.print()
        console.print(
            Panel(
                Text(_json.dumps(self._state.to_dict(), default=str, indent=2), style="dim white"),
                title="[bold cyan]  Session State  [/bold cyan]",
                border_style="cyan",
                box=box.ROUNDED,
                padding=(0, 2),
            )
        )

    def _print_history(self) -> None:
        console.print()
        table = Table(
            title="[bold cyan]Conversation History[/bold cyan]",
            box=box.ROUNDED,
            border_style="cyan",
            show_header=True,
            header_style="bold cyan",
            padding=(0, 1),
        )
        table.add_column("Role",    width=12)
        table.add_column("Message", style="dim white")
        for msg in self._history[-20:]:
            role_style = "bold cyan" if msg["role"] == "assistant" else "bold green"
            table.add_row(
                f"[{role_style}]{msg['role']}[/{role_style}]",
                msg["content"][:200],
            )
        console.print(table)

    def _clear_all(self) -> None:
        self._state.reset()
        self._history.clear()
        _ok("State and history cleared")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _explain_findings(tool_name: str, parsed: dict) -> None:
    """After a tool finishes, surface known vulnerabilities cleanly."""
    from kernox.utils.report_generator import explain_vulnerability, VULN_EXPLANATIONS

    explained: set = set()

    def _show_vuln(info: dict) -> None:
        name = info.get("name", "")
        if name in explained:
            return
        explained.add(name)
        sev = info.get("severity", "HIGH").upper()
        color, badge = SEV_STYLE.get(sev.lower(), ("white", sev))
        body = ""
        if info.get("description"):
            body += f"[white]{info['description']}[/white]\n\n"
        if info.get("impact"):
            body += f"[dim]Impact :[/dim]  {info['impact']}\n"
        if info.get("recommendation"):
            body += f"[dim]Exploit    :[/dim]  {info['recommendation']}"
        if info.get("references"):
            body += "\n" + "  ".join(f"[dim]{r}[/dim]" for r in info["references"])
        console.print()
        console.print(
            Panel(
                body.strip(),
                title=f"[{color}]{badge}[/{color}]  [bold white]{name}[/bold white]",
                border_style=color,
                box=box.ROUNDED,
                padding=(0, 2),
            )
        )

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
                    sev = finding["severity"]
                    color, badge = SEV_STYLE.get(sev, ("white", sev.upper()))
                    console.print()
                    console.print(
                        Panel(
                            f"[white]{desc}[/white]" + (
                                f"\n\n[dim]Matched:[/dim]  {finding.get('matched','')[:80]}"
                                if finding.get("matched") else ""
                            ),
                            title=f"[{color}]{badge}[/{color}]  [bold white]{finding.get('name', '')}[/bold white]",
                            border_style=color,
                            box=box.ROUNDED,
                            padding=(0, 2),
                        )
                    )

    elif tool_name == "zapcli":
        for alert in parsed.get("alerts", []):
            if alert.get("severity") in ("critical", "high"):
                sev = alert["severity"]
                color, badge = SEV_STYLE.get(sev, ("white", sev.upper()))
                urls = alert.get("urls", [])
                console.print()
                console.print(
                    Panel(
                        f"[dim]Instances:[/dim]  {alert.get('count', 1)}"
                        + (f"\n[dim]URLs     :[/dim]  {', '.join(urls[:3])}" if urls else ""),
                        title=f"[{color}]{badge}[/{color}]  [bold white]{alert.get('name', 'ZAP Alert')}[/bold white]",
                        border_style=color,
                        box=box.ROUNDED,
                        padding=(0, 2),
                    )
                )

    elif tool_name == "hydra":
        cracked = parsed.get("cracked", [])
        if cracked:
            lines = "\n".join(
                f"  [bold green]{c.get('username','')}[/bold green]:[bold white]{c.get('password','')}[/bold white]  "
                f"[dim]{c.get('service','')}[/dim]"
                for c in cracked[:10]
            )
            color, badge = SEV_STYLE["critical"]
            console.print()
            console.print(
                Panel(
                    lines,
                    title=f"[{color}]{badge}[/{color}]  [bold white]{len(cracked)} credential(s) cracked[/bold white]",
                    border_style=color,
                    box=box.ROUNDED,
                    padding=(0, 2),
                )
            )

    elif tool_name == "theharvester":
        emails     = parsed.get("emails", [])
        subdomains = parsed.get("subdomains", [])
        if emails or subdomains:
            body = ""
            if emails:
                body += f"[dim]Emails ({len(emails)}):[/dim]  {', '.join(emails[:8])}\n"
            if subdomains:
                body += f"[dim]Subdomains ({len(subdomains)}):[/dim]  {', '.join(subdomains[:8])}"
            console.print()
            console.print(
                Panel(
                    body.strip(),
                    title="[bold cyan]  theHarvester · OSINT  [/bold cyan]",
                    border_style="cyan",
                    box=box.ROUNDED,
                    padding=(0, 2),
                )
            )

    elif tool_name == "onesixtyone":
        communities = parsed.get("communities", [])
        if communities:
            lines = "\n".join(
                f"  [{c.get('community','')}]  [dim]{c.get('info','')[:60]}[/dim]"
                for c in communities[:5]
            )
            color, badge = SEV_STYLE["high"]
            console.print()
            console.print(
                Panel(
                    lines,
                    title=f"[{color}]{badge}[/{color}]  [bold white]SNMP community strings found: {len(communities)}[/bold white]",
                    border_style=color,
                    box=box.ROUNDED,
                    padding=(0, 2),
                )
            )

    elif tool_name == "sqlmap" and parsed.get("vulnerable"):
        color, badge = SEV_STYLE["critical"]
        console.print()
        console.print(
            Panel(
                f"[dim]DBMS       :[/dim]  {parsed.get('dbms', 'unknown')}\n"
                f"[dim]Parameters :[/dim]  {', '.join(parsed.get('parameters', []))}",
                title=f"[{color}]{badge}[/{color}]  [bold white]SQL Injection confirmed[/bold white]",
                border_style=color,
                box=box.ROUNDED,
                padding=(0, 2),
            )
        )


def _build_smart_summary(tool_name: str, parsed: dict, target: str) -> str:
    """Build a human-readable summary of tool results for the AI."""
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
                lines.append(f"  [{f.get('severity', '').upper()}] {f.get('name', '')} -> {f.get('matched', '')[:80]}")
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
                lines.append(f"  SUB: {s.get('subdomain', '')} -> {s.get('ip', '')}")
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
    """
    Safely extract a JSON plan dict from AI output.

    Attempts (in order):
      1. Markdown-fenced ```json ... ``` block
      2. Bare JSON object at start of string
      3. Bare JSON array at start of string  →  wrapped into a plan dict
      4. Bounded character-by-character brace scan (capped at MAX_EXTRACT_SIZE)

    The inner brace scan is bounded so malformed / huge AI responses never
    cause an O(n²) hang.
    """
    import re

    MAX_EXTRACT_SIZE = 10_000   # chars — ignore any JSON candidate larger than this

    # ── 1. Markdown fenced block ──────────────────────────────────────────────
    pattern = r"```(?:json)?\s*(\{.*?\})\s*```"
    match = re.search(pattern, text, re.DOTALL)
    if match:
        candidate = match.group(1)
        if len(candidate) <= MAX_EXTRACT_SIZE:
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass

    stripped = text.strip()

    # ── 2. Bare JSON object ───────────────────────────────────────────────────
    if stripped.startswith("{"):
        if len(stripped) <= MAX_EXTRACT_SIZE:
            try:
                return json.loads(stripped)
            except json.JSONDecodeError:
                pass

    # ── 3. Bare JSON array ────────────────────────────────────────────────────
    if stripped.startswith("["):
        if len(stripped) <= MAX_EXTRACT_SIZE:
            try:
                arr = json.loads(stripped)
                if isinstance(arr, list):
                    return {
                        "analysis": "AI suggested tools",
                        "steps":    arr,
                        "message":  f"Suggested {len(arr)} tool(s)",
                    }
            except json.JSONDecodeError:
                pass

    # ── 4. Bounded brace scan ─────────────────────────────────────────────────
    # Only scan the first MAX_EXTRACT_SIZE characters to prevent O(n²) hangs
    # on huge or pathologically malformed AI responses.
    search_text = text[:MAX_EXTRACT_SIZE]
    brace_positions = [i for i, c in enumerate(search_text) if c == "{"]

    for start in brace_positions:
        brace_depth = 0
        end_pos     = -1

        # Inner scan is also capped: never read beyond MAX_EXTRACT_SIZE chars
        # from this opening brace.
        max_pos = min(start + MAX_EXTRACT_SIZE, len(search_text))

        for i in range(start, max_pos):
            c = search_text[i]
            if c == "{":
                brace_depth += 1
            elif c == "}":
                brace_depth -= 1
                if brace_depth == 0:
                    end_pos = i
                    break

        if end_pos == -1:
            # No matching close-brace found within the cap — skip this opener
            continue

        candidate = search_text[start : end_pos + 1]
        if len(candidate) > MAX_EXTRACT_SIZE:
            continue

        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict) and (
                "steps" in parsed or "message" in parsed or "analysis" in parsed
            ):
                return parsed
        except json.JSONDecodeError:
            pass  # not valid JSON — try next opening brace

    return None
