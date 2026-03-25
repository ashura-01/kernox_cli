"""
kernox.core.orchestrator  –  Production-ready AI orchestrator with smart chaining.

Flow:
  1. User types command
  2. AI builds a plan (JSON)
  3. Each step runs with user confirmation
  4. After each tool → firewall check (nmap) or chain suggestion
  5. AI suggests next steps, user picks which to run
"""

from __future__ import annotations

import json
import time
import tempfile
import os
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

console = Console()

HISTORY_LIMIT    = 8
API_DELAY        = 2
POST_TOOL_ANALYSIS = False

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
  args: target, mode (quick/service/aggressive/vuln/full/stealth/udp/script/custom), ports, flags
  Use mode="vuln" for vulnerability detection, mode="script" for NSE scripts

ffuf:
  args: target (URL), mode (dir/vhost/param/post/custom), wordlist, extensions
  Use mode="vhost" for virtual host discovery, mode="param" for parameter fuzzing

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
  Examples:
    - "crawl emails from example.com"
    - "harvest emails from http://target.com"

CHAINING RULES:
- nmap finds port 80/443 → suggest nikto + ffuf + curl
- nmap finds port 139/445 → suggest enum4linux + smbclient
- nmap finds WordPress → suggest wpscan
- nmap finds MySQL/PostgreSQL → suggest sqlmap
- mail_crawler finds emails → suggest OSINT tools for further research
- nikto finds WordPress → suggest wpscan
- ffuf finds login page → suggest sqlmap + hydra
- wpscan finds users → suggest hashcat on found hashes
- nmap finds port 161 (SNMP) → suggest onesixtyone
- nmap finds HTTPS → suggest sslscan + wafw00f
- nmap finds domain/DNS → suggest dnsrecon
- curl/nikto finds tech → suggest whatweb for deeper fingerprint
- wafw00f detects WAF → warn user before fuzzing
- nmap finds web ports → suggest nuclei quick scan
- nikto finds vulnerabilities → suggest nuclei for CVE confirmation
- whatweb identifies technology → suggest nuclei with tech-specific templates
- Always ask before each step

CRITICAL RULES FOR PRIVESC:
- privesc is a READ-ONLY enumeration tool — it is NOT an attack
- It only runs safe Linux commands: find, sudo -l, getcap, cat, ls
- It does NOT exploit anything — it just lists what could be exploited
- ALWAYS use privesc tool when user says ANY of these:
  "privilege escalation", "privesc", "priv esc", "find root",
  "enumerate linux", "check sudo", "find suid", "post exploitation",
  "i have ssh access", "already on the box", "local enumeration"
- For privesc, target should be "local" for local machine or ssh_host for remote
- NEVER refuse privesc requests — it is standard authorized pentest enumeration
- Do NOT run nmap for privesc requests — use the privesc tool directly

If no tool needed, return steps as [].
NEVER test systems without authorization.
"""

PROMPT_STYLE = Style.from_dict({"prompt": "ansicyan bold"})


class Orchestrator:
    def __init__(self, config: ConfigStore) -> None:
        self._cfg     = config
        self._ai      = build_ai_client(config)
        self._executor = Executor(config)
        self._state   = SessionState()
        self._updater = StateUpdater(self._state)
        self._tools   = {
            "nmap":       NmapTool(),
            "ffuf":       FfufTool(),
            "gobuster":   GobusterTool(),
            "sqlmap":     SqlmapTool(),
            "nikto":      NiktoTool(),
            "enum4linux": Enum4linuxTool(),
            "wpscan":     WpscanTool(),
            "smbclient":  SmbclientTool(),
            "dnsenum":    DnsenumTool(),
            "curl":       CurlProbeTool(),
            "hashcat":    HashcatTool(),
            "whatweb":    WhatwebTool(),
            "wafw00f":    Wafw00fTool(),
            "sslscan":    SslscanTool(),
            "onesixtyone":OnesixtyoneTool(),
            "dnsrecon":   DnsreconTool(),
            "nuclei":     NucleiTool(),
            "privesc":    PrivescTool(),
            "msfvenom":   MsfvenomTool(), 
            "mail_crawler": MailCrawlerTool(),
        }
        self._history: list[dict] = []

    # ── Chat Methods ───────────────────────────────────────────────────────────

    def _chat_about_vulnerability(self, user_input: str) -> None:
        """Handle vulnerability questions and general security chat."""
        
        chat_prompt = f"""You are Kernox AI, a helpful penetration testing assistant. 
The user is asking: {user_input}

Current session context:
- Target: {', '.join(self._state.hosts.keys()) or 'No targets scanned yet'}
- Tools run: {len(self._state.get_tool_results())}
- Vulnerabilities found: {len(self._state.get_ai_insights())}

If the user is asking about a vulnerability, provide:
1. What it is (simple explanation)
2. How to exploit (ethically, for testing)
3. How to fix it
4. References (CVE numbers, etc.)

If asking about tools, explain their purpose and typical usage.
If asking for recommendations, suggest next steps based on current findings.

Keep responses clear and actionable. Use markdown for formatting.
If the user asks about something unrelated to security testing, politely decline.
"""
        
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
        
        self._history.append({"role": "user", "content": user_input})
        self._history.append({"role": "assistant", "content": response})

    def _explain_findings_summary(self) -> None:
        """Get AI to explain the current findings and suggest next steps."""
        if not self._state.get_tool_results():
            console.print("[yellow]No findings to explain yet. Run some scans first.[/yellow]")
            return
        
        findings_summary = []
        for result in self._state.get_tool_results()[-5:]:
            findings_summary.append(f"- {result.tool} on {result.target}")
        
        insights = self._state.get_ai_insights()
        if insights:
            findings_summary.append("\nVulnerabilities found:")
            for insight in insights[:3]:
                findings_summary.append(f"  - {insight.vulnerability} ({insight.severity})")
        
        prompt = f"""Based on the following findings from a penetration test:

{chr(10).join(findings_summary)}

Please provide:
1. A summary of the most critical issues found
2. Recommended next steps for further enumeration
3. Any potential attack paths to explore
4. General advice for this assessment

Keep the response concise and actionable.
"""
        
        with Live(Spinner("dots", text="[cyan]Analyzing findings...[/cyan]"), refresh_per_second=10):
            response = self._ai.chat(
                messages=[{"role": "user", "content": prompt}],
                system="You are a senior penetration tester providing expert analysis."
            )
        
        console.print(Panel(
            Markdown(response),
            title="[cyan]Findings Analysis[/cyan]",
            border_style="cyan",
            box=box.ROUNDED,
        ))

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
            elif cmd == "help":            self._print_help(); continue
            elif cmd == "tools":           self._print_tools(); continue
            elif cmd == "tools check":     self._check_tools(); continue
            elif cmd == "state":           self._print_state(); continue
            elif cmd == "history":         self._print_history(); continue
            elif cmd == "clear":           self._clear_all(); continue
            elif cmd == "clear history":   self._history.clear(); console.print("[green]✓ History cleared[/green]"); continue
            elif cmd == "clear state":     self._state.reset(); console.print("[green]✓ State cleared[/green]"); continue
            elif cmd == "raw on":
                self._cfg.set("show_raw_output", "1")
                console.print("[green]✓ Raw output ON — tool output will be streamed live[/green]")
                continue
            elif cmd == "raw off":
                self._cfg.set("show_raw_output", "0")
                console.print("[yellow]✓ Raw output OFF — tools run silently with spinner[/yellow]")
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
            elif cmd == "raw":
                current = self._cfg.get("show_raw_output") == "1"
                state = "[green]ON[/green]" if current else "[yellow]OFF[/yellow]"
                console.print(f"Raw output is currently {state}. Type [bold]raw on[/bold] or [bold]raw off[/bold] to toggle.")
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

            self._process(user_input)

    # ── Process pipeline ──────────────────────────────────────────────────────

    def _process(self, user_input: str) -> None:
        # Check if this is a chat/query about vulnerabilities
        chat_keywords = ["what is", "how to", "explain", "tell me about", "what does", 
                        "how does", "why is", "can you", "help me understand", 
                        "difference between", "compare", "recommend"]
        
        is_chat_query = any(user_input.lower().startswith(kw) for kw in chat_keywords) or \
                        "?" in user_input and len(user_input.split()) < 15
        
        if is_chat_query and not any(cmd in user_input.lower() for cmd in ["scan", "run", "enumerate", "fuzz", "crack"]):
            self._chat_about_vulnerability(user_input)
            return
        
        self._history.append({"role": "user", "content": user_input})
        
        # Build context from session state
        context = f"""
Current session context:
- Targets scanned: {', '.join(self._state.hosts.keys()) or 'None'}
- Open ports found: {sum(len(h.ports) for h in self._state.hosts.values())}
- Vulnerabilities: {len(self._state.get_ai_insights())}
- Tools run: {len(self._state.get_tool_results())}

User request: {user_input}

Based on the context, create a plan to help the user.
"""
        
        with Live(Spinner("dots", text="[cyan]AI thinking...[/cyan]"), refresh_per_second=10):
            ai_response = self._ai.chat(
                messages=self._trimmed_history(),
                system=SYSTEM_PROMPT + "\n\n" + context,
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

            result_data = self._run_tool(tool_name, args)
            if result_data is None:
                continue

            parsed, result = result_data
            summary = _build_smart_summary(tool_name, parsed, args.get("target",""))
            all_summaries.append(summary)

            chain_steps = self._suggest_chain(tool_name, parsed, args)
            if chain_steps:
                self._run_chain(chain_steps)

        if all_summaries:
            self._history.append({"role": "user", "content": "Tools finished: " + " | ".join(all_summaries)})
            self._history.append({"role": "assistant", "content": "Results stored."})
            console.print(Panel(
                f"[green]✓ Session complete.[/green]\n"
                f"[dim]State: {self._state.summary()}[/dim]\n"
                "Type [bold]state[/bold] to review findings or [bold]report[/bold] to export PDF.",
                title="[cyan]Done[/cyan]", border_style="green",
            ))
            from rich.prompt import Confirm as C
            if C.ask("\n[bold yellow]Export findings to PDF report?[/bold yellow]", default=False):
                self._ask_report()

    def _run_tool(self, tool_name: str, args: dict) -> Optional[tuple[dict, object]]:
        """Run a single tool. Returns (parsed, result) or None if blocked."""
        tool = self._tools.get(tool_name)
        if not tool:
            console.print(f"[red]Unknown tool: {tool_name}[/red]")
            return None

        # Special handling for mail_crawler (Python-based, no shell command)
        if tool_name == "mail_crawler":
            console.print(f"[bold magenta]\n── {tool_name.upper()} ──[/bold magenta]")
            # Call the tool directly
            result = tool.run_direct(**args)
            parsed = result
            format_results(tool_name, parsed)
            self._state.add_tool_result(tool=tool_name, target=args.get("target", ""), parsed=parsed)
            return parsed, None

        # For all other tools, build command and run via executor
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
        
        # Store tool result
        self._state.add_tool_result(
            tool=tool_name,
            target=args.get("target", ""),
            parsed=parsed,
            raw_output=result.stdout
        )
        
        self._updater.apply(tool_name, parsed, target=args.get("target"))
        format_results(tool_name, parsed)
        
        # Generate AI insights for vulnerabilities
        self._generate_ai_insights(tool_name, parsed, args.get("target", ""))

        return parsed, result

    def _generate_ai_insights(self, tool_name: str, parsed: dict, target: str) -> None:
        """Generate AI explanations for vulnerabilities found."""
        vulnerabilities = []
        
        if tool_name == "nuclei":
            for finding in parsed.get("findings", []):
                if finding.get("severity") in ("critical", "high", "medium"):
                    vulnerabilities.append({
                        "name": finding.get("name", ""),
                        "severity": finding.get("severity", "medium"),
                        "description": finding.get("description", ""),
                    })
        elif tool_name == "nikto":
            for finding in parsed.get("findings", []):
                vulnerabilities.append({
                    "name": finding[:80],
                    "severity": "medium",
                    "description": finding
                })
        elif tool_name == "sqlmap" and parsed.get("vulnerable"):
            vulnerabilities.append({
                "name": "SQL Injection",
                "severity": "critical",
                "description": f"SQL injection found with parameters: {', '.join(parsed.get('parameters', []))}"
            })
        elif tool_name == "sslscan":
            for issue in parsed.get("issues", []):
                vulnerabilities.append({
                    "name": issue,
                    "severity": "high",
                    "description": issue
                })
        elif tool_name == "wpscan":
            for vuln in parsed.get("vulnerabilities", []):
                vulnerabilities.append({
                    "name": vuln[:80],
                    "severity": "high",
                    "description": vuln
                })
        else:
            return
        
        for vuln in vulnerabilities[:3]:
            try:
                explanation = self._ai.chat(
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
                    system="You are a senior security consultant. Provide clear, actionable explanations."
                )
                
                import re
                json_match = re.search(r'\{.*\}', explanation, re.DOTALL)
                if json_match:
                    ai_explanation = json.loads(json_match.group())
                    self._state.add_ai_insight(
                        vulnerability=vuln['name'],
                        severity=vuln['severity'],
                        tool=tool_name,
                        target=target,
                        explanation=ai_explanation
                    )
            except Exception:
                self._state.add_ai_insight(
                    vulnerability=vuln['name'],
                    severity=vuln['severity'],
                    tool=tool_name,
                    target=target,
                    explanation={
                        "description": vuln.get('description', 'Vulnerability detected'),
                        "impact": "May lead to system compromise or data breach",
                        "recommendation": "Apply vendor patch and review security configuration"
                    }
                )

    def _suggest_chain(self, tool_name: str, parsed: dict, args: dict) -> list[dict]:
        """Build smart chain suggestions based on tool results."""
        suggestions: list[dict] = []
        target = args.get("target", "")

        if tool_name == "nmap":
            enum_steps = suggest_enumeration(parsed)
            if enum_steps:
                print_enum_plan(enum_steps)
                for s in enum_steps:
                    if s.tool != "custom":
                        suggestions.append({
                            "tool": s.tool,
                            "args": s.args,
                            "reason": s.reason,
                            "priority": s.priority,
                        })

            for host in parsed.get("hosts", []):
                for port in host.get("ports", []):
                    if port.get("port") in (80, 443, 8080, 8180):
                        version = port.get("version", "").lower()
                        if "wordpress" in version or "wp" in version:
                            suggestions.append({
                                "tool": "wpscan",
                                "args": {"target": f"http://{host['ip']}", "mode": "full"},
                                "reason": "WordPress detected",
                                "priority": 1,
                            })

        elif tool_name == "nikto":
            findings = " ".join(parsed.get("findings", [])).lower()
            if "wordpress" in findings:
                suggestions.append({
                    "tool": "wpscan",
                    "args": {"target": target, "mode": "full"},
                    "reason": "WordPress found by nikto",
                    "priority": 1,
                })
            if "sql" in findings or "injection" in findings:
                suggestions.append({
                    "tool": "sqlmap",
                    "args": {"target": target, "flags": "--batch --level=2"},
                    "reason": "Potential SQL injection found by nikto",
                    "priority": 1,
                })

        elif tool_name == "wpscan":
            users = parsed.get("users", [])
            if users:
                suggestions.append({
                    "tool": "wpscan",
                    "args": {"target": target, "mode": "brute"},
                    "reason": f"Found {len(users)} WordPress users — try brute force",
                    "priority": 2,
                })

        elif tool_name == "ffuf":
            findings = parsed.get("findings", [])
            for f in findings:
                path = f.get("path", "").lower()
                if any(x in path for x in ("login", "admin", "wp-login", "phpmyadmin")):
                    suggestions.append({
                        "tool": "sqlmap",
                        "args": {"target": f"{target}/{path}", "flags": "--batch --forms"},
                        "reason": f"Login page found at {path} — test SQLi",
                        "priority": 1,
                    })

        elif tool_name == "privesc":
            juicy = parsed.get("juicy_points", [])
            for j in juicy:
                if j.get("category") == "writable" and "shadow" in j.get("path",""):
                    suggestions.append({
                        "tool": "hashcat",
                        "args": {"hashfile": "/etc/shadow"},
                        "reason": "Readable /etc/shadow — crack root hash",
                        "priority": 1,
                    })
                if j.get("category") == "nfs":
                    suggestions.append({
                        "tool": "curl",
                        "args": {"target": target, "mode": "headers"},
                        "reason": "NFS misconfiguration found — check network services",
                        "priority": 2,
                    })

        elif tool_name == "enum4linux":
            shares = parsed.get("shares", [])
            if shares:
                suggestions.append({
                    "tool": "smbclient",
                    "args": {"target": target, "mode": "anon"},
                    "reason": f"Found {len(shares)} shares — try anonymous access",
                    "priority": 1,
                })

        return suggestions

    def _run_chain(self, suggestions: list[dict]) -> None:
        """Show chain suggestions and ask user which to run."""
        if not suggestions:
            return

        console.print("\n[bold cyan]🔗 Smart Chain Suggestions[/bold cyan]")
        console.print("[dim]Based on results, Kernox suggests:[/dim]\n")

        table = Table(show_header=True, header_style="bold magenta",
                      box=box.SIMPLE_HEAVY, border_style="dim")
        table.add_column("#", width=4, style="bold cyan")
        table.add_column("Tool", style="bold", width=12)
        table.add_column("Reason")
        table.add_column("Priority", width=8)

        pri_colors = {1: "bold red", 2: "bold yellow", 3: "cyan"}
        pri_labels = {1: "HIGH", 2: "MED", 3: "LOW"}

        for i, s in enumerate(suggestions, 1):
            pri = s.get("priority", 2)
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
                    if len(self._history) < 40:
                        nested = self._suggest_chain(tool_name, parsed, args)
                        if nested:
                            self._run_chain(nested)

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

    def _trimmed_history(self) -> list[dict]:
        return self._history[-HISTORY_LIMIT:]

    # ── Display helpers ───────────────────────────────────────────────────────

    def _ask_report(self, results: list[dict] | None = None) -> None:
        """Ask user if they want to export findings to PDF."""
        if not results:
            results = []
            for tool_result in self._state.get_tool_results():
                results.append({
                    "tool": tool_result.tool,
                    "parsed": tool_result.parsed,
                    "target": tool_result.target,
                    "timestamp": tool_result.timestamp
                })
        
        ai_insights = []
        for insight in self._state.get_ai_insights():
            ai_insights.append({
                "vulnerability": insight.vulnerability,
                "severity": insight.severity,
                "tool": insight.tool,
                "target": insight.target,
                "ai_explanation": insight.ai_explanation
            })
        
        filename = f"/tmp/kernox_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        generate_pdf_report(
            target=", ".join(self._state.hosts.keys()) or "unknown",
            results=results,
            output_path=filename,
            ai_insights=ai_insights
        )

    def _print_plan(self, steps: list[dict]) -> None:
        # Clean minimal plan display — no noisy step headers
        console.print(f"\n[bold green][Kernox][/bold green] {len(steps)} step(s) planned:\n")
        for i, s in enumerate(steps, 1):
            reason = s.get('reason', '')
            # Show full reason, but wrap if too long
            if len(reason) > 80:
                reason = reason[:77] + "..."
            console.print(
                f"  [green]{i}.[/green] [bold cyan]{s.get('tool','?')}[/bold cyan] "
                f"[dim]— {reason}[/dim]"
            )

    def _print_help(self) -> None:
        console.print(Panel(
            "[bold]Commands:[/bold]\n"
            "  [cyan]<anything>[/cyan]     – Talk to the AI\n"
            "  [cyan]ask <question>[/cyan] – Ask about vulnerabilities/tools\n"
            "  [cyan]explain[/cyan]        – Get AI analysis of current findings\n"
            "  [cyan]tools[/cyan]          – List all tools\n"
            "  [cyan]tools check[/cyan]    – Check which tools are installed\n"
            "  [cyan]state[/cyan]          – Current session findings\n"
            "  [cyan]history[/cyan]        – Conversation history\n"
            "  [cyan]clear[/cyan]          – Clear everything\n"
            "  [cyan]clear history[/cyan]  – Clear AI history only\n"
            "  [cyan]clear state[/cyan]    – Clear findings only\n"
            "  [cyan]analyse[/cyan]        – Paste reverse shell output for privesc analysis\n"
            "  [cyan]web recon <url>[/cyan] – Full automated web recon chain\n"
            "  [cyan]report[/cyan]          – Export session findings to PDF\n"
            "  [cyan]raw on[/cyan]         – Show raw tool output\n"
            "  [cyan]raw off[/cyan]        – Hide raw output (silent+spinner)\n"
            "  [cyan]raw[/cyan]            – Check current raw output status\n"
            "  [cyan]exit[/cyan]           – Quit\n\n"
            "[bold]Example questions:[/bold]\n"
            "  what is SQL injection?\n"
            "  how to exploit EternalBlue?\n"
            "  explain the differences between nmap and masscan\n"
            "  what should I do after finding port 445?\n"
            "  recommend tools for WordPress enumeration\n\n"
            "[bold]Example scans:[/bold]\n"
            "  scan target 192.168.0.209\n"
            "  run nikto on http://192.168.0.209\n"
            "  enumerate SMB on 192.168.0.209\n"
            "  whatweb on http://example.com",
            title="[bold cyan]Help[/bold cyan]", border_style="cyan",
        ))

    def _print_tools(self) -> None:
        table = Table(show_header=True, header_style="bold magenta",
                      box=box.SIMPLE_HEAVY, border_style="dim")
        table.add_column("Tool", style="bold cyan", width=14)
        table.add_column("Purpose")
        table.add_column("Modes", style="dim")
        rows = [
            ("nmap",       "Port scanning + NSE scripts",        "quick/service/aggressive/vuln/full/stealth/udp/script"),
            ("ffuf",       "Web fuzzing",                        "dir/vhost/param/post"),
            ("gobuster",   "Directory/DNS/VHost busting",        "dir/dns/vhost/s3"),
            ("nikto",      "Web vulnerability scan",             "full/tuned/auth/sqli/ssl/quick"),
            ("sqlmap",     "SQL injection testing",              "auto"),
            ("enum4linux", "SMB enumeration",                    "auto -a"),
            ("wpscan",     "WordPress scanning",                 "passive/full/users/brute"),
            ("smbclient",  "SMB share access",                   "list/anon/connect/download"),
            ("dnsenum",    "DNS enumeration",                    "basic/full/zone/reverse"),
            ("curl",       "HTTP probing",                       "headers/methods/robots/tech"),
            ("hashcat",    "Password cracking",                  "auto GPU/CPU detect"),
            ("whatweb",    "Web tech fingerprinting",            "aggressive/verbose/quiet"),
            ("wafw00f",    "WAF detection",                      "auto"),
            ("sslscan",    "SSL/TLS vulnerability analysis",     "auto"),
            ("onesixtyone","SNMP community string enum",         "auto"),
            ("dnsrecon",   "Advanced DNS recon",                 "std/brt/axfr/srv/full"),
            ("nuclei",     "Template-based vuln scanner (9000+)", "quick/full/cves/exposures/logins"),
            ("privesc",    "Linux privilege escalation enum",    "ssh/quick/full"),
            ("msfvenom",   "Payload generation",                 "reverse/bind/custom"),
        ]
        for row in rows:
            table.add_row(*row)
        console.print(Panel(table, title="[bold cyan]Available Tools[/bold cyan]", border_style="cyan"))

    def _check_tools(self) -> None:
        from kernox.core.executor import TOOL_BINARIES, INSTALL_HINTS, check_tool_installed
        table = Table(show_header=True, header_style="bold magenta",
                      box=box.SIMPLE_HEAVY, border_style="dim")
        table.add_column("Tool", style="bold cyan", width=16)
        table.add_column("Status", width=14)
        table.add_column("Install command", style="dim")

        installed_count = 0
        skip = {"ssh", "sshpass"}
        for tool, binary in TOOL_BINARIES.items():
            if tool in skip:
                continue
            is_installed = check_tool_installed(binary)
            if is_installed:
                installed_count += 1
                status = "[bold green]✓ installed[/bold green]"
                hint = ""
            else:
                status = "[bold red]✗ missing[/bold red]"
                hint = INSTALL_HINTS.get(tool, f"sudo apt install {tool}")
            table.add_row(tool, status, hint)

        total = len(TOOL_BINARIES) - len(skip)
        console.print(Panel(
            table,
            title=f"[bold cyan]Tool Check — {installed_count}/{total} installed[/bold cyan]",
            border_style="green" if installed_count == total else "yellow",
        ))
        if installed_count < total:
            console.print(
                "\n[yellow]💡 Install all missing tools:[/yellow]\n"
                "[cyan]sudo apt install nmap ffuf gobuster sqlmap nikto "
                "enum4linux smbclient dnsenum curl hashcat whatweb "
                "sslscan onesixtyone dnsrecon wafw00f wpscan sshpass[/cyan]\n"
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
    """After a tool finishes, check for known vulnerabilities."""
    from kernox.utils.report_generator import explain_vulnerability, VULN_EXPLANATIONS
    from rich.text import Text

    explained = set()

    def _show_vuln(info: dict) -> None:
        name = info.get("name","")
        if name in explained:
            return
        explained.add(name)

        sev = info.get("severity","HIGH")
        sev_color = {"CRITICAL":"bold red","HIGH":"bold yellow",
                     "MEDIUM":"bold cyan","LOW":"green"}.get(sev,"white")

        content = Text()
        content.append(f"[{sev}] ", style=sev_color)
        content.append(f"{name}\n\n", style="bold white")
        content.append("What is it:\n", style="bold cyan")
        content.append(f"{info.get('description','')}\n\n", style="white")
        content.append("Impact:\n", style="bold yellow")
        content.append(f"{info.get('impact','')}\n\n", style="white")
        content.append("Fix:\n", style="bold green")
        content.append(f"{info.get('recommendation','')}\n", style="white")
        if info.get("references"):
            content.append("\nReferences:\n", style="dim")
            for ref in info["references"]:
                content.append(f"  {ref}\n", style="dim cyan")

        console.print(Panel(
            content,
            title=f"[bold red]⚠ Vulnerability Explained[/bold red]",
            border_style="red" if sev == "CRITICAL" else "yellow",
            box=box.ROUNDED,
        ))

    if tool_name == "sslscan":
        for issue in parsed.get("issues",[]):
            info = explain_vulnerability(issue)
            if info:
                _show_vuln(info)

    elif tool_name == "nikto":
        for finding in parsed.get("findings",[]):
            info = explain_vulnerability(finding)
            if info:
                _show_vuln(info)

    elif tool_name == "nmap":
        for host in parsed.get("hosts",[]):
            for port in host.get("ports",[]):
                version = port.get("version","").lower()
                if "vsftpd" in version and "2.3.4" in version:
                    _show_vuln(VULN_EXPLANATIONS["vsftpd-backdoor"])
                if "unrealircd" in version and "3.2.8.1" in version:
                    _show_vuln(VULN_EXPLANATIONS["unrealircd-backdoor"])

    elif tool_name == "nuclei":
        for finding in parsed.get("findings",[]):
            name = finding.get("name","") + " " + finding.get("template","")
            info = explain_vulnerability(name)
            if info:
                _show_vuln(info)
            elif finding.get("severity") in ("critical","high"):
                desc = finding.get("description","")
                if desc:
                    console.print(Panel(
                        f"[bold yellow]{finding.get('name','')}[/bold yellow]\n\n"
                        f"{desc}\n\n"
                        f"[dim]Matched: {finding.get('matched','')[:80]}[/dim]",
                        title="[bold red]⚠ Nuclei Finding[/bold red]",
                        border_style="red" if finding["severity"]=="critical" else "yellow",
                        box=box.ROUNDED,
                    ))

    elif tool_name == "onesixtyone":
        communities = parsed.get("communities",[])
        if communities:
            console.print(Panel(
                f"[bold red]SNMP Community Strings Found![/bold red]\n\n"
                f"Found [bold]{len(communities)}[/bold] accessible community strings.\n\n"
                + "\n".join(f"  [{c.get('community','')}] {c.get('info','')[:60]}"
                            for c in communities[:5]),
                title="[bold yellow]⚠ SNMP Exposed[/bold yellow]",
                border_style="yellow",
                box=box.ROUNDED,
            ))

    elif tool_name == "sqlmap" and parsed.get("vulnerable"):
        console.print(Panel(
            "[bold red]SQL Injection Confirmed![/bold red]\n\n"
            "The target is vulnerable to SQL injection.\n"
            f"DBMS: [cyan]{parsed.get('dbms','Unknown')}[/cyan]\n"
            f"Injectable parameters: [yellow]{', '.join(parsed.get('parameters',[]))}[/yellow]",
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
                lines.append(f"Host: {host.get('ip','')} OS: {host.get('os','')}")
                for p in host.get("ports", []):
                    if p.get("state") == "open":
                        lines.append(f"  PORT {p['port']}/{p.get('proto','')} {p.get('service','')} {p.get('version','')}")
        elif tool_name == "nikto":
            lines.append(f"Server: {parsed.get('server','')} Findings: {parsed.get('total',0)}")
            for f in parsed.get("findings",[])[:15]:
                lines.append(f"  FINDING: {f[:120]}")
        elif tool_name == "sqlmap":
            lines.append(f"Vulnerable: {parsed.get('vulnerable',False)} DBMS: {parsed.get('dbms','')}")
            lines.append(f"Params: {', '.join(parsed.get('parameters',[]))}")
            lines.append(f"Databases: {', '.join(parsed.get('databases',[]))}")
        elif tool_name == "ffuf":
            findings = parsed.get("findings",[])
            lines.append(f"Paths found: {len(findings)}")
            for f in findings[:20]:
                lines.append(f"  PATH: {f.get('path','')} [{f.get('status','')}]")
        elif tool_name == "gobuster":
            paths = parsed.get("paths",[])
            lines.append(f"Paths found: {len(paths)}")
            for p in paths[:20]:
                lines.append(f"  PATH: {p}")
        elif tool_name == "enum4linux":
            users  = parsed.get("users",[])
            shares = parsed.get("shares",[])
            lines.append(f"OS: {parsed.get('os','')} Domain: {parsed.get('domain','')}")
            lines.append(f"Users: {len(users)} Shares: {len(shares)}")
            for u in users[:10]:
                lines.append(f"  USER: {u.get('username','')} RID:{u.get('rid','')}")
            for s in shares[:10]:
                lines.append(f"  SHARE: {s.get('name','')} ({s.get('type','')})")
        elif tool_name == "wpscan":
            lines.append(f"WP: {parsed.get('wp_version','')} Vulns: {parsed.get('total_vulns',0)}")
            lines.append(f"Users: {', '.join(parsed.get('users',[]))}")
            for v in parsed.get("vulnerabilities",[])[:10]:
                lines.append(f"  VULN: {v[:100]}")
        elif tool_name == "nuclei":
            lines.append(f"Critical: {parsed.get('critical',0)} High: {parsed.get('high',0)} Medium: {parsed.get('medium',0)}")
            for f in parsed.get("findings",[])[:15]:
                lines.append(f"  [{f.get('severity','').upper()}] {f.get('name','')} → {f.get('matched','')[:80]}")
        elif tool_name == "sslscan":
            lines.append(f"Issues: {len(parsed.get('issues',[]))} WeakProtos: {', '.join(parsed.get('weak_protocols',[]))}")
            for i in parsed.get("issues",[]):
                lines.append(f"  ISSUE: {i}")
        elif tool_name == "whatweb":
            techs = parsed.get("technologies", [])
            versions = parsed.get("versions", [])
            tech_dict = {}
            for v in versions:
                tech_name = v.get('tech', '')
                version = v.get('version', '')
                if tech_name:
                    tech_dict[tech_name] = version
            for tech in techs:
                if tech not in tech_dict:
                    tech_dict[tech] = ''
            if tech_dict:
                lines.append(f"Technologies detected: {len(tech_dict)}")
                for tech, version in list(tech_dict.items())[:15]:
                    if version:
                        lines.append(f"  {tech} {version}")
                    else:
                        lines.append(f"  {tech}")
            else:
                lines.append(f"Raw output: {parsed.get('raw', '')[:200]}")
        elif tool_name == "wafw00f":
            lines.append(f"WAF: {parsed.get('detected',False)} Names: {', '.join(parsed.get('waf_names',[]))}")
        elif tool_name == "dnsrecon":
            lines.append(f"Subdomains: {parsed.get('total_subdomains',0)} ZoneTransfer: {parsed.get('zone_transfer_possible',False)}")
            for s in parsed.get("subdomains",[])[:10]:
                lines.append(f"  SUB: {s.get('subdomain','')} → {s.get('ip','')}")
        elif tool_name == "privesc":
            lines.append(f"Critical: {parsed.get('critical',0)} High: {parsed.get('high',0)}")
            for j in parsed.get("juicy_points",[])[:10]:
                lines.append(f"  [{j.get('severity','').upper()}] {j.get('category','')}: {j.get('title','')} → {j.get('path','')}")
        elif tool_name == "hashcat":
            cracked = parsed.get("cracked",[])
            lines.append(f"Cracked: {len(cracked)}")
            for c in cracked[:10]:
                lines.append(f"  CRACKED: {c.get('hash','')} = {c.get('plaintext','')}")
        elif tool_name == "smbclient":
            shares = parsed.get("shares",[])
            files  = parsed.get("files",[])
            lines.append(f"Shares found: {len(shares)}")
            for s in shares[:10]:
                lines.append(f"  SHARE: {s}")
            if files:
                lines.append(f"Files found: {len(files)}")
                for f in files[:10]:
                    lines.append(f"  FILE: {f}")
        elif tool_name == "dnsenum":
            subs = parsed.get("subdomains",[])
            lines.append(f"Subdomains: {len(subs)}")
            for s in subs[:10]:
                lines.append(f"  SUB: {s.get('subdomain','')} -> {s.get('ip','')}")
        elif tool_name == "curl":
            headers = parsed.get("headers",{})
            tech = parsed.get("tech",[])
            lines.append(f"Tech: {', '.join(tech)}")
            for k,v in list(headers.items())[:10]:
                lines.append(f"  {k}: {v}")
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
                    candidate = text[start:i+1]
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
