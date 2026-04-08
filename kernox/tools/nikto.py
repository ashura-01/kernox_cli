"""
kernox.tools.nikto  –  AI-powered nikto wrapper with dynamic tuning.
"""

from __future__ import annotations

import json
import re
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich import box
from rich.table import Table
from rich.panel import Panel
from rich.spinner import Spinner
from rich.live import Live

from kernox.parsers.nikto_parser import NiktoParser
from kernox.utils.url_helper import preserve_url, get_base_url

console = Console()

TUNING_OPTIONS = {
    "0": "File Upload",
    "1": "Interesting File / Seen in logs",
    "2": "Misconfiguration / Default File",
    "3": "Information Disclosure",
    "4": "Injection (XSS/Script/HTML)",
    "5": "Remote File Retrieval - Inside Web Root",
    "6": "Denial of Service",
    "7": "Remote File Retrieval - Server Wide",
    "8": "Command Execution / Remote Shell",
    "9": "SQL Injection",
    "a": "Authentication Bypass",
    "b": "Software Identification",
    "c": "Remote Source Inclusion",
    "x": "Reverse Tuning (exclude)",
}


class NiktoTool:
    name = "nikto"

    def __init__(self, ai_client=None):
        """Initialize with optional AI client for strategy planning."""
        self._ai_client = ai_client
        self._strategy_cache = {}

    def build_command(
        self,
        target: str,
        flags: str = "",
        mode: str = "",
        context: dict = None,
        **kwargs,
    ) -> str:
        """Build nikto command with AI-driven strategy."""
        if not target.startswith("http"):
            target = f"http://{target}"

        # ── SMART TARGET DETECTION ─────────────────────────────────────────
        # Check if target is old/slow (like Metasploitable)
        is_slow_target = False
        slow_reason = ""
        
        if context:
            server = context.get("headers", {}).get("server", "").lower()
            techs = [t.lower() for t in context.get("technologies", [])]
            open_ports = context.get("open_ports", [])
            
            # Signs of a vintage/slow target
            if "apache/2.2" in server:
                is_slow_target = True
                slow_reason = "Apache 2.2.x is slow and outdated"
            elif "apache/1.3" in server:
                is_slow_target = True
                slow_reason = "Apache 1.3.x is extremely slow"
            
            if "php/5.2" in str(techs) or "php/5.3" in str(techs):
                is_slow_target = True
                slow_reason += " + PHP 5.2/5.3 (slow processing)"
            
            if "ubuntu 8.04" in str(context) or "debian 4" in str(context):
                is_slow_target = True
                slow_reason += " + Vintage OS (Ubuntu 8.04/Debian 4)"
            
            # If bindshell or backdoor already found, skip nikto entirely
            if 1524 in open_ports:
                console.print(Panel(
                    "[bold red]⚠ Bindshell detected on port 1524[/bold red]\n"
                    "This gives immediate root access. Nikto web scan is unnecessary.\n\n"
                    "[bold]Recommended:[/bold] nc 192.168.0.209 1524",
                    title="🎯 Higher Priority Finding",
                    border_style="red"
                ))
                return ""  # Skip nikto entirely

        if is_slow_target:
            console.print(Panel(
                f"[bold yellow]⚠ Slow target detected[/bold yellow]\n"
                f"Reason: {slow_reason}\n\n"
                "Nikto scans on vintage systems can take 1-2 hours or more.\n\n"
                "[bold]Recommended alternatives:[/bold]\n"
                "  • whatweb - quick technology detection (seconds)\n"
                "  • nuclei - faster CVE scanning with -tags tech\n"
                "  • manual checks - known vulnerabilities for this stack\n\n"
                "[bold]Continue nikto anyway?[/bold]",
                title="⏱ Performance Warning",
                border_style="yellow"
            ))
            if not Confirm.ask("Run nikto despite timeout risk?", default=False):
                console.print("[yellow]⏭ Skipping nikto - use 'whatweb' or 'nuclei' instead[/yellow]")
                return ""

        # If flags provided directly, use them (manual override)
        if flags:
            return f"nikto -h {target} {flags} -output /tmp/kernox_nikto.txt -Format txt"

        # If AI client available, let AI decide the strategy
        if self._ai_client and not mode:
            strategy = self._ai_decide_strategy(target, context or {})
            
            # Check if AI decided to skip
            if strategy.get("skip"):
                console.print(f"[yellow]⏭ {strategy.get('reason', 'Skipping nikto')}[/yellow]")
                return ""
            
            console.print(Panel(
                f"[bold cyan]AI Strategy:[/bold cyan] {strategy.get('analysis', '')}\n\n"
                f"[bold]Command:[/bold] [yellow]{strategy.get('command', '')}[/yellow]\n"
                f"[bold]Tuning codes:[/bold] {strategy.get('tuning', 'default')}\n"
                f"[bold]Reason:[/bold] {strategy.get('reason', '')}",
                title="🧠 AI Nikto Strategy",
                border_style="cyan",
                box=box.ROUNDED
            ))
            
            if Confirm.ask("\nUse this AI-recommended scan?", default=True):
                return strategy.get("command", f"nikto -h {target} -output /tmp/kernox_nikto.txt")
            mode = self._pick_mode()

        # Fallback to interactive mode selection
        mode = mode or self._pick_mode()
        return self._build_from_mode(mode, target)

    def _ai_decide_strategy(self, target: str, context: dict) -> dict:
        """Let AI decide optimal nikto strategy based on target and previous findings."""
        
        # Build context from previous scans
        context_str = ""
        techs = []
        if context:
            techs = context.get("technologies", [])
            ports = context.get("open_ports", [])
            headers = context.get("headers", {})
            
            context_str = f"""
Previous findings on {target}:
- Technologies detected: {', '.join(techs) if techs else 'Unknown'}
- Open ports: {ports if ports else 'Unknown'}
- Server headers: {headers.get('server', 'Unknown')}
- Powered by: {headers.get('x-powered-by', 'Unknown')}
"""

        # Check for vintage tech that makes nikto impractical
        vintage_indicators = ["apache/2.2", "php/5.2", "ubuntu 8.04", "debian 4", "apache/1.3"]
        is_vintage = any(ind in str(context).lower() for ind in vintage_indicators)
        
        if is_vintage:
            return {
                "analysis": "Target uses vintage software that will cause nikto to run extremely slowly (1-2+ hours)",
                "command": "",
                "tuning": "",
                "reason": "Target too slow for nikto - use whatweb or nuclei instead",
                "estimated_time": "impossible",
                "skip": True
            }

        # Check if there are higher priority findings
        if 1524 in context.get("open_ports", []):
            return {
                "analysis": "Bindshell on port 1524 is a higher priority finding",
                "command": "",
                "tuning": "",
                "reason": "Use nc to get immediate root shell instead of scanning web",
                "estimated_time": "instant",
                "skip": True
            }

        prompt = f"""You are a senior penetration tester planning a nikto scan.

Target: {target}
{context_str}

Based on the target and any previous findings, recommend the OPTIMAL nikto scan strategy.

Consider:
1. If the target is WordPress/Joomla/Drupal → use specific tuning
2. If SSL/HTTPS detected → include SSL checks
3. If previous scan showed login pages → include auth bypass checks
4. If SQLi suspected → include SQL injection checks
5. If time is limited → use quick scan with high-priority checks

Choose appropriate tuning codes from:
0=File Upload, 1=Interesting Files, 2=Misconfiguration, 3=Info Disclosure,
4=Injection (XSS), 5=Remote File Retrieval, 6=DoS, 7=Remote File Retrieval (Server),
8=Command Execution, 9=SQL Injection, a=Auth Bypass, b=Software ID, c=Remote Source Include

Respond with a JSON object (no other text):
{{
    "analysis": "Brief 1-2 sentence explanation of your strategy",
    "command": "full nikto command with -maxtime to prevent hanging",
    "tuning": "tuning codes (e.g., '1234' or '9a' or 'x4')",
    "reason": "Why this tuning is optimal for this target",
    "estimated_time": "fast/medium/slow"
}}

IMPORTANT: Always include -maxtime 300 to prevent infinite hangs.
Example: "command": "nikto -h {target} -Tuning 123b -maxtime 300 -output /tmp/kernox_nikto.txt"

Example responses:
- WordPress: {{"analysis": "WordPress detected, focusing on plugin enumeration", "command": "nikto -h {target} -Tuning 123b -maxtime 300 -output /tmp/kernox_nikto.txt", "tuning": "123b", "reason": "WordPress needs file enumeration", "estimated_time": "medium"}}
- SQLi suspected: {{"analysis": "SQL injection suspected", "command": "nikto -h {target} -Tuning 9 -maxtime 120 -output /tmp/kernox_nikto.txt", "tuning": "9", "reason": "Focus only on SQL injection", "estimated_time": "fast"}}
- Full scan: {{"analysis": "New target, comprehensive scan with timeout", "command": "nikto -h {target} -maxtime 300 -output /tmp/kernox_nikto.txt", "tuning": "", "reason": "No prior info, run all checks with timeout", "estimated_time": "slow"}}
"""

        try:
            with Live(Spinner("dots", text="[dim]AI planning optimal nikto strategy...[/dim]"), refresh_per_second=10):
                response = self._ai_client.chat(
                    messages=[{"role": "user", "content": prompt}],
                    system="You are a penetration testing expert. Return ONLY valid JSON.",
                    max_tokens=400,
                    temperature=0.2
                )
            
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                strategy = json.loads(json_match.group())
                self._strategy_cache[target] = strategy
                return strategy
        except Exception as e:
            console.print(f"[dim]AI strategy failed: {e}, using fallback[/dim]")
        
        # Fallback to default with timeout
        return {
            "analysis": "Default comprehensive scan with 5-minute timeout",
            "command": f"nikto -h {target} -maxtime 300 -output /tmp/kernox_nikto.txt",
            "tuning": "",
            "reason": "No prior information about target",
            "estimated_time": "slow"
        }

    def _pick_mode(self) -> str:
        """Interactive mode selection."""
        console.print("\n[bold cyan]Nikto Scan Mode[/bold cyan]\n")
        table = Table(show_header=True, header_style="bold magenta",
                      box=box.SIMPLE_HEAVY, border_style="dim")
        table.add_column("#", width=4, style="bold cyan")
        table.add_column("Mode", style="bold")
        table.add_column("Description")

        modes = [
            ("1", "ai",       "Let AI decide optimal strategy"),
            ("2", "full",     "Full scan — all checks"),
            ("3", "tuned",    "Pick specific check categories"),
            ("4", "sqli",     "SQL injection checks only"),
            ("5", "auth",     "Authentication bypass checks only"),
            ("6", "ssl",      "SSL/TLS checks"),
            ("7", "quick",    "Quick scan — fast, fewer checks"),
            ("8", "custom",   "Custom flags"),
        ]
        for row in modes:
            table.add_row(*row)
        console.print(table)

        choice = Prompt.ask("Select mode", 
                           choices=[str(i) for i in range(1, len(modes)+1)], 
                           default="1")
        mode_map = {"1": "ai", "2": "full", "3": "tuned", "4": "sqli",
                    "5": "auth", "6": "ssl", "7": "quick", "8": "custom"}
        return mode_map[choice]

    def _build_from_mode(self, mode: str, target: str) -> str:
        """Build command from selected mode."""
        port = Prompt.ask("Target port (blank=default)", default="")
        port_flag = f"-p {port}" if port else ""
        out = "-output /tmp/kernox_nikto.txt -Format txt"

        if mode == "ai":
            if self._ai_client:
                strategy = self._ai_decide_strategy(target, {})
                if strategy.get("skip"):
                    return ""
                return strategy.get("command", f"nikto -h {target} -maxtime 300 {out}")
            return f"nikto -h {target} -maxtime 300 {out}"

        elif mode == "full":
            return f"nikto -h {target} {port_flag} -maxtime 300 {out}"

        elif mode == "tuned":
            self._show_tuning_options()
            tuning = Prompt.ask("Tuning codes (e.g., 1234 or 9a)", default="1234")
            return f"nikto -h {target} {port_flag} -Tuning {tuning} -maxtime 300 {out}"

        elif mode == "sqli":
            return f"nikto -h {target} {port_flag} -Tuning 9 -maxtime 120 {out}"

        elif mode == "auth":
            return f"nikto -h {target} {port_flag} -Tuning a -maxtime 120 {out}"

        elif mode == "ssl":
            return f"nikto -h {target} {port_flag} -ssl -maxtime 300 {out}"

        elif mode == "quick":
            return f"nikto -h {target} {port_flag} -Tuning 123b -maxtime 120 {out}"

        elif mode == "custom":
            flags = Prompt.ask("Custom nikto flags")
            return f"nikto -h {target} {flags} {out}"

        return f"nikto -h {target} -maxtime 300 {out}"

    def _show_tuning_options(self) -> None:
        """Show tuning options table."""
        console.print("\n[bold cyan]Tuning Options:[/bold cyan]")
        for code, desc in TUNING_OPTIONS.items():
            console.print(f"  [green]{code}[/green] – {desc}")
        console.print()

    def parse(self, output: str) -> dict:
        """Parse nikto output."""
        return NiktoParser().parse(output)