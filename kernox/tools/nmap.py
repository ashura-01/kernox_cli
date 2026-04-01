"""
kernox.tools.nmap  –  AI-powered Nmap wrapper with dynamic strategy.
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

from kernox.parsers.nmap_parser import NmapParser
from kernox.utils.url_helper import get_domain

console = Console()


class NmapTool:
    name = "nmap"

    def __init__(self, ai_client=None):
        """Initialize with optional AI client for strategy planning."""
        self._ai_client = ai_client
        self._strategy_cache = {}

    def build_command(self, **kwargs) -> str:
        """Build nmap command with AI-driven strategy."""
        target = kwargs.get("target", "")
        flags = kwargs.get("flags", "")
        mode = kwargs.get("mode", "")
        ports = kwargs.get("ports", "")
        scripts = kwargs.get("scripts", "")
        context = kwargs.get("context", {})  # Previous scan results

        # Extract domain/IP from URL if needed
        if target.startswith("http"):
            target = get_domain(target)

        # If flags provided directly, use them (manual override)
        if flags:
            cmd = f"nmap {flags} {target}"
            if ports:
                cmd += f" -p {ports}"
            return cmd

        # If AI client available and mode not forced, let AI decide
        if self._ai_client and not mode:
            strategy = self._ai_decide_strategy(target, context, mode)
            console.print(Panel(
                f"[bold cyan]AI Strategy:[/bold cyan] {strategy.get('analysis', '')}\n\n"
                f"[bold]Command:[/bold] [yellow]{strategy.get('command', '')}[/yellow]\n"
                f"[bold]Reason:[/bold] {strategy.get('reason', '')}",
                title="🧠 AI Nmap Strategy",
                border_style="cyan",
                box=box.ROUNDED
            ))

            if Confirm.ask("\nUse this AI-recommended scan?", default=True):
                return strategy.get("command", "")
            # Fall back to interactive mode if user declines
            mode = self._pick_mode()

        # Interactive mode selection (fallback)
        mode = mode or self._pick_mode()
        return self._build_from_mode(mode, target, ports, scripts)

    def _ai_decide_strategy(self, target: str, context: dict, hint_mode: str = "") -> dict:
        """Let AI decide the optimal nmap strategy based on target and context."""

        # Build context from previous scans if available
        context_str = ""
        if context:
            context_str = f"""
Previous findings on {target}:
- Open ports: {context.get('open_ports', [])}
- Services: {context.get('services', [])}
- OS guess: {context.get('os', 'Unknown')}
- Known vulnerabilities: {context.get('vulns', [])}
"""

        # Build AI prompt for nmap strategy
        prompt = f"""You are a senior penetration tester planning an nmap scan.

Target: {target}
{context_str}
User intent: {hint_mode if hint_mode else "Comprehensive reconnaissance"}

Based on the target and any previous findings, recommend the OPTIMAL nmap scan strategy.

Consider:
1. Target type (public web server, internal network, single host, etc.)
2. If it's a web server (ports 80/443 open), prioritize web-relevant scans
3. If previous scan showed open ports, target those specifically
4. Firewall evasion if needed
5. Speed vs thoroughness balance
6. Appropriate NSE scripts based on detected services

Respond with a JSON object (no other text):
{{
    "analysis": "Brief 1-2 sentence explanation of your strategy",
    "command": "full nmap command with all flags",
    "reason": "Why this is optimal for this target",
    "estimated_time": "estimated scan time (fast/medium/slow)",
    "detection_risk": "low/medium/high"
}}

Example responses:
- Web server: {{"analysis": "Web server detected, focusing on web-related services", "command": "nmap -sV -p 80,443,8080,8443 --script=http-enum,http-headers,http-title -T4 {target}", "reason": "Quick scan of web ports with enumeration scripts", "estimated_time": "fast", "detection_risk": "low"}}
- Internal network: {{"analysis": "Internal host, comprehensive scan", "command": "nmap -sS -sV -O -T4 --open -p- {target}", "reason": "Full port scan with OS detection for internal host", "estimated_time": "slow", "detection_risk": "medium"}}
- Firewall suspected: {{"analysis": "Firewall likely present, using evasion techniques", "command": "nmap -f -D RND:10 --mtu 24 -T2 -sS -p- {target}", "reason": "Fragmentation, decoys, and stealth scan to bypass firewall", "estimated_time": "medium", "detection_risk": "low"}}
"""

        try:
            with Live(Spinner("dots", text="[dim]AI planning optimal nmap strategy...[/dim]"), refresh_per_second=10):
                response = self._ai_client.chat(
                    messages=[{"role": "user", "content": prompt}],
                    system="You are an expert penetration tester. Return ONLY valid JSON.",
                    max_tokens=400,
                    temperature=0.2
                )

            # Extract JSON from response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                strategy = json.loads(json_match.group())
                # Cache the strategy for this target
                self._strategy_cache[target] = strategy
                return strategy
        except Exception as e:
            console.print(f"[dim]AI strategy failed: {e}, using fallback[/dim]")

        # Fallback to default strategy
        return {
            "analysis": "Default comprehensive scan",
            "command": f"nmap -sV -T4 --open {target} -oN /tmp/kernox_nmap.txt",
            "reason": "Standard service version scan",
            "estimated_time": "medium",
            "detection_risk": "medium"
        }

    def _pick_mode(self) -> str:
        """Interactive mode selection with AI recommendations."""
        console.print("\n[bold cyan]Nmap Scan Mode[/bold cyan]\n")
        table = Table(show_header=True, header_style="bold magenta",
                      box=box.SIMPLE_HEAVY, border_style="dim")
        table.add_column("#", width=4, style="bold cyan")
        table.add_column("Mode", style="bold")
        table.add_column("Description")
        table.add_column("Speed", width=8)

        modes = [
            ("1", "quick",      "Top 1000 ports, no scripts",           "Fast"),
            ("2", "service",    "Service & version detection",           "Med"),
            ("3", "aggressive", "Full -A (OS+version+scripts+traceroute)","Slow"),
            ("4", "vuln",       "NSE vulnerability scripts",             "Slow"),
            ("5", "full",       "All 65535 ports",                       "Slow"),
            ("6", "stealth",    "SYN stealth scan (needs root)",         "Fast"),
            ("7", "udp",        "UDP scan top 200",                      "Slow"),
            ("8", "firewall",   "Firewall evasion (fragments+decoys)",   "Med"),
            ("9", "script",     "Pick specific NSE script category",     "Med"),
            ("10", "ai",        "Let AI decide optimal strategy",        "Adaptive"),
            ("11", "custom",    "Enter custom flags manually",           "N/A"),
        ]

        for row in modes:
            table.add_row(*row)

        console.print(table)
        choice = Prompt.ask("Select mode",
                           choices=[str(i) for i in range(1, len(modes)+1)],
                           default="2")

        mode_map = {
            "1": "quick", "2": "service", "3": "aggressive", "4": "vuln",
            "5": "full", "6": "stealth", "7": "udp", "8": "firewall",
            "9": "script", "10": "ai", "11": "custom"
        }
        return mode_map[choice]

    def _build_from_mode(self, mode: str, target: str, ports: str, scripts: str) -> str:
        out = "-oN /tmp/kernox_nmap.txt"

        if mode == "quick":
            return f"nmap -T4 --open {target} {out}"

        elif mode == "service":
            p = ports or Prompt.ask("Ports (blank=top1000)", default="")
            pflag = f"-p {p}" if p else ""
            return f"nmap -sV -T4 --open {pflag} {target} {out}"

        elif mode == "aggressive":
            return f"nmap -A -T4 --open {target} {out}"

        elif mode == "vuln":
            return f"nmap -sV --script=vuln -T4 {target} {out}"

        elif mode == "full":
            console.print("[yellow]⚠ Full scan may take 10-30 minutes[/yellow]")
            return f"nmap -sV -p- -T4 --open {target} {out}"

        elif mode == "stealth":
            console.print("[dim]Stealth scan needs root/sudo[/dim]")
            return f"nmap -sS -T2 --open {target} {out}"

        elif mode == "udp":
            console.print("[yellow]UDP scan is slow (15+ min)[/yellow]")
            return f"nmap -sU --top-ports 200 -T4 {target} {out}"

        elif mode == "firewall":
            return self._build_firewall_evasion(target, ports)

        elif mode == "script":
            if not scripts:
                scripts = self._pick_nse_scripts()
            port_flag = f"-p {ports}" if ports else ""
            return f"nmap -sV --script={scripts} -T4 {port_flag} {target} {out}"

        elif mode == "ai":
            # AI mode - let AI decide
            if self._ai_client:
                strategy = self._ai_decide_strategy(target, {})
                return strategy.get("command", f"nmap -sV -T4 {target} {out}")
            return f"nmap -sV -T4 {target} {out}"

        elif mode == "custom":
            flags = Prompt.ask("Custom nmap flags")
            return f"nmap {flags} {target} {out}"

        return f"nmap -sV -T4 {target} {out}"

    def _build_firewall_evasion(self, target: str, ports: str) -> str:
        """Build nmap command with multiple firewall evasion techniques."""
        console.print("\n[bold cyan]Firewall Evasion Options:[/bold cyan]")
        console.print("  1. [yellow]Basic[/yellow] - Fragmentation only")
        console.print("  2. [yellow]Decoys[/yellow] - Use decoy IPs")
        console.print("  3. [yellow]MTU[/yellow] - Custom MTU size")
        console.print("  4. [yellow]Full[/yellow] - All techniques combined")
        console.print("  5. [yellow]Custom[/yellow] - Manual flags")

        choice = Prompt.ask("Select evasion level", choices=["1","2","3","4","5"], default="4")

        evasion_flags = {
            "1": "-f -sS -T2",
            "2": "-D RND:10 -sS -T2",
            "3": "--mtu 24 -sS -T2",
            "4": "-f -D RND:10 --mtu 24 -sS -T2",
        }

        flags = evasion_flags.get(choice, Prompt.ask("Custom evasion flags"))

        cmd = f"nmap {flags} --open"
        if ports:
            cmd += f" -p {ports}"
        cmd += f" {target} -oN /tmp/kernox_nmap.txt"

        return cmd

    def _pick_nse_scripts(self) -> str:
        """Interactive NSE script selection."""
        console.print("\n[bold cyan]NSE Script Category[/bold cyan]")
        cats = ["http", "smb", "ftp", "ssh", "vuln", "brute", "discovery", "custom"]

        for i, c in enumerate(cats, 1):
            console.print(f"  [green]{i}[/green] – {c}")

        choice = Prompt.ask("Select",
                           choices=[str(i) for i in range(1, len(cats)+1)],
                           default="1")
        idx = int(choice) - 1
        category = cats[idx]

        if category == "custom":
            return Prompt.ask("Script name(s) comma-separated")

        # Return category-based scripts
        category_map = {
            "http": "http-enum,http-headers,http-title,http-methods,http-auth-finder",
            "smb": "smb-vuln-ms17-010,smb-enum-shares,smb-enum-users,smb-os-discovery",
            "ftp": "ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor",
            "ssh": "ssh-auth-methods,ssh-hostkey,ssh2-enum-algos",
            "vuln": "vuln",
            "brute": "http-brute,ftp-brute,ssh-brute,smtp-brute",
            "discovery": "smb-enum-shares,dns-brute,snmp-brute"
        }

        scripts = category_map.get(category, "default")
        console.print(f"[dim]Selected: {scripts}[/dim]")

        port = Prompt.ask("Port(s) for script (blank=all)", default="")
        if port:
            return f"-p {port} --script={scripts}"
        return f"--script={scripts}"

    def parse(self, output: str) -> dict:
        """Parse nmap output."""
        return NmapParser().parse(output)
