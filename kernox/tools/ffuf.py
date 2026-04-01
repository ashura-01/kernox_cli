"""
kernox.tools.ffuf  –  AI-powered ffuf wrapper with dynamic strategy.
Supports directory fuzzing, vhost discovery, parameter fuzzing, and POST fuzzing.
Handles subdomains and complex target patterns intelligently.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich import box
from rich.table import Table
from rich.panel import Panel
from rich.spinner import Spinner
from rich.live import Live

from kernox.parsers.ffuf_parser import FfufParser
from kernox.utils.wordlist import pick_wordlist
from kernox.utils.url_helper import preserve_url, get_base_url, get_domain

console = Console()


class FfufTool:
    name = "ffuf"

    def __init__(self, ai_client=None):
        """Initialize with optional AI client for strategy planning."""
        self._ai_client = ai_client
        self._strategy_cache = {}

    def build_command(
        self,
        target: str,
        wordlist: str = "",
        mode: str = "",
        flags: str = "",
        extensions: str = "",
        context: dict = None,
        **kwargs,
    ) -> str:
        """Build ffuf command with AI-driven strategy."""
        # Handle direct flags
        if flags and not mode:
            return f"ffuf {flags}"

        # If AI client available and mode not forced, let AI decide
        if self._ai_client and not mode:
            strategy = self._ai_decide_strategy(target, context or {}, mode)
            console.print(Panel(
                f"[bold cyan]AI Strategy:[/bold cyan] {strategy.get('analysis', '')}\n\n"
                f"[bold]Command:[/bold] [yellow]{strategy.get('command', '')}[/yellow]\n"
                f"[bold]Wordlist:[/bold] {strategy.get('wordlist', '')}\n"
                f"[bold]Extensions:[/bold] {strategy.get('extensions', 'none')}\n"
                f"[bold]Filters:[/bold] {strategy.get('filters', 'auto')}",
                title="🧠 AI ffuf Strategy",
                border_style="cyan",
                box=box.ROUNDED
            ))

            if Confirm.ask("\nUse this AI-recommended fuzzing strategy?", default=True):
                return strategy.get("command", "")
            mode = self._pick_mode()

        # Interactive mode selection (fallback)
        mode = mode or self._pick_mode()
        return self._build_from_mode(mode, target, wordlist, extensions, context)

    def _ai_decide_strategy(self, target: str, context: dict, hint_mode: str = "") -> dict:
        """Let AI decide optimal ffuf strategy based on target and context."""
        
        # Parse target
        parsed = urlparse(target if target.startswith('http') else f"http://{target}")
        hostname = parsed.hostname or target
        is_subdomain = len(hostname.split('.')) > 2
        
        # Build context string
        techs = context.get("technologies", [])
        server = context.get("server", "")
        has_login = context.get("has_login_page", False)
        
        tech_str = f"Technologies detected: {', '.join(techs) if techs else 'Unknown'}"
        server_str = f"Server: {server}" if server else ""
        subdomain_str = f"Target is a subdomain: {hostname}" if is_subdomain else ""
        
        # Detect likely mode from target
        suggested_mode = "dir"
        if is_subdomain and any(kw in hint_mode for kw in ["vhost", "virtual", "host"]):
            suggested_mode = "vhost"
        elif "param" in hint_mode.lower():
            suggested_mode = "param"
        elif "post" in hint_mode.lower():
            suggested_mode = "post"
        
        prompt = f"""You are a penetration tester planning a web fuzzing scan.

Target: {target}
Hostname: {hostname}
{tech_str}
{server_str}
{subdomain_str}
Has login page detected: {has_login}
Suggested mode: {suggested_mode}

Based on this information, recommend the OPTIMAL ffuf configuration.

Choose:
1. Mode (dir, vhost, param, post)
2. Wordlist path (from common locations)
3. File extensions to try (if directory fuzzing)
4. Filters to reduce false positives

Common wordlist locations:
- /usr/share/wordlists/dirb/common.txt (small, fast)
- /usr/share/wordlists/dirb/big.txt (medium)
- /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt (good for depth)
- /usr/share/seclists/Discovery/Web-Content/common.txt (comprehensive)
- /usr/share/seclists/Discovery/Web-Content/subdomains-top1million-5000.txt (for vhost)

Respond with a JSON object (no other text):
{{
    "analysis": "Brief 1-2 sentence explanation",
    "command": "full ffuf command",
    "mode": "dir/vhost/param/post",
    "wordlist": "path to wordlist",
    "extensions": "extensions to try (comma-separated, or 'none')",
    "filters": "filter flags (e.g., -fc 404,403)",
    "estimated_time": "fast/medium/slow"
}}

Example responses:
- PHP app: {{"analysis": "PHP application detected, common PHP extensions", "command": "ffuf -u http://target/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .php,.html -fc 404,403 -t 50 -c", "mode": "dir", "wordlist": "/usr/share/wordlists/dirb/common.txt", "extensions": ".php,.html", "filters": "-fc 404,403", "estimated_time": "fast"}}
- Subdomain vhost: {{"analysis": "Subdomain target, discovering other vhosts", "command": "ffuf -u http://target -w /usr/share/seclists/Discovery/Web-Content/subdomains-top1million-5000.txt -H 'Host: FUZZ.{hostname}' -fc 404 -t 40 -c", "mode": "vhost", "wordlist": "/usr/share/seclists/Discovery/Web-Content/subdomains-top1million-5000.txt", "extensions": "none", "filters": "-fc 404", "estimated_time": "medium"}}
"""

        try:
            with Live(Spinner("dots", text="[dim]AI planning optimal ffuf strategy...[/dim]"), refresh_per_second=10):
                response = self._ai_client.chat(
                    messages=[{"role": "user", "content": prompt}],
                    system="You are a penetration testing expert. Return ONLY valid JSON.",
                    max_tokens=500,
                    temperature=0.2
                )

            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                strategy = json.loads(json_match.group())
                self._strategy_cache[target] = strategy
                return strategy
        except Exception as e:
            console.print(f"[dim]AI strategy failed: {e}, using fallback[/dim]")

        # Fallback based on target type
        if is_subdomain:
            return {
                "analysis": "Subdomain target, vhost discovery recommended",
                "command": f"ffuf -u http://{hostname} -w /usr/share/seclists/Discovery/Web-Content/subdomains-top1million-5000.txt -H 'Host: FUZZ.{hostname}' -fc 404 -t 40 -c -o /tmp/kernox_ffuf.json -of json",
                "mode": "vhost",
                "wordlist": "/usr/share/seclists/Discovery/Web-Content/subdomains-top1million-5000.txt",
                "extensions": "none",
                "filters": "-fc 404",
                "estimated_time": "medium"
            }
        else:
            return {
                "analysis": "Default directory fuzzing",
                "command": f"ffuf -u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -fc 404 -t 50 -c -o /tmp/kernox_ffuf.json -of json",
                "mode": "dir",
                "wordlist": "/usr/share/wordlists/dirb/common.txt",
                "extensions": "none",
                "filters": "-fc 404",
                "estimated_time": "fast"
            }

    def _pick_mode(self) -> str:
        """Interactive mode selection."""
        console.print("\n[bold cyan]ffuf Mode[/bold cyan]\n")
        table = Table(show_header=True, header_style="bold magenta",
                      box=box.SIMPLE_HEAVY, border_style="dim")
        table.add_column("#", width=4, style="bold cyan")
        table.add_column("Mode", style="bold")
        table.add_column("Description")

        modes = [
            ("1", "dir",    "Directory & file fuzzing (FUZZ in path)"),
            ("2", "vhost",  "Virtual host discovery (Host header fuzzing)"),
            ("3", "param",  "GET parameter fuzzing (?FUZZ=value)"),
            ("4", "post",   "POST parameter fuzzing"),
            ("5", "ai",     "Let AI decide optimal strategy"),
            ("6", "custom", "Enter custom ffuf flags manually"),
        ]
        for row in modes:
            table.add_row(*row)
        console.print(table)

        choice = Prompt.ask("Select mode", choices=["1","2","3","4","5","6"], default="1")
        mode_map = {"1":"dir","2":"vhost","3":"param","4":"post","5":"ai","6":"custom"}
        return mode_map[choice]

    def _build_from_mode(self, mode: str, target: str, wordlist: str, extensions: str, context: dict = None) -> str:
        """Build command from selected mode."""
        filters = self._pick_filters(mode)

        if mode == "dir":
            base = preserve_url(target)
            url = base if "FUZZ" in base else f"{base.rstrip('/')}/FUZZ"
            
            # Smart extensions based on context
            if not extensions and context:
                techs = context.get("technologies", [])
                tech_str = " ".join(techs).lower()
                if "php" in tech_str:
                    extensions = ".php,.html"
                elif "asp" in tech_str or "aspx" in tech_str:
                    extensions = ".asp,.aspx"
                elif "jsp" in tech_str:
                    extensions = ".jsp,.do"
                else:
                    extensions = self._ask_extensions()
            elif not extensions:
                extensions = self._ask_extensions()
            
            ext_flag = f"-e {extensions}" if extensions else ""
            cmd = f"ffuf -u {url} -w {wordlist} {ext_flag} -t 50 -c"

        elif mode == "vhost":
            # Parse hostname
            parsed = urlparse(target if target.startswith('http') else f"http://{target}")
            hostname = parsed.hostname or target
            
            console.print(f"\n[bold cyan]Virtual Host Discovery[/bold cyan]")
            console.print(f"[dim]Target hostname: {hostname}[/dim]")
            console.print("[dim]Common patterns:[/dim]")
            console.print("  1. FUZZ.domain.com - (subdomain brute force)")
            console.print("  2. subdomain.FUZZ.com - (different pattern)")
            console.print("  3. Custom pattern")
            
            choice = Prompt.ask("Select pattern", choices=["1","2","3"], default="1")
            
            parts = hostname.split('.')
            if choice == "1":
                if len(parts) > 2:
                    # Already a subdomain: test.fuzz.example.com -> FUZZ.example.com
                    domain = '.'.join(parts[-2:])
                    pattern = f"FUZZ.{domain}"
                else:
                    pattern = f"FUZZ.{hostname}"
            elif choice == "2":
                if len(parts) > 2:
                    sub = parts[0]
                    domain = '.'.join(parts[1:])
                    pattern = f"{sub}.FUZZ.{domain}"
                else:
                    pattern = f"FUZZ.{hostname}"
            else:
                pattern = Prompt.ask("Enter custom pattern (use FUZZ as placeholder)", default="FUZZ.example.com")
            
            url = get_base_url(target)
            cmd = f"ffuf -u {url} -w {wordlist} -H 'Host: {pattern}' -t 40 -c"

        elif mode == "param":
            # Add FUZZ as parameter name
            sep = "&" if "?" in target else "?"
            url = f"{target}{sep}FUZZ=test"
            cmd = f"ffuf -u {url} -w {wordlist} -t 40 -c"

        elif mode == "post":
            data = Prompt.ask("POST data (use FUZZ as placeholder)", default="username=FUZZ&password=test")
            cmd = f"ffuf -u {target} -w {wordlist} -X POST -d '{data}' -H 'Content-Type: application/x-www-form-urlencoded' -t 40 -c"

        elif mode == "ai":
            if self._ai_client:
                strategy = self._ai_decide_strategy(target, context or {})
                return strategy.get("command", f"ffuf -u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -fc 404 -t 50 -c")
            return f"ffuf -u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -fc 404 -t 50 -c"

        elif mode == "custom":
            return Prompt.ask("Enter full ffuf command")

        else:
            cmd = f"ffuf -u {target}/FUZZ -w {wordlist} -t 50 -c"

        # Add filters
        if filters:
            cmd += f" {filters}"
        # Default filter if none selected
        elif mode != "vhost":
            cmd += " -fc 404"
        
        # Output
        cmd += " -o /tmp/kernox_ffuf.json -of json"
        return cmd

    def _pick_filters(self, mode: str) -> str:
        """Build smart filter flags interactively."""
        console.print("\n[bold cyan]Smart Filter Setup[/bold cyan]")
        console.print("[dim]Filters remove false positives from results[/dim]\n")

        console.print("  [green]1[/green] – Auto     (filter by most common response size)")
        console.print("  [green]2[/green] – Status   (filter specific HTTP codes)")
        console.print("  [green]3[/green] – Size     (filter by response size in bytes)")
        console.print("  [green]4[/green] – Words    (filter by word count)")
        console.print("  [green]5[/green] – Lines    (filter by line count)")
        console.print("  [green]6[/green] – Match    (match specific codes only)")
        console.print("  [green]7[/green] – None     (no filters)\n")

        choice = Prompt.ask("Filter type", choices=["1","2","3","4","5","6","7"], default="1")

        if choice == "1":
            return "-fs 0"
        elif choice == "2":
            codes = Prompt.ask("Filter status codes (comma-separated)", default="404,400,403")
            return f"-fc {codes}"
        elif choice == "3":
            size = Prompt.ask("Filter response size (bytes)", default="0")
            return f"-fs {size}"
        elif choice == "4":
            words = Prompt.ask("Filter word count", default="0")
            return f"-fw {words}"
        elif choice == "5":
            lines = Prompt.ask("Filter line count", default="0")
            return f"-fl {lines}"
        elif choice == "6":
            codes = Prompt.ask("Match only these status codes", default="200,301,302")
            return f"-mc {codes}"
        return ""

    def _ask_extensions(self) -> str:
        """Ask for file extensions."""
        use_ext = Confirm.ask("Add file extensions? (php, html, txt etc)", default=False)
        if use_ext:
            ext = Prompt.ask("Extensions (comma-separated)", default=".php,.html,.txt,.bak")
            return ext
        return ""

    def parse(self, output: str) -> dict:
        """Parse ffuf output."""
        return FfufParser().parse(output)