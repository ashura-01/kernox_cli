"""
kernox.tools.nikto  –  Full production nikto wrapper.
"""

from __future__ import annotations

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich import box
from rich.table import Table

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

    def build_command(
        self,
        target: str,
        flags: str = "",
        mode: str = "",
        **kwargs,
    ) -> str:
        if flags and not mode:
            if not target.startswith("http"):
                target = f"http://{target}"
            return f"nikto -h {target} {flags} -output /tmp/kernox_nikto.txt"

        mode = mode or self._pick_mode()
        return self._build_from_mode(mode, target)

    def _pick_mode(self) -> str:
        console.print("\n[bold cyan]Nikto Scan Mode[/bold cyan]\n")
        table = Table(show_header=True, header_style="bold magenta",
                      box=box.SIMPLE_HEAVY, border_style="dim")
        table.add_column("#", width=4, style="bold cyan")
        table.add_column("Mode", style="bold")
        table.add_column("Description")

        modes = [
            ("1", "full",    "Full scan — all checks"),
            ("2", "tuned",   "Pick specific check categories"),
            ("3", "auth",    "Authentication bypass checks only"),
            ("4", "sqli",    "SQL injection checks only"),
            ("5", "ssl",     "SSL/TLS checks"),
            ("6", "quick",   "Quick scan — fast, fewer checks"),
            ("7", "custom",  "Custom flags"),
        ]
        for row in modes:
            table.add_row(*row)
        console.print(table)

        choice = Prompt.ask("Select mode", choices=["1","2","3","4","5","6","7"], default="1")
        return {"1":"full","2":"tuned","3":"auth","4":"sqli",
                "5":"ssl","6":"quick","7":"custom"}[choice]

    def _build_from_mode(self, mode: str, target: str) -> str:
        if not target.startswith("http"):
            target = f"http://{target}"

        port = Prompt.ask("Target port (blank=default)", default="")
        port_flag = f"-p {port}" if port else ""
        out = "-output /tmp/kernox_nikto.txt -Format txt"

        if mode == "full":
            return f"nikto -h {target} {port_flag} {out}"

        elif mode == "tuned":
            self._show_tuning_options()
            tuning = Prompt.ask("Tuning codes (e.g. 123 or x4)", default="1234")
            return f"nikto -h {target} {port_flag} -Tuning {tuning} {out}"

        elif mode == "auth":
            return f"nikto -h {target} {port_flag} -Tuning a {out}"

        elif mode == "sqli":
            return f"nikto -h {target} {port_flag} -Tuning 9 {out}"

        elif mode == "ssl":
            return f"nikto -h {target} {port_flag} -ssl {out}"

        elif mode == "quick":
            return f"nikto -h {target} {port_flag} -Tuning 123b -maxtime 120 {out}"

        elif mode == "custom":
            flags = Prompt.ask("Custom nikto flags")
            return f"nikto -h {target} {flags} {out}"

        return f"nikto -h {target} {out}"

    def _show_tuning_options(self) -> None:
        console.print("\n[bold cyan]Tuning Options:[/bold cyan]")
        for code, desc in TUNING_OPTIONS.items():
            console.print(f"  [green]{code}[/green] – {desc}")
        console.print()

    def parse(self, output: str) -> dict:
        return NiktoParser().parse(output)
