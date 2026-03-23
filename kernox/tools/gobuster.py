"""
kernox.tools.gobuster  –  Full production gobuster wrapper.

Modes: dir, dns, vhost, s3
"""

from __future__ import annotations

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich import box
from rich.table import Table

from kernox.utils.wordlist import pick_wordlist
from kernox.utils.url_helper import get_domain, get_base_url, preserve_url

console = Console()


class GobusterTool:
    name = "gobuster"

    def build_command(
        self,
        target: str,
        mode: str = "",
        wordlist: str = "",
        flags: str = "",
        **kwargs,
    ) -> str:
        if flags and not mode:
            return f"gobuster {flags}"

        mode = mode or self._pick_mode()
        wordlist = wordlist or pick_wordlist("gobuster")
        return self._build_from_mode(mode, target, wordlist)

    def _pick_mode(self) -> str:
        console.print("\n[bold cyan]Gobuster Mode[/bold cyan]\n")
        table = Table(show_header=True, header_style="bold magenta",
                      box=box.SIMPLE_HEAVY, border_style="dim")
        table.add_column("#", width=4, style="bold cyan")
        table.add_column("Mode", style="bold")
        table.add_column("Description")

        modes = [
            ("1", "dir",    "Directory/file brute forcing"),
            ("2", "dns",    "DNS subdomain enumeration"),
            ("3", "vhost",  "Virtual host discovery"),
            ("4", "s3",     "AWS S3 bucket enumeration"),
            ("5", "custom", "Custom flags"),
        ]
        for row in modes:
            table.add_row(*row)
        console.print(table)

        choice = Prompt.ask("Select mode", choices=["1","2","3","4","5"], default="1")
        return {"1":"dir","2":"dns","3":"vhost","4":"s3","5":"custom"}[choice]

    def _build_from_mode(self, mode: str, target: str, wordlist: str) -> str:

        if mode == "dir":
            ext = ""
            if Confirm.ask("Add extensions?", default=False):
                ext_list = Prompt.ask("Extensions (comma-separated)", default="php,html,txt,bak")
                ext = f"-x {ext_list}"
            threads = Prompt.ask("Threads", default="50")
            status = Prompt.ask("Status codes to show", default="200,301,302,403")
            return (
                f"gobuster dir -u {target} -w {wordlist} "
                f"{ext} -t {threads} -s {status} "
                f"--no-error -o /tmp/kernox_gobuster.txt"
            )

        elif mode == "dns":
            domain = get_domain(target)
            threads = Prompt.ask("Threads", default="50")
            show_ip = "-i" if Confirm.ask("Show IP addresses?", default=True) else ""
            return (
                f"gobuster dns -d {domain} -w {wordlist} "
                f"-t {threads} {show_ip} "
                f"--no-error -o /tmp/kernox_gobuster_dns.txt"
            )

        elif mode == "vhost":
            domain = get_domain(target)
            url = get_base_url(target)
            threads = Prompt.ask("Threads", default="40")
            return (
                f"gobuster vhost -u {url} -w {wordlist} "
                f"--domain {domain} -t {threads} "
                f"--no-error -o /tmp/kernox_gobuster_vhost.txt"
            )

        elif mode == "s3":
            threads = Prompt.ask("Threads", default="10")
            return (
                f"gobuster s3 -w {wordlist} "
                f"-t {threads} --no-error "
                f"-o /tmp/kernox_gobuster_s3.txt"
            )

        elif mode == "custom":
            return Prompt.ask("Enter full gobuster command")

        return f"gobuster dir -u {target} -w {wordlist} --no-error"

    def parse(self, output: str) -> dict:
        paths = []
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("[") or line.startswith("Error") or line.startswith("="):
                continue
            if "(Status:" in line or "Found:" in line or line.startswith("/"):
                paths.append(line)
        return {"paths": paths, "total": len(paths), "raw": output}
