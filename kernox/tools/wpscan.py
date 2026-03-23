"""
kernox.tools.wpscan  –  WordPress vulnerability scanner wrapper.
"""

from __future__ import annotations

from rich.console import Console
from rich.prompt import Prompt, Confirm

from kernox.parsers.wpscan_parser import WpscanParser
from kernox.utils.url_helper import preserve_url

console = Console()


class WpscanTool:
    name = "wpscan"

    def build_command(self, target: str, flags: str = "", mode: str = "", **kwargs) -> str:
        if flags and not mode:
            return f"wpscan --url {target} {flags}"
        mode = mode or self._pick_mode()
        return self._build_from_mode(mode, target)

    def _pick_mode(self) -> str:
        console.print("\n[bold cyan]WPScan Mode[/bold cyan]")
        console.print("  [green]1[/green] – passive   (no brute force, fast)")
        console.print("  [green]2[/green] – full      (enumerate plugins, themes, users)")
        console.print("  [green]3[/green] – users     (enumerate users only)")
        console.print("  [green]4[/green] – brute     (brute force login)")
        console.print("  [green]5[/green] – custom    (manual flags)\n")
        choice = Prompt.ask("Select mode", choices=["1","2","3","4","5"], default="2")
        return {"1":"passive","2":"full","3":"users","4":"brute","5":"custom"}[choice]

    def _build_from_mode(self, mode: str, target: str) -> str:
        target = preserve_url(target)

        out = "--output /tmp/kernox_wpscan.txt --format cli-no-colour"

        if mode == "passive":
            return f"wpscan --url {target} --no-update {out}"

        elif mode == "full":
            return (
                f"wpscan --url {target} "
                f"--enumerate p,t,u,tt,cb,dbe "
                f"--plugins-detection aggressive "
                f"--no-update {out}"
            )

        elif mode == "users":
            return f"wpscan --url {target} --enumerate u --no-update {out}"

        elif mode == "brute":
            userlist = Prompt.ask("User list path", default="/usr/share/wordlists/metasploit/unix_users.txt")
            passlist = Prompt.ask("Password list path", default="/usr/share/wordlists/rockyou.txt")
            threads  = Prompt.ask("Threads", default="5")
            return (
                f"wpscan --url {target} "
                f"--usernames {userlist} "
                f"--passwords {passlist} "
                f"--max-threads {threads} "
                f"--no-update {out}"
            )

        elif mode == "custom":
            flags = Prompt.ask("Custom wpscan flags")
            return f"wpscan --url {target} {flags} {out}"

        return f"wpscan --url {target} --no-update {out}"

    def parse(self, output: str) -> dict:
        return WpscanParser().parse(output)
