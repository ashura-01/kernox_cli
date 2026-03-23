"""kernox.tools.enum4linux – Full enum4linux wrapper."""
from __future__ import annotations
from rich.console import Console
from rich.prompt import Prompt, Confirm
from kernox.parsers.enum4linux_parser import Enum4linuxParser

console = Console()

class Enum4linuxTool:
    name = "enum4linux"

    def build_command(self, target: str, flags: str = "", mode: str = "", **kwargs) -> str:
        if flags and not mode:
            return f"enum4linux {flags} {target}"
        mode = mode or self._pick_mode()
        return self._build_from_mode(mode, target)

    def _pick_mode(self) -> str:
        console.print("\n[bold cyan]Enum4linux Mode[/bold cyan]")
        console.print("  [green]1[/green] – full      (-a) All checks")
        console.print("  [green]2[/green] – users     (-U) User enumeration")
        console.print("  [green]3[/green] – shares    (-S) Share enumeration")
        console.print("  [green]4[/green] – groups    (-G) Group enumeration")
        console.print("  [green]5[/green] – policy    (-P) Password policy")
        console.print("  [green]6[/green] – os        (-o) OS information")
        console.print("  [green]7[/green] – rid       (-r) RID cycling (user brute)")
        console.print("  [green]8[/green] – custom    (manual flags)\n")
        c = Prompt.ask("Select", choices=["1","2","3","4","5","6","7","8"], default="1")
        return {"1":"full","2":"users","3":"shares","4":"groups",
                "5":"policy","6":"os","7":"rid","8":"custom"}[c]

    def _build_from_mode(self, mode: str, target: str) -> str:
        creds = ""
        if Confirm.ask("Use credentials?", default=False):
            user = Prompt.ask("Username")
            pwd  = Prompt.ask("Password")
            creds = f"-u '{user}' -p '{pwd}'"

        out = "-v"
        flag_map = {
            "full":   f"-a {creds} {out}",
            "users":  f"-U {creds} {out}",
            "shares": f"-S {creds} {out}",
            "groups": f"-G {creds} {out}",
            "policy": f"-P {creds} {out}",
            "os":     f"-o {creds} {out}",
            "rid":    f"-r {creds} {out}",
        }
        if mode == "custom":
            flags = Prompt.ask("Custom flags")
            return f"enum4linux {flags} {target}"

        return f"enum4linux {flag_map.get(mode, f'-a {creds}')} {target}"

    def parse(self, output: str) -> dict:
        return Enum4linuxParser().parse(output)
