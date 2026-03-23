"""kernox.tools.whatweb – Web technology fingerprinting."""
from __future__ import annotations
from rich.console import Console
from rich.prompt import Prompt
from kernox.parsers.whatweb_parser import WhatwebParser
from kernox.utils.url_helper import preserve_url
console = Console()

class WhatwebTool:
    name = "whatweb"

    def build_command(self, target: str, flags: str = "", mode: str = "", **kwargs) -> str:
        target = preserve_url(target)
        mode = mode or self._pick_mode()
        if mode == "quiet":
            return f"whatweb -q {target}"
        elif mode == "verbose":
            return f"whatweb -v {target}"
        elif mode == "aggressive":
            return f"whatweb -a 3 {target}"
        elif mode == "custom":
            flags = Prompt.ask("Custom whatweb flags")
            return f"whatweb {flags} {target}"
        return f"whatweb -a 3 -v {target}"

    def _pick_mode(self) -> str:
        console.print("\n[bold cyan]WhatWeb Mode[/bold cyan]")
        console.print("  [green]1[/green] – aggressive (level 3, recommended)")
        console.print("  [green]2[/green] – verbose   (detailed output)")
        console.print("  [green]3[/green] – quiet     (minimal output)")
        console.print("  [green]4[/green] – custom\n")
        c = Prompt.ask("Select", choices=["1","2","3","4"], default="1")
        return {"1":"aggressive","2":"verbose","3":"quiet","4":"custom"}[c]

    def parse(self, output: str) -> dict:
        return WhatwebParser().parse(output)
