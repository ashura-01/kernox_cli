"""kernox.tools.whatweb – AI-powered web technology fingerprinting."""
from __future__ import annotations
import json
import re
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.spinner import Spinner
from rich.live import Live
from kernox.parsers.whatweb_parser import WhatwebParser
from kernox.utils.url_helper import preserve_url

console = Console()


class WhatwebTool:
    name = "whatweb"

    def __init__(self, ai_client=None):
        """Initialize with optional AI client for strategy planning."""
        self._ai_client = ai_client

    def build_command(self, target: str, flags: str = "", mode: str = "", context: dict = None, **kwargs) -> str:
        target = preserve_url(target)
        
        # If AI client and no mode/flags forced, let AI decide
        if self._ai_client and not mode and not flags:
            strategy = self._ai_decide_strategy(target, context or {})
            console.print(Panel(
                f"[bold cyan]AI Strategy:[/bold cyan] {strategy.get('analysis', '')}\n"
                f"[bold]Mode:[/bold] {strategy.get('mode', 'aggressive')}",
                title="🧠 AI WhatWeb Strategy",
                border_style="cyan"
            ))
            if Confirm.ask("Use AI-recommended mode?", default=True):
                mode = strategy.get("mode", "aggressive")
        
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

    def _ai_decide_strategy(self, target: str, context: dict) -> dict:
        """Let AI decide optimal whatweb mode based on target."""
        open_ports = context.get("open_ports", [])
        server = context.get("server", "")
        
        prompt = f"""You are a penetration tester. Choose the best whatweb mode for:

Target: {target}
Open ports: {open_ports}
Server header: {server}

Modes:
- aggressive (-a 3): thorough fingerprinting, slower
- verbose (-v): detailed output, faster
- quiet (-q): minimal output, fastest

Respond with JSON: {{"mode": "aggressive/verbose/quiet", "analysis": "reason for choice"}}"""

        try:
            with Live(Spinner("dots", text="[dim]AI analyzing target...[/dim]"), refresh_per_second=10):
                response = self._ai_client.chat(
                    messages=[{"role": "user", "content": prompt}],
                    system="You are a penetration testing expert. Return ONLY valid JSON.",
                    max_tokens=200,
                    temperature=0.2
                )
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
        except Exception:
            pass
        
        return {"mode": "aggressive", "analysis": "Default aggressive scan"}

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

# """kernox.tools.whatweb – Web technology fingerprinting."""
# from __future__ import annotations
# from rich.console import Console
# from rich.prompt import Prompt
# from kernox.parsers.whatweb_parser import WhatwebParser
# from kernox.utils.url_helper import preserve_url
# console = Console()

# class WhatwebTool:
#     name = "whatweb"

#     def build_command(self, target: str, flags: str = "", mode: str = "", **kwargs) -> str:
#         target = preserve_url(target)
#         mode = mode or self._pick_mode()
#         if mode == "quiet":
#             return f"whatweb -q {target}"
#         elif mode == "verbose":
#             return f"whatweb -v {target}"
#         elif mode == "aggressive":
#             return f"whatweb -a 3 {target}"
#         elif mode == "custom":
#             flags = Prompt.ask("Custom whatweb flags")
#             return f"whatweb {flags} {target}"
#         return f"whatweb -a 3 -v {target}"

#     def _pick_mode(self) -> str:
#         console.print("\n[bold cyan]WhatWeb Mode[/bold cyan]")
#         console.print("  [green]1[/green] – aggressive (level 3, recommended)")
#         console.print("  [green]2[/green] – verbose   (detailed output)")
#         console.print("  [green]3[/green] – quiet     (minimal output)")
#         console.print("  [green]4[/green] – custom\n")
#         c = Prompt.ask("Select", choices=["1","2","3","4"], default="1")
#         return {"1":"aggressive","2":"verbose","3":"quiet","4":"custom"}[c]

#     def parse(self, output: str) -> dict:
#         return WhatwebParser().parse(output)
