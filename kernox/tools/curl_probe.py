"""kernox.tools.curl_probe – Full curl HTTP probing wrapper."""
from __future__ import annotations
from rich.console import Console
from rich.prompt import Prompt, Confirm
from kernox.utils.url_helper import preserve_url

console = Console()

class CurlProbeTool:
    name = "curl"

    def build_command(self, target: str, flags: str = "", mode: str = "", **kwargs) -> str:
        target = preserve_url(target)
        mode = mode or self._pick_mode()
        return self._build_from_mode(mode, target)

    def _pick_mode(self) -> str:
        console.print("\n[bold cyan]HTTP Probe Mode[/bold cyan]")
        console.print("  [green]1[/green] – headers    (response headers)")
        console.print("  [green]2[/green] – methods    (allowed HTTP methods)")
        console.print("  [green]3[/green] – robots     (robots.txt)")
        console.print("  [green]4[/green] – tech       (fingerprint tech stack)")
        console.print("  [green]5[/green] – auth       (with authentication)")
        console.print("  [green]6[/green] – proxy      (through proxy)")
        console.print("  [green]7[/green] – cookies    (with custom cookies)")
        console.print("  [green]8[/green] – redirect   (follow redirects)")
        console.print("  [green]9[/green] – custom     (manual flags)\n")
        c = Prompt.ask("Select", choices=[str(i) for i in range(1,10)], default="1")
        return {"1":"headers","2":"methods","3":"robots","4":"tech","5":"auth",
                "6":"proxy","7":"cookies","8":"redirect","9":"custom"}[c]

    def _build_from_mode(self, mode: str, target: str) -> str:
        base = "curl -s --max-time 15 -L"

        if mode == "headers":
            return f"{base} -I -v {target} 2>&1"

        elif mode == "methods":
            return f"{base} -X OPTIONS -i -v {target} 2>&1"

        elif mode == "robots":
            from kernox.utils.url_helper import get_base_url
            return f"{base} {get_base_url(target)}/robots.txt"

        elif mode == "tech":
            return (
                f"{base} -I {target} && "
                f"curl -s --max-time 10 {target} | "
                f"grep -iE 'generator|powered|framework|cms|version' | head -10"
            )

        elif mode == "auth":
            console.print("  [green]1[/green] Basic  [green]2[/green] Bearer  [green]3[/green] Digest  [green]4[/green] NTLM")
            ac = Prompt.ask("Auth type", choices=["1","2","3","4"], default="1")
            if ac == "1":
                user = Prompt.ask("Username")
                pwd  = Prompt.ask("Password")
                return f"{base} -u '{user}:{pwd}' -v {target} 2>&1"
            elif ac == "2":
                token = Prompt.ask("Bearer token")
                return f"{base} -H 'Authorization: Bearer {token}' -v {target} 2>&1"
            elif ac == "3":
                user = Prompt.ask("Username")
                pwd  = Prompt.ask("Password")
                return f"{base} --digest -u '{user}:{pwd}' -v {target} 2>&1"
            elif ac == "4":
                user = Prompt.ask("Username")
                pwd  = Prompt.ask("Password")
                return f"{base} --ntlm -u '{user}:{pwd}' -v {target} 2>&1"

        elif mode == "proxy":
            proxy = Prompt.ask("Proxy URL", default="http://127.0.0.1:8080")
            return f"{base} --proxy {proxy} -v {target} 2>&1"

        elif mode == "cookies":
            cookies = Prompt.ask("Cookie string (e.g. session=abc; token=xyz)")
            return f"{base} -b '{cookies}' -v {target} 2>&1"

        elif mode == "redirect":
            return f"curl -v -L --max-time 15 --max-redirs 10 {target} 2>&1"

        elif mode == "custom":
            flags = Prompt.ask("Custom curl flags")
            return f"curl {flags} {target}"

        return f"{base} -I {target}"

    def parse(self, output: str) -> dict:
        import re
        headers, tech = {}, []
        for line in output.splitlines():
            if ":" in line and not line.startswith("<") and not line.startswith(">"):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    headers[parts[0].strip()] = parts[1].strip()
        server  = headers.get("Server","")
        powered = headers.get("X-Powered-By","")
        if server:  tech.append(f"Server: {server}")
        if powered: tech.append(f"Powered-By: {powered}")
        return {"headers": headers, "tech": tech, "raw": output}
