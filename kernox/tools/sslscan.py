"""kernox.tools.sslscan – Full sslscan wrapper."""
from __future__ import annotations
from rich.console import Console
from rich.prompt import Prompt, Confirm
from kernox.parsers.sslscan_parser import SslscanParser
from kernox.utils.url_helper import get_domain

console = Console()

class SslscanTool:
    name = "sslscan"

    def build_command(self, target: str, flags: str = "", mode: str = "", **kwargs) -> str:
        host = get_domain(target)
        mode = mode or self._pick_mode()
        return self._build_from_mode(mode, host)

    def _pick_mode(self) -> str:
        console.print("\n[bold cyan]SSLScan Mode[/bold cyan]")
        console.print("  [green]1[/green] – full       (all checks, recommended)")
        console.print("  [green]2[/green] – ciphers    (show all cipher suites)")
        console.print("  [green]3[/green] – tls1only   (TLS 1.x only, skip SSL)")
        console.print("  [green]4[/green] – heartbleed (heartbleed check only)")
        console.print("  [green]5[/green] – xml        (XML output for parsing)")
        console.print("  [green]6[/green] – custom     (manual flags)\n")
        c = Prompt.ask("Select", choices=["1","2","3","4","5","6"], default="1")
        return {"1":"full","2":"ciphers","3":"tls1only","4":"heartbleed","5":"xml","6":"custom"}[c]

    def _build_from_mode(self, mode: str, host: str) -> str:
        port = Prompt.ask("Port", default="443")
        target = f"{host}:{port}"

        if mode == "full":
            return (
                f"sslscan --show-certificate --show-ciphers "
                f"--show-client-cas --tlsall {target}"
            )
        elif mode == "ciphers":
            return f"sslscan --show-ciphers --no-failed {target}"

        elif mode == "tls1only":
            return f"sslscan --show-certificate --tls10 --tls11 --tls12 --tls13 {target}"

        elif mode == "heartbleed":
            return f"sslscan --heartbleed {target}"

        elif mode == "xml":
            outfile = f"/tmp/kernox_sslscan_{host.replace('.','_')}.xml"
            return f"sslscan --xml={outfile} --show-certificate --show-ciphers {target}"

        elif mode == "custom":
            flags = Prompt.ask("Custom sslscan flags")
            return f"sslscan {flags} {target}"

        return f"sslscan --show-certificate --show-ciphers {target}"

    def parse(self, output: str) -> dict:
        return SslscanParser().parse(output)
