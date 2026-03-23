"""kernox.tools.dnsrecon – Advanced DNS reconnaissance."""
from __future__ import annotations
from rich.console import Console
from rich.prompt import Prompt
from kernox.parsers.dnsrecon_parser import DnsreconParser
from kernox.utils.url_helper import get_domain
console = Console()

class DnsreconTool:
    name = "dnsrecon"

    def build_command(self, target: str, mode: str = "", flags: str = "", **kwargs) -> str:
        domain = get_domain(target)
        mode = mode or self._pick_mode()
        out = f"-j /tmp/kernox_dnsrecon.json"

        if mode == "std":
            return f"dnsrecon -d {domain} -t std {out}"
        elif mode == "brt":
            wordlist = Prompt.ask("Subdomain wordlist", default="/usr/share/wordlists/dirb/common.txt")
            return f"dnsrecon -d {domain} -t brt -D {wordlist} {out}"
        elif mode == "axfr":
            return f"dnsrecon -d {domain} -t axfr {out}"
        elif mode == "srv":
            return f"dnsrecon -d {domain} -t srv {out}"
        elif mode == "full":
            wordlist = Prompt.ask("Wordlist", default="/usr/share/wordlists/dirb/common.txt")
            return f"dnsrecon -d {domain} -t std,brt,srv,axfr -D {wordlist} {out}"
        return f"dnsrecon -d {domain} -t std {out}"

    def _pick_mode(self) -> str:
        console.print("\n[bold cyan]DNSRecon Mode[/bold cyan]")
        console.print("  [green]1[/green] – std   (standard records: A, MX, NS, SOA)")
        console.print("  [green]2[/green] – brt   (brute force subdomains)")
        console.print("  [green]3[/green] – axfr  (zone transfer attempt)")
        console.print("  [green]4[/green] – srv   (SRV record enum)")
        console.print("  [green]5[/green] – full  (all of the above)\n")
        c = Prompt.ask("Select", choices=["1","2","3","4","5"], default="1")
        return {"1":"std","2":"brt","3":"axfr","4":"srv","5":"full"}[c]

    def parse(self, output: str) -> dict:
        return DnsreconParser().parse(output)
