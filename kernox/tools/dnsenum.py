"""
kernox.tools.dnsenum  –  DNS enumeration wrapper.
"""

from __future__ import annotations

from rich.console import Console
from rich.prompt import Prompt, Confirm
from kernox.utils.url_helper import get_domain

console = Console()


class DnsenumTool:
    name = "dnsenum"

    def build_command(self, target: str, flags: str = "", mode: str = "", **kwargs) -> str:
        domain = get_domain(target)
        mode = mode or self._pick_mode()
        return self._build_from_mode(mode, domain)

    def _pick_mode(self) -> str:
        console.print("\n[bold cyan]DNS Enumeration Mode[/bold cyan]")
        console.print("  [green]1[/green] – basic     (A, MX, NS records)")
        console.print("  [green]2[/green] – full      (brute force subdomains)")
        console.print("  [green]3[/green] – zone      (zone transfer attempt)")
        console.print("  [green]4[/green] – reverse   (reverse lookup on range)")
        choice = Prompt.ask("Select mode", choices=["1","2","3","4"], default="1")
        return {"1":"basic","2":"full","3":"zone","4":"reverse"}[choice]

    def _build_from_mode(self, mode: str, domain: str) -> str:
        out = f"--output /tmp/kernox_dnsenum.xml"

        if mode == "basic":
            return f"dnsenum --noreverse --nocolor {domain}"

        elif mode == "full":
            wordlist = Prompt.ask(
                "Subdomain wordlist",
                default="/usr/share/wordlists/dirb/common.txt"
            )
            threads = Prompt.ask("Threads", default="20")
            return (
                f"dnsenum --nocolor -f {wordlist} "
                f"--threads {threads} {domain}"
            )

        elif mode == "zone":
            return f"dnsenum --nocolor --dnsserver {domain} {domain}"

        elif mode == "reverse":
            cidr = Prompt.ask("IP range for reverse lookup (e.g. 192.168.0)")
            return f"dnsenum --nocolor -r {cidr} {domain}"

        return f"dnsenum --nocolor {domain}"

    def parse(self, output: str) -> dict:
        import re
        subdomains, ips, nameservers, mx = [], [], [], []

        sub_re = re.compile(r"(\S+\.\S+)\s+\d+\s+IN\s+A\s+(\d+\.\d+\.\d+\.\d+)")
        ns_re  = re.compile(r"(\S+)\s+\d+\s+IN\s+NS\s+(\S+)")
        mx_re  = re.compile(r"(\S+)\s+\d+\s+IN\s+MX\s+\d+\s+(\S+)")

        for m in sub_re.finditer(output):
            subdomains.append({"subdomain": m.group(1), "ip": m.group(2)})
        for m in ns_re.finditer(output):
            nameservers.append(m.group(2))
        for m in mx_re.finditer(output):
            mx.append(m.group(2))

        return {
            "subdomains": subdomains,
            "nameservers": list(set(nameservers)),
            "mx_records": list(set(mx)),
            "total_subdomains": len(subdomains),
            "raw": output,
        }
