"""
kernox.tools.nmap  –  Full production Nmap wrapper with NSE scripts.
"""

from __future__ import annotations

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich import box
from rich.table import Table

from kernox.parsers.nmap_parser import NmapParser
from kernox.utils.url_helper import get_domain

console = Console()

NSE_SERVICE_SCRIPTS = {
    "ftp":        "ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor,ftp-proftpd-backdoor",
    "ssh":        "ssh-auth-methods,ssh-hostkey,ssh2-enum-algos",
    "smtp":       "smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344",
    "http":       "http-title,http-headers,http-methods,http-auth-finder,http-shellshock,http-put,http-git,http-robots.txt",
    "smb":        "smb-vuln-ms17-010,smb-vuln-ms08-067,smb-enum-shares,smb-enum-users,smb-security-mode",
    "mysql":      "mysql-info,mysql-empty-password,mysql-databases,mysql-enum",
    "rdp":        "rdp-enum-encryption,rdp-vuln-ms12-020",
    "vnc":        "vnc-info,vnc-brute",
    "irc":        "irc-info,irc-unrealircd-backdoor",
    "rpcbind":    "rpcinfo,nfs-ls,nfs-showmount,nfs-statfs",
    "tomcat":     "http-tomcat-manager,ajp-headers",
    "postgresql": "pgsql-brute",
    "telnet":     "telnet-ntlm-info",
}

VULN_SCRIPTS = (
    "vuln,smb-vuln-ms17-010,smb-vuln-ms08-067,"
    "ftp-vsftpd-backdoor,irc-unrealircd-backdoor,"
    "http-shellshock,ssl-heartbleed,ssl-poodle,"
    "rdp-vuln-ms12-020"
)


class NmapTool:
    name = "nmap"

    def build_command(
        self,
        target: str,
        flags: str = "",
        mode: str = "",
        ports: str = "",
        scripts: str = "",
        **kwargs,
    ) -> str:
        # Extract domain/IP from URL if needed
        if target.startswith("http"):
            from kernox.utils.url_helper import get_domain
            target = get_domain(target)
        if flags and not mode:
            cmd = f"nmap {flags} {target}"
            if ports:
                cmd += f" -p {ports}"
            return cmd
        mode = mode or self._pick_mode()
        return self._build_from_mode(mode, target, ports, scripts)

    def _pick_mode(self) -> str:
        console.print("\n[bold cyan]Nmap Scan Mode[/bold cyan]\n")
        table = Table(show_header=True, header_style="bold magenta",
                      box=box.SIMPLE_HEAVY, border_style="dim")
        table.add_column("#", width=4, style="bold cyan")
        table.add_column("Mode", style="bold")
        table.add_column("Description")
        table.add_column("Speed", width=8)
        modes = [
            ("1", "quick",      "Top 1000 ports, no scripts",           "Fast"),
            ("2", "service",    "Service & version detection",           "Med"),
            ("3", "aggressive", "Full -A (OS+version+scripts+traceroute)","Slow"),
            ("4", "vuln",       "NSE vulnerability scripts",             "Slow"),
            ("5", "full",       "All 65535 ports",                       "Slow"),
            ("6", "stealth",    "SYN stealth scan (needs root)",         "Fast"),
            ("7", "udp",        "UDP scan top 200",                      "Slow"),
            ("8", "script",     "Pick specific NSE script category",     "Med"),
            ("9", "custom",     "Enter custom flags manually",           "N/A"),
        ]
        for row in modes:
            table.add_row(*row)
        console.print(table)
        choice = Prompt.ask("Select mode", choices=[str(i) for i in range(1, 10)], default="2")
        return {"1":"quick","2":"service","3":"aggressive","4":"vuln",
                "5":"full","6":"stealth","7":"udp","8":"script","9":"custom"}[choice]

    def _build_from_mode(self, mode: str, target: str, ports: str, scripts: str) -> str:
        out = "-oN /tmp/kernox_nmap.txt"

        if mode == "quick":
            return f"nmap -T4 --open {target} {out}"

        elif mode == "service":
            p = ports or Prompt.ask("Ports (blank=top1000)", default="")
            pflag = f"-p {p}" if p else ""
            return f"nmap -sV -T4 --open {pflag} {target} {out}"

        elif mode == "aggressive":
            return f"nmap -A -T4 --open {target} {out}"

        elif mode == "vuln":
            return f"nmap -sV --script={VULN_SCRIPTS} -T4 {target} {out}"

        elif mode == "full":
            console.print("[yellow]Full scan may take 10-30 minutes[/yellow]")
            return f"nmap -sV -p- -T4 --open {target} {out}"

        elif mode == "stealth":
            console.print("[dim]Stealth scan needs root/sudo[/dim]")
            return f"nmap -sS -T2 --open {target} {out}"

        elif mode == "udp":
            console.print("[yellow]UDP scan is slow (15+ min)[/yellow]")
            return f"nmap -sU --top-ports 200 -T4 {target} {out}"

        elif mode == "script":
            flags = self._pick_nse_scripts()
            return f"nmap {flags} {target} {out}"

        elif mode == "custom":
            flags = Prompt.ask("Custom nmap flags")
            return f"nmap {flags} {target} {out}"

        return f"nmap -sV -T4 {target} {out}"

    def _pick_nse_scripts(self) -> str:
        console.print("\n[bold cyan]NSE Script Category[/bold cyan]")
        cats = list(NSE_SERVICE_SCRIPTS.keys()) + ["vuln (all)", "custom"]
        for i, c in enumerate(cats, 1):
            console.print(f"  [green]{i}[/green] – {c}")
        choice = Prompt.ask("Select", choices=[str(i) for i in range(1, len(cats)+1)], default="1")
        idx = int(choice) - 1
        if idx < len(NSE_SERVICE_SCRIPTS):
            key = list(NSE_SERVICE_SCRIPTS.keys())[idx]
            script = NSE_SERVICE_SCRIPTS[key]
        elif cats[idx] == "vuln (all)":
            script = VULN_SCRIPTS
        else:
            script = Prompt.ask("Script name(s) comma-separated")

        port = Prompt.ask("Port(s) for script (blank=all)", default="")
        flags = f"-sV --script={script} -T4"
        if port:
            flags += f" -p {port}"
        return flags

    def parse(self, output: str) -> dict:
        return NmapParser().parse(output)
