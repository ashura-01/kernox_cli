"""kernox.tools.sqlmap – Full production sqlmap wrapper."""
from __future__ import annotations
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich import box
from rich.table import Table
from kernox.parsers.sqlmap_parser import SqlmapParser
from kernox.utils.url_helper import preserve_url

console = Console()

TAMPER_SCRIPTS = {
    "space2comment":    "Replaces spaces with comments (WAF bypass)",
    "between":          "Replaces > with BETWEEN (filter bypass)",
    "randomcase":       "Random case mutation",
    "charencode":       "URL encode characters",
    "base64encode":     "Base64 encode payload",
    "equaltolike":      "Replace = with LIKE",
    "greatest":         "Replace > with GREATEST()",
    "ifnull2ifisnull":  "Replace IFNULL with IF(ISNULL)",
    "multiplespaces":   "Add multiple spaces around keywords",
    "unmagicquotes":    "Strip magic quotes",
}

class SqlmapTool:
    name = "sqlmap"

    def build_command(self, target: str, flags: str = "", mode: str = "", **kwargs) -> str:
        target = preserve_url(target) if target.startswith('http') else target
        if flags and not mode:
            return f"sqlmap -u '{target}' {flags}"
        mode = mode or self._pick_mode()
        return self._build_from_mode(mode, target)

    def _pick_mode(self) -> str:
        console.print("\n[bold cyan]SQLMap Mode[/bold cyan]\n")
        table = Table(show_header=True, header_style="bold magenta",
                      box=box.SIMPLE_HEAVY, border_style="dim")
        table.add_column("#", width=4, style="bold cyan")
        table.add_column("Mode", style="bold")
        table.add_column("Description")
        modes = [
            ("1", "auto",      "Auto-detect injection point (GET params)"),
            ("2", "forms",     "Test all forms on the page"),
            ("3", "post",      "POST data injection"),
            ("4", "cookie",    "Cookie-based injection"),
            ("5", "headers",   "HTTP header injection (User-Agent, Referer, X-Forwarded-For)"),
            ("6", "auth",      "With authentication (Basic/Digest/Bearer)"),
            ("7", "crawl",     "Crawl and test entire site"),
            ("8", "tamper",    "With WAF bypass tamper scripts"),
            ("9", "full",      "Full aggressive scan (all techniques)"),
            ("10","custom",    "Enter custom flags"),
        ]
        for row in modes:
            table.add_row(*row)
        console.print(table)
        choice = Prompt.ask("Select mode", choices=[str(i) for i in range(1,11)], default="1")
        return {"1":"auto","2":"forms","3":"post","4":"cookie","5":"headers",
                "6":"auth","7":"crawl","8":"tamper","9":"full","10":"custom"}[choice]

    def _build_from_mode(self, mode: str, target: str) -> str:
        base = f"sqlmap -u '{target}' --batch"
        out  = "--output-dir=/tmp/kernox_sqlmap"
        level = Prompt.ask("Level (1-5)", default="2")
        risk  = Prompt.ask("Risk (1-3)", default="1")
        base += f" --level={level} --risk={risk}"

        if mode == "auto":
            return f"{base} -v 1 {out}"

        elif mode == "forms":
            return f"{base} --forms -v 1 {out}"

        elif mode == "post":
            data = Prompt.ask("POST data (e.g. user=test&pass=test)")
            return f"{base} --data='{data}' -v 1 {out}"

        elif mode == "cookie":
            cookie = Prompt.ask("Cookie value (e.g. PHPSESSID=abc123)")
            return f"{base} --cookie='{cookie}' -v 1 {out}"

        elif mode == "headers":
            console.print("  [green]1[/green] User-Agent  [green]2[/green] Referer  [green]3[/green] X-Forwarded-For  [green]4[/green] Custom")
            hc = Prompt.ask("Header", choices=["1","2","3","4"], default="1")
            hmap = {"1":"User-Agent","2":"Referer","3":"X-Forwarded-For"}
            if hc == "4":
                header = Prompt.ask("Header name")
            else:
                header = hmap[hc]
            return f"{base} -p '{header}' --header='{header}: *' -v 1 {out}"

        elif mode == "auth":
            console.print("  [green]1[/green] Basic  [green]2[/green] Digest  [green]3[/green] Bearer token")
            ac = Prompt.ask("Auth type", choices=["1","2","3"], default="1")
            if ac in ("1","2"):
                user = Prompt.ask("Username")
                pwd  = Prompt.ask("Password")
                atype = "Basic" if ac == "1" else "Digest"
                return f"{base} --auth-type={atype} --auth-cred='{user}:{pwd}' -v 1 {out}"
            else:
                token = Prompt.ask("Bearer token")
                return f"{base} --headers='Authorization: Bearer {token}' -v 1 {out}"

        elif mode == "crawl":
            depth = Prompt.ask("Crawl depth", default="3")
            return f"{base} --crawl={depth} --forms -v 1 {out}"

        elif mode == "tamper":
            console.print("\n[bold cyan]Tamper Scripts:[/bold cyan]")
            for i, (name, desc) in enumerate(TAMPER_SCRIPTS.items(), 1):
                console.print(f"  [green]{i}[/green] {name} — {desc}")
            tc = Prompt.ask("Select tamper(s) (comma-separated or 'all')", default="1")
            scripts = list(TAMPER_SCRIPTS.keys())
            if tc.strip().lower() == "all":
                selected = ",".join(scripts)
            else:
                selected = ",".join(scripts[int(x)-1] for x in tc.split(",") if x.strip().isdigit())
            return f"{base} --tamper={selected} -v 1 {out}"

        elif mode == "full":
            return (
                f"{base} --forms --crawl=3 --level=5 --risk=3 "
                f"--technique=BEUSTQ --dbs --tables -v 1 {out}"
            )

        elif mode == "custom":
            flags = Prompt.ask("Custom sqlmap flags")
            return f"sqlmap -u '{target}' {flags} {out}"

        return f"{base} -v 1 {out}"

    def parse(self, output: str) -> dict:
        return SqlmapParser().parse(output)
