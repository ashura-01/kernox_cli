"""
kernox.tools.ffuf  –  Full production ffuf wrapper.

Modes:
  dir    - Directory/file fuzzing
  vhost  - Virtual host discovery
  param  - GET/POST parameter fuzzing
  custom - Manual flags
"""

from __future__ import annotations

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich import box
from rich.table import Table

from kernox.parsers.ffuf_parser import FfufParser
from kernox.utils.wordlist import pick_wordlist

console = Console()


class FfufTool:
    name = "ffuf"

    def build_command(
        self,
        target: str,
        wordlist: str = "",
        mode: str = "",
        flags: str = "",
        extensions: str = "",
        **kwargs,
    ) -> str:
        if flags and not mode:
            return f"ffuf {flags}"

        mode = mode or self._pick_mode()
        wordlist = wordlist or pick_wordlist("ffuf")
        return self._build_from_mode(mode, target, wordlist, extensions)

    def _pick_mode(self) -> str:
        console.print("\n[bold cyan]ffuf Mode[/bold cyan]\n")
        table = Table(show_header=True, header_style="bold magenta",
                      box=box.SIMPLE_HEAVY, border_style="dim")
        table.add_column("#", width=4, style="bold cyan")
        table.add_column("Mode", style="bold")
        table.add_column("Description")

        modes = [
            ("1", "dir",    "Directory & file fuzzing (FUZZ in path)"),
            ("2", "vhost",  "Virtual host discovery (Host header fuzzing)"),
            ("3", "param",  "GET parameter fuzzing (?FUZZ=value)"),
            ("4", "post",   "POST parameter fuzzing"),
            ("5", "custom", "Enter custom ffuf flags manually"),
        ]
        for row in modes:
            table.add_row(*row)
        console.print(table)

        choice = Prompt.ask("Select mode", choices=["1","2","3","4","5"], default="1")
        return {"1":"dir","2":"vhost","3":"param","4":"post","5":"custom"}[choice]

    def _build_from_mode(self, mode: str, target: str, wordlist: str, extensions: str) -> str:

        # ── Smart filter builder ─────────────────────────────────────────────
        filters = self._pick_filters(mode)

        if mode == "dir":
            base = preserve_url(target)
            url = base if "FUZZ" in base else f"{base.rstrip('/')}/FUZZ"
            ext_flag = f"-e {extensions}" if extensions else self._ask_extensions()
            cmd = f"ffuf -u {url} -w {wordlist} {ext_flag} -t 50 -c"

        elif mode == "vhost":
            domain = get_domain(target)
            url = get_base_url(target)
            cmd = f"ffuf -u {url} -w {wordlist} -H 'Host: FUZZ.{domain}' -t 40 -c"

        elif mode == "param":
            # Add FUZZ as parameter name
            sep = "&" if "?" in target else "?"
            url = f"{target}{sep}FUZZ=test"
            cmd = f"ffuf -u {url} -w {wordlist} -t 40 -c"

        elif mode == "post":
            data = Prompt.ask("POST data (use FUZZ as placeholder)", default="username=FUZZ&password=test")
            cmd = f"ffuf -u {target} -w {wordlist} -X POST -d '{data}' -H 'Content-Type: application/x-www-form-urlencoded' -t 40 -c"

        elif mode == "custom":
            cmd = Prompt.ask("Enter full ffuf command")
            return cmd

        else:
            cmd = f"ffuf -u {target}/FUZZ -w {wordlist} -t 50 -c"

        # Append filters
        cmd += f" {filters}"
        # Output
        cmd += " -o /tmp/kernox_ffuf.json -of json"
        return cmd

    def _pick_filters(self, mode: str) -> str:
        """Build smart filter flags interactively."""
        console.print("\n[bold cyan]Smart Filter Setup[/bold cyan]")
        console.print("[dim]Filters remove false positives from results[/dim]\n")

        console.print("  [green]1[/green] – Auto     (filter by most common response size)")
        console.print("  [green]2[/green] – Status   (filter specific HTTP codes)")
        console.print("  [green]3[/green] – Size     (filter by response size in bytes)")
        console.print("  [green]4[/green] – Words    (filter by word count)")
        console.print("  [green]5[/green] – Lines    (filter by line count)")
        console.print("  [green]6[/green] – Match    (match specific codes only)")
        console.print("  [green]7[/green] – None     (no filters)\n")

        choice = Prompt.ask("Filter type", choices=["1","2","3","4","5","6","7"], default="1")

        if choice == "1":
            # Auto — most common size filtered
            return "-fs 0"

        elif choice == "2":
            codes = Prompt.ask("Filter status codes (comma-separated)", default="404,400,403")
            return f"-fc {codes}"

        elif choice == "3":
            size = Prompt.ask("Filter response size (bytes)", default="0")
            return f"-fs {size}"

        elif choice == "4":
            words = Prompt.ask("Filter word count", default="0")
            return f"-fw {words}"

        elif choice == "5":
            lines = Prompt.ask("Filter line count", default="0")
            return f"-fl {lines}"

        elif choice == "6":
            codes = Prompt.ask("Match only these status codes", default="200,301,302")
            return f"-mc {codes}"

        return ""

    def _ask_extensions(self) -> str:
        use_ext = Confirm.ask("Add file extensions? (php, html, txt etc)", default=False)
        if use_ext:
            ext = Prompt.ask("Extensions (comma-separated)", default=".php,.html,.txt,.bak")
            return f"-e {ext}"
        return ""

    def parse(self, output: str) -> dict:
        return FfufParser().parse(output)
