"""kernox.tools.smbclient – Full smbclient wrapper."""
from __future__ import annotations
from rich.console import Console
from rich.prompt import Prompt, Confirm

console = Console()

class SmbclientTool:
    name = "smbclient"

    def build_command(self, target: str, flags: str = "", mode: str = "", **kwargs) -> str:
        mode = mode or self._pick_mode()
        return self._build_from_mode(mode, target)

    def _pick_mode(self) -> str:
        console.print("\n[bold cyan]SMBClient Mode[/bold cyan]")
        console.print("  [green]1[/green] – list       (list all shares)")
        console.print("  [green]2[/green] – anon       (anonymous access)")
        console.print("  [green]3[/green] – auth       (authenticated access)")
        console.print("  [green]4[/green] – recursive  (recursive file listing)")
        console.print("  [green]5[/green] – download   (download all files)")
        console.print("  [green]6[/green] – upload     (test write access)\n")
        c = Prompt.ask("Select", choices=["1","2","3","4","5","6"], default="1")
        return {"1":"list","2":"anon","3":"auth","4":"recursive","5":"download","6":"upload"}[c]

    def _build_from_mode(self, mode: str, target: str) -> str:
        if mode == "list":
            return f"smbclient -L //{target} -N 2>/dev/null"

        elif mode == "anon":
            share = Prompt.ask("Share name", default="tmp")
            return f"smbclient //{target}/{share} -N -c 'ls; recurse ON; ls'"

        elif mode == "auth":
            share = Prompt.ask("Share name")
            user  = Prompt.ask("Username")
            pwd   = Prompt.ask("Password")
            return f"smbclient //{target}/{share} -U '{user}%{pwd}' -c 'ls'"

        elif mode == "recursive":
            share = Prompt.ask("Share name", default="tmp")
            user  = ""
            creds = "-N"
            if Confirm.ask("Use credentials?", default=False):
                user = Prompt.ask("Username")
                pwd  = Prompt.ask("Password")
                creds = f"-U '{user}%{pwd}'"
            return (
                f"smbclient //{target}/{share} {creds} "
                f"-c 'recurse ON; ls'"
            )

        elif mode == "download":
            share  = Prompt.ask("Share name", default="tmp")
            outdir = Prompt.ask("Save to", default="/tmp/kernox_smb")
            creds  = "-N"
            if Confirm.ask("Use credentials?", default=False):
                user = Prompt.ask("Username")
                pwd  = Prompt.ask("Password")
                creds = f"-U '{user}%{pwd}'"
            return (
                f"mkdir -p {outdir} && "
                f"smbclient //{target}/{share} {creds} "
                f"-c 'prompt OFF; recurse ON; lcd {outdir}; mget *'"
            )

        elif mode == "upload":
            share   = Prompt.ask("Share name", default="tmp")
            testfile= "/tmp/kernox_write_test.txt"
            creds   = "-N"
            if Confirm.ask("Use credentials?", default=False):
                user = Prompt.ask("Username")
                pwd  = Prompt.ask("Password")
                creds = f"-U '{user}%{pwd}'"
            return (
                f"echo 'kernox_write_test' > {testfile} && "
                f"smbclient //{target}/{share} {creds} "
                f"-c 'put {testfile} kernox_test.txt; ls'"
            )

        return f"smbclient -L //{target} -N"

    def parse(self, output: str) -> dict:
        shares, files = [], []
        for line in output.splitlines():
            line = line.strip()
            if any(x in line for x in ("Disk","IPC","Printer")):
                shares.append(line)
            elif line and not line.startswith("session") and not line.startswith("Try"):
                files.append(line)
        return {"shares": shares, "files": files, "raw": output}
