"""
kernox.tools.hashcat  –  Smart hashcat wrapper (auto CPU/GPU detection).
"""

from __future__ import annotations

import subprocess
import shutil
from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich import box
from rich.table import Table

from kernox.parsers.hashcat_parser import HashcatParser

console = Console()

HASH_TYPES = {
    "0":    "MD5",
    "100":  "SHA-1",
    "1400": "SHA-256",
    "1700": "SHA-512",
    "1800": "sha512crypt (Linux $6$)",
    "500":  "md5crypt (Linux $1$)",
    "3200": "bcrypt (Web $2a$)",
    "1000": "NTLM (Windows)",
    "5600": "NetNTLMv2",
    "2500": "WPA/WPA2 (PMKID)",
    "22000":"WPA-PBKDF2-PMKID (new)",
    "900":  "MD4",
    "1500": "DES (Unix)",
    "3000": "LM (Windows old)",
}

ATTACK_MODES = {
    "0": "Straight (wordlist)",
    "1": "Combination (two wordlists)",
    "3": "Brute-force (mask)",
    "6": "Hybrid wordlist + mask",
    "7": "Hybrid mask + wordlist",
}


def _detect_device() -> tuple[str, str]:
    """Auto-detect best compute device. Returns (device_flag, description)."""
    # Check for GPU via OpenCL/CUDA
    try:
        result = subprocess.run(
            ["hashcat", "-I"],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout + result.stderr
        if "OpenCL" in output or "CUDA" in output:
            if "GeForce" in output or "Radeon" in output or "RTX" in output or "GTX" in output:
                return "-d 1", "GPU detected — using GPU"
    except Exception:
        pass

    # Fall back to CPU
    return "-D 1", "No GPU found — using CPU"


class HashcatTool:
    name = "hashcat"

    def build_command(
        self,
        hashfile: str,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        hash_type: str = "",
        attack_mode: str = "0",
        flags: str = "",
        **kwargs,
    ) -> str:

        # Auto-detect device
        device_flag, device_desc = _detect_device()
        console.print(f"\n[dim]Device:[/dim] [cyan]{device_desc}[/cyan]")

        # Handle raw hash string → save to temp file
        if hashfile and not hashfile.startswith("/") and " " not in hashfile:
            import tempfile
            tmp = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, prefix="kernox_hash_"
            )
            tmp.write(hashfile.strip() + "\n")
            tmp.close()
            console.print(f"[dim]Hash saved to:[/dim] [cyan]{tmp.name}[/cyan]")
            hashfile = tmp.name

        # Auto-detect hash type if not given
        if not hash_type:
            hash_type = self._detect_hash_type(hashfile)

        # Hash type picker if auto-detect failed
        if not hash_type:
            hash_type = self._pick_hash_type()

        # Attack mode
        attack_mode = self._pick_attack_mode()

        # Wordlist / mask
        if attack_mode == "0":
            console.print(f"\n[dim]Default wordlist:[/dim] [cyan]{wordlist}[/cyan]")
            if Confirm.ask("Use custom wordlist?", default=False):
                while True:
                    custom = Prompt.ask("Wordlist path")
                    if Path(custom).exists():
                        wordlist = custom
                        break
                    console.print(f"[red]Not found: {custom}[/red]")
            attack_str = wordlist

        elif attack_mode == "3":
            mask = Prompt.ask("Mask (e.g. ?a?a?a?a?a?a for 6-char)", default="?a?a?a?a?a?a")
            attack_str = mask

        elif attack_mode in ("1", "6", "7"):
            wl1 = Prompt.ask("First wordlist", default=wordlist)
            wl2 = Prompt.ask("Second wordlist / mask")
            attack_str = f"{wl1} {wl2}"

        else:
            attack_str = wordlist

        # Rules
        use_rules = Confirm.ask("Apply rules? (boosts cracking power)", default=False)
        rules_flag = ""
        if use_rules:
            console.print("  [green]1[/green] best64  [green]2[/green] rockyou-30000  [green]3[/green] d3ad0ne  [green]4[/green] custom")
            rc = Prompt.ask("Rule", choices=["1","2","3","4"], default="1")
            rule_map = {
                "1": "/usr/share/hashcat/rules/best64.rule",
                "2": "/usr/share/hashcat/rules/rockyou-30000.rule",
                "3": "/usr/share/hashcat/rules/d3ad0ne.rule",
            }
            if rc == "4":
                rules_flag = f"-r {Prompt.ask('Rule file path')}"
            else:
                rules_flag = f"-r {rule_map[rc]}"

        cmd = (
            f"hashcat -m {hash_type} -a {attack_mode} "
            f"{device_flag} "
            f"{hashfile} {attack_str} "
            f"{rules_flag} "
            f"--status --status-timer=10 "
            f"--outfile=/tmp/kernox_cracked.txt "
            f"--outfile-format=2"
        ).strip()

        if flags:
            cmd += f" {flags}"

        return cmd

    def _detect_hash_type(self, hashfile: str) -> str:
        """Try to auto-detect hash type from hash string."""
        try:
            with open(hashfile, "r") as f:
                first_hash = f.readline().strip().split(":")[0]
        except Exception:
            first_hash = hashfile

        length = len(first_hash)
        if first_hash.startswith("$6$"):
            console.print("[dim]Auto-detected: sha512crypt (type 1800)[/dim]")
            return "1800"
        elif first_hash.startswith("$1$"):
            console.print("[dim]Auto-detected: md5crypt (type 500)[/dim]")
            return "500"
        elif first_hash.startswith("$2a$") or first_hash.startswith("$2y$"):
            console.print("[dim]Auto-detected: bcrypt (type 3200)[/dim]")
            return "3200"
        elif length == 32 and all(c in "0123456789abcdefABCDEF" for c in first_hash):
            console.print("[dim]Auto-detected: MD5 (type 0)[/dim]")
            return "0"
        elif length == 40:
            console.print("[dim]Auto-detected: SHA-1 (type 100)[/dim]")
            return "100"
        elif length == 64:
            console.print("[dim]Auto-detected: SHA-256 (type 1400)[/dim]")
            return "1400"
        elif length == 128:
            console.print("[dim]Auto-detected: SHA-512 (type 1700)[/dim]")
            return "1700"
        return ""

    def _pick_hash_type(self) -> str:
        console.print("\n[bold cyan]Hash Type[/bold cyan]")
        table = Table(show_header=True, header_style="bold magenta",
                      box=box.SIMPLE_HEAVY, border_style="dim")
        table.add_column("Code", style="bold cyan", width=8)
        table.add_column("Type")
        for code, name in HASH_TYPES.items():
            table.add_row(code, name)
        console.print(table)
        return Prompt.ask("Hash type code", default="0")

    def _pick_attack_mode(self) -> str:
        console.print("\n[bold cyan]Attack Mode[/bold cyan]")
        for code, desc in ATTACK_MODES.items():
            console.print(f"  [green]{code}[/green] – {desc}")
        return Prompt.ask("Attack mode", choices=list(ATTACK_MODES.keys()), default="0")

    def parse(self, output: str) -> dict:
        return HashcatParser().parse(output)
