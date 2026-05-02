"""
kernox.features.attack_log — Timestamped attack timeline.

Every tool execution is appended here automatically from command_executor.
Displayed with `log` command. Persisted to /tmp/kernox/attack_log.jsonl.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich import box

console  = Console()
LOG_PATH = Path("/tmp/kernox/attack_log.jsonl")

SEV_COLOR = {
    "critical": "#ff6b6b",
    "high":     "red",
    "medium":   "#00b894",
    "low":      "cyan",
    "info":     "dim white",
}


def log_tool_run(
    tool:        str,
    command:     str,
    target:      str,
    duration:    float,
    return_code: int,
    output_path: str = "",
) -> None:
    """Append a tool execution entry to the attack log."""
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts":          datetime.now().isoformat(timespec="seconds"),
        "type":        "tool",
        "tool":        tool,
        "command":     command,
        "target":      target,
        "duration":    round(duration, 2),
        "return_code": return_code,
        "output_path": output_path,
    }
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def log_finding(
    vuln_name: str,
    severity:  str,
    tool:      str,
    target:    str,
    exploit:   str = "",
) -> None:
    """Append a vulnerability finding to the attack log."""
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts":       datetime.now().isoformat(timespec="seconds"),
        "type":     "finding",
        "vuln":     vuln_name,
        "severity": severity,
        "tool":     tool,
        "target":   target,
        "exploit":  exploit,
    }
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def show_attack_log(tail: int = 50) -> None:
    """Display the attack timeline as a table. `log` command."""
    if not LOG_PATH.exists():
        console.print("[dim]No attack log yet. Run some tools first.[/dim]")
        return

    entries = []
    with LOG_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if not entries:
        console.print("[dim]Attack log is empty.[/dim]")
        return

    shown = entries[-tail:]

    t = Table(
        title=f"Attack Timeline  [{len(entries)} total]",
        box=box.MINIMAL,
        show_header=True,
        header_style="bold cyan",
        border_style="dim cyan",
        padding=(0, 1),
    )
    t.add_column("Time",    style="dim",  width=19)
    t.add_column("Type",    width=8)
    t.add_column("Tool",    style="cyan", width=12)
    t.add_column("Target",  style="dim",  width=22)
    t.add_column("Detail",  style="white")

    for e in shown:
        ts   = e.get("ts", "")
        typ  = e.get("type", "")

        if typ == "tool":
            rc    = e.get("return_code", 0)
            dur   = e.get("duration", 0.0)
            col   = "#55efc4" if rc == 0 else "#ff6b6b"
            detail = f"[{col}]exit {rc}[/{col}]  [{dur}s]"
            t.add_row(ts, "[cyan]exec[/cyan]", e.get("tool", ""), e.get("target", ""), detail)

        elif typ == "finding":
            sev   = e.get("severity", "info").lower()
            col   = SEV_COLOR.get(sev, "dim white")
            detail = f"[{col}]{e.get('vuln', '')}[/{col}]"
            t.add_row(ts, f"[{col}]vuln[/{col}]", e.get("tool", ""), e.get("target", ""), detail)

    console.print(t)


def clear_log() -> None:
    """Wipe the attack log file."""
    if LOG_PATH.exists():
        LOG_PATH.unlink()
        console.print("[green]✓ Attack log cleared[/green]")
    else:
        console.print("[dim]No log to clear.[/dim]")
