"""
kernox.core.orchestrator_helpers.on_demand_analyzer

Reads saved /tmp/kernox output files and feeds them to the existing
ai_analyzer.analyze() + command_executor._offer_chain() pipeline.

Commands:
    analyze / analyze all   -> every saved file merged
    analyze last            -> most recent file
    analyze select          -> pick file(s) from a numbered table
    analyze <tool>          -> all files for that tool
    analyze <ip>            -> all files for that target IP

No logic is duplicated here. Analysis and step-selection are fully
owned by AIAnalyzer and CommandExecutor respectively.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console
from rich.table import Table
from rich import box

if TYPE_CHECKING:
    from kernox.engine.state import SessionState
    from .ai_analyzer import AIAnalyzer
    from .command_executor import CommandExecutor

console = Console()

TMP_DIR      = Path("/tmp/kernox")
MERGE_LIMIT  = 400_000          # chars; ai_analyzer chunks at 100k internally
_FILE_SEP    = "\n\n" + ("=" * 60) + "\n\n"
_FILENAME_RE = re.compile(r"^(?P<tool>[^_]+)_(?P<target>.+?)_\d{8}_\d{6}\.txt$")
_IP_RE       = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


# ── helpers ───────────────────────────────────────────────────────────────────

def _saved_outputs() -> list[tuple[Path, str, str]]:
    """[(path, tool, target), ...] oldest → newest."""
    out = []
    if TMP_DIR.exists():
        for p in sorted(TMP_DIR.glob("*.txt"), key=os.path.getmtime):
            m = _FILENAME_RE.match(p.name)
            if m:
                out.append((p, m.group("tool"), m.group("target")))
    return out


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _merge(entries: list[tuple[Path, str, str]]) -> tuple[str, str, str]:
    """
    Merge entries into one labelled blob.
    Drops oldest sections when total exceeds MERGE_LIMIT.
    Returns (blob, last_tool, last_target).
    """
    sections = []
    for path, tool, target in entries:
        body = _read(path).strip()
        if body:
            sections.append((f"[{tool.upper()} → {target}]\n{body}", tool, target))

    while len(sections) > 1 and sum(len(s[0]) for s in sections) > MERGE_LIMIT:
        sections.pop(0)

    if not sections:
        return "", "", ""

    blob        = _FILE_SEP.join(s[0] for s in sections)
    last_tool   = sections[-1][1]
    last_target = sections[-1][2]
    return blob, last_tool, last_target


# ── main class ────────────────────────────────────────────────────────────────

class OnDemandAnalyzer:

    def __init__(self, state: "SessionState", ai_analyzer: "AIAnalyzer") -> None:
        self._state       = state
        self._ai          = ai_analyzer
        self._cmd: "CommandExecutor | None" = None

    def set_command_executor(self, executor: "CommandExecutor") -> None:
        self._cmd = executor

    # ── public entry point ────────────────────────────────────────────────────

    def run(self, argument: str) -> None:
        arg = argument.strip().lower()
        if arg in ("", "all"):
            self._run_entries(_saved_outputs(), "Full session")
        elif arg == "last":
            self._run_last()
        elif arg == "select":
            self._run_select()
        elif _IP_RE.match(arg):
            entries = [(p, t, tgt) for p, t, tgt in _saved_outputs() if arg in tgt]
            self._run_entries(entries, f"Host {arg}")
        else:
            entries = [(p, t, tgt) for p, t, tgt in _saved_outputs() if t.lower() == arg]
            self._run_entries(entries, f"Tool '{arg}'")

    # ── core: merge → analyze → offer ────────────────────────────────────────

    def _run_entries(self, entries: list[tuple[Path, str, str]], label: str) -> None:
        if not entries:
            console.print("[dim]No saved output found.[/dim]")
            return

        blob, tool, target = _merge(entries)
        if not blob:
            console.print("[dim]All matched files were empty.[/dim]")
            return

        console.print(f"\n[dim cyan]{label} — {len(entries)} file(s)[/dim cyan]")

        next_steps = self._ai.analyze(
            tool_name  = tool,
            target     = target,
            raw_output = blob,
        )

        if self._cmd:
            self._cmd._offer_chain(next_steps, intensity=None, depth=0)

    # ── strategies ────────────────────────────────────────────────────────────

    def _run_last(self) -> None:
        saved = _saved_outputs()
        for entry in reversed(saved):
            if _read(entry[0]).strip():
                self._run_entries([entry], "Last output")
                return
        console.print("[dim]No saved output found.[/dim]")

    def _run_select(self) -> None:
        saved = _saved_outputs()
        if not saved:
            console.print("[dim]No saved output files found.[/dim]")
            return

        tbl = Table(box=box.SIMPLE_HEAVY, show_lines=False)
        tbl.add_column("#",      style="bold cyan", no_wrap=True)
        tbl.add_column("Tool",   style="green",     no_wrap=True)
        tbl.add_column("Target", style="yellow")
        tbl.add_column("Size",   style="dim",       justify="right")

        for i, (path, tool, target) in enumerate(saved, 1):
            sz = path.stat().st_size if path.exists() else 0
            tbl.add_row(str(i), tool, target,
                        f"{sz // 1024} KB" if sz >= 1024 else f"{sz} B")
        console.print(tbl)

        try:
            raw = input("  Select [#, #,#, #-#, all, none]: ").strip().lower() or "none"
        except (EOFError, KeyboardInterrupt):
            console.print()
            return

        if raw in ("none", ""):
            return

        n       = len(saved)
        indices = []
        if raw == "all":
            indices = list(range(n))
        else:
            for tok in raw.split(","):
                tok = tok.strip()
                m   = re.match(r"^(\d+)-(\d+)$", tok)
                if m:
                    indices += [i for i in range(int(m.group(1)) - 1, int(m.group(2)))
                                if 0 <= i < n]
                elif tok.isdigit() and 0 <= int(tok) - 1 < n:
                    indices.append(int(tok) - 1)

        seen, unique = set(), []
        for i in indices:
            if i not in seen:
                seen.add(i)
                unique.append(i)

        if not unique:
            console.print("[dim]No valid selection.[/dim]")
            return

        self._run_entries([saved[i] for i in unique], f"Selected ({len(unique)} file(s))")

    # ── utility ───────────────────────────────────────────────────────────────

    def available_tools(self) -> list[str]:
        from_files = {t for _, t, _ in _saved_outputs()}
        from_state = {r.tool.lower() for r in self._state.get_tool_results() if r.tool}
        return sorted(from_files | from_state)
