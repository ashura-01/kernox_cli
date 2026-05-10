"""
kernox.core.orchestrator_helpers.on_demand_analyzer

On-demand analysis system. Reads saved /tmp/kernox output files so that
AI analysis never has to re-run the tool — only parses stored output.

Commands handled (all dispatched by Orchestrator):
    analyze                → full session
    analyze all            → full session
    analyze last           → most recent tool output
    analyze <toolname>     → all outputs from that tool (dynamic, no hardcoded names)
    analyze <ip>           → all outputs for a specific host IP

Produces IDENTICAL output to auto-analysis (same AIAnalyzer.analyze call)
so the rich Finding panels, CVSS bars, and CVE tables appear unchanged.
"""

from __future__ import annotations

import glob
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

if TYPE_CHECKING:
    from kernox.engine.state import SessionState
    from .ai_analyzer import AIAnalyzer

console = Console()

TMP_DIR = Path("/tmp/kernox")

# Regex: matches filenames like  nmap_192.168.0.1_20250510_123456.txt
_FILENAME_RE = re.compile(
    r"^(?P<tool>[^_]+)_(?P<target>.+?)_\d{8}_\d{6}\.txt$"
)

# IPv4 pattern (loose — just to detect IP arguments)
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _read_file(path: Path) -> str:
    """Read a saved tool output file, return empty string on failure."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _list_saved_outputs() -> list[tuple[Path, str, str]]:
    """
    Return [(path, tool_name, target), ...] sorted oldest→newest
    by reading /tmp/kernox/*.txt filenames.
    """
    results = []
    if not TMP_DIR.exists():
        return results
    for path in sorted(TMP_DIR.glob("*.txt"), key=os.path.getmtime):
        m = _FILENAME_RE.match(path.name)
        if m:
            results.append((path, m.group("tool"), m.group("target")))
    return results


def _state_tool_names(state: "SessionState") -> set[str]:
    """Dynamically extract tool names from session state (no hardcoding)."""
    names = set()
    for r in state.get_tool_results():
        if r.tool:
            names.add(r.tool.lower())
    return names


class OnDemandAnalyzer:
    """
    Dispatches `analyze` commands and feeds output to the shared AIAnalyzer
    so results are 100% identical to auto-analysis.
    """

    def __init__(self, state: "SessionState", ai_analyzer: "AIAnalyzer") -> None:
        self._state       = state
        self._ai_analyzer = ai_analyzer

    # ── Public entry point ────────────────────────────────────────────────────

    def run(self, argument: str) -> None:
        """
        Route the argument to the right analysis strategy.

        argument is the stripped text after "analyze", e.g.:
            ""         → full session
            "all"      → full session
            "last"     → most recent output
            "192.168.0.1" → by IP
            "nmap"     → by tool name (dynamic from state)
        """
        arg = argument.strip().lower()

        if arg in ("", "all"):
            self._analyze_session()
        elif arg == "last":
            self._analyze_last()
        elif _IP_RE.match(arg):
            self._analyze_by_ip(arg)
        else:
            # Check if it matches a known tool name from session state
            known_tools = _state_tool_names(self._state)
            if arg in known_tools:
                self._analyze_by_tool(arg)
            else:
                # Could be a partial tool name or typo — try prefix match
                matches = [t for t in known_tools if t.startswith(arg)]
                if len(matches) == 1:
                    self._analyze_by_tool(matches[0])
                elif len(matches) > 1:
                    console.print(
                        f"[yellow]Ambiguous tool name '{arg}'. "
                        f"Matches: {', '.join(sorted(matches))}[/yellow]"
                    )
                else:
                    # Fall back: try to find saved files matching the name
                    self._analyze_by_tool_from_files(arg)

    # ── Analysis strategies ───────────────────────────────────────────────────

    def _analyze_session(self) -> None:
        """Analyze every saved output file in the session."""
        saved = _list_saved_outputs()
        if not saved:
            self._analyze_from_state_results()
            return

        console.print(
            f"\n[dim cyan]Analyzing full session — "
            f"{len(saved)} saved output(s)...[/dim cyan]"
        )
        for path, tool, target in saved:
            raw = _read_file(path)
            if raw.strip():
                console.print(f"\n[dim]→ {tool} / {target}[/dim]")
                self._ai_analyzer.analyze(
                    tool_name=tool,
                    target=target,
                    raw_output=raw,
                )

    def _analyze_last(self) -> None:
        """Analyze only the most recently saved output file."""
        saved = _list_saved_outputs()
        if saved:
            path, tool, target = saved[-1]
            raw = _read_file(path)
            if raw.strip():
                console.print(
                    f"\n[dim cyan]Analyzing last output: "
                    f"{tool} / {target}[/dim cyan]"
                )
                self._ai_analyzer.analyze(
                    tool_name=tool,
                    target=target,
                    raw_output=raw,
                )
                return

        # Fallback: use session state
        results = self._state.get_tool_results()
        if not results:
            console.print("[dim]No tool output in session yet.[/dim]")
            return
        last = results[-1]
        if not last.raw_output:
            console.print("[dim]Last result has no stored output.[/dim]")
            return
        console.print(
            f"\n[dim cyan]Analyzing last: {last.tool} / {last.target}[/dim cyan]"
        )
        self._ai_analyzer.analyze(
            tool_name=last.tool,
            target=last.target or "unknown",
            raw_output=last.raw_output,
        )

    def _analyze_by_tool(self, tool_name: str) -> None:
        """Analyze all saved outputs for a given tool name (from files)."""
        saved = _list_saved_outputs()
        matches = [(p, t, tgt) for p, t, tgt in saved if t.lower() == tool_name]

        if matches:
            console.print(
                f"\n[dim cyan]Analyzing {len(matches)} output(s) "
                f"from '{tool_name}'...[/dim cyan]"
            )
            for path, tool, target in matches:
                raw = _read_file(path)
                if raw.strip():
                    console.print(f"\n[dim]→ {tool} / {target}[/dim]")
                    self._ai_analyzer.analyze(
                        tool_name=tool,
                        target=target,
                        raw_output=raw,
                    )
            return

        # Fallback: session state raw_output
        results = [
            r for r in self._state.get_tool_results()
            if r.tool.lower() == tool_name and r.raw_output
        ]
        if not results:
            console.print(
                f"[dim]No saved outputs found for tool '{tool_name}'.[/dim]"
            )
            return
        console.print(
            f"\n[dim cyan]Analyzing {len(results)} state result(s) "
            f"from '{tool_name}'...[/dim cyan]"
        )
        for r in results:
            self._ai_analyzer.analyze(
                tool_name=r.tool,
                target=r.target or "unknown",
                raw_output=r.raw_output,
            )

    def _analyze_by_tool_from_files(self, name: str) -> None:
        """
        Last-resort: search /tmp/kernox/*.txt whose filename starts with `name`.
        Handles cases where the tool ran but wasn't recorded in state.
        """
        saved = _list_saved_outputs()
        matches = [(p, t, tgt) for p, t, tgt in saved if t.lower().startswith(name)]
        if not matches:
            # Show what IS available so user knows what to type
            tools_in_state = _state_tool_names(self._state)
            tools_in_files = {t for _, t, _ in saved}
            all_tools = tools_in_state | tools_in_files
            if all_tools:
                console.print(
                    f"[yellow]No outputs for '{name}'. "
                    f"Available: {', '.join(sorted(all_tools))}[/yellow]"
                )
            else:
                console.print(
                    f"[dim]No outputs found for '{name}'. "
                    f"Run a tool first.[/dim]"
                )
            return

        console.print(
            f"\n[dim cyan]Analyzing {len(matches)} output(s) "
            f"matching '{name}'...[/dim cyan]"
        )
        for path, tool, target in matches:
            raw = _read_file(path)
            if raw.strip():
                self._ai_analyzer.analyze(
                    tool_name=tool,
                    target=target,
                    raw_output=raw,
                )

    def _analyze_by_ip(self, ip: str) -> None:
        """Analyze all saved outputs whose target matches the given IP."""
        # Normalize: the filename uses underscores for dots in IPs
        ip_in_filename = ip.replace(".", "_")
        saved = _list_saved_outputs()
        # Match either the real IP or the underscore-escaped version
        matches = [
            (p, t, tgt) for p, t, tgt in saved
            if tgt == ip or tgt == ip_in_filename or ip in tgt
        ]

        if matches:
            console.print(
                f"\n[dim cyan]Analyzing {len(matches)} output(s) "
                f"for host {ip}...[/dim cyan]"
            )
            for path, tool, target in matches:
                raw = _read_file(path)
                if raw.strip():
                    console.print(f"\n[dim]→ {tool} / {target}[/dim]")
                    self._ai_analyzer.analyze(
                        tool_name=tool,
                        target=target,
                        raw_output=raw,
                    )
            return

        # Fallback: session state
        results = [
            r for r in self._state.get_tool_results()
            if ip in (r.target or "") and r.raw_output
        ]
        if not results:
            console.print(f"[dim]No saved outputs found for host {ip}.[/dim]")
            return
        console.print(
            f"\n[dim cyan]Analyzing {len(results)} state result(s) "
            f"for host {ip}...[/dim cyan]"
        )
        for r in results:
            self._ai_analyzer.analyze(
                tool_name=r.tool,
                target=r.target or "unknown",
                raw_output=r.raw_output,
            )

    def _analyze_from_state_results(self) -> None:
        """Emergency fallback: no files on disk — use state raw_output directly."""
        results = [r for r in self._state.get_tool_results() if r.raw_output]
        if not results:
            console.print(
                "[dim]No tool output in session yet. Run a scan first.[/dim]"
            )
            return
        console.print(
            f"\n[dim cyan]Analyzing {len(results)} result(s) "
            f"from session state...[/dim cyan]"
        )
        for r in results:
            self._ai_analyzer.analyze(
                tool_name=r.tool,
                target=r.target or "unknown",
                raw_output=r.raw_output,
            )

    # ── Available-tools helper (used by Orchestrator for tab completion / help) ─

    def available_tools(self) -> list[str]:
        """Return all tool names found in state + saved files, sorted."""
        from_state = _state_tool_names(self._state)
        from_files = {t for _, t, _ in _list_saved_outputs()}
        return sorted(from_state | from_files)
