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

KEY DESIGN: multiple files are MERGED into one blob before the single
ai_analyzer.analyze() call — never one call per file.  This prevents
rate-limit storms (e.g. 6 rustscan files → was 12 AI calls, now 1-2).

MERGE_LIMIT controls the maximum characters fed into one analyze() call.
ai_analyzer already chunks internally at CHUNK_SIZE (10 000 chars), so
any blob under MERGE_LIMIT is handled efficiently regardless of size.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console

if TYPE_CHECKING:
    from kernox.engine.state import SessionState
    from .ai_analyzer import AIAnalyzer

console = Console()

TMP_DIR = Path("/tmp/kernox")

# Maximum characters to merge before passing to analyze().
# ai_analyzer chunks at 10 000 — this caps us at ~4 chunks max per analyze call.
MERGE_LIMIT = 40_000

# Regex: matches filenames like  nmap_192.168.0.1_20250510_123456.txt
_FILENAME_RE = re.compile(
    r"^(?P<tool>[^_]+)_(?P<target>.+?)_\d{8}_\d{6}\.txt$"
)

# IPv4 pattern (loose — just to detect IP arguments)
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# Separator inserted between merged file contents so the AI can tell them apart
_FILE_SEP = "\n\n{'='*60}\n\n"


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


def _merge_files(
    entries: list[tuple[Path, str, str]],
) -> tuple[str, str, str]:
    """
    Merge multiple (path, tool, target) entries into one blob.

    Returns (merged_output, representative_tool, representative_target).
    Files are labeled with a header so the AI knows the source of each
    section.  If the merged content would exceed MERGE_LIMIT the oldest
    files are dropped until it fits (newest = most relevant).
    """
    # Build labeled sections newest-first, then reverse so oldest is first
    sections: list[str] = []
    for path, tool, target in entries:
        raw = _read_file(path)
        if raw.strip():
            header = f"[{tool.upper()} → {target}]"
            sections.append(f"{header}\n{raw.strip()}")

    if not sections:
        return "", "", ""

    # Trim oldest sections if total exceeds MERGE_LIMIT
    while len(sections) > 1:
        candidate = _FILE_SEP.join(sections)
        if len(candidate) <= MERGE_LIMIT:
            break
        sections.pop(0)   # drop oldest

    merged = _FILE_SEP.join(sections)

    # Use the most recent entry's tool/target as the representative label
    last_path, last_tool, last_target = entries[-1]
    return merged, last_tool, last_target


class OnDemandAnalyzer:
    """
    Dispatches `analyze` commands and feeds output to the shared AIAnalyzer
    so results are 100% identical to auto-analysis.

    All multi-file strategies merge into ONE analyze() call to avoid
    rate-limit storms on providers like Groq.
    """

    def __init__(self, state: "SessionState", ai_analyzer: "AIAnalyzer") -> None:
        self._state       = state
        self._ai_analyzer = ai_analyzer

    # ── Public entry point ────────────────────────────────────────────────────

    def run(self, argument: str) -> None:
        """
        Route the argument to the right analysis strategy.

        argument is the stripped text after "analyze", e.g.:
            ""            → full session
            "all"         → full session
            "last"        → most recent output
            "192.168.0.1" → by IP
            "nmap"        → by tool name (dynamic from state)
        """
        arg = argument.strip().lower()

        if arg in ("", "all"):
            self._analyze_session()
        elif arg == "last":
            self._analyze_last()
        elif _IP_RE.match(arg):
            self._analyze_by_ip(arg)
        else:
            # Check session state first for exact tool name match
            known_tools = _state_tool_names(self._state)
            if arg in known_tools:
                self._analyze_by_tool(arg)
            else:
                # Prefix match inside state tools
                prefix_matches = [t for t in known_tools if t.startswith(arg)]
                if len(prefix_matches) == 1:
                    self._analyze_by_tool(prefix_matches[0])
                elif len(prefix_matches) > 1:
                    console.print(
                        f"[yellow]Ambiguous tool name '{arg}'. "
                        f"Matches: {', '.join(sorted(prefix_matches))}[/yellow]"
                    )
                else:
                    # Last resort: search saved files by filename prefix
                    self._analyze_by_tool_from_files(arg)

    # ── Internal: single analyze() call ──────────────────────────────────────

    def _fire(self, entries: list[tuple[Path, str, str]], label: str) -> None:
        """
        Merge entries → ONE ai_analyzer.analyze() call.
        `label` is shown to the user before analysis starts.
        """
        if not entries:
            console.print("[dim]No output to analyze.[/dim]")
            return

        merged, tool, target = _merge_files(entries)
        if not merged.strip():
            console.print("[dim]All matched files were empty.[/dim]")
            return

        n = len(entries)
        skipped = 0
        # Count how many were actually dropped due to MERGE_LIMIT
        # (_merge_files silently trims oldest; recount to inform user)
        raw_total = sum(
            len(_read_file(p)) for p, _, _ in entries if _read_file(p).strip()
        )
        if raw_total > MERGE_LIMIT and n > 1:
            skipped = n - merged.count("[") // 1  # rough — header count
            # simpler: just note that trimming may have occurred
            console.print(
                f"\n[dim cyan]{label} — merging {n} file(s) into 1 analysis call"
                f" (oldest trimmed if total > {MERGE_LIMIT // 1000}k chars)[/dim cyan]"
            )
        else:
            console.print(f"\n[dim cyan]{label} — {n} file(s) merged[/dim cyan]")

        self._ai_analyzer.analyze(
            tool_name=tool,
            target=target,
            raw_output=merged,
        )

    def _fire_from_state(
        self, results: list, label: str
    ) -> None:
        """
        Same as _fire but sources come from state raw_output instead of disk.
        Merges all raw_output strings into one blob → single analyze() call.
        """
        if not results:
            console.print("[dim]No output to analyze.[/dim]")
            return

        sections: list[str] = []
        last_tool = last_target = ""
        for r in results:
            if r.raw_output and r.raw_output.strip():
                header = f"[{r.tool.upper()} → {r.target or 'unknown'}]"
                sections.append(f"{header}\n{r.raw_output.strip()}")
                last_tool   = r.tool
                last_target = r.target or "unknown"

        if not sections:
            console.print("[dim]All matched state results were empty.[/dim]")
            return

        # Trim to MERGE_LIMIT
        while len(sections) > 1 and len(_FILE_SEP.join(sections)) > MERGE_LIMIT:
            sections.pop(0)

        merged = _FILE_SEP.join(sections)
        console.print(
            f"\n[dim cyan]{label} — {len(results)} result(s) merged[/dim cyan]"
        )
        self._ai_analyzer.analyze(
            tool_name=last_tool,
            target=last_target,
            raw_output=merged,
        )

    # ── Analysis strategies ───────────────────────────────────────────────────

    def _analyze_session(self) -> None:
        """Merge ALL saved session outputs → single analyze() call."""
        saved = _list_saved_outputs()
        if not saved:
            self._analyze_from_state_results()
            return
        self._fire(saved, f"Full session ({len(saved)} file(s))")

    def _analyze_last(self) -> None:
        """Analyze only the most recently saved output file."""
        saved = _list_saved_outputs()
        if saved:
            self._fire([saved[-1]], "Last output")
            return

        # Fallback: session state
        results = self._state.get_tool_results()
        if not results:
            console.print("[dim]No tool output in session yet.[/dim]")
            return
        last = results[-1]
        if not (last.raw_output and last.raw_output.strip()):
            console.print("[dim]Last result has no stored output.[/dim]")
            return
        self._fire_from_state([last], "Last state result")

    def _analyze_by_tool(self, tool_name: str) -> None:
        """Merge all saved files for a tool → single analyze() call."""
        saved = _list_saved_outputs()
        matches = [(p, t, tgt) for p, t, tgt in saved if t.lower() == tool_name]

        if matches:
            self._fire(matches, f"{tool_name} ({len(matches)} file(s))")
            return

        # Fallback: session state
        state_results = [
            r for r in self._state.get_tool_results()
            if r.tool.lower() == tool_name and r.raw_output
        ]
        if not state_results:
            console.print(
                f"[dim]No saved outputs found for tool '{tool_name}'.[/dim]"
            )
            return
        self._fire_from_state(
            state_results, f"{tool_name} ({len(state_results)} state result(s))"
        )

    def _analyze_by_tool_from_files(self, name: str) -> None:
        """
        Filename-prefix fallback for tools not recorded in state.
        Merges all prefix-matching files → single analyze() call.
        """
        saved = _list_saved_outputs()
        matches = [(p, t, tgt) for p, t, tgt in saved if t.lower().startswith(name)]

        if not matches:
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
                    f"[dim]No outputs found for '{name}'. Run a tool first.[/dim]"
                )
            return

        self._fire(matches, f"'{name}' prefix ({len(matches)} file(s))")

    def _analyze_by_ip(self, ip: str) -> None:
        """Merge all saved outputs for a host IP → single analyze() call."""
        ip_in_filename = ip.replace(".", "_")
        saved = _list_saved_outputs()
        matches = [
            (p, t, tgt) for p, t, tgt in saved
            if tgt == ip or tgt == ip_in_filename or ip in tgt
        ]

        if matches:
            self._fire(matches, f"Host {ip} ({len(matches)} file(s))")
            return

        # Fallback: session state
        state_results = [
            r for r in self._state.get_tool_results()
            if ip in (r.target or "") and r.raw_output
        ]
        if not state_results:
            console.print(f"[dim]No saved outputs found for host {ip}.[/dim]")
            return
        self._fire_from_state(
            state_results, f"Host {ip} ({len(state_results)} state result(s))"
        )

    def _analyze_from_state_results(self) -> None:
        """Emergency fallback: no files on disk — merge state raw_output → one call."""
        results = [r for r in self._state.get_tool_results() if r.raw_output]
        if not results:
            console.print(
                "[dim]No tool output in session yet. Run a scan first.[/dim]"
            )
            return
        self._fire_from_state(results, f"Full session state ({len(results)} result(s))")

    # ── Available-tools helper (used by Orchestrator for tab-complete / help) ─

    def available_tools(self) -> list[str]:
        """Return all tool names found in state + saved files, sorted."""
        from_state = _state_tool_names(self._state)
        from_files = {t for _, t, _ in _list_saved_outputs()}
        return sorted(from_state | from_files)