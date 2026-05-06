"""
output_formatter.py — Universal AI-driven display layer.

Phase 1 (immediate): Show ALL raw output — every line, no truncation.
                     Fast regex used ONLY for known structured formats (nmap/ffuf etc.)
                     to render a table. Falls back to raw lines for anything else.

Phase 2 (after AI):  Show AI-refined vulnerability panels + next steps.
                     format_vulnerability() and format_analysis_summary() are called
                     by ai_analyzer after it processes the output.

Design: output_formatter NEVER truncates. It shows everything.
"""

from __future__ import annotations

import re
import json as _json
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()

# ANSI escape code stripper
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[mGKHFABCDsuJr]|\x1b[=>]|\x1b\[\?[0-9;]*[lh]")

def _strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from text."""
    return _ANSI_RE.sub("", text)


def _print_raw_lines(output: str) -> None:
    """Print every non-empty line of output, stripping ANSI codes.
    Uses markup=False and highlight=False so Rich doesn't misparse
    brackets, color codes, or special chars in tool output.
    """
    for line in output.splitlines():
        clean = _strip_ansi(line).rstrip()
        if clean:
            console.print(f"  {clean}", markup=False, highlight=False)


C = {
    "primary": "cyan",
    "ok":      "#55efc4",
    "warn":    "#00b894",
    "err":     "#ff6b6b",
    "dim":     "dim cyan",
}

SEV_COLORS = {
    "critical": ("#ff6b6b", True),
    "high":     ("red",     True),
    "medium":   ("#00b894", False),
    "low":      ("cyan",    False),
    "info":     ("dim white", False),
}


class OutputFormatter:

    @staticmethod
    def format_output(tool_name: str, output: str, target: str = "") -> None:
        """
        Show ALL tool output immediately after execution.
        Tries structured table display first (for known tools), then ALWAYS
        prints the full raw output below. Never truncates. Never hides output.
        """
        if not output or not output.strip():
            return

        # Try structured parsers in order — if a match is found, show the
        # table for quick reading AND then print the full raw output below.
        for parser in [
            OutputFormatter._parse_nmap,
            OutputFormatter._parse_ffuf,
            OutputFormatter._parse_gobuster,
            OutputFormatter._parse_nikto,
            OutputFormatter._parse_whatweb,
            OutputFormatter._parse_hydra,
            OutputFormatter._parse_sqlmap,
            OutputFormatter._parse_searchsploit,
            OutputFormatter._parse_nuclei,
            OutputFormatter._parse_generic_table,
        ]:
            table = parser(output)
            if table is not None:
                console.print(table)
                # Also show full raw output so nothing is hidden
                console.print("[dim]─── full output ───[/dim]")
                _print_raw_lines(output)
                return

        # No structured parser matched — print EVERY line raw, no truncation
        _print_raw_lines(output)

    @staticmethod
    def format_analysis_summary(summary: str, next_steps: list[dict]) -> None:
        if summary:
            console.print(f"\n[bold cyan]⚡ Analysis:[/bold cyan] {summary}")
        if next_steps:
            console.print(f"\n[{C['ok']}]Suggested next steps:[/{C['ok']}]")
            for i, step in enumerate(next_steps, 1):
                cmd    = step.get("args", {}).get("command", "")
                reason = step.get("reason", "")
                console.print(f"  [{C['dim']}]{i}.[/{C['dim']}] [white]{cmd}[/white]")
                if reason:
                    console.print(f"     [dim]{reason}[/dim]")

    @staticmethod
    def format_vulnerability(vuln: dict) -> None:
        sev           = vuln.get("severity", "info").lower()
        col, is_bold  = SEV_COLORS.get(sev, ("dim white", False))
        bold          = "bold " if is_bold else ""
        bars          = "█" * {"critical":5,"high":4,"medium":3,"low":2,"info":1}.get(sev, 1)

        lines = [f"[{bold}{col}]{bars} {sev.upper()}[/{bold}{col}]\n"]
        name  = vuln.get("name", "Unknown")
        lines.append(f"[bold white]{name}[/bold white]\n")
        if vuln.get("description"):
            lines.append(f"[dim]{vuln['description']}[/dim]\n")
        if vuln.get("impact"):
            lines.append(f"\n[{C['warn']}]Impact:[/{C['warn']}] {vuln['impact']}")
        if vuln.get("exploit"):
            lines.append(f"\n[{C['ok']}]Exploit:[/{C['ok']}]")
            lines.append(f"\n[dim cyan]{vuln['exploit']}[/dim cyan]")

        console.print(Panel(
            "\n".join(lines),
            title=f"[{bold}{col}] Finding [/{bold}{col}]",
            border_style=col,
            box=box.ROUNDED,
            padding=(0, 1),
        ))

    # ── Structured parsers — ALL rows, no caps ─────────────────────────────────

    @staticmethod
    def _parse_nmap(raw: str) -> Table | None:
        re_port = re.compile(r"(\d+/\w+)\s+(open|closed|filtered)\s+(\S+)(.*)")
        rows = [m for m in (re_port.match(l) for l in raw.splitlines()) if m]
        if not rows:
            return None
        t = _table("nmap — ports", ["PORT","STATE","SERVICE","VERSION"])
        for m in rows:
            col = C["ok"] if m.group(2) == "open" else C["err"]
            t.add_row(
                f"[{C['primary']}]{m.group(1)}[/{C['primary']}]",
                f"[{col}]{m.group(2)}[/{col}]",
                m.group(3), m.group(4).strip(),
            )
        return t

    @staticmethod
    def _parse_ffuf(raw: str) -> Table | None:
        if '"results"' in raw and '"url"' in raw:
            try:
                results = _json.loads(raw).get("results", [])
                if not results:
                    return None
                t = _table("ffuf — results", ["STATUS","LENGTH","WORDS","URL"])
                for r in results:
                    st  = str(r.get("status",""))
                    col = C["ok"] if st=="200" else C["warn"] if st.startswith("3") else C["primary"]
                    t.add_row(f"[{col}]{st}[/{col}]",
                              str(r.get("length","")), str(r.get("words","")), r.get("url",""))
                return t
            except Exception:
                pass
        re_line = re.compile(r"\*\s+\w+\s+\[Status:\s*(\d+)[^\]]*\]\s+\*\s+\S+\s+(.+)")
        rows = [m for m in (re_line.search(l) for l in raw.splitlines()) if m]
        if not rows:
            return None
        t = _table("ffuf — results", ["STATUS","SIZE","PATH"])
        for m in rows:
            st  = m.group(1)
            col = C["ok"] if st=="200" else C["warn"] if st.startswith("3") else C["primary"]
            t.add_row(f"[{col}]{st}[/{col}]", "", m.group(2).strip())
        return t

    @staticmethod
    def _parse_gobuster(raw: str) -> Table | None:
        re_line = re.compile(r"(/\S+)\s+\(Status:\s*(\d+)\)")
        rows = [m for m in (re_line.search(l) for l in raw.splitlines()) if m]
        if not rows:
            return None
        t = _table("gobuster — paths", ["PATH","STATUS"])
        for m in rows:
            st  = m.group(2)
            col = C["ok"] if st=="200" else C["warn"] if st.startswith("3") else C["primary"]
            t.add_row(m.group(1), f"[{col}]{st}[/{col}]")
        return t

    @staticmethod
    def _parse_nikto(raw: str) -> Table | None:
        re_line = re.compile(r"\+\s+(OSVDB-\d+|[A-Z]{2,}[^:]*)?:?\s*(.{20,})")
        rows = [m for m in (re_line.match(l) for l in raw.splitlines()) if m]
        if len(rows) < 2:
            return None
        t = _table("nikto — findings", ["ID","Finding"])
        for m in rows:
            t.add_row(f"[{C['warn']}]{m.group(1) or '—'}[/{C['warn']}]", m.group(2).strip())
        return t

    @staticmethod
    def _parse_whatweb(raw: str) -> Table | None:
        if "WhatWeb" not in raw and "whatweb" not in raw.lower():
            return None
        re_url = re.compile(r"(https?://\S+)\s+\[(\d+)[^\]]*\]\s+(.*)")
        rows = [m for m in (re_url.match(l) for l in raw.splitlines()) if m]
        if not rows:
            return None
        t = _table("whatweb — technologies", ["URL","STATUS","Technologies"])
        for m in rows:
            t.add_row(f"[{C['primary']}]{m.group(1)}[/{C['primary']}]", m.group(2), m.group(3))
        return t

    @staticmethod
    def _parse_hydra(raw: str) -> Table | None:
        re_cred = re.compile(r"\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)")
        rows = [m for m in (re_cred.search(l) for l in raw.splitlines()) if m]
        if not rows:
            return None
        t = _table("hydra — credentials", ["PORT","SERVICE","HOST","LOGIN","PASSWORD"], border=C["ok"])
        for m in rows:
            t.add_row(m.group(1), m.group(2), m.group(3),
                      f"[{C['ok']}]{m.group(4)}[/{C['ok']}]",
                      f"[bold {C['ok']}]{m.group(5)}[/bold {C['ok']}]")
        return t

    @staticmethod
    def _parse_sqlmap(raw: str) -> Table | None:
        if "sqlmap" not in raw.lower():
            return None
        re_kv = re.compile(r"(Parameter|Type|Title|Payload|Place):\s+(.+)", re.IGNORECASE)
        rows  = [(m.group(1), m.group(2)) for m in (re_kv.search(l) for l in raw.splitlines()) if m]
        if len(rows) < 2:
            return None
        t = _table("sqlmap — injection", ["Field","Value"])
        for k, v in rows:
            t.add_row(f"[{C['warn']}]{k}[/{C['warn']}]", v)
        return t

    @staticmethod
    def _parse_searchsploit(raw: str) -> Table | None:
        sep_re = re.compile(r"-{10,}")
        lines  = raw.splitlines()
        seps   = [i for i, l in enumerate(lines) if sep_re.match(l)]
        if len(seps) < 2:
            return None
        data = lines[seps[0]+1:seps[1]]
        t    = _table("searchsploit — exploits", ["Title","Path"])
        for line in data:
            if "|" in line:
                p = line.split("|", 1)
                t.add_row(p[0].strip(), f"[{C['dim']}]{p[1].strip()}[/{C['dim']}]")
        return t if t.row_count else None

    @staticmethod
    def _parse_nuclei(raw: str) -> Table | None:
        re_line = re.compile(
            r"\[(critical|high|medium|low|info)\]\s+\[([^\]]+)\]\s+(\S+)(.*)", re.IGNORECASE)
        rows = [m for m in (re_line.search(l) for l in raw.splitlines()) if m]
        if not rows:
            return None
        t = _table("nuclei — findings", ["SEV","TEMPLATE","TARGET","INFO"])
        for m in rows:
            sev = m.group(1).lower()
            col = SEV_COLORS.get(sev, ("dim white", False))[0]
            t.add_row(f"[{col}]{sev.upper()}[/{col}]",
                      m.group(2), m.group(3), m.group(4).strip())
        return t

    @staticmethod
    def _parse_generic_table(raw: str) -> Table | None:
        lines     = [l for l in raw.splitlines() if l.strip()]
        tab_lines = [l for l in lines if "\t" in l]
        if len(tab_lines) < 3:
            return None
        cols = tab_lines[0].split("\t")
        if not (2 <= len(cols) <= 10):
            return None
        t = _table("output", [c.strip()[:25] for c in cols])
        for row in tab_lines[1:]:
            t.add_row(*[c.strip() for c in row.split("\t")[:len(cols)]])
        return t if t.row_count else None


def _table(title: str, columns: list[str], border: str = "dim cyan") -> Table:
    t = Table(title=title, box=box.MINIMAL, show_header=True,
              header_style=f"bold {C['primary']}", border_style=border,
              title_style=f"bold {C['primary']}", padding=(0,1))
    for col in columns:
        t.add_column(col, style="white", no_wrap=False)
    return t

