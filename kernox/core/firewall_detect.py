"""
kernox.core.firewall_detect  –  Detect firewall/IDS blocking and suggest evasion.

After an nmap scan, this module analyses the results for signs of filtering
and returns an evasion strategy the orchestrator can apply on retry.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich import box

console = Console()


@dataclass
class FirewallAnalysis:
    detected: bool
    confidence: str          # "high" | "medium" | "low"
    indicators: list[str]
    evasion_flags: str       # ready-to-use nmap flags for retry
    strategy: str            # human-readable explanation


# ── Indicator patterns ────────────────────────────────────────────────────────

FILTERED_PORT_RE = re.compile(r"\d+/tcp\s+filtered", re.MULTILINE)
RESET_COUNT_RE   = re.compile(r"(\d+) closed tcp ports \(reset\)")
NO_RESPONSE_RE   = re.compile(r"(\d+) closed tcp ports \(no-response\)")
ADMIN_PROHIB_RE  = re.compile(r"admin-prohibited", re.IGNORECASE)
PKT_FILTERED_RE  = re.compile(r"packet-filtered", re.IGNORECASE)
HOST_DOWN_RE     = re.compile(r"Host seems down", re.IGNORECASE)
ALL_FILTERED_RE  = re.compile(r"All \d+ scanned ports.*filtered", re.IGNORECASE)
ZERO_HOSTS_RE    = re.compile(r"0 hosts up", re.IGNORECASE)


def analyse_firewall(nmap_output: str) -> FirewallAnalysis:
    """
    Analyse raw nmap output for firewall/IDS indicators.
    Returns a FirewallAnalysis with evasion recommendations.
    """
    indicators: list[str] = []
    score = 0

    # Count filtered ports
    filtered_ports = FILTERED_PORT_RE.findall(nmap_output)
    if len(filtered_ports) > 5:
        indicators.append(f"{len(filtered_ports)} filtered ports detected")
        score += 3
    elif len(filtered_ports) > 0:
        indicators.append(f"{len(filtered_ports)} filtered port(s) detected")
        score += 1

    # Host appears down (likely ICMP blocked)
    if HOST_DOWN_RE.search(nmap_output):
        indicators.append("Host appears down — ICMP likely blocked")
        score += 3

    # All ports filtered
    if ALL_FILTERED_RE.search(nmap_output):
        indicators.append("All scanned ports are filtered")
        score += 3

    # No-response closed ports (stateful firewall)
    no_resp = NO_RESPONSE_RE.search(nmap_output)
    if no_resp and int(no_resp.group(1)) > 100:
        indicators.append("High no-response closed ports — stateful firewall likely")
        score += 2

    # Admin prohibited ICMP
    if ADMIN_PROHIB_RE.search(nmap_output):
        indicators.append("ICMP admin-prohibited responses — firewall confirmed")
        score += 3

    # Packet filtered
    if PKT_FILTERED_RE.search(nmap_output):
        indicators.append("Packet filtering detected")
        score += 2

    # Zero hosts up
    if ZERO_HOSTS_RE.search(nmap_output):
        indicators.append("No hosts reported up — host discovery blocked")
        score += 3

    detected = score > 0

    if score >= 6:
        confidence = "high"
    elif score >= 3:
        confidence = "medium"
    else:
        confidence = "low"

    evasion_flags, strategy = _build_evasion(indicators, score)

    return FirewallAnalysis(
        detected=detected,
        confidence=confidence,
        indicators=indicators,
        evasion_flags=evasion_flags,
        strategy=strategy,
    )


def _build_evasion(indicators: list[str], score: int) -> tuple[str, str]:
    """Build nmap evasion flags based on detected indicators."""
    flags: list[str] = []
    strategies: list[str] = []

    # Always skip host discovery if firewall detected
    flags.append("-Pn")
    strategies.append("-Pn: skip ICMP host discovery")

    if score >= 6:
        # Heavy firewall — use fragmentation + decoy + slow timing
        flags += ["-sS", "-f", "--scan-delay", "500ms", "-T2"]
        strategies += [
            "-sS: SYN stealth scan",
            "-f: fragment packets",
            "--scan-delay 500ms: slow down to evade IDS",
            "-T2: polite timing",
        ]
    elif score >= 3:
        # Medium firewall — SYN scan + slight delay
        flags += ["-sS", "--scan-delay", "200ms", "-T3"]
        strategies += [
            "-sS: SYN stealth scan",
            "--scan-delay 200ms: slight delay",
        ]
    else:
        # Light filtering — just skip host discovery
        flags += ["-T4"]

    return " ".join(flags), " | ".join(strategies)


def print_firewall_analysis(analysis: FirewallAnalysis) -> None:
    """Render firewall analysis as a rich panel."""
    if not analysis.detected:
        return

    color = {"high": "red", "medium": "yellow", "low": "cyan"}.get(analysis.confidence, "yellow")

    lines = [
        f"[bold {color}]🛡 Firewall/IDS detected[/bold {color}]  "
        f"[dim](confidence: {analysis.confidence})[/dim]\n",
    ]

    for indicator in analysis.indicators:
        lines.append(f"  [dim]•[/dim] {indicator}")

    lines.append(f"\n[bold green]Evasion strategy:[/bold green] {analysis.strategy}")
    lines.append(f"[dim]Retry flags:[/dim] [cyan]{analysis.evasion_flags}[/cyan]")

    console.print(Panel(
        "\n".join(lines),
        title="[bold red]Firewall Analysis[/bold red]",
        border_style=color,
        box=box.ROUNDED,
    ))
