"""
orchestrator_helpers.context_builder — Builds agent memory context.

Turns SessionState into a concise text block injected into every
AI planning call so the AI acts on what it already knows.

This is what makes Kernox a real agent — the AI sees:
  - Every host discovered + open ports
  - Every vulnerability already found
  - Every tool already run + what it found
  - Outstanding high-value targets not yet attacked

Without this, the AI plans blind every turn.
"""

from __future__ import annotations

from kernox.engine.state import SessionState


def build_agent_context(state: SessionState) -> str:
    """
    Returns a concise context block for injection into the planning prompt.
    Empty string if session has no data yet (first run).
    """
    parts: list[str] = []

    # ── Vulnerabilities — critical/high FIRST so any cap keeps them ──────────
    insights = state.get_ai_insights()
    if insights:
        crit  = [i for i in insights if i.severity.lower() == "critical"]
        high  = [i for i in insights if i.severity.lower() == "high"]
        other = [i for i in insights if i.severity.lower() not in ("critical","high")]

        parts.append("VULNS:")
        for ins in (crit + high)[:8]:
            expl = ""
            if isinstance(ins.ai_explanation, dict):
                expl = ins.ai_explanation.get("exploit","")[:80]
            parts.append(
                f"  [{ins.severity.upper()}] {ins.vulnerability}@{ins.target}"
                + (f" → {expl}" if expl else "")
            )
        if other:
            parts.append(f"  +{len(other)} medium/low")

    # ── Hosts — after vulns so critical findings always survive a cap ─────────
    hosts = state.hosts
    if hosts:
        parts.append("HOSTS:")
        for ip, h in list(hosts.items())[:8]:
            ports_str = ", ".join(
                f"{p['port']}/{p.get('service','?')}"
                for p in (h.ports or [])[:10]
            )
            os_str = f"[{h.os}]" if h.os else ""
            parts.append(f"  {ip}{os_str}: {ports_str or 'unknown'}")

    # ── Tools already run ─────────────────────────────────────────────────────
    results = state.get_tool_results()
    if results:
        # Deduplicate: show each tool+target combo once
        seen: set[str] = set()
        tool_lines: list[str] = []
        for r in reversed(results):   # most recent first
            key = f"{r.tool}@{r.target}"
            if key not in seen:
                seen.add(key)
                tool_lines.append(f"  {r.tool} → {r.target}")
            if len(seen) >= 12:
                break
        parts.append(f"TOOLS ALREADY RUN ({len(results)} total):")
        parts.extend(tool_lines)

    # ── Paths discovered ──────────────────────────────────────────────────────
    paths = state.paths
    if paths:
        parts.append("WEB PATHS FOUND:")
        for target, found in list(paths.items())[:3]:
            sample = ", ".join(f["path"] for f in found[:6])
            parts.append(f"  {target}: {sample}")

    # ── Reflection notes (AI's own observations) ──────────────────────────────
    notes = [n for n in state._notes if n.startswith("[REFLECTION")]
    if notes:
        parts.append("AI REFLECTIONS (recent):")
        for note in notes[-5:]:   # last 5 reflections
            parts.append(f"  {note[:200]}")

    if not parts:
        return ""

    return (
        "\n--- AGENT MEMORY (what you already know) ---\n"
        + "\n".join(parts)
        + "\n--- USE THIS TO PLAN NEXT STEPS — don't repeat completed work ---\n"
    )


def build_cve_fallback(vuln_name: str, severity: str) -> str:
    """
    Called when CVE lookup returns nothing.
    Returns a human-readable message instead of silent nothing.
    """
    score_map = {
        "critical": "9.0–10.0",
        "high":     "7.0–8.9",
        "medium":   "4.0–6.9",
        "low":      "0.1–3.9",
        "info":     "0.0",
    }
    score_range = score_map.get(severity.lower(), "unknown")
    return (
        f"  [dim]No CVE match found for '{vuln_name[:50]}' — "
        f"AI-assessed severity: {severity.upper()} "
        f"(CVSS ~{score_range})[/dim]"
    )
