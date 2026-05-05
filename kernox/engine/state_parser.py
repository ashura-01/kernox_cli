"""
kernox.engine.state_parser — Universal AI-driven tool output parser.

IMPORTANT DESIGN DECISION:
  state_parser is now a THIN WRAPPER that delegates to ai_analyzer.
  The ai_analyzer ALREADY sends full output to AI for vuln analysis.
  We extract structured state (hosts/ports/paths/creds) from THAT same
  analysis response — no second AI call.

  auto_parse() is called with the ai_analyzer instance.
  If ai_analyzer is None (e.g. PTY tools), it makes its own compact call.
"""

from __future__ import annotations

import json
import re
from kernox.engine.state import SessionState


_EXTRACT_SYSTEM = (
    "You are a data extraction engine. Read pentesting tool output and "
    "extract structured findings. Return ONLY valid JSON. No markdown."
)

_EXTRACT_PROMPT = """\
Tool: {tool}
Target: {target}
Output:
{output}

Return ONLY this JSON (empty arrays if nothing found):
{{
  "hosts": [{{"ip":"","hostname":"","os":""}}],
  "ports": [{{"ip":"","port":0,"proto":"tcp","service":"","version":""}}],
  "credentials": [{{"host":"","service":"","login":"","password":""}}],
  "paths": [{{"path":"","status":0}}],
  "findings": [{{"type":"","detail":"","severity":"info"}}]
}}"""


def auto_parse(
    tool_name:  str,
    target:     str,
    raw_output: str,
    state:      SessionState,
    ai_client=None,
    parsed_data: dict | None = None,
) -> None:
    """
    Update state with structured data from tool output.

    Two modes:
    1. parsed_data provided — ai_analyzer already parsed it, just apply to state
       (zero extra AI calls — this is the normal path)
    2. parsed_data=None + ai_client provided — make a compact AI call ourselves
       (used for PTY tools where ai_analyzer doesn't run)
    """
    if not raw_output or not raw_output.strip():
        return

    try:
        if parsed_data is not None:
            # Fast path: use already-parsed data from ai_analyzer
            _apply_to_state(parsed_data, target, state)
        elif ai_client is not None:
            # PTY path: make our own compact extraction call
            preview = raw_output[:6000]
            prompt  = _EXTRACT_PROMPT.format(
                tool=tool_name, target=target, output=preview
            )
            response = ai_client.chat(
                messages=[{"role": "user", "content": prompt}],
                system=_EXTRACT_SYSTEM,
                max_tokens=500,
            )
            data = _extract_json(response)
            if data:
                _apply_to_state(data, target, state)
    except Exception:
        pass


def _apply_to_state(data: dict, target: str, state: SessionState) -> None:
    for h in data.get("hosts", []):
        ip = (h.get("ip") or "").strip()
        if ip:
            state.upsert_host(
                ip,
                hostname=(h.get("hostname") or "").strip() or None,
                os=(h.get("os") or "").strip() or None,
            )

    for p in data.get("ports", []):
        ip   = (p.get("ip") or target).strip() or target
        port = p.get("port")
        if port:
            try:
                port = int(port)
            except (ValueError, TypeError):
                continue
            if port > 0:
                state.upsert_host(ip)
                state.add_ports(ip, [{
                    "port":    port,
                    "proto":   p.get("proto", "tcp"),
                    "service": p.get("service", ""),
                    "version": str(p.get("version", ""))[:80],
                }])

    for c in data.get("credentials", []):
        host = (c.get("host") or target).strip() or target
        if c.get("login") or c.get("password"):
            state.add_vuln(host, {
                "type":     "credential",
                "service":  c.get("service", ""),
                "login":    c.get("login", ""),
                "password": c.get("password", ""),
            })

    paths = [p for p in data.get("paths", []) if p.get("path")]
    if paths:
        state.add_paths(target, [
            {"path": p["path"], "status": p.get("status", 0)}
            for p in paths
        ])

    for f in data.get("findings", []):
        if f.get("detail") or f.get("type"):
            state.add_vuln(target, {
                "type":     f.get("type", "finding"),
                "detail":   str(f.get("detail", ""))[:300],
                "severity": f.get("severity", "info"),
            })


def _extract_json(text: str) -> dict | None:
    text = text.strip()
    if text.startswith("```"):
        text = "\n".join(
            l for l in text.split("\n")
            if not l.strip().startswith("```")
        ).strip()
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group())
    except json.JSONDecodeError:
        return None
