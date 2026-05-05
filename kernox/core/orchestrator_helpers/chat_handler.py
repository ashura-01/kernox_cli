"""
chat_handler.py — NL command routing and chat handling.

Routing is done by the AI via is_chat flag in JSON response.
No hardcoded keyword lists. No mechanical routing.

Built-in command detection from natural language:
  "generate report" → triggers report
  "show findings"   → triggers state
  "save session"    → triggers save
  etc.
"""

from __future__ import annotations

import re

# ── Natural language → built-in command mapping ───────────────────────────────
# These patterns are checked BEFORE sending to AI so built-ins always work
# regardless of how the user phrases them.
_BUILTIN_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Report
    (re.compile(r"(generate|create|make|export|write|produce|give|show).{0,20}report", re.I), "report"),
    (re.compile(r"report.{0,20}(generate|create|make|export|pdf)", re.I), "report"),
    (re.compile(r"\bpdf\b", re.I), "report"),

    # State / findings
    (re.compile(r"(show|display|list|what|any).{0,20}(finding|vuln|result|discover|found)", re.I), "state"),
    (re.compile(r"(show|display|print).{0,20}state", re.I), "state"),
    (re.compile(r"what.{0,10}(did you|have you|was).{0,10}find", re.I), "state"),

    # Score
    (re.compile(r"(show|display|list|what).{0,20}(cvss|score|risk|severity)", re.I), "score"),

    # Log
    (re.compile(r"(show|display|list|print).{0,20}(log|timeline|history|attack)", re.I), "log"),

    # Save
    (re.compile(r"(save|store|backup).{0,20}session", re.I), "save"),

    # Sessions
    (re.compile(r"(list|show|display).{0,20}session", re.I), "sessions"),

    # Payload
    (re.compile(r"(build|create|make|generate).{0,20}payload", re.I), "payload"),
    (re.compile(r"\bmsfvenom\b.*(help|guide|build|create|generate)", re.I), "payload"),

    # CVE
    (re.compile(r"\bcve\b", re.I), "cve"),
    (re.compile(r"(search|lookup|find|check).{0,20}(cve|vulnerability|exploit)", re.I), "cve"),

    # Mode
    (re.compile(r"(switch|change|set).{0,20}(mode|intensity|stealth|aggressive|normal|full)", re.I), "mode"),
]


def detect_builtin(text: str) -> str | None:
    """
    Check if natural language input maps to a built-in command.
    Returns the command string or None.
    """
    for pattern, cmd in _BUILTIN_PATTERNS:
        if pattern.search(text):
            return cmd
    return None


class ChatHandler:
    def __init__(self, ai_client, state, history):
        self._ai      = ai_client
        self._state   = state
        self._history = history

    def chat(self, question: str) -> str:
        """Handle a pure chat/question — no tool execution."""
        response = self._ai.chat(
            messages=[{"role": "user", "content": question}],
            system=(
                "You are Kernox, an autonomous offensive security pentesting AI. "
                "Answer concisely with exact commands and attack techniques. "
                "Never suggest patching, hardening, or remediation. "
                "Use markdown and code blocks for commands."
            ),
            max_tokens=800,
        )
        return response
