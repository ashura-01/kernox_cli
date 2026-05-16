"""
chat_handler.py — NL command routing and chat handling with ACTUAL output access.
"""

from __future__ import annotations

import re
import glob
import os
from pathlib import Path
from typing import Optional

_BUILTIN_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(generate|create|make|export|write|produce|give|show).{0,20}report", re.I), "report"),
    (re.compile(r"report.{0,20}(generate|create|make|export|pdf)", re.I), "report"),
    (re.compile(r"\bpdf\b", re.I), "report"),
    (re.compile(r"(show|display|list|what|any).{0,20}(finding|vuln|result|discover|found)", re.I), "state"),
    (re.compile(r"(show|display|print).{0,20}state", re.I), "state"),
    (re.compile(r"what.{0,10}(did you|have you|was).{0,10}find", re.I), "state"),
    (re.compile(r"(show|display|list|what).{0,20}(cvss|score|risk|severity)", re.I), "score"),
    (re.compile(r"(show|display|list|print).{0,20}(log|timeline|history|attack)", re.I), "log"),
    (re.compile(r"(save|store|backup).{0,20}session", re.I), "save"),
    (re.compile(r"(list|show|display).{0,20}session", re.I), "sessions"),
    (re.compile(r"(build|create|make|generate).{0,20}payload", re.I), "payload"),
    (re.compile(r"\bmsfvenom\b.*(help|guide|build|create|generate)", re.I), "payload"),
    (re.compile(r"\bcve\b", re.I), "cve"),
    (re.compile(r"(search|lookup|find|check).{0,20}(cve|vulnerability|exploit)", re.I), "cve"),
    (re.compile(r"(switch|change|set).{0,20}(mode|intensity|stealth|aggressive|normal|full)", re.I), "mode"),
]


def detect_builtin(text: str) -> str | None:
    for pattern, cmd in _BUILTIN_PATTERNS:
        if pattern.search(text):
            return cmd
    return None


class ChatHandler:
    def __init__(self, ai_client, state, history):
        self._ai      = ai_client
        self._state   = state
        self._history = history
        self._output_dir = Path("/tmp/kernox")
        self._command_history = []

    def _get_extracted_file_content(self) -> Optional[str]:
        """Get the content of the extracted file (target.jpg.out)"""
        out_file = Path("target.jpg.out")
        if out_file.exists():
            return out_file.read_text(encoding='utf-8', errors='replace').strip()
        return None

    def _get_stegseek_log(self) -> Optional[tuple[Path, str]]:
        """Get the stegseek log file"""
        try:
            if self._output_dir.exists():
                files = list(self._output_dir.glob("stegseek_*.txt"))
                if files:
                    latest = max(files, key=lambda p: p.stat().st_ctime)
                    content = latest.read_text(encoding='utf-8', errors='replace')
                    return latest, content
        except Exception:
            pass
        return None

    def _get_latest_output_file(self) -> Optional[Path]:
        try:
            if self._output_dir.exists():
                files = list(self._output_dir.glob("*.txt"))
                if files:
                    return max(files, key=lambda p: p.stat().st_ctime)
            return None
        except Exception:
            return None

    def chat(self, question: str) -> str:
        """Answer questions using AI with full context of what happened."""

        # Build context from session state and recent commands
        context_parts = []

        # Add recent tool outputs
        results = self._state.get_tool_results()
        if results:
            recent = results[-3:]  # Last 3 tool runs
            for r in recent:
                context_parts.append(f"Tool: {r.tool}")
                context_parts.append(f"Target: {r.target}")
                if r.raw_output:
                    # Truncate long outputs
                    output = r.raw_output[:2000]
                    context_parts.append(f"Output:\n{output}")

        # Add conversation history
        if self._history:
            recent_history = self._history[-5:]  # Last 5 exchanges
            for msg in recent_history:
                role = msg.get("role", "unknown")
                content = msg.get("content", "")[:500]
                context_parts.append(f"[{role}]: {content}")

        context = "\n".join(context_parts) if context_parts else "No previous commands run yet."

        system_prompt = f"""You are Kernox, an AI penetration testing assistant. Answer the user's question based ONLY on the context provided.

    CONTEXT (previous commands and their outputs):
    {context}

    USER QUESTION: {question}

    RULES:
    - If the user asks for IPs or hosts, list them exactly as they appeared in tool outputs
    - Be specific and factual - don't invent data not in context
    - If the answer isn't in context, say "I don't see that in the previous command outputs"
    - Keep answers concise and useful

    Answer:"""

        try:
            response = self._ai.chat(
                messages=[{"role": "user", "content": system_prompt}],
                max_tokens=500,
            )
            return response
        except Exception as e:
            return f"Error: {e}\n\nTry being more specific about what you want to know."

        # Fallback to file reading only if AI fails
        latest = self._get_latest_output_file()
        if latest:
            content = latest.read_text(encoding='utf-8', errors='replace')[:1000]
            return f"**Last output file:** `{latest.name}`\n```\n{content}\n```"

        return "No output files found. Run a command first."

    def record_command(self, command: str, output_file: str):
        # print(f"[DEBUG] Recording: {command} -> {output_file}")
        self._command_history.append({
            'command': command,
            'output_file': output_file,
            'timestamp': __import__('time').time()
        })
