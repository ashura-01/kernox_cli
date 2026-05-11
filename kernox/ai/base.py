"""
kernox.ai.base  –  Abstract contract for all AI backends.

Global rate limiter
───────────────────
A single module-level lock + timestamp gates every .chat() call across
ALL backends and ALL callers (orchestrator, ai_analyzer, reflection_engine).

Why here and not in each caller:
  - One place to change the delay
  - Subclasses get it for free — no changes to OllamaClient, ClaudeClient, etc.
  - No import chains or circular dependencies

Provider-safe defaults
  Cerebras free : ~30 req/min, enforces ~2 s between requests
  Groq free     : ~30 req/min, enforces ~2 s between requests
  OpenAI        : no hard per-request interval (but we still space calls)
  Claude        : generous limits, 1 s spacing is fine
  Ollama        : local, no limit — delay is effectively 0 after first call

INTER_CALL_DELAY is conservative enough for every free-tier provider.
Users on paid tiers can lower it via config (see __init_subclass__ hook below)
or by setting BaseAIClient.INTER_CALL_DELAY at startup.
"""

from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from typing import Optional

# ── Global rate-limit state ───────────────────────────────────────────────────


_RATE_LOCK      = threading.Lock()
_last_call_time: float = 0.0


INTER_CALL_DELAY: float = 2.0


class BaseAIClient(ABC):

    INTER_CALL_DELAY: float | None = None

    # ── Rate limiting ─────────────────────────────────────────────────────────

    def _wait_for_rate_limit(self) -> None:
        """
        Block until enough time has passed since the last API call.

        Uses a process-wide lock so concurrent calls (shouldn't happen in
        kernox's single-threaded loop, but just in case) don't race.
        """
        global _last_call_time

        delay = (
            self.INTER_CALL_DELAY
            if self.INTER_CALL_DELAY is not None
            else INTER_CALL_DELAY
        )

        if delay <= 0:
            return

        with _RATE_LOCK:
            elapsed = time.monotonic() - _last_call_time
            remaining = delay - elapsed
            if remaining > 0:
                time.sleep(remaining)
            _last_call_time = time.monotonic()

    # ── Public interface ──────────────────────────────────────────────────────

    def chat(
        self,
        messages: list[dict],
        *,
        system: Optional[str] = None,
        max_tokens: int = 2048,
        temperature: float = 0.2,
    ) -> str:
        """
        Send *messages* to the AI and return the assistant reply as a string.

        Rate-limits automatically before calling _chat_impl().
        Subclasses implement _chat_impl(), not this method.

        Parameters
        ----------
        messages:
            List of ``{"role": "user"|"assistant", "content": "..."}`` dicts.
        system:
            Optional system prompt.
        max_tokens:
            Upper limit on generated tokens.
        temperature:
            Sampling temperature (lower = more deterministic).
        """
        self._wait_for_rate_limit()
        return self._chat_impl(
            messages=messages,
            system=system,
            max_tokens=max_tokens,
            temperature=temperature,
        )

    @abstractmethod
    def _chat_impl(
        self,
        messages: list[dict],
        *,
        system: Optional[str] = None,
        max_tokens: int = 2048,
        temperature: float = 0.2,
    ) -> str:
        """
        Backend-specific implementation.  Do NOT call _wait_for_rate_limit()
        here — the base chat() already did it.
        """
        ...

    def is_available(self) -> bool:
        """Return True if the backend can be reached (optional health check)."""
        return True
