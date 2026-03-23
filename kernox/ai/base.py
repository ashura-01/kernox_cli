"""
kernox.ai.base  –  Abstract contract for all AI backends.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional


class BaseAIClient(ABC):
    """Every AI backend must implement this interface."""

    @abstractmethod
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
        ...

    def is_available(self) -> bool:
        """Return True if the backend can be reached (optional health check)."""
        return True
