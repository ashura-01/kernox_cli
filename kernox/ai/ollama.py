"""
kernox.ai.ollama  –  Local Ollama AI client.
"""

from __future__ import annotations

from typing import Optional

import requests
from rich.console import Console

from kernox.ai.base import BaseAIClient

console = Console()


class OllamaClient(BaseAIClient):
    """Talks to a locally-running Ollama instance via its REST API."""

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3") -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model

    def chat(
        self,
        messages: list[dict],
        *,
        system: Optional[str] = None,
        max_tokens: int = 2048,
        temperature: float = 0.2,
    ) -> str:
        payload: dict = {
            "model": self._model,
            "messages": messages,
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "temperature": temperature,
            },
        }
        if system:
            payload["system"] = system

        try:
            resp = requests.post(
                f"{self._base_url}/api/chat",
                json=payload,
                timeout=120,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["message"]["content"]
        except requests.exceptions.ConnectionError:
            console.print(
                f"[red]Cannot connect to Ollama at {self._base_url}. "
                "Is it running?[/red]"
            )
            return "Error: Ollama is not reachable."
        except Exception as exc:
            console.print(f"[red]Ollama error: {exc}[/red]")
            return f"Error: {exc}"

    def is_available(self) -> bool:
        try:
            resp = requests.get(f"{self._base_url}/api/tags", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False
