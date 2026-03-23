"""
kernox.ai.api  –  API-based AI clients (Anthropic Claude, OpenAI-compatible, Google Gemini).
"""

from __future__ import annotations

from typing import Optional

import requests
from rich.console import Console

from kernox.ai.base import BaseAIClient

console = Console()


class ClaudeClient(BaseAIClient):
    """Anthropic Claude via the official Messages API."""

    API_URL = "https://api.anthropic.com/v1/messages"
    DEFAULT_MODEL = "claude-opus-4-5"

    def __init__(self, api_key: str, model: str = DEFAULT_MODEL) -> None:
        self._api_key = api_key
        self._model = model

    def chat(
        self,
        messages: list[dict],
        *,
        system: Optional[str] = None,
        max_tokens: int = 2048,
        temperature: float = 0.2,
    ) -> str:
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload: dict = {
            "model": self._model,
            "max_tokens": max_tokens,
            "messages": messages,
        }
        if system:
            payload["system"] = system

        try:
            resp = requests.post(self.API_URL, headers=headers, json=payload, timeout=60)
            resp.raise_for_status()
            data = resp.json()
            return data["content"][0]["text"]
        except requests.HTTPError as exc:
            console.print(f"[red]Claude API HTTP error: {exc} – {resp.text[:300]}[/red]")
            return f"Error: {exc}"
        except Exception as exc:
            console.print(f"[red]Claude API error: {exc}[/red]")
            return f"Error: {exc}"


class OpenAICompatibleClient(BaseAIClient):
    """Client for any OpenAI-compatible REST endpoint."""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.openai.com/v1",
        model: str = "gpt-4o",
    ) -> None:
        self._api_key = api_key
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
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        all_messages = []
        if system:
            all_messages.append({"role": "system", "content": system})
        all_messages.extend(messages)

        payload = {
            "model": self._model,
            "messages": all_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        try:
            resp = requests.post(
                f"{self._base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=60,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]
        except requests.HTTPError as exc:
            console.print(f"[red]OpenAI API HTTP error: {exc}[/red]")
            return f"Error: {exc}"
        except Exception as exc:
            console.print(f"[red]OpenAI API error: {exc}[/red]")
            return f"Error: {exc}"


class GeminiClient(BaseAIClient):
    """Google Gemini via the Generative Language REST API."""

    API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    DEFAULT_MODEL = "gemini-1.5-pro"

    def __init__(self, api_key: str, model: str = DEFAULT_MODEL) -> None:
        self._api_key = api_key
        self._model = model

    def chat(
        self,
        messages: list[dict],
        *,
        system: Optional[str] = None,
        max_tokens: int = 2048,
        temperature: float = 0.2,
    ) -> str:
        url = self.API_URL.format(model=self._model)

        # Convert messages to Gemini's "contents" format
        contents = []
        for msg in messages:
            role = "user" if msg["role"] == "user" else "model"
            contents.append({
                "role": role,
                "parts": [{"text": msg["content"]}],
            })

        payload: dict = {
            "contents": contents,
            "generationConfig": {
                "maxOutputTokens": max_tokens,
                "temperature": temperature,
            },
        }

        # Gemini supports a system instruction block
        if system:
            payload["system_instruction"] = {
                "parts": [{"text": system}]
            }

        try:
            resp = requests.post(
                url,
                params={"key": self._api_key},
                json=payload,
                timeout=60,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except requests.HTTPError as exc:
            console.print(f"[red]Gemini API HTTP error: {exc} – {resp.text[:300]}[/red]")
            return f"Error: {exc}"
        except (KeyError, IndexError) as exc:
            console.print(f"[red]Gemini response parse error: {exc}[/red]")
            return f"Error parsing Gemini response: {exc}"
        except Exception as exc:
            console.print(f"[red]Gemini API error: {exc}[/red]")
            return f"Error: {exc}"
