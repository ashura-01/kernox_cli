"""
kernox.ai.api  –  API-based AI clients (Anthropic Claude, OpenAI-compatible, Google Gemini).
"""

from __future__ import annotations

import time
from typing import Optional

import requests
from rich.console import Console

from kernox.ai.base import BaseAIClient

console = Console()

# Retry settings
_MAX_RETRIES = 3
_RETRY_DELAY = 2.0  # seconds, doubles each attempt


def _retry_request(fn, retries: int = _MAX_RETRIES, delay: float = _RETRY_DELAY):
    """Run fn() with exponential-backoff retries on transient errors."""
    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            return fn()
        except (requests.ConnectionError, requests.Timeout) as exc:
            last_exc = exc
            if attempt < retries:
                wait = delay * (2 ** (attempt - 1))
                console.print(
                    f"[yellow]⚠ API connection error (attempt {attempt}/{retries}). "
                    f"Retrying in {wait:.0f}s…[/yellow]"
                )
                time.sleep(wait)
        except requests.HTTPError as exc:
            # Only retry on 5xx server errors, not 4xx client errors
            if exc.response is not None and exc.response.status_code >= 500:
                last_exc = exc
                if attempt < retries:
                    wait = delay * (2 ** (attempt - 1))
                    console.print(
                        f"[yellow]⚠ Server error {exc.response.status_code} "
                        f"(attempt {attempt}/{retries}). Retrying in {wait:.0f}s…[/yellow]"
                    )
                    time.sleep(wait)
            else:
                raise
    raise last_exc


class ClaudeClient(BaseAIClient):
    """Anthropic Claude via the official Messages API."""

    API_URL = "https://api.anthropic.com/v1/messages"
    DEFAULT_MODEL = "claude-sonnet-4-5"  # claude-sonnet-4-5 is the correct API model string

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

        def _do_request():
            resp = requests.post(self.API_URL, headers=headers, json=payload, timeout=60)
            resp.raise_for_status()
            data = resp.json()
            return data["content"][0]["text"]

        try:
            return _retry_request(_do_request)
        except requests.HTTPError as exc:
            resp_text = exc.response.text[:300] if exc.response is not None else ""
            console.print(f"[red]Claude API HTTP error: {exc} – {resp_text}[/red]")
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

        def _do_request():
            resp = requests.post(
                f"{self._base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=60,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]

        try:
            return _retry_request(_do_request)
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

        def _do_request():
            resp = requests.post(
                url,
                params={"key": self._api_key},
                json=payload,
                timeout=60,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]

        try:
            return _retry_request(_do_request)
        except requests.HTTPError as exc:
            resp_text = exc.response.text[:300] if exc.response is not None else ""
            console.print(f"[red]Gemini API HTTP error: {exc} – {resp_text}[/red]")
            return f"Error: {exc}"
        except (KeyError, IndexError) as exc:
            console.print(f"[red]Gemini response parse error: {exc}[/red]")
            return f"Error parsing Gemini response: {exc}"
        except Exception as exc:
            console.print(f"[red]Gemini API error: {exc}[/red]")
            return f"Error: {exc}"
