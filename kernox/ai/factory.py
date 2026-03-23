"""
kernox.ai.factory  –  Build the correct AI client from config.
"""

from __future__ import annotations

from rich.console import Console

from kernox.ai.base import BaseAIClient
from kernox.config.config_store import ConfigStore
from kernox.security.key_store import KeyStore

console = Console()


def build_ai_client(config: ConfigStore) -> BaseAIClient:
    """Instantiate and return the AI client specified in config."""
    backend = config.get("ai_backend") or "ollama"
    ks = KeyStore()

    if backend == "ollama":
        from kernox.ai.ollama import OllamaClient
        url = config.get("ollama_url") or "http://localhost:11434"
        model = config.get("ollama_model") or "llama3"
        client = OllamaClient(base_url=url, model=model)
        if not client.is_available():
            console.print(
                f"[yellow]⚠ Ollama is not reachable at {url}. "
                "Responses will fail until it is started.[/yellow]"
            )
        return client

    elif backend == "claude":
        from kernox.ai.api import ClaudeClient
        api_key = ks.retrieve("claude_api_key") or ""
        if not api_key:
            console.print("[yellow]⚠ No Claude API key found. Run `kernox --config` to set it.[/yellow]")
        model = config.get("claude_model") or ClaudeClient.DEFAULT_MODEL
        return ClaudeClient(api_key=api_key, model=model)

    elif backend == "openai":
        from kernox.ai.api import OpenAICompatibleClient
        api_key = ks.retrieve("openai_api_key") or ""
        if not api_key:
            console.print("[yellow]⚠ No OpenAI API key found. Run `kernox --config` to set it.[/yellow]")
        base_url = config.get("openai_base_url") or "https://api.openai.com/v1"
        model = config.get("openai_model") or "gpt-4o"
        return OpenAICompatibleClient(api_key=api_key, base_url=base_url, model=model)

    elif backend == "gemini":
        from kernox.ai.api import GeminiClient
        api_key = ks.retrieve("gemini_api_key") or ""
        if not api_key:
            console.print("[yellow]⚠ No Gemini API key found. Run `kernox --config` to set it.[/yellow]")
        model = config.get("gemini_model") or GeminiClient.DEFAULT_MODEL
        return GeminiClient(api_key=api_key, model=model)

    else:
        console.print(f"[red]Unknown AI backend '{backend}'. Falling back to Ollama.[/red]")
        from kernox.ai.ollama import OllamaClient
        return OllamaClient()
