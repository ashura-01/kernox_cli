"""
kernox.core.first_run_setup  –  Interactive first-time configuration wizard.
"""

from __future__ import annotations

from rich.console import Console
from rich.prompt import Prompt, Confirm

from kernox.config.config_store import ConfigStore
from kernox.security.key_store import KeyStore
from kernox.core.first_run import mark_setup_complete
from kernox.utils.secure_input import secure_prompt

console = Console()


def run_first_time_setup() -> None:
    """Walk the user through initial configuration. Persists everything."""
    console.rule("[bold cyan]Kernox First-Time Setup[/bold cyan]")
    console.print(
        "[dim]This wizard will configure your AI backend and security settings.\n"
        "You can change anything later with `kernox --config`.[/dim]\n"
    )

    cfg = ConfigStore()
    ks = KeyStore()

    # ── 1. Choose AI backend ────────────────────────────────────────────────
    console.print("[bold]Step 1 of 3:[/bold] Choose your AI backend\n")
    console.print("  [green]1[/green] – Ollama  [dim](local, free, private)[/dim]")
    console.print("  [green]2[/green] – Claude API  [dim](Anthropic, requires key)[/dim]")
    console.print("  [green]3[/green] – OpenAI-compatible  [dim](custom base URL)[/dim]")
    console.print("  [green]4[/green] – Gemini  [dim](Google, requires key)[/dim]\n")

    choice = Prompt.ask(
        "Your choice",
        choices=["1", "2", "3", "4"],
        default="1",
    )
    ai_map = {"1": "ollama", "2": "claude", "3": "openai", "4": "gemini"}
    ai_backend = ai_map[choice]
    cfg.set("ai_backend", ai_backend)
    console.print(f"[green]✓[/green] AI backend set to: [bold]{ai_backend}[/bold]\n")

    # ── 2. Backend-specific configuration ───────────────────────────────────
    console.print("[bold]Step 2 of 3:[/bold] Backend configuration\n")

    if ai_backend == "ollama":
        ollama_url = Prompt.ask(
            "Ollama base URL",
            default="http://localhost:11434",
        )
        cfg.set("ollama_url", ollama_url)
        model = Prompt.ask("Ollama model name", default="llama3")
        cfg.set("ollama_model", model)

    elif ai_backend == "claude":
        api_key = secure_prompt("Anthropic API key (input hidden)")
        if api_key:
            ks.store("claude_api_key", api_key)
        model = Prompt.ask(
            "Claude model",
            default="claude-opus-4-5",
        )
        cfg.set("claude_model", model)

    elif ai_backend == "openai":
        base_url = Prompt.ask(
            "OpenAI-compatible base URL",
            default="https://api.openai.com/v1",
        )
        cfg.set("openai_base_url", base_url)
        api_key = secure_prompt("API key (input hidden)")
        if api_key:
            ks.store("openai_api_key", api_key)
        model = Prompt.ask("Model name", default="gpt-4o")
        cfg.set("openai_model", model)

    elif ai_backend == "gemini":
        api_key = secure_prompt("Google Gemini API key (input hidden)")
        if api_key:
            ks.store("gemini_api_key", api_key)
        model = Prompt.ask(
            "Gemini model",
            default="gemini-1.5-pro",
        )
        cfg.set("gemini_model", model)

    console.print("[green]✓[/green] Backend configured.\n")

    # ── 3. Safety / scope preferences ───────────────────────────────────────
    console.print("[bold]Step 3 of 3:[/bold] Safety & scope defaults\n")

    confirm_before_exec = Confirm.ask(
        "Require confirmation before executing each tool?",
        default=True,
    )
    cfg.set("confirm_before_exec", "1" if confirm_before_exec else "0")

    allowed_networks = Prompt.ask(
        "Allowed target networks (CIDR, comma-separated, blank = no restriction)",
        default="",
    )
    cfg.set("allowed_networks", allowed_networks)

    console.print("[green]✓[/green] Safety settings saved.\n")

    # ── Finalise ─────────────────────────────────────────────────────────────
    mark_setup_complete()
    console.rule("[bold green]Setup Complete[/bold green]")
    console.print(
        "\n[bold green]Kernox is ready![/bold green]  "
        "Run [bold]`kernox --config`[/bold] to revisit these settings anytime.\n"
    )
