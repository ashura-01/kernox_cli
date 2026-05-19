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
    console.print("[bold]Step 1 of 4:[/bold] Choose your AI backend\n")
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

    # ── 2. Backend configuration ───────────────────────────────────────────
    console.print("[bold]Step 2 of 4:[/bold] Backend configuration\n")

    def safe_store(key: str, value: str) -> None:
        try:
            ks.store(key, value)
        except Exception as e:
            console.print(f"[red]Failed to store {key}: {e}[/red]")

    if ai_backend == "ollama":
        cfg.set("ollama_url", Prompt.ask("Ollama base URL", default="http://localhost:11434"))
        cfg.set("ollama_model", Prompt.ask("Ollama model name", default="llama3"))

    elif ai_backend == "claude":
        api_key = secure_prompt("Anthropic API key (input hidden)")
        if api_key:
            safe_store("claude_api_key", api_key)

        cfg.set("claude_model", Prompt.ask("Claude model", default="claude-opus-4-5"))

    elif ai_backend == "openai":
        cfg.set("openai_base_url", Prompt.ask(
            "OpenAI-compatible base URL",
            default="https://api.openai.com/v1",
        ))

        api_key = secure_prompt("API key (input hidden)")
        if api_key:
            safe_store("openai_api_key", api_key)

        cfg.set("openai_model", Prompt.ask("Model name", default="gpt-4o"))

    elif ai_backend == "gemini":
        api_key = secure_prompt("Google Gemini API key (input hidden)")
        if api_key:
            safe_store("gemini_api_key", api_key)

        cfg.set("gemini_model", Prompt.ask("Gemini model", default="gemini-1.5-pro"))

    console.print("[green]✓[/green] Backend configured.\n")

    # ── 3. Safety settings ────────────────────────────────────────────────
    console.print("[bold]Step 3 of 4:[/bold] Safety & scope defaults\n")

    cfg.set(
        "confirm_before_exec",
        Confirm.ask("Require confirmation before executing each tool?", default=True),
    )

    allowed_networks = Prompt.ask(
        "Allowed target networks (CIDR, comma-separated, blank = no restriction)",
        default="",
    ).strip()

    cfg.set("allowed_networks", allowed_networks)

    console.print("[green]✓[/green] Safety settings saved.\n")

    # ── 4. Enrichment APIs ────────────────────────────────────────────────
    console.print("[bold]Step 4 of 4:[/bold] Enrichment & Notifications\n")

    nvd_key = secure_prompt("NVD API key (optional, Enter to skip)")
    if nvd_key:
        safe_store("nvd_api_key", nvd_key)

    # ── Telegram setup ────────────────────────────────────────────────────
    console.print("\n[bold]Optional:[/bold] Telegram Notifications\n")

    if Confirm.ask("Set up Telegram notifications?", default=False):
        console.print("\n[dim]1. Create bot via @BotFather[/dim]")
        console.print("[dim]2. Get bot token[/dim]")
        console.print("[dim]3. Get chat ID via @userinfobot[/dim]\n")

        bot_token = secure_prompt("Telegram bot token (hidden)")
        chat_id = Prompt.ask("Telegram chat ID").strip()

        if bot_token and chat_id:

            safe_store("telegram_bot_token", bot_token)
            cfg.set("telegram_chat_id", chat_id)
            cfg.set("telegram_enabled", True)

            console.print("[green]✓[/green] Telegram enabled\n")

            # Test bot
            try:
                import requests

                url = f"https://api.telegram.org/bot{bot_token}/getMe"
                resp = requests.get(url, timeout=5)

                if resp.ok:
                    console.print("[green]✓[/green] Telegram bot verified\n")
                else:
                    console.print(f"[yellow]⚠ Telegram error: {resp.status_code}[/yellow]\n")

            except Exception as e:
                console.print(f"[yellow]⚠ Telegram check failed: {e}[/yellow]\n")

        else:
            console.print("[dim]Telegram setup skipped[/dim]\n")
    else:
        console.print("[dim]Telegram disabled[/dim]\n")

    # ── Finalize ─────────────────────────────────────────────────────────
    mark_setup_complete()

    console.rule("[bold green]Setup Complete[/bold green]")
    console.print(
        "\n[bold green]Kernox is ready![/bold green] Run [bold]kernox --config[/bold] anytime.\n"
    )