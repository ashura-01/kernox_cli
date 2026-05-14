"""
kernox.core.config_menu  –  Interactive `kernox --config` settings menu.
"""

from __future__ import annotations

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table

from kernox.config.config_store import ConfigStore
from kernox.security.key_store import KeyStore
from kernox.utils.secure_input import secure_prompt

console = Console()


def open_config_menu() -> None:
    """Display and edit Kernox settings interactively."""
    cfg = ConfigStore()
    ks = KeyStore()

    while True:
        console.rule("[bold cyan]Kernox Configuration[/bold cyan]")
        _show_current_config(cfg)

        console.print("\n[bold]Options:[/bold]")
        console.print("  [green]1[/green] – Change AI backend")
        console.print("  [green]2[/green] – Update API key")
        console.print("  [green]3[/green] – Toggle execution confirmation")
        console.print("  [green]4[/green] – Set allowed networks")
        console.print("  [green]5[/green] – Toggle raw output (show/hide tool output)")
        console.print("  [green]6[/green] – Show stored key names")
        console.print("  [green]7[/green] – Delete a stored key")
        console.print("  [green]8[/green] – Update NVD API key  [dim](CVE enrichment)[/dim]")
        console.print("  [green]9[/green] – Update VirusTotal API key")
        console.print("  [green]10[/green] – Setup Telegram bot  [dim](send reports to phone)[/dim]")
        console.print("  [green]11[/green] – Remove Telegram token")
        console.print("  [green]q[/green] – Quit config menu\n")

        choice = Prompt.ask("Select option", choices=["1","2","3","4","5","6","7","8","9","10","11","q"])

        if choice == "q":
            console.print("[dim cyan]Exiting config menu.[/dim cyan]")
            break
        elif choice == "1":
            _change_backend(cfg, ks)
        elif choice == "2":
            _update_api_key(cfg, ks)
        elif choice == "3":
            _toggle_confirmation(cfg)
        elif choice == "4":
            _set_allowed_networks(cfg)
        elif choice == "5":
            _toggle_raw_output(cfg)
        elif choice == "6":
            _show_key_names(ks)
        elif choice == "7":
            _delete_key(ks)
        elif choice == "8":
            _update_enrichment_key(ks, "nvd_api_key", "NVD (nvd.nist.gov)")
        elif choice == "9":
            _update_enrichment_key(ks, "virustotal_api_key", "VirusTotal")
        elif choice == "10":
            _setup_telegram(cfg, ks)
        elif choice == "11":
            _remove_telegram(cfg, ks)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _show_current_config(cfg: ConfigStore) -> None:
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="white")
    for key, value in cfg.all().items():
        table.add_row(key, str(value))
    console.print(table)


def _change_backend(cfg: ConfigStore, ks: KeyStore) -> None:
    console.print("\n  [green]1[/green] ollama  [green]2[/green] claude  [green]3[/green] openai  [green]4[/green] gemini")
    choice = Prompt.ask("New backend", choices=["1", "2", "3", "4"])
    ai_map = {"1": "ollama", "2": "claude", "3": "openai", "4": "gemini"}
    backend = ai_map[choice]
    cfg.set("ai_backend", backend)

    if backend == "ollama":
        url = Prompt.ask("Ollama URL", default=cfg.get("ollama_url") or "http://localhost:11434")
        model = Prompt.ask("Ollama model", default=cfg.get("ollama_model") or "llama3")
        cfg.set("ollama_url", url)
        cfg.set("ollama_model", model)
    elif backend == "claude":
        console.print("[dim]Available: claude-sonnet-4-5, claude-opus-4-5, claude-haiku-4-5-20251001[/dim]")
        model = Prompt.ask("Claude model", default=cfg.get("claude_model") or "claude-sonnet-4-5")
        cfg.set("claude_model", model)
    elif backend == "openai":
        url = Prompt.ask("Base URL", default=cfg.get("openai_base_url") or "https://api.openai.com/v1")
        model = Prompt.ask("Model", default=cfg.get("openai_model") or "gpt-4o")
        cfg.set("openai_base_url", url)
        cfg.set("openai_model", model)
    elif backend == "gemini":
        model = Prompt.ask("Gemini model", default=cfg.get("gemini_model") or "gemini-1.5-pro")
        cfg.set("gemini_model", model)

    console.print(f"[green]✓ Backend updated to {backend}[/green]\n")


def _update_api_key(cfg: ConfigStore, ks: KeyStore) -> None:
    backend = cfg.get("ai_backend") or "claude"
    key_name_map = {"claude": "claude_api_key", "openai": "openai_api_key", "gemini": "gemini_api_key"}
    key_name = key_name_map.get(backend, "api_key")
    new_key = secure_prompt(f"New API key for {backend} (hidden)")
    if new_key:
        ks.store(key_name, new_key)
        console.print("[green]✓ Key updated.[/green]\n")
    else:
        console.print("[dim cyan]No key entered. Unchanged.[/dim cyan]\n")


def _toggle_raw_output(cfg: ConfigStore) -> None:
    current = cfg.get("show_raw_output") == "1"
    new_val = not current
    cfg.set("show_raw_output", "1" if new_val else "0")
    state = "[green]ON[/green] (verbose)" if new_val else "[dim cyan]OFF[/dim cyan] (silent + spinner)"
    console.print(f"[green]✓ Raw tool output {state}[/green]\n")


def _toggle_confirmation(cfg: ConfigStore) -> None:
    current = cfg.get("confirm_before_exec") == "1"
    new_val = not current
    cfg.set("confirm_before_exec", "1" if new_val else "0")
    state = "enabled" if new_val else "disabled"
    console.print(f"[green]✓ Execution confirmation {state}.[/green]\n")


def _set_allowed_networks(cfg: ConfigStore) -> None:
    nets = Prompt.ask(
        "Allowed networks (CIDR, comma-separated, blank = unrestricted)",
        default=cfg.get("allowed_networks") or "",
    )
    cfg.set("allowed_networks", nets)
    console.print("[green]✓ Allowed networks updated.[/green]\n")


def _show_key_names(ks: KeyStore) -> None:
    names = ks.list_keys()
    if names:
        console.print("[cyan]Stored key names:[/cyan] " + ", ".join(names))
    else:
        console.print("[dim cyan]No keys stored.[/dim cyan]")
    console.print()


def _delete_key(ks: KeyStore) -> None:
    names = ks.list_keys()
    if not names:
        console.print("[dim cyan]No keys to delete.[/dim cyan]\n")
        return
    name = Prompt.ask("Key name to delete", choices=names)
    ks.delete(name)
    console.print(f"[green]✓ Key '{name}' deleted.[/green]\n")


def _update_enrichment_key(ks: KeyStore, key_name: str, label: str) -> None:
    existing = ks.retrieve(key_name)
    status = "[green]set[/green]" if existing else "[dim]not set[/dim]"
    console.print(f"\n  {label} key currently: {status}")
    new_key = secure_prompt(f"New {label} API key (hidden, Enter to cancel)")
    if new_key:
        ks.store(key_name, new_key)
        console.print(f"[green]✓ {label} key updated.[/green]\n")
    else:
        console.print("[dim cyan]Unchanged.[/dim cyan]\n")


def _setup_telegram(cfg: ConfigStore, ks: KeyStore) -> None:
    """Setup Telegram bot token and chat ID."""
    console.print("\n[bold cyan]Telegram Bot Setup[/bold cyan]")
    console.print("\n[dim]Quick setup guide:[/dim]")
    console.print("  [dim]1. Open Telegram → search @BotFather → /newbot → create a bot[/dim]")
    console.print("  [dim]2. Copy the bot token[/dim]")
    console.print("  [dim]3. Search @userinfobot → /start → get your chat ID[/dim]\n")

    bot_token = secure_prompt("Enter Telegram bot token (input hidden)")
    if not bot_token:
        console.print("[dim]Telegram setup cancelled[/dim]\n")
        return

    chat_id = Prompt.ask("Enter your chat ID")
    if not chat_id:
        console.print("[dim]Chat ID required. Setup cancelled.[/dim]\n")
        return

    ks.store("telegram_bot_token", bot_token)
    cfg.set("telegram_chat_id", chat_id)
    cfg.set("telegram_enabled", "1")

    # Test connection
    try:
        import requests
        url = f"https://api.telegram.org/bot{bot_token}/getMe"
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            console.print("[green]✓ Telegram configured and verified![/green]\n")

            # Send test message
            test_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            test_payload = {"chat_id": chat_id, "text": "✓Kernox Telegram notifications enabled!"}
            requests.post(test_url, json=test_payload, timeout=5)
            console.print("[green]✓ Test message sent to your Telegram[/green]\n")
        else:
            console.print("[yellow]⚠ Bot token may be invalid. Check and try again.[/yellow]\n")
    except Exception as e:
        console.print(f"[yellow]⚠ Could not verify bot: {e}[/yellow]")
        console.print("[dim]Settings saved but not verified[/dim]\n")


def _remove_telegram(cfg: ConfigStore, ks: KeyStore) -> None:
    """Remove Telegram configuration."""
    if Confirm.ask("Remove Telegram configuration?", default=False):
        ks.delete("telegram_bot_token")
        cfg.set("telegram_enabled", "0")
        console.print("[green]✓ Telegram configuration removed[/green]\n")
    else:
        console.print("[dim]Cancelled[/dim]\n")
