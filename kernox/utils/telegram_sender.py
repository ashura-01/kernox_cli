"""
kernox.utils.telegram_sender – Send files and notifications to Telegram.
"""

from __future__ import annotations

import requests
from pathlib import Path
from typing import Optional
from rich.console import Console

console = Console()


class TelegramSender:
    def __init__(self):
        self._token = None
        self._chat_id = None
        self._enabled = False
        self._load_config()

    def _load_config(self):
        """Load Telegram config from KeyStore and ConfigStore."""
        try:
            from kernox.config.config_store import ConfigStore
            from kernox.security.key_store import KeyStore

            cfg = ConfigStore()
            ks = KeyStore()

            self._token = ks.retrieve("telegram_bot_token")
            self._chat_id = cfg.get("telegram_chat_id")

            if self._token and self._chat_id:
                self._enabled = cfg.get("telegram_enabled") == "1"
                if self._enabled:
                    console.print("[green]✓ Telegram sender ready[/green]")
        except Exception:
            pass

    def _is_enabled(self) -> bool:
        """Check if Telegram is configured and enabled."""
        if not self._enabled:
            return False
        if not self._token or not self._chat_id:
            return False
        return True

    def send_message(self, text: str) -> bool:
        """Send a text message to Telegram."""
        if not self._is_enabled():
            return False

        try:
            url = f"https://api.telegram.org/bot{self._token}/sendMessage"
            payload = {
                "chat_id": self._chat_id,
                "text": text[:4000],
                "parse_mode": "HTML"
            }
            resp = requests.post(url, json=payload, timeout=10)
            return resp.status_code == 200
        except Exception as e:
            console.print(f"[dim]⚠ Telegram send failed: {e}[/dim]")
            return False

    def send_file(self, file_path: str, caption: str = "") -> bool:
        """Send a file to Telegram."""
        if not self._is_enabled():
            return False

        try:
            url = f"https://api.telegram.org/bot{self._token}/sendDocument"
            with open(file_path, 'rb') as f:
                files = {"document": f}
                data = {"chat_id": self._chat_id}
                if caption:
                    data["caption"] = caption[:1000]
                resp = requests.post(url, data=data, files=files, timeout=30)
            return resp.status_code == 200
        except Exception as e:
            console.print(f"[dim]⚠ Telegram file send failed: {e}[/dim]")
            return False

    def notify_scan_start(self, target: str) -> None:
        """Notify that a scan is starting."""
        if self._is_enabled():
            self.send_message(f"🔍 Starting scan on: {target}")

    def notify_scan_complete(self, tool: str, target: str, output_path: str) -> None:
        """Send tool output when scan completes."""
        if self._is_enabled() and output_path:
            self.send_file(output_path, f"{tool} scan on {target}")

    def notify_report(self, report_path: str, target: str) -> None:
        """Send PDF report when generated."""
        if self._is_enabled() and report_path:
            self.send_file(report_path, f"Kernox Report: {target}")


# Singleton
_telegram = None

def get_telegram() -> TelegramSender:
    global _telegram
    if _telegram is None:
        _telegram = TelegramSender()
    return _telegram
