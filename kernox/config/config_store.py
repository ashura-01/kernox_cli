"""
kernox.config.config_store  –  Persistent key-value config in SQLite.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Optional

DB_PATH = Path.home() / ".kernox" / "config.db"


class ConfigStore:
    def __init__(self, db_path: Path = DB_PATH) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path))
        self._init_db()

    # ── Public ───────────────────────────────────────────────────────────────

    def get(self, key: str) -> Optional[str]:
        row = self._conn.execute(
            "SELECT value FROM config WHERE key = ?", (key,)
        ).fetchone()
        return row[0] if row else None

    def set(self, key: str, value: str) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
                (key, value),
            )

    def delete(self, key: str) -> None:
        with self._conn:
            self._conn.execute("DELETE FROM config WHERE key = ?", (key,))

    def all(self) -> dict[str, str]:
        rows = self._conn.execute("SELECT key, value FROM config ORDER BY key").fetchall()
        return {r[0]: r[1] for r in rows}

    def reset(self) -> None:
        with self._conn:
            self._conn.execute("DELETE FROM config")

    # ── Internal ─────────────────────────────────────────────────────────────

    def _init_db(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS config (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
