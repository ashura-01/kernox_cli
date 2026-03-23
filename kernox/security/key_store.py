"""
kernox.security.key_store  –  Encrypted API key storage backed by SQLite.

Keys are encrypted with Fernet (AES-128-CBC + HMAC-SHA256) before storage.
The Fernet key itself is derived from a machine-local secret stored in the
same database under a special row.  This is not HSM-grade but prevents
casual plaintext exposure in the database file.
"""

from __future__ import annotations

import base64
import os
import sqlite3
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet

DB_PATH = Path.home() / ".kernox" / "keys.db"


class KeyStore:
    def __init__(self, db_path: Path = DB_PATH) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path))
        self._init_db()
        self._fernet = Fernet(self._get_or_create_fernet_key())

    # ── Public interface ─────────────────────────────────────────────────────

    def store(self, name: str, secret: str) -> None:
        """Encrypt and store *secret* under *name*."""
        encrypted = self._fernet.encrypt(secret.encode()).decode()
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO keys (name, value) VALUES (?, ?)",
                (name, encrypted),
            )

    def retrieve(self, name: str) -> Optional[str]:
        """Return the decrypted secret for *name*, or None."""
        row = self._conn.execute(
            "SELECT value FROM keys WHERE name = ?", (name,)
        ).fetchone()
        if row is None:
            return None
        try:
            return self._fernet.decrypt(row[0].encode()).decode()
        except Exception:
            return None

    def delete(self, name: str) -> None:
        with self._conn:
            self._conn.execute("DELETE FROM keys WHERE name = ?", (name,))

    def list_keys(self) -> list[str]:
        rows = self._conn.execute("SELECT name FROM keys ORDER BY name").fetchall()
        return [r[0] for r in rows]

    def reset(self) -> None:
        """Delete all stored keys."""
        with self._conn:
            self._conn.execute("DELETE FROM keys")

    # ── Internal ─────────────────────────────────────────────────────────────

    def _init_db(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS keys (
                    name  TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS meta (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )

    def _get_or_create_fernet_key(self) -> bytes:
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key = 'fernet_key'"
        ).fetchone()
        if row:
            return base64.urlsafe_b64decode(row[0])
        fernet_key = Fernet.generate_key()
        with self._conn:
            self._conn.execute(
                "INSERT INTO meta (key, value) VALUES ('fernet_key', ?)",
                (base64.urlsafe_b64encode(fernet_key).decode(),),
            )
        return fernet_key
