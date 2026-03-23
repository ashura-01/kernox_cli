"""
kernox.core.first_run  –  Detect whether this is the first Kernox execution.

The sentinel is a row in the config SQLite database.  If the database does
not yet contain a 'setup_complete' key, it is a first run.
"""

from __future__ import annotations

from kernox.config.config_store import ConfigStore


def is_first_run() -> bool:
    """Return True if Kernox has never been configured on this machine."""
    cfg = ConfigStore()
    return cfg.get("setup_complete") is None


def mark_setup_complete() -> None:
    """Persist the sentinel so subsequent runs skip setup."""
    cfg = ConfigStore()
    cfg.set("setup_complete", "1")
