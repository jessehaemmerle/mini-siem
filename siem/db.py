"""Haupt-Datenbank (``data/siem.db``): Benutzer, Regeln, Alarme, Einstellungen.

Die Events selbst liegen in den Tagesdateien (siehe ``storage.py``).
Schema-Änderungen werden über ``MIGRATIONS`` versioniert eingespielt.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

MIGRATIONS: list[str] = [
    # Version 1
    """
    CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        display_name TEXT,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
        active INTEGER NOT NULL DEFAULT 1,
        created REAL NOT NULL,
        last_login REAL
    );
    CREATE TABLE sessions (
        token_hash TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created REAL NOT NULL,
        expires REAL NOT NULL,
        ip TEXT
    );
    CREATE TABLE api_tokens (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        prefix TEXT NOT NULL,
        created REAL NOT NULL,
        created_by TEXT,
        last_used REAL,
        events INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE rules (
        id INTEGER PRIMARY KEY,
        key TEXT UNIQUE,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        query TEXT NOT NULL,
        severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
        threshold INTEGER NOT NULL DEFAULT 1,
        window INTEGER NOT NULL DEFAULT 300,
        group_by TEXT,
        distinct_field TEXT,
        enabled INTEGER NOT NULL DEFAULT 1,
        builtin INTEGER NOT NULL DEFAULT 0,
        created REAL NOT NULL,
        updated REAL NOT NULL
    );
    CREATE TABLE alerts (
        id INTEGER PRIMARY KEY,
        rule_id INTEGER REFERENCES rules(id) ON DELETE SET NULL,
        rule_name TEXT NOT NULL,
        severity TEXT NOT NULL,
        group_value TEXT,
        count INTEGER NOT NULL DEFAULT 1,
        first_seen REAL NOT NULL,
        last_seen REAL NOT NULL,
        status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'ack', 'closed')),
        assignee TEXT,
        resolution TEXT,
        hosts TEXT,
        samples TEXT NOT NULL DEFAULT '[]',
        created REAL NOT NULL,
        updated REAL NOT NULL
    );
    CREATE INDEX ix_alerts_status ON alerts(status, last_seen);
    CREATE INDEX ix_alerts_rule ON alerts(rule_id, group_value, status);
    CREATE TABLE alert_comments (
        id INTEGER PRIMARY KEY,
        alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
        username TEXT NOT NULL,
        ts REAL NOT NULL,
        text TEXT NOT NULL
    );
    CREATE TABLE sources (
        id INTEGER PRIMARY KEY,
        host TEXT NOT NULL,
        input TEXT NOT NULL,
        source_ip TEXT,
        first_seen REAL NOT NULL,
        last_seen REAL NOT NULL,
        events INTEGER NOT NULL DEFAULT 0,
        UNIQUE (host, input)
    );
    CREATE TABLE settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    CREATE TABLE audit_log (
        id INTEGER PRIMARY KEY,
        ts REAL NOT NULL,
        username TEXT,
        ip TEXT,
        action TEXT NOT NULL,
        details TEXT
    );
    CREATE INDEX ix_audit_ts ON audit_log(ts);
    """,
    # Version 2: Agenten und Connectoren (Microsoft 365)
    """
    CREATE TABLE agents (
        id INTEGER PRIMARY KEY,
        machine_id TEXT NOT NULL UNIQUE,
        hostname TEXT NOT NULL,
        name TEXT,
        os TEXT,
        os_version TEXT,
        arch TEXT,
        version TEXT,
        ip TEXT,
        token_hash TEXT NOT NULL UNIQUE,
        enrolled REAL NOT NULL,
        last_seen REAL,
        config TEXT,
        stats TEXT,
        events INTEGER NOT NULL DEFAULT 0,
        disabled INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE connector_state (
        connector TEXT NOT NULL,
        key TEXT NOT NULL,
        value TEXT NOT NULL,
        updated REAL NOT NULL,
        PRIMARY KEY (connector, key)
    );
    CREATE TABLE connector_seen (
        connector TEXT NOT NULL,
        item TEXT NOT NULL,
        ts REAL NOT NULL,
        PRIMARY KEY (connector, item)
    ) WITHOUT ROWID;
    """,
]

DEFAULT_SETTINGS: dict[str, Any] = {
    "retention_days": 90,
    "source_silent_minutes": 60,
    "session_hours": 12,
    "alert_retention_days": 365,
    "agent_auto_update": True,
}


class Database:
    """Dünne, thread-sichere Hülle um eine SQLite-Verbindung."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._write_lock = threading.RLock()
        self._migrate()

    def conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(str(self.path), timeout=30, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=30000")
            self._local.conn = conn
        return conn

    def _migrate(self) -> None:
        conn = self.conn()
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        for i, script in enumerate(MIGRATIONS[version:], start=version + 1):
            with conn:
                conn.executescript(script)
                conn.execute(f"PRAGMA user_version = {int(i)}")

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """Schreibende Transaktion."""
        with self._write_lock:
            conn = self.conn()
            with conn:
                yield conn

    def one(self, sql: str, params=()) -> dict | None:
        row = self.conn().execute(sql, params).fetchone()
        return dict(row) if row else None

    def all(self, sql: str, params=()) -> list[dict]:
        return [dict(r) for r in self.conn().execute(sql, params).fetchall()]

    def execute(self, sql: str, params=()) -> sqlite3.Cursor:
        with self.tx() as conn:
            return conn.execute(sql, params)

    # ---------------------------------------------------------------- Einstellungen

    def get_setting(self, key: str) -> Any:
        row = self.one("SELECT value FROM settings WHERE key = ?", (key,))
        if row is None:
            return DEFAULT_SETTINGS.get(key)
        return json.loads(row["value"])

    def all_settings(self) -> dict:
        out = dict(DEFAULT_SETTINGS)
        for row in self.all("SELECT key, value FROM settings"):
            out[row["key"]] = json.loads(row["value"])
        return out

    def set_setting(self, key: str, value: Any) -> None:
        self.execute(
            "INSERT INTO settings(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, json.dumps(value)),
        )

    # ---------------------------------------------------------------- Audit

    def audit(self, username: str | None, action: str, details: str = "", ip: str | None = None) -> None:
        self.execute(
            "INSERT INTO audit_log(ts, username, ip, action, details) VALUES (?, ?, ?, ?, ?)",
            (time.time(), username, ip, action, details),
        )
