"""Zusammenbau aller Komponenten und Ersteinrichtung."""

from __future__ import annotations

import logging
import os
import secrets
import time

from .agents import DEFAULT_AGENT_CONFIG, AgentDist, AgentRegistry, new_enroll_key
from .auth import LoginThrottle, TokenCache, hash_password
from .config import Settings
from .db import Database
from .detection import DetectionEngine
from .m365 import M365Connector
from .pipeline import Pipeline
from .rules_default import DEFAULT_RULES, RULE_UPGRADES
from .storage import EventStore

log = logging.getLogger("siem")


class Core:
    def __init__(self, settings: Settings):
        self.settings = settings
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        self.db = Database(settings.main_db)
        self.store = EventStore(settings.events_dir, settings.query_timeout)
        self.engine = DetectionEngine(self.db)
        self.tokens = TokenCache(self.db)
        self.agents = AgentRegistry(self.db)
        self.agent_dist = AgentDist(settings.agent_dist_dir)
        self.throttle = LoginThrottle()
        self.started = time.time()
        self._bootstrap()
        self.pipeline = Pipeline(settings, self.db, self.store, self.engine)
        self.pipeline.hooks.append(self.agents.flush_counts)
        self.m365 = M365Connector(self.db, self.pipeline)

    # ------------------------------------------------------------------ Ersteinrichtung

    def _bootstrap(self) -> None:
        if self.db.one("SELECT value FROM settings WHERE key = 'retention_days'") is None:
            self.db.set_setting("retention_days", self.settings.default_retention_days)
        if not self.db.get_setting("agent_enroll_key"):
            self.db.set_setting("agent_enroll_key", new_enroll_key())
        if self.db.get_setting("agent_config") is None:
            self.db.set_setting("agent_config", DEFAULT_AGENT_CONFIG)
        self._seed_rules()
        self._create_admin()

    def _seed_rules(self) -> None:
        seeded = set(self.db.get_setting("seeded_rules") or [])
        existing = {r["key"] for r in self.db.all("SELECT key FROM rules WHERE key IS NOT NULL")}
        now = time.time()
        added = 0
        with self.db.tx() as conn:
            for rule in DEFAULT_RULES:
                if rule["key"] in seeded or rule["key"] in existing:
                    continue
                conn.execute(
                    "INSERT INTO rules(key, name, description, query, severity, threshold, window, "
                    "group_by, distinct_field, enabled, builtin, created, updated) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
                    (rule["key"], rule["name"], rule["description"], rule["query"], rule["severity"],
                     rule["threshold"], rule["window"], rule.get("group_by"),
                     rule.get("distinct_field"), int(rule.get("enabled", True)), now, now),
                )
                added += 1
            for key, steps in RULE_UPGRADES.items():
                for old_query, new_query in steps:
                    cur = conn.execute("UPDATE rules SET query = ?, updated = ? WHERE key = ? AND builtin = 1 "
                                       "AND query = ?", (new_query, now, key, old_query))
                    if cur.rowcount:
                        log.info("Mitgelieferte Regel '%s' aktualisiert", key)
        if added:
            log.info("%d mitgelieferte Erkennungsregel(n) angelegt", added)
        self.db.set_setting("seeded_rules", sorted(seeded | existing | {r["key"] for r in DEFAULT_RULES}))

    def _create_admin(self) -> None:
        if self.db.one("SELECT id FROM users LIMIT 1"):
            return
        password = self.settings.admin_password
        generated = not password
        if generated:
            password = secrets.token_urlsafe(12)
        self.db.execute(
            "INSERT INTO users(username, display_name, password_hash, role, created) "
            "VALUES (?, ?, ?, 'admin', ?)",
            (self.settings.admin_user, "Administrator", hash_password(password), time.time()),
        )
        self.db.audit("system", "user.create", f"Erstes Admin-Konto '{self.settings.admin_user}' angelegt")
        if generated:
            path = self.settings.data_dir / "initial-admin-password.txt"
            path.write_text(f"Benutzer: {self.settings.admin_user}\nPasswort: {password}\n", encoding="utf-8")
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            banner = "=" * 64
            log.warning(
                "\n%s\n  Erstes Admin-Konto angelegt\n  Benutzer: %s\n  Passwort: %s\n"
                "  (auch gespeichert in %s – bitte nach der Anmeldung ändern)\n%s",
                banner, self.settings.admin_user, password, path, banner,
            )
