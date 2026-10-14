"""Benutzer, Passwörter, Sitzungen, API-Tokens und Rollen.

Rollen:
* ``viewer``  – darf alles ansehen
* ``analyst`` – zusätzlich Alarme bearbeiten und Regeln pflegen
* ``admin``   – zusätzlich Benutzer, Tokens und Einstellungen verwalten
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from collections import defaultdict, deque

ROLES = ("viewer", "analyst", "admin")
ROLE_RANK = {r: i for i, r in enumerate(ROLES)}
ROLE_LABELS = {"viewer": "Nur lesen", "analyst": "Analyst", "admin": "Administrator"}

SESSION_COOKIE = "siem_session"
_SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1}


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, dklen=32, **_SCRYPT)
    return "scrypt$%d$%d$%d$%s$%s" % (
        _SCRYPT["n"], _SCRYPT["r"], _SCRYPT["p"],
        base64.b64encode(salt).decode(), base64.b64encode(digest).decode(),
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt_b64, hash_b64 = stored.split("$")
        if algo != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        digest = hashlib.scrypt(password.encode(), salt=salt, dklen=len(expected),
                                n=int(n), r=int(r), p=int(p))
        return hmac.compare_digest(digest, expected)
    except (ValueError, TypeError):
        return False


def check_password_policy(password: str) -> None:
    if len(password) < 10:
        raise ValueError("Das Passwort muss mindestens 10 Zeichen lang sein")
    if len(password) > 256:
        raise ValueError("Das Passwort ist zu lang (max. 256 Zeichen)")


def hash_token(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


# --------------------------------------------------------------------------- Sitzungen


def create_session(db, user_id: int, ip: str | None, hours: int) -> str:
    token = secrets.token_urlsafe(32)
    now = time.time()
    db.execute(
        "INSERT INTO sessions(token_hash, user_id, created, expires, ip) VALUES (?, ?, ?, ?, ?)",
        (hash_token(token), user_id, now, now + hours * 3600, ip),
    )
    db.execute("UPDATE users SET last_login = ? WHERE id = ?", (now, user_id))
    return token


def session_user(db, token: str | None, hours: int) -> dict | None:
    if not token:
        return None
    th = hash_token(token)
    row = db.one(
        "SELECT u.id, u.username, u.display_name, u.role, u.active, s.expires "
        "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
        (th,),
    )
    now = time.time()
    if not row or row["expires"] < now or not row["active"]:
        return None
    # gleitende Gültigkeit: bei Aktivität verlängern
    if row["expires"] - now < hours * 3600 / 2:
        db.execute("UPDATE sessions SET expires = ? WHERE token_hash = ?", (now + hours * 3600, th))
    row.pop("expires")
    return row


def delete_session(db, token: str | None) -> None:
    if token:
        db.execute("DELETE FROM sessions WHERE token_hash = ?", (hash_token(token),))


# --------------------------------------------------------------------------- API-Tokens


def create_api_token(db, name: str, created_by: str) -> tuple[int, str]:
    token = "siem_" + secrets.token_urlsafe(30)
    cur = db.execute(
        "INSERT INTO api_tokens(name, token_hash, prefix, created, created_by) VALUES (?, ?, ?, ?, ?)",
        (name, hash_token(token), token[:10], time.time(), created_by),
    )
    return cur.lastrowid, token


class TokenCache:
    """Hält gültige Sende-Tokens im Speicher (keine DB-Abfrage pro Request)."""

    def __init__(self, db):
        self.db = db
        self._tokens: dict[str, int] = {}
        self._loaded = 0.0

    def invalidate(self) -> None:
        self._loaded = 0.0

    def lookup(self, token: str | None) -> int | None:
        if not token:
            return None
        if time.time() - self._loaded > 60:
            self._tokens = {r["token_hash"]: r["id"] for r in self.db.all("SELECT id, token_hash FROM api_tokens")}
            self._loaded = time.time()
        return self._tokens.get(hash_token(token.strip()))


# --------------------------------------------------------------------------- Schutz vor Raten


class LoginThrottle:
    def __init__(self, max_failures: int = 10, window: int = 900):
        self.max = max_failures
        self.window = window
        self._fail: dict[str, deque] = defaultdict(deque)

    def _prune(self, key: str) -> deque:
        dq = self._fail[key]
        limit = time.time() - self.window
        while dq and dq[0] < limit:
            dq.popleft()
        return dq

    def blocked(self, key: str) -> bool:
        return len(self._prune(key)) >= self.max

    def failure(self, key: str) -> None:
        self._prune(key).append(time.time())
        if len(self._fail) > 10_000:
            for k in list(self._fail)[:5000]:
                del self._fail[k]

    def success(self, key: str) -> None:
        self._fail.pop(key, None)
