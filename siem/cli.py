"""Kommandozeile für Betrieb und Wartung.

    python -m siem                         Server starten (Standard)
    python -m siem backup [--tage N] [ZIEL]  Sicherung als .tar.gz erstellen
    python -m siem passwort BENUTZER       neues Passwort für ein Konto setzen

Im Container: ``docker compose exec siem python -m siem backup``
"""

from __future__ import annotations

import argparse
import secrets
import sqlite3
import sys
import tarfile
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .config import Settings


def _sqlite_copy(src: Path, dst: Path) -> None:
    """Konsistente Kopie einer SQLite-Datei – auch während der Server läuft."""
    s = sqlite3.connect(str(src), timeout=60)
    d = sqlite3.connect(str(dst))
    try:
        s.backup(d)
    finally:
        d.close()
        s.close()


def backup(settings: Settings, target: str | None, days: int | None) -> Path:
    data = settings.data_dir
    if not settings.main_db.exists():
        raise SystemExit(f"Keine Datenbank gefunden in {data}")
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = Path(target) if target else data / "backups" / f"siem-backup-{stamp}.tar.gz"
    if out.is_dir():
        out = out / f"siem-backup-{stamp}.tar.gz"
    out.parent.mkdir(parents=True, exist_ok=True)
    cutoff = None
    if days:
        cutoff = (datetime.now(timezone.utc).date() - timedelta(days=days)).isoformat()
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        (tmpdir / "events").mkdir()
        _sqlite_copy(settings.main_db, tmpdir / "siem.db")
        n = 0
        for f in sorted(settings.events_dir.glob("*.db")):
            if cutoff and f.stem < cutoff:
                continue
            _sqlite_copy(f, tmpdir / "events" / f.name)
            n += 1
        with tarfile.open(out, "w:gz") as tar:
            tar.add(tmpdir / "siem.db", arcname="siem.db")
            tar.add(tmpdir / "events", arcname="events")
    print(f"Sicherung erstellt: {out} ({n} Tagesdatei(en), {out.stat().st_size / 1048576:.1f} MB)")
    print("Wiederherstellen: Container stoppen, Archiv in das Datenverzeichnis entpacken, Container starten.")
    return out


def reset_password(settings: Settings, username: str) -> None:
    from .auth import hash_password
    from .db import Database

    db = Database(settings.main_db)
    user = db.one("SELECT id FROM users WHERE username = ?", (username,))
    if not user:
        names = ", ".join(r["username"] for r in db.all("SELECT username FROM users"))
        raise SystemExit(f"Benutzer '{username}' nicht gefunden. Vorhanden: {names}")
    password = secrets.token_urlsafe(12)
    db.execute("UPDATE users SET password_hash = ?, active = 1 WHERE id = ?", (hash_password(password), user["id"]))
    db.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
    db.audit("system", "password.reset", f"{username} (Kommandozeile)")
    print(f"Neues Passwort für {username}: {password}")
    print("Bitte nach der Anmeldung unter Ihrem Namen (unten links) ändern.")


def main(argv: list[str] | None = None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in ("serve", "server", "start"):
        from .main import run
        run()
        return
    ap = argparse.ArgumentParser(prog="python -m siem", description="Mini-SIEM Wartung")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("backup", help="Sicherung erstellen")
    b.add_argument("ziel", nargs="?", help="Datei oder Ordner (Standard: <daten>/backups/)")
    b.add_argument("--tage", type=int, help="nur Events der letzten N Tage sichern")
    pw = sub.add_parser("passwort", aliases=["reset-password"], help="neues Passwort setzen")
    pw.add_argument("benutzer")
    args = ap.parse_args(argv)
    settings = Settings()
    started = time.time()
    if args.cmd == "backup":
        backup(settings, args.ziel, args.tage)
        print(f"Dauer: {time.time() - started:.1f} s")
    else:
        reset_password(settings, args.benutzer)
