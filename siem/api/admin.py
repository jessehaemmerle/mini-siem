"""Verwaltung: Benutzer, Ingest-Tokens, Einstellungen, Audit-Log, Systemstatus."""

from __future__ import annotations

import shutil
import time
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from .. import __version__
from ..auth import ROLE_LABELS, check_password_policy, create_api_token, hash_password
from .deps import admin, client_ip, get_core, viewer

router = APIRouter(prefix="/api", tags=["Verwaltung"])

Role = Literal["viewer", "analyst", "admin"]


# --------------------------------------------------------------------------- Benutzer


class UserIn(BaseModel):
    username: str = Field(min_length=2, max_length=64, pattern=r"^[A-Za-z0-9._@\-]+$")
    display_name: str | None = Field(None, max_length=100)
    role: Role = "viewer"
    password: str = Field(max_length=256)


class UserUpdate(BaseModel):
    display_name: str | None = Field(None, max_length=100)
    role: Role | None = None
    active: bool | None = None
    password: str | None = Field(None, max_length=256)


def _admins(core) -> int:
    return core.db.one("SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND active = 1")["n"]


@router.get("/users")
def list_users(user=Depends(admin), core=Depends(get_core)):
    rows = core.db.all("SELECT id, username, display_name, role, active, created, last_login FROM users "
                       "ORDER BY username COLLATE NOCASE")
    for r in rows:
        r["role_label"] = ROLE_LABELS[r["role"]]
    return {"users": rows}


@router.post("/users")
def create_user(body: UserIn, request: Request, user=Depends(admin), core=Depends(get_core)):
    try:
        check_password_policy(body.password)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    if core.db.one("SELECT id FROM users WHERE username = ?", (body.username,)):
        raise HTTPException(400, "Dieser Benutzername ist bereits vergeben")
    core.db.execute(
        "INSERT INTO users(username, display_name, password_hash, role, created) VALUES (?, ?, ?, ?, ?)",
        (body.username, body.display_name or None, hash_password(body.password), body.role, time.time()),
    )
    core.db.audit(user["username"], "user.create", f"{body.username} ({ROLE_LABELS[body.role]})", client_ip(request))
    return {"ok": True}


@router.put("/users/{user_id}")
def update_user(user_id: int, body: UserUpdate, request: Request, user=Depends(admin), core=Depends(get_core)):
    target = core.db.one("SELECT * FROM users WHERE id = ?", (user_id,))
    if not target:
        raise HTTPException(404, "Benutzer nicht gefunden")
    demotes_admin = target["role"] == "admin" and target["active"] and (
        (body.role and body.role != "admin") or body.active is False)
    if demotes_admin and _admins(core) <= 1:
        raise HTTPException(400, "Es muss mindestens ein aktiver Administrator bestehen bleiben")
    sets, params, notes = [], [], []
    if "display_name" in body.model_fields_set:
        sets.append("display_name = ?")
        params.append(body.display_name or None)
    if body.role and body.role != target["role"]:
        sets.append("role = ?")
        params.append(body.role)
        notes.append(f"Rolle {ROLE_LABELS[body.role]}")
    if body.active is not None and int(body.active) != target["active"]:
        sets.append("active = ?")
        params.append(int(body.active))
        notes.append("aktiviert" if body.active else "deaktiviert")
    if body.password:
        try:
            check_password_policy(body.password)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        sets.append("password_hash = ?")
        params.append(hash_password(body.password))
        notes.append("Passwort neu gesetzt")
    if sets:
        core.db.execute("UPDATE users SET " + ", ".join(sets) + " WHERE id = ?", [*params, user_id])
        if body.password or body.active is False:
            core.db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        core.db.audit(user["username"], "user.update", f"{target['username']}: " + ", ".join(notes or ["Name"]),
                      client_ip(request))
    return {"ok": True}


@router.delete("/users/{user_id}")
def delete_user(user_id: int, request: Request, user=Depends(admin), core=Depends(get_core)):
    target = core.db.one("SELECT * FROM users WHERE id = ?", (user_id,))
    if not target:
        raise HTTPException(404, "Benutzer nicht gefunden")
    if target["id"] == user["id"]:
        raise HTTPException(400, "Das eigene Konto kann nicht gelöscht werden")
    if target["role"] == "admin" and target["active"] and _admins(core) <= 1:
        raise HTTPException(400, "Es muss mindestens ein aktiver Administrator bestehen bleiben")
    core.db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    core.db.audit(user["username"], "user.delete", target["username"], client_ip(request))
    return {"ok": True}


# --------------------------------------------------------------------------- Tokens


class TokenIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)


@router.get("/tokens")
def list_tokens(user=Depends(admin), core=Depends(get_core)):
    return {"tokens": core.db.all(
        "SELECT id, name, prefix, created, created_by, last_used, events FROM api_tokens ORDER BY created DESC")}


@router.post("/tokens")
def create_token(body: TokenIn, request: Request, user=Depends(admin), core=Depends(get_core)):
    tid, token = create_api_token(core.db, body.name.strip(), user["username"])
    core.tokens.invalidate()
    core.db.audit(user["username"], "token.create", body.name, client_ip(request))
    return {"id": tid, "name": body.name, "token": token}


@router.delete("/tokens/{token_id}")
def delete_token(token_id: int, request: Request, user=Depends(admin), core=Depends(get_core)):
    row = core.db.one("SELECT name FROM api_tokens WHERE id = ?", (token_id,))
    if not row:
        raise HTTPException(404, "Token nicht gefunden")
    core.db.execute("DELETE FROM api_tokens WHERE id = ?", (token_id,))
    core.tokens.invalidate()
    core.db.audit(user["username"], "token.delete", row["name"], client_ip(request))
    return {"ok": True}


# --------------------------------------------------------------------------- Einstellungen


class SettingsIn(BaseModel):
    retention_days: int | None = Field(None, ge=1, le=3650)
    alert_retention_days: int | None = Field(None, ge=7, le=3650)
    source_silent_minutes: int | None = Field(None, ge=5, le=10080)
    session_hours: int | None = Field(None, ge=1, le=720)


@router.get("/settings")
def get_settings(user=Depends(viewer), core=Depends(get_core)):
    s = core.db.all_settings()
    return {k: s[k] for k in ("retention_days", "alert_retention_days", "source_silent_minutes", "session_hours")}


@router.put("/settings")
def put_settings(body: SettingsIn, request: Request, user=Depends(admin), core=Depends(get_core)):
    changed = []
    for key, value in body.model_dump(exclude_none=True).items():
        if core.db.get_setting(key) != value:
            core.db.set_setting(key, value)
            changed.append(f"{key}={value}")
    if changed:
        core.db.audit(user["username"], "settings.update", ", ".join(changed), client_ip(request))
        if body.retention_days:
            core.pipeline.request_maintenance(body.retention_days)
    return get_settings(user, core)


# --------------------------------------------------------------------------- Audit & System


@router.get("/audit")
def audit_log(limit: int = Query(200, ge=1, le=1000), user=Depends(admin), core=Depends(get_core)):
    return {"entries": core.db.all("SELECT * FROM audit_log ORDER BY ts DESC LIMIT ?", (limit,))}


@router.get("/system")
def system(user=Depends(viewer), core=Depends(get_core)):
    s = core.settings
    p = core.pipeline
    parts = core.store.partitions()
    try:
        disk = shutil.disk_usage(s.data_dir)
        disk_info = {"total": disk.total, "used": disk.used, "free": disk.free}
    except OSError:
        disk_info = None
    main_db = s.main_db.stat().st_size if s.main_db.exists() else 0
    return {
        "version": __version__,
        "started": core.started,
        "uptime": time.time() - core.started,
        "pipeline": {
            "queue": p.queue.qsize(),
            "queue_max": s.queue_size,
            "rate": p.rate,
            "processed": p.total,
            "dropped_full": p.dropped_full,
            "dropped_old": p.dropped_old,
            "parse_errors": p.parse_errors,
        },
        "detection": {
            "rules_active": len(core.engine.detector.rules),
            "alerts_created": core.engine.alerts_created,
        },
        "storage": {
            "partitions": parts[-120:],
            "partition_count": len(parts),
            "events_bytes": sum(x["bytes"] for x in parts),
            "main_db_bytes": main_db,
            "oldest_day": parts[0]["day"] if parts else None,
            "disk": disk_info,
        },
        "listeners": {
            "http_port": s.http_port,
            "syslog_udp": s.syslog_udp_port,
            "syslog_tcp": s.syslog_tcp_port,
            "syslog_tls": s.syslog_tls_port,
            "syslog_allow": [str(n) for n in s.syslog_allow],
            "public_syslog_port": s.public_syslog_port,
        },
        "retention_days": p.retention_days,
    }
