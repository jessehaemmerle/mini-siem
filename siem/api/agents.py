"""Agenten: Installation, Registrierung, Konfiguration, Event-Annahme, Verwaltung."""

from __future__ import annotations

import hmac
import json
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from .. import __version__
from ..agents import (INSTALL_PS1, INSTALL_SH, ONLINE_SECONDS, PLATFORMS, config_version, new_agent_token,
                      new_enroll_key, validate_config)
from ..auth import hash_token
from .deps import admin, client_ip, get_core, viewer
from .ingest import IngestError, _read_body

router = APIRouter(tags=["Agenten"])

MAX_EVENTS_PER_REQUEST = 20_000


def server_url(request: Request, core) -> str:
    if core.settings.public_url:
        return core.settings.public_url
    return f"{request.url.scheme}://{request.headers.get('host') or request.url.netloc}"


def _bearer(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    scheme, _, value = auth.partition(" ")
    return value.strip() if scheme.lower() == "bearer" else None


def _agent(request: Request, core) -> dict:
    agent = core.agents.lookup(_bearer(request))
    if agent is None:
        raise HTTPException(401, "Agent unbekannt oder gesperrt")
    return agent


def effective_config(core, agent_row: dict) -> dict:
    if agent_row.get("config"):
        try:
            return validate_config(json.loads(agent_row["config"]))
        except (ValueError, TypeError):
            pass
    return validate_config(core.db.get_setting("agent_config") or {})


# --------------------------------------------------------------------------- öffentlich


@router.get("/api/agent/install.sh", include_in_schema=False)
def install_sh(request: Request, core=Depends(get_core)):
    return PlainTextResponse(INSTALL_SH.replace("__SERVER__", server_url(request, core)),
                             media_type="text/x-shellscript; charset=utf-8")


@router.get("/api/agent/install.ps1", include_in_schema=False)
def install_ps1(request: Request, core=Depends(get_core)):
    # Ohne BOM: „irm“ dekodiert anhand von charset=utf-8, ein BOM stünde sonst vor dem param()-Block
    body = INSTALL_PS1.replace("__SERVER__", server_url(request, core)).replace("\n", "\r\n")
    return PlainTextResponse(body, media_type="text/plain; charset=utf-8")


@router.get("/api/agent/download/{name}", include_in_schema=False)
def download(name: str, core=Depends(get_core)):
    platform, _, ext = name.partition(".")
    if platform not in PLATFORMS or ext not in ("", "sha256"):
        raise HTTPException(404, "Unbekannte Plattform")
    path = core.agent_dist.path(platform)
    if path is None:
        raise HTTPException(404, "Für diese Plattform ist kein Agent im Container enthalten")
    if ext == "sha256":
        return PlainTextResponse(core.agent_dist.sha256(platform) + "\n")
    return FileResponse(path, media_type="application/octet-stream", filename=core.agent_dist.filename(platform))


class EnrollIn(BaseModel):
    key: str = Field(max_length=200)
    machine_id: str = Field(min_length=8, max_length=200)
    hostname: str = Field(min_length=1, max_length=255)
    os: str = Field(max_length=40)
    os_version: str | None = Field(None, max_length=200)
    arch: str | None = Field(None, max_length=40)
    version: str | None = Field(None, max_length=40)


@router.post("/api/agent/enroll")
def enroll(body: EnrollIn, request: Request, core=Depends(get_core)):
    ip = client_ip(request) or "?"
    if core.throttle.blocked("enroll|" + ip):
        raise HTTPException(429, "Zu viele Fehlversuche")
    expected = core.db.get_setting("agent_enroll_key") or ""
    if not expected or not hmac.compare_digest(body.key.strip(), expected):
        core.throttle.failure("enroll|" + ip)
        core.db.audit(None, "agent.enroll.failed", body.hostname[:100], ip)
        raise HTTPException(403, "Registrierungsschlüssel ist falsch")
    token = new_agent_token()
    now = time.time()
    hostname = body.hostname.strip().lower()
    existing = core.db.one("SELECT id FROM agents WHERE machine_id = ?", (body.machine_id,))
    with core.db.tx() as conn:
        if existing:
            conn.execute(
                "UPDATE agents SET hostname = ?, os = ?, os_version = ?, arch = ?, version = ?, ip = ?, "
                "token_hash = ?, last_seen = ?, disabled = 0 WHERE id = ?",
                (hostname, body.os, body.os_version, body.arch, body.version, ip, hash_token(token), now,
                 existing["id"]),
            )
            agent_id = existing["id"]
        else:
            cur = conn.execute(
                "INSERT INTO agents(machine_id, hostname, os, os_version, arch, version, ip, token_hash, enrolled, "
                "last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (body.machine_id, hostname, body.os, body.os_version, body.arch, body.version, ip,
                 hash_token(token), now, now),
            )
            agent_id = cur.lastrowid
    core.agents.invalidate()
    core.db.audit(None, "agent.enroll", f"{hostname} ({body.os})", ip)
    return {"agent_id": agent_id, "token": token, "hostname": hostname}


class CheckinIn(BaseModel):
    version: str | None = Field(None, max_length=40)
    hostname: str | None = Field(None, max_length=255)
    os_version: str | None = Field(None, max_length=200)
    stats: dict | None = None


@router.post("/api/agent/checkin")
def checkin(body: CheckinIn, request: Request, core=Depends(get_core)):
    agent = _agent(request, core)
    row = core.db.one("SELECT * FROM agents WHERE id = ?", (agent["id"],))
    stats = json.dumps(body.stats or {}, default=str)[:20_000]
    core.db.execute(
        "UPDATE agents SET last_seen = ?, ip = ?, version = COALESCE(?, version), "
        "os_version = COALESCE(?, os_version), stats = ? WHERE id = ?",
        (time.time(), client_ip(request), body.version, body.os_version, stats, agent["id"]),
    )
    cfg = effective_config(core, row)
    update = None
    dist_version = core.agent_dist.version()
    platform = f"{(row['os'] or '').lower()}-{(row['arch'] or '').lower()}"
    if (core.db.get_setting("agent_auto_update") and dist_version and body.version
            and body.version != dist_version and core.agent_dist.path(platform)):
        update = {
            "version": dist_version,
            "sha256": core.agent_dist.sha256(platform),
            "url": f"/api/agent/download/{platform}",
        }
    return {
        "agent_id": agent["id"],
        "name": row["name"] or row["hostname"],
        "config": cfg,
        "config_version": config_version(cfg),
        "update": update,
        "server_time": time.time(),
    }


@router.post("/api/agent/events")
async def agent_events(request: Request, core=Depends(get_core)):
    agent = core.agents.lookup(_bearer(request))
    if agent is None:
        return JSONResponse({"detail": "Agent unbekannt oder gesperrt"}, status_code=401)
    try:
        data = await _read_body(request)
        items = await run_in_threadpool(json.loads, data.decode("utf-8", errors="replace") or "[]")
    except IngestError as exc:
        return JSONResponse({"detail": exc.message}, status_code=exc.status)
    except ValueError:
        return JSONResponse({"detail": "Ungültiges JSON"}, status_code=400)
    if isinstance(items, dict):
        items = [items]
    if not isinstance(items, list) or len(items) > MAX_EVENTS_PER_REQUEST:
        return JSONResponse({"detail": "Erwartet wird eine Liste mit höchstens 20.000 Events"}, status_code=413)
    if not core.pipeline.has_capacity(len(items)):
        return JSONResponse({"detail": "Das SIEM ist ausgelastet – bitte später erneut senden"}, status_code=503,
                            headers={"Retry-After": "30"})
    ip = client_ip(request)
    host = agent["hostname"]
    now = time.time()
    accepted = sum(1 for obj in items
                   if isinstance(obj, dict) and core.pipeline.submit("agent", (obj, host), ip, now))
    core.agents.count(agent["id"], accepted)
    return {"accepted": accepted}


# --------------------------------------------------------------------------- Verwaltung


def _public_agent(r: dict, now: float) -> dict:
    out = {k: r[k] for k in ("id", "hostname", "name", "os", "os_version", "arch", "version", "ip", "enrolled",
                              "last_seen", "events", "disabled")}
    out["online"] = bool(r["last_seen"] and r["last_seen"] > now - ONLINE_SECONDS and not r["disabled"])
    out["has_own_config"] = bool(r["config"])
    try:
        out["stats"] = json.loads(r["stats"]) if r["stats"] else {}
    except ValueError:
        out["stats"] = {}
    return out


@router.get("/api/agents")
def list_agents(user=Depends(viewer), core=Depends(get_core)):
    now = time.time()
    rows = core.db.all("SELECT * FROM agents ORDER BY hostname COLLATE NOCASE")
    return {"agents": [_public_agent(r, now) for r in rows], "server_version": core.agent_dist.version() or __version__}


@router.get("/api/agents/{agent_id}/config")
def get_agent_config(agent_id: int, user=Depends(admin), core=Depends(get_core)):
    row = core.db.one("SELECT * FROM agents WHERE id = ?", (agent_id,))
    if not row:
        raise HTTPException(404, "Agent nicht gefunden")
    return {"own": bool(row["config"]), "config": effective_config(core, row)}


class AgentUpdate(BaseModel):
    name: str | None = Field(None, max_length=100)
    disabled: bool | None = None
    config: dict | None = None
    use_default: bool | None = None


@router.patch("/api/agents/{agent_id}")
def update_agent(agent_id: int, body: AgentUpdate, request: Request, user=Depends(admin), core=Depends(get_core)):
    row = core.db.one("SELECT * FROM agents WHERE id = ?", (agent_id,))
    if not row:
        raise HTTPException(404, "Agent nicht gefunden")
    sets, params, notes = [], [], []
    if "name" in body.model_fields_set:
        sets.append("name = ?")
        params.append((body.name or "").strip() or None)
        notes.append("Name")
    if body.disabled is not None:
        sets.append("disabled = ?")
        params.append(int(body.disabled))
        notes.append("gesperrt" if body.disabled else "entsperrt")
    if body.use_default:
        sets.append("config = NULL")
        notes.append("Standard-Einstellungen")
    elif body.config is not None:
        try:
            cfg = validate_config(body.config)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        sets.append("config = ?")
        params.append(json.dumps(cfg))
        notes.append("eigene Einstellungen")
    if sets:
        core.db.execute("UPDATE agents SET " + ", ".join(sets) + " WHERE id = ?", [*params, agent_id])
        core.agents.invalidate()
        core.db.audit(user["username"], "agent.update", f"{row['hostname']}: " + ", ".join(notes), client_ip(request))
    return {"ok": True}


@router.delete("/api/agents/{agent_id}")
def delete_agent(agent_id: int, request: Request, user=Depends(admin), core=Depends(get_core)):
    row = core.db.one("SELECT hostname FROM agents WHERE id = ?", (agent_id,))
    if not row:
        raise HTTPException(404, "Agent nicht gefunden")
    core.db.execute("DELETE FROM agents WHERE id = ?", (agent_id,))
    core.agents.invalidate()
    core.db.audit(user["username"], "agent.delete", row["hostname"], client_ip(request))
    return {"ok": True}


@router.get("/api/agents-settings")
def get_agent_settings(request: Request, user=Depends(admin), core=Depends(get_core)):
    url = server_url(request, core)
    key = core.db.get_setting("agent_enroll_key")
    return {
        "enroll_key": key,
        "server_url": url,
        "config": validate_config(core.db.get_setting("agent_config") or {}),
        "auto_update": bool(core.db.get_setting("agent_auto_update")),
        "version": core.agent_dist.version(),
        "platforms": core.agent_dist.available(),
        "commands": {
            "linux": f"curl -fsSL {url}/api/agent/install.sh | sudo bash -s -- --key {key}",
            "windows": f"& ([scriptblock]::Create((irm {url}/api/agent/install.ps1))) -Key {key}",
        },
    }


class AgentSettingsIn(BaseModel):
    config: dict | None = None
    auto_update: bool | None = None


@router.put("/api/agents-settings")
def put_agent_settings(body: AgentSettingsIn, request: Request, user=Depends(admin), core=Depends(get_core)):
    notes = []
    if body.config is not None:
        try:
            cfg = validate_config(body.config)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        core.db.set_setting("agent_config", cfg)
        notes.append("Standard-Einstellungen")
    if body.auto_update is not None:
        core.db.set_setting("agent_auto_update", bool(body.auto_update))
        notes.append("automatische Updates " + ("an" if body.auto_update else "aus"))
    if notes:
        core.db.audit(user["username"], "agent.settings", ", ".join(notes), client_ip(request))
    return get_agent_settings(request, user, core)


@router.post("/api/agents-settings/enroll-key")
def rotate_enroll_key(request: Request, user=Depends(admin), core=Depends(get_core)):
    core.db.set_setting("agent_enroll_key", new_enroll_key())
    core.db.audit(user["username"], "agent.enroll_key", "neuer Registrierungsschlüssel", client_ip(request))
    return get_agent_settings(request, user, core)
