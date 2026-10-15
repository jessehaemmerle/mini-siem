"""Microsoft 365: Einstellungen, Verbindungstest und Status des Connectors."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ..m365 import SOURCES, public_config, validate_m365
from .deps import admin, client_ip, get_core, viewer

router = APIRouter(prefix="/api/m365", tags=["Microsoft 365"])


class M365In(BaseModel):
    enabled: bool | None = None
    tenant_id: str | None = Field(None, max_length=64)
    client_id: str | None = Field(None, max_length=64)
    client_secret: str | None = Field(None, max_length=512, description="leer = bisherigen Schlüssel behalten")
    sources: dict[str, bool] | None = None
    skip_noise: bool | None = None
    interval: int | None = Field(None, ge=60, le=3600)


def _sources() -> list[dict]:
    return [{"key": k, "label": v["label"], "permission": v["permission"]} for k, v in SOURCES.items()]


@router.get("")
def get_m365(user=Depends(admin), core=Depends(get_core)):
    return {"config": public_config(core.m365.config()), "sources": _sources(), "status": core.m365.snapshot()}


@router.get("/status")
def m365_status(user=Depends(viewer), core=Depends(get_core)):
    cfg = core.m365.config()
    return {"enabled": cfg["enabled"], "status": core.m365.snapshot()}


def _merge(body: M365In, core) -> dict:
    stored = core.db.get_setting("m365") or {}
    data = {k: v for k, v in body.model_dump().items() if v is not None}
    try:
        return validate_m365(data, stored)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None


@router.put("")
def put_m365(body: M365In, request: Request, user=Depends(admin), core=Depends(get_core)):
    cfg = _merge(body, core)
    old = core.m365.config()
    core.m365.save_config(cfg)
    notes = []
    if cfg["enabled"] != old["enabled"]:
        notes.append("aktiviert" if cfg["enabled"] else "deaktiviert")
    if (cfg["tenant_id"], cfg["client_id"]) != (old["tenant_id"], old["client_id"]):
        notes.append(f"Mandant {cfg['tenant_id'] or '–'}, App {cfg['client_id'] or '–'}")
    if body.client_secret:
        notes.append("neuer Clientschlüssel")
    if cfg["sources"] != old["sources"]:
        notes.append("Bereiche: " + ", ".join(SOURCES[k]["label"] for k, on in cfg["sources"].items() if on))
    core.db.audit(user["username"], "m365.settings", "; ".join(notes) or "gespeichert", client_ip(request))
    return get_m365(user, core)


@router.post("/test")
def test_m365(body: M365In, user=Depends(admin), core=Depends(get_core)):
    """Testet die eingegebenen (noch nicht gespeicherten) Werte."""
    cfg = _merge(body.model_copy(update={"enabled": False}), core)
    missing = [n for k, n in (("tenant_id", "Verzeichnis-ID"), ("client_id", "Anwendungs-ID"),
                              ("client_secret", "geheimer Clientschlüssel")) if not cfg[k]]
    if missing:
        raise HTTPException(400, "Für den Test fehlt: " + ", ".join(missing))
    results = core.m365.test(cfg)
    if not results:
        raise HTTPException(400, "Bitte mindestens einen Bereich auswählen")
    return {"ok": all(r["ok"] for r in results), "results": results}


@router.post("/poll")
def poll_m365(user=Depends(admin), core=Depends(get_core)):
    cfg = core.m365.config()
    if not cfg["enabled"]:
        raise HTTPException(400, "Der Microsoft-365-Connector ist nicht aktiviert")
    core.m365.wake()
    return {"ok": True}


@router.delete("")
def delete_m365(request: Request, user=Depends(admin), core=Depends(get_core)):
    """Verbindung entfernen: Zugangsdaten und Abrufstand löschen (gespeicherte Events bleiben)."""
    core.m365.save_config(validate_m365({"enabled": False, "tenant_id": "", "client_id": ""}, {}))
    core.m365.reset_state()
    core.db.audit(user["username"], "m365.delete", "Verbindung entfernt", client_ip(request))
    return {"ok": True}
