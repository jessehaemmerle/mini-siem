"""Gemeinsame Abhängigkeiten der API: Anmeldung, Rollen, Zeitbereiche."""

from __future__ import annotations

import time

from fastapi import Depends, HTTPException, Query, Request

from ..auth import ROLE_RANK, SESSION_COOKIE, session_user
from ..core import Core

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
CSRF_HEADER = "x-siem"


def get_core(request: Request) -> Core:
    return request.app.state.core


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def current_user(request: Request, core: Core = Depends(get_core)) -> dict:
    token = request.cookies.get(SESSION_COOKIE)
    hours = int(core.db.get_setting("session_hours") or 12)
    user = session_user(core.db, token, hours)
    if user is None:
        raise HTTPException(401, "Nicht angemeldet")
    # Schutz vor CSRF: Browser senden diesen Header nur von der eigenen Seite
    if request.method not in SAFE_METHODS and request.headers.get(CSRF_HEADER) != "1":
        raise HTTPException(403, "Fehlender Sicherheits-Header")
    return user


def require(role: str):
    def dep(user: dict = Depends(current_user)) -> dict:
        if ROLE_RANK.get(user["role"], -1) < ROLE_RANK[role]:
            raise HTTPException(403, "Für diese Aktion fehlen die Berechtigungen")
        return user

    return dep


viewer = require("viewer")
analyst = require("analyst")
admin = require("admin")


class TimeRange:
    def __init__(self, t_from: float, t_to: float):
        self.t_from = t_from
        self.t_to = t_to


def time_range(
    from_: float | None = Query(None, alias="from", description="Start (Unix-Zeit, Sekunden)"),
    to: float | None = Query(None, description="Ende (Unix-Zeit, Sekunden)"),
) -> TimeRange:
    now = time.time()
    t_to = to if to is not None else now
    t_from = from_ if from_ is not None else t_to - 86400
    if t_from >= t_to:
        raise HTTPException(400, "Der Startzeitpunkt muss vor dem Ende liegen")
    if t_to - t_from > 400 * 86400:
        t_from = t_to - 400 * 86400
    return TimeRange(t_from, t_to)
