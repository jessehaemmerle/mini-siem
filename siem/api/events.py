"""Suche, Histogramm, Top-Werte, Dashboard und Quellen."""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException, Query

from .. import query as q
from ..storage import TOP_FIELDS, QueryTimeout
from .deps import TimeRange, analyst, get_core, time_range, viewer

router = APIRouter(prefix="/api", tags=["Events"])


def _parse(qs: str | None):
    try:
        return q.parse(qs)
    except q.QueryError as exc:
        raise HTTPException(400, str(exc)) from None


def _timeout():
    return HTTPException(408, "Die Abfrage hat zu lange gedauert. Bitte den Zeitraum verkleinern "
                              "oder die Suche genauer formulieren.")


@router.get("/query/check")
def check_query(q_: str = Query("", alias="q"), user=Depends(viewer)):
    try:
        q.parse(q_)
        return {"ok": True}
    except q.QueryError as exc:
        return {"ok": False, "error": str(exc)}


@router.get("/events")
def search_events(
    q_: str = Query("", alias="q", max_length=4000),
    limit: int = Query(100, ge=1, le=1000),
    cursor: str | None = None,
    tr: TimeRange = Depends(time_range),
    user=Depends(viewer),
    core=Depends(get_core),
):
    node = _parse(q_)
    started = time.monotonic()
    try:
        events, next_cursor = core.store.search(node, tr.t_from, tr.t_to, limit, cursor)
    except QueryTimeout:
        raise _timeout() from None
    return {"events": events, "next_cursor": next_cursor,
            "took_ms": int((time.monotonic() - started) * 1000)}


@router.get("/events/histogram")
def histogram(q_: str = Query("", alias="q", max_length=4000), tr: TimeRange = Depends(time_range),
              user=Depends(viewer), core=Depends(get_core)):
    node = _parse(q_)
    try:
        return core.store.histogram(node, tr.t_from, tr.t_to)
    except QueryTimeout:
        raise _timeout() from None


@router.get("/events/top")
def top_values(field: str, q_: str = Query("", alias="q", max_length=4000), limit: int = Query(10, ge=1, le=50),
               tr: TimeRange = Depends(time_range), user=Depends(viewer), core=Depends(get_core)):
    if field not in TOP_FIELDS:
        raise HTTPException(400, f"Feld '{field}' kann nicht ausgewertet werden")
    node = _parse(q_)
    try:
        return {"field": field, "values": core.store.top_values(node, field, tr.t_from, tr.t_to, limit)}
    except QueryTimeout:
        raise _timeout() from None


@router.get("/dashboard")
def dashboard(tr: TimeRange = Depends(time_range), user=Depends(viewer), core=Depends(get_core)):
    try:
        stats = core.store.stats_overview(tr.t_from, tr.t_to)
    except QueryTimeout:
        raise _timeout() from None
    db = core.db
    alerts_by_status = {r["status"]: r["n"] for r in db.all(
        "SELECT status, COUNT(*) AS n FROM alerts GROUP BY status")}
    open_by_sev = {r["severity"]: r["n"] for r in db.all(
        "SELECT severity, COUNT(*) AS n FROM alerts WHERE status != 'closed' GROUP BY severity")}
    new_alerts = db.one("SELECT COUNT(*) AS n FROM alerts WHERE created >= ? AND created < ?",
                        (tr.t_from, tr.t_to))["n"]
    recent = db.all(
        "SELECT id, rule_name, severity, group_value, count, last_seen, status FROM alerts "
        "WHERE status != 'closed' ORDER BY last_seen DESC LIMIT 8")
    top_rules = db.all(
        "SELECT rule_name, COUNT(*) AS n, SUM(count) AS hits FROM alerts WHERE created >= ? "
        "GROUP BY rule_name ORDER BY n DESC LIMIT 5", (tr.t_from,))
    silent_min = int(db.get_setting("source_silent_minutes") or 60)
    now = time.time()
    src = db.one(
        "SELECT COUNT(*) AS total, SUM(CASE WHEN last_seen < ? THEN 1 ELSE 0 END) AS silent FROM sources",
        (now - silent_min * 60,))
    return {
        "range": {"from": tr.t_from, "to": tr.t_to},
        "events": stats,
        "alerts": {
            "by_status": alerts_by_status,
            "open_by_severity": open_by_sev,
            "new_in_range": new_alerts,
            "recent": recent,
            "top_rules": top_rules,
        },
        "sources": {"total": src["total"] or 0, "silent": src["silent"] or 0},
        "rate": core.pipeline.rate,
    }


@router.get("/sources")
def sources(user=Depends(viewer), core=Depends(get_core)):
    silent_min = int(core.db.get_setting("source_silent_minutes") or 60)
    now = time.time()
    rows = core.db.all("SELECT * FROM sources ORDER BY last_seen DESC")
    for r in rows:
        r["silent"] = r["last_seen"] < now - silent_min * 60
    return {"sources": rows, "silent_minutes": silent_min}


@router.delete("/sources/{source_id}")
def delete_source(source_id: int, user=Depends(analyst), core=Depends(get_core)):
    row = core.db.one("SELECT host, input FROM sources WHERE id = ?", (source_id,))
    if not row:
        raise HTTPException(404, "Quelle nicht gefunden")
    core.db.execute("DELETE FROM sources WHERE id = ?", (source_id,))
    core.db.audit(user["username"], "source.delete", f"{row['host']} ({row['input']})")
    return {"ok": True}


@router.get("/fields")
def fields(user=Depends(viewer)):
    return {"fields": [{"name": k, "type": v} for k, v in q.FIELDS.items()],
            "aliases": q.ALIASES, "severities": q.SEVERITY_LABELS}

