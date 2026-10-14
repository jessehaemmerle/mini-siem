"""Alarme: auflisten, ansehen, bearbeiten, kommentieren."""

from __future__ import annotations

import json
import time
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from .deps import analyst, client_ip, get_core, viewer

router = APIRouter(prefix="/api/alerts", tags=["Alarme"])

STATUS_LABELS = {"open": "offen", "ack": "in Bearbeitung", "closed": "geschlossen"}


class AlertUpdate(BaseModel):
    status: Literal["open", "ack", "closed"] | None = None
    assignee: str | None = Field(None, max_length=100)
    resolution: str | None = Field(None, max_length=2000)


class BulkUpdate(BaseModel):
    ids: list[int] = Field(max_length=1000)
    status: Literal["open", "ack", "closed"]


class CommentIn(BaseModel):
    text: str = Field(min_length=1, max_length=5000)


def _decode(row: dict) -> dict:
    for k, default in (("samples", []), ("hosts", [])):
        if k in row:
            try:
                row[k] = json.loads(row[k] or "null") or default
            except ValueError:
                row[k] = default
    return row


@router.get("")
def list_alerts(
    status: Literal["open", "ack", "closed", "active", "all"] = "active",
    severity: Literal["low", "medium", "high", "critical"] | None = None,
    rule_id: int | None = None,
    search: str | None = Query(None, max_length=200),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user=Depends(viewer),
    core=Depends(get_core),
):
    where, params = ["1"], []
    if status == "active":
        where.append("status != 'closed'")
    elif status != "all":
        where.append("status = ?")
        params.append(status)
    if severity:
        where.append("severity = ?")
        params.append(severity)
    if rule_id:
        where.append("rule_id = ?")
        params.append(rule_id)
    if search:
        where.append("(rule_name LIKE ? OR group_value LIKE ? OR hosts LIKE ? OR assignee LIKE ?)")
        params += [f"%{search}%"] * 4
    cond = " AND ".join(where)
    total = core.db.one("SELECT COUNT(*) AS n FROM alerts WHERE " + cond, params)["n"]
    rows = core.db.all(
        "SELECT id, rule_id, rule_name, severity, group_value, count, first_seen, last_seen, status, "
        "assignee, hosts, created, updated, "
        "(SELECT COUNT(*) FROM alert_comments c WHERE c.alert_id = alerts.id) AS comments "
        "FROM alerts WHERE " + cond + " "
        "ORDER BY CASE status WHEN 'open' THEN 0 WHEN 'ack' THEN 1 ELSE 2 END, "
        "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, "
        "last_seen DESC LIMIT ? OFFSET ?",
        [*params, limit, offset],
    )
    counts = {r["status"]: r["n"] for r in core.db.all("SELECT status, COUNT(*) AS n FROM alerts GROUP BY status")}
    return {"alerts": [_decode(r) for r in rows], "total": total, "counts": counts}


@router.get("/{alert_id}")
def get_alert(alert_id: int, user=Depends(viewer), core=Depends(get_core)):
    row = core.db.one("SELECT * FROM alerts WHERE id = ?", (alert_id,))
    if not row:
        raise HTTPException(404, "Alarm nicht gefunden")
    row = _decode(row)
    row["comments"] = core.db.all(
        "SELECT id, username, ts, text FROM alert_comments WHERE alert_id = ? ORDER BY ts", (alert_id,))
    row["rule"] = core.db.one(
        "SELECT id, name, description, query, threshold, window, group_by, distinct_field, enabled "
        "FROM rules WHERE id = ?", (row["rule_id"],)) if row["rule_id"] else None
    return row


def _comment(core, alert_id: int, username: str, text: str) -> None:
    core.db.execute("INSERT INTO alert_comments(alert_id, username, ts, text) VALUES (?, ?, ?, ?)",
                    (alert_id, username, time.time(), text))


@router.patch("/{alert_id}")
def update_alert(alert_id: int, body: AlertUpdate, request: Request, user=Depends(analyst), core=Depends(get_core)):
    row = core.db.one("SELECT * FROM alerts WHERE id = ?", (alert_id,))
    if not row:
        raise HTTPException(404, "Alarm nicht gefunden")
    sets, params, notes = [], [], []
    fields = body.model_fields_set
    if body.status and body.status != row["status"]:
        sets.append("status = ?")
        params.append(body.status)
        notes.append(f"Status: {STATUS_LABELS[row['status']]} → {STATUS_LABELS[body.status]}")
    if "assignee" in fields and (body.assignee or None) != row["assignee"]:
        sets.append("assignee = ?")
        params.append(body.assignee or None)
        notes.append(f"Zuständig: {body.assignee or '–'}")
    if "resolution" in fields and body.resolution != row["resolution"]:
        sets.append("resolution = ?")
        params.append(body.resolution or None)
        if body.resolution:
            notes.append(f"Ergebnis: {body.resolution}")
    if not sets:
        return get_alert(alert_id, user, core)
    sets.append("updated = ?")
    params.append(time.time())
    core.db.execute("UPDATE alerts SET " + ", ".join(sets) + " WHERE id = ?", [*params, alert_id])
    _comment(core, alert_id, user["username"], " · ".join(notes))
    core.db.audit(user["username"], "alert.update", f"#{alert_id}: " + "; ".join(notes), client_ip(request))
    return get_alert(alert_id, user, core)


@router.post("/bulk")
def bulk_update(body: BulkUpdate, request: Request, user=Depends(analyst), core=Depends(get_core)):
    if not body.ids:
        return {"updated": 0}
    marks = ",".join("?" * len(body.ids))
    now = time.time()
    rows = core.db.all("SELECT id, status FROM alerts WHERE id IN (" + marks + ")", body.ids)
    changed = [r["id"] for r in rows if r["status"] != body.status]
    with core.db.tx() as conn:
        for aid in changed:
            conn.execute("UPDATE alerts SET status = ?, updated = ? WHERE id = ?", (body.status, now, aid))
            conn.execute("INSERT INTO alert_comments(alert_id, username, ts, text) VALUES (?, ?, ?, ?)",
                         (aid, user["username"], now, f"Status: {STATUS_LABELS[body.status]} (Sammelaktion)"))
    if changed:
        core.db.audit(user["username"], "alert.bulk", f"{len(changed)} Alarm(e) → {STATUS_LABELS[body.status]}",
                      client_ip(request))
    return {"updated": len(changed)}


@router.post("/{alert_id}/comments")
def add_comment(alert_id: int, body: CommentIn, user=Depends(analyst), core=Depends(get_core)):
    if not core.db.one("SELECT id FROM alerts WHERE id = ?", (alert_id,)):
        raise HTTPException(404, "Alarm nicht gefunden")
    _comment(core, alert_id, user["username"], body.text.strip())
    core.db.execute("UPDATE alerts SET updated = ? WHERE id = ?", (time.time(), alert_id))
    return get_alert(alert_id, user, core)
