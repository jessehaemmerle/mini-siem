"""Erkennungsregeln verwalten und testen."""

from __future__ import annotations

import time
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .. import query as q
from ..detection import simulate, validate_rule
from ..storage import QueryTimeout
from .deps import analyst, client_ip, get_core, viewer

router = APIRouter(prefix="/api/rules", tags=["Regeln"])


class RuleIn(BaseModel):
    name: str = Field(max_length=200)
    description: str = Field("", max_length=2000)
    query: str = Field(max_length=4000)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    threshold: int = Field(1, ge=1, le=1_000_000)
    window: int = Field(300, ge=10, le=7 * 86400)
    group_by: str | None = None
    distinct_field: str | None = None
    enabled: bool = True


class RuleTest(RuleIn):
    name: str = Field("Test", max_length=200)
    hours: int = Field(24, ge=1, le=24 * 30)


def _validated(body: RuleIn) -> dict:
    try:
        return validate_rule(body.model_dump())
    except (ValueError, q.QueryError) as exc:
        raise HTTPException(400, str(exc)) from None


@router.get("")
def list_rules(user=Depends(viewer), core=Depends(get_core)):
    rows = core.db.all(
        "SELECT r.*, "
        "(SELECT COUNT(*) FROM alerts a WHERE a.rule_id = r.id) AS alerts_total, "
        "(SELECT COUNT(*) FROM alerts a WHERE a.rule_id = r.id AND a.status != 'closed') AS alerts_open, "
        "(SELECT MAX(last_seen) FROM alerts a WHERE a.rule_id = r.id) AS last_alert "
        "FROM rules r ORDER BY r.enabled DESC, r.name COLLATE NOCASE")
    return {"rules": rows}


@router.get("/{rule_id}")
def get_rule(rule_id: int, user=Depends(viewer), core=Depends(get_core)):
    row = core.db.one("SELECT * FROM rules WHERE id = ?", (rule_id,))
    if not row:
        raise HTTPException(404, "Regel nicht gefunden")
    return row


@router.post("")
def create_rule(body: RuleIn, request: Request, user=Depends(analyst), core=Depends(get_core)):
    r = _validated(body)
    now = time.time()
    cur = core.db.execute(
        "INSERT INTO rules(name, description, query, severity, threshold, window, group_by, "
        "distinct_field, enabled, builtin, created, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
        (r["name"], r["description"], r["query"], r["severity"], r["threshold"], r["window"],
         r["group_by"], r["distinct_field"], int(r["enabled"]), now, now),
    )
    core.engine.request_reload()
    core.db.audit(user["username"], "rule.create", r["name"], client_ip(request))
    return get_rule(cur.lastrowid, user, core)


@router.put("/{rule_id}")
def update_rule(rule_id: int, body: RuleIn, request: Request, user=Depends(analyst), core=Depends(get_core)):
    if not core.db.one("SELECT id FROM rules WHERE id = ?", (rule_id,)):
        raise HTTPException(404, "Regel nicht gefunden")
    r = _validated(body)
    core.db.execute(
        "UPDATE rules SET name = ?, description = ?, query = ?, severity = ?, threshold = ?, window = ?, "
        "group_by = ?, distinct_field = ?, enabled = ?, updated = ? WHERE id = ?",
        (r["name"], r["description"], r["query"], r["severity"], r["threshold"], r["window"],
         r["group_by"], r["distinct_field"], int(r["enabled"]), time.time(), rule_id),
    )
    core.db.execute("UPDATE alerts SET rule_name = ? WHERE rule_id = ? AND status != 'closed'",
                    (r["name"], rule_id))
    core.engine.request_reload()
    core.db.audit(user["username"], "rule.update",
                  f"{r['name']} ({'aktiv' if r['enabled'] else 'deaktiviert'})", client_ip(request))
    return get_rule(rule_id, user, core)


@router.delete("/{rule_id}")
def delete_rule(rule_id: int, request: Request, user=Depends(analyst), core=Depends(get_core)):
    row = core.db.one("SELECT name FROM rules WHERE id = ?", (rule_id,))
    if not row:
        raise HTTPException(404, "Regel nicht gefunden")
    core.db.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
    core.engine.request_reload()
    core.db.audit(user["username"], "rule.delete", row["name"], client_ip(request))
    return {"ok": True}


@router.post("/test")
def test_rule(body: RuleTest, user=Depends(viewer), core=Depends(get_core)):
    """Spielt die Regel gegen die Events der letzten Stunden ab."""
    r = _validated(body)
    node = q.parse(r["query"])
    now = time.time()
    max_events = 50_000
    matched = 0
    samples: list[dict] = []

    def events():
        nonlocal matched
        for ev in core.store.iter_matching(node, now - body.hours * 3600, now, max_events):
            matched += 1
            samples.append(ev)
            if len(samples) > 10:
                samples.pop(0)
            yield ev

    try:
        alerts = simulate(r, events())
    except QueryTimeout:
        raise HTTPException(408, "Der Test hat zu lange gedauert. Bitte den Zeitraum verkleinern.") from None
    return {
        "matched": matched,
        "truncated": matched >= max_events,
        "samples": list(reversed(samples)),
        "alerts": alerts[:50],
        "alert_count": len(alerts),
        "hours": body.hours,
    }
