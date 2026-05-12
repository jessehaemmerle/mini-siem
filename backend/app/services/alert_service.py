from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Alert, AlertComment, User
from app.services.audit_service import audit


def create_alert(
    db: Session,
    *,
    tenant_id: str,
    title: str,
    description: str,
    severity: str,
    risk_score: int,
    dedup_key: str,
    rule_id: str | None = None,
    matched_events: list[dict[str, Any]] | None = None,
    mitre_tactic: str = "",
    mitre_technique: str = "",
    mitre_technique_id: str = "",
    response_recommendation: str = "",
) -> tuple[Alert, bool]:
    existing = db.scalar(select(Alert).where(Alert.dedup_key == dedup_key))
    if existing:
        return existing, False
    alert = Alert(
        tenant_id=tenant_id,
        title=title,
        description=description,
        severity=severity,
        risk_score=risk_score,
        rule_id=rule_id,
        matched_events=matched_events or [],
        mitre_tactic=mitre_tactic,
        mitre_technique=mitre_technique,
        mitre_technique_id=mitre_technique_id,
        response_recommendation=response_recommendation,
        dedup_key=dedup_key,
    )
    db.add(alert)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        existing = db.scalar(select(Alert).where(Alert.dedup_key == dedup_key))
        if existing:
            return existing, False
        raise
    audit(db, action="alert_created", entity_type="alert", entity_id=alert.id, tenant_id=tenant_id, new_value={"title": title})
    return alert, True


def set_alert_status(db: Session, alert: Alert, *, status: str, actor: User | None = None, comment: str = "") -> Alert:
    old = {"status": alert.status}
    alert.status = status
    if status == "acknowledged":
        alert.acknowledged_at = datetime.now(UTC)
    if status in {"resolved", "false_positive"}:
        alert.resolved_at = datetime.now(UTC)
    if status == "false_positive":
        alert.false_positive = True
    if comment:
        alert.resolution_comment = comment
    audit(db, action="alert_status_changed", entity_type="alert", entity_id=alert.id, tenant_id=alert.tenant_id, actor=actor, old_value=old, new_value={"status": status})
    return alert


def add_alert_comment(db: Session, alert: Alert, *, user: User, comment: str) -> AlertComment:
    row = AlertComment(alert_id=alert.id, user_id=user.id, comment=comment)
    db.add(row)
    audit(db, action="alert_comment_added", entity_type="alert", entity_id=alert.id, tenant_id=alert.tenant_id, actor=user, new_value={"comment": comment})
    return row
