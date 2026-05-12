from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.api.deps import accessible_tenant_ids, require_permission
from app.db.session import get_db
from app.models import Alert, AlertComment, User
from app.schemas import AlertCommentCreate, AlertRead, AlertUpdate
from app.services.alert_service import add_alert_comment, set_alert_status
from app.services.audit_service import audit

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertRead])
def list_alerts(
    tenant_id: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("alerts:read")),
):
    stmt = select(Alert).where(Alert.tenant_id.in_(accessible_tenant_ids(db, user, tenant_id))).order_by(Alert.created_at.desc())
    if status:
        stmt = stmt.where(Alert.status == status)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    return db.scalars(stmt.limit(500)).all()


def _get_alert(db: Session, user: User, alert_id: str) -> Alert:
    alert = db.scalar(select(Alert).options(selectinload(Alert.comments)).where(Alert.id == alert_id))
    if not alert or alert.tenant_id not in accessible_tenant_ids(db, user):
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.get("/{alert_id}")
def get_alert(alert_id: str, db: Session = Depends(get_db), user: User = Depends(require_permission("alerts:read"))):
    alert = _get_alert(db, user, alert_id)
    data = AlertRead.model_validate(alert).model_dump(mode="json")
    data["comments"] = [
        {"id": comment.id, "user_id": comment.user_id, "comment": comment.comment, "created_at": comment.created_at}
        for comment in alert.comments
    ]
    return data


@router.put("/{alert_id}", response_model=AlertRead)
def update_alert(alert_id: str, payload: AlertUpdate, request: Request, db: Session = Depends(get_db), user: User = Depends(require_permission("alerts:write"))):
    alert = _get_alert(db, user, alert_id)
    old = {"status": alert.status, "severity": alert.severity, "risk_score": alert.risk_score, "assigned_to": alert.assigned_to}
    data = payload.model_dump(exclude_unset=True)
    status = data.pop("status", None)
    if status:
        set_alert_status(db, alert, status=status, actor=user, comment=data.get("resolution_comment") or "")
    for key, value in data.items():
        setattr(alert, key, value)
    audit(db, action="alert_updated", entity_type="alert", entity_id=alert.id, tenant_id=alert.tenant_id, actor=user, old_value=old, new_value=payload.model_dump(exclude_unset=True), request=request)
    db.commit()
    db.refresh(alert)
    return alert


@router.post("/{alert_id}/acknowledge", response_model=AlertRead)
def acknowledge(alert_id: str, db: Session = Depends(get_db), user: User = Depends(require_permission("alerts:write"))):
    alert = _get_alert(db, user, alert_id)
    set_alert_status(db, alert, status="acknowledged", actor=user)
    db.commit()
    db.refresh(alert)
    return alert


@router.post("/{alert_id}/resolve", response_model=AlertRead)
def resolve(alert_id: str, payload: AlertUpdate | None = None, db: Session = Depends(get_db), user: User = Depends(require_permission("alerts:write"))):
    alert = _get_alert(db, user, alert_id)
    set_alert_status(db, alert, status="resolved", actor=user, comment=payload.resolution_comment if payload else "")
    db.commit()
    db.refresh(alert)
    return alert


@router.post("/{alert_id}/false-positive", response_model=AlertRead)
def false_positive(alert_id: str, db: Session = Depends(get_db), user: User = Depends(require_permission("alerts:write"))):
    alert = _get_alert(db, user, alert_id)
    set_alert_status(db, alert, status="false_positive", actor=user)
    db.commit()
    db.refresh(alert)
    return alert


@router.post("/{alert_id}/comments")
def add_comment(alert_id: str, payload: AlertCommentCreate, db: Session = Depends(get_db), user: User = Depends(require_permission("alerts:write"))):
    alert = _get_alert(db, user, alert_id)
    comment = add_alert_comment(db, alert, user=user, comment=payload.comment)
    db.commit()
    return {"id": comment.id, "comment": comment.comment}
