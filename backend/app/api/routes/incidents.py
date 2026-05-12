from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.api.deps import accessible_tenant_ids, require_permission, resolve_tenant_id
from app.db.session import get_db
from app.models import Alert, Incident, IncidentAlert, IncidentTimelineEntry, User
from app.schemas import IncidentAddAlert, IncidentCreate, IncidentRead, IncidentUpdate, TimelineCreate
from app.services.audit_service import audit

router = APIRouter(prefix="/incidents", tags=["incidents"])


def _incident_payload(db: Session, incident: Incident) -> dict:
    alert_links = db.scalars(select(IncidentAlert).where(IncidentAlert.incident_id == incident.id)).all()
    alerts = [db.get(Alert, link.alert_id) for link in alert_links]
    return {
        **IncidentRead.model_validate(incident).model_dump(mode="json"),
        "alerts": [alert.id for alert in alerts if alert],
        "timeline": [
            {"id": item.id, "entry_type": item.entry_type, "message": item.message, "user_id": item.user_id, "created_at": item.created_at}
            for item in incident.timeline
        ],
    }


@router.get("")
def list_incidents(tenant_id: str | None = None, db: Session = Depends(get_db), user: User = Depends(require_permission("incidents:read"))):
    rows = db.scalars(select(Incident).where(Incident.tenant_id.in_(accessible_tenant_ids(db, user, tenant_id))).order_by(Incident.created_at.desc()).limit(500)).all()
    return rows


@router.post("", status_code=status.HTTP_201_CREATED)
def create_incident(payload: IncidentCreate, request: Request, db: Session = Depends(get_db), user: User = Depends(require_permission("incidents:write"))):
    tenant_id = resolve_tenant_id(db, user, tenant_id=payload.tenant_id)
    incident = Incident(tenant_id=tenant_id, title=payload.title, description=payload.description, severity=payload.severity, owner=payload.owner)
    db.add(incident)
    db.flush()
    for alert_id in payload.alert_ids:
        alert = db.get(Alert, alert_id)
        if alert and alert.tenant_id == tenant_id:
            db.add(IncidentAlert(incident_id=incident.id, alert_id=alert.id))
    db.add(IncidentTimelineEntry(incident_id=incident.id, user_id=user.id, entry_type="created", message="Incident created"))
    audit(db, action="incident_created", entity_type="incident", entity_id=incident.id, tenant_id=tenant_id, actor=user, new_value=payload.model_dump(), request=request)
    db.commit()
    incident = db.scalar(select(Incident).options(selectinload(Incident.timeline)).where(Incident.id == incident.id))
    return _incident_payload(db, incident)


@router.get("/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db), user: User = Depends(require_permission("incidents:read"))):
    incident = db.scalar(select(Incident).options(selectinload(Incident.timeline)).where(Incident.id == incident_id))
    if not incident or incident.tenant_id not in accessible_tenant_ids(db, user):
        raise HTTPException(status_code=404, detail="Incident not found")
    return _incident_payload(db, incident)


@router.put("/{incident_id}")
def update_incident(incident_id: str, payload: IncidentUpdate, request: Request, db: Session = Depends(get_db), user: User = Depends(require_permission("incidents:write"))):
    incident = db.get(Incident, incident_id)
    if not incident or incident.tenant_id not in accessible_tenant_ids(db, user):
        raise HTTPException(status_code=404, detail="Incident not found")
    old = {"status": incident.status, "severity": incident.severity, "owner": incident.owner}
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(incident, key, value)
    audit(db, action="incident_updated", entity_type="incident", entity_id=incident.id, tenant_id=incident.tenant_id, actor=user, old_value=old, new_value=payload.model_dump(exclude_unset=True), request=request)
    db.commit()
    return get_incident(incident_id, db, user)


@router.post("/{incident_id}/add-alert")
def add_alert(incident_id: str, payload: IncidentAddAlert, request: Request, db: Session = Depends(get_db), user: User = Depends(require_permission("incidents:write"))):
    incident = db.get(Incident, incident_id)
    alert = db.get(Alert, payload.alert_id)
    if not incident or not alert or incident.tenant_id != alert.tenant_id or incident.tenant_id not in accessible_tenant_ids(db, user):
        raise HTTPException(status_code=404, detail="Incident or alert not found")
    if not db.scalar(select(IncidentAlert).where(IncidentAlert.incident_id == incident.id, IncidentAlert.alert_id == alert.id)):
        db.add(IncidentAlert(incident_id=incident.id, alert_id=alert.id))
    db.add(IncidentTimelineEntry(incident_id=incident.id, user_id=user.id, entry_type="alert_added", message=f"Alert {alert.id} added"))
    audit(db, action="incident_alert_added", entity_type="incident", entity_id=incident.id, tenant_id=incident.tenant_id, actor=user, new_value={"alert_id": alert.id}, request=request)
    db.commit()
    return {"ok": True}


@router.post("/{incident_id}/timeline")
def add_timeline(incident_id: str, payload: TimelineCreate, db: Session = Depends(get_db), user: User = Depends(require_permission("incidents:write"))):
    incident = db.get(Incident, incident_id)
    if not incident or incident.tenant_id not in accessible_tenant_ids(db, user):
        raise HTTPException(status_code=404, detail="Incident not found")
    item = IncidentTimelineEntry(incident_id=incident.id, user_id=user.id, entry_type=payload.entry_type, message=payload.message)
    db.add(item)
    db.commit()
    return {"id": item.id}


@router.post("/{incident_id}/close")
def close_incident(incident_id: str, payload: TimelineCreate | None = None, db: Session = Depends(get_db), user: User = Depends(require_permission("incidents:write"))):
    incident = db.get(Incident, incident_id)
    if not incident or incident.tenant_id not in accessible_tenant_ids(db, user):
        raise HTTPException(status_code=404, detail="Incident not found")
    incident.status = "closed"
    incident.closed_at = datetime.now(UTC)
    db.add(IncidentTimelineEntry(incident_id=incident.id, user_id=user.id, entry_type="closed", message=payload.message if payload else "Incident closed"))
    db.commit()
    return {"ok": True}
