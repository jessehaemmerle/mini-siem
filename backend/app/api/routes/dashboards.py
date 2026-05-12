from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import accessible_tenant_ids, get_current_user
from app.db.session import get_db
from app.models import Alert, AuditLog, LogEventMeta, LogSource, User
from app.services.opensearch_service import search_logs

router = APIRouter(prefix="/dashboard", tags=["dashboards"])


def _overview(db: Session, tenant_ids: list[str], hours: int = 24):
    start = datetime.now(UTC) - timedelta(hours=hours)
    events = db.scalar(select(func.count(LogEventMeta.id)).where(LogEventMeta.tenant_id.in_(tenant_ids), LogEventMeta.timestamp >= start)) or 0
    open_alerts = db.scalar(select(func.count(Alert.id)).where(Alert.tenant_id.in_(tenant_ids), Alert.status.in_(["new", "acknowledged", "investigating"]))) or 0
    critical_alerts = db.scalar(select(func.count(Alert.id)).where(Alert.tenant_id.in_(tenant_ids), Alert.severity == "critical", Alert.status != "resolved")) or 0
    alerts_by_severity = dict(db.execute(select(Alert.severity, func.count(Alert.id)).where(Alert.tenant_id.in_(tenant_ids)).group_by(Alert.severity)).all())
    aggs = search_logs(db, tenant_ids=tenant_ids, start_time=start, size=0).get("aggregations", {})
    return {
        "metrics": {"events_24h": events, "open_alerts": open_alerts, "critical_alerts": critical_alerts, "new_alerts": alerts_by_severity.get("new", 0)},
        "alerts_by_severity": alerts_by_severity,
        "log_aggregations": aggs,
        "system_health": {"backend": "ok", "postgres": "ok"},
    }


@router.get("/overview")
def overview(tenant_id: str | None = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return _overview(db, accessible_tenant_ids(db, user, tenant_id))


@router.get("/authentication")
def authentication(tenant_id: str | None = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    tenant_ids = accessible_tenant_ids(db, user, tenant_id)
    rows = db.execute(select(LogEventMeta.event_action, func.count()).where(LogEventMeta.tenant_id.in_(tenant_ids), LogEventMeta.event_category == "authentication").group_by(LogEventMeta.event_action)).all()
    return {"authentication": dict(rows), "top_users": db.execute(select(LogEventMeta.user_name, func.count()).where(LogEventMeta.tenant_id.in_(tenant_ids)).group_by(LogEventMeta.user_name).order_by(func.count().desc()).limit(10)).all()}


@router.get("/network")
def network(tenant_id: str | None = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    tenant_ids = accessible_tenant_ids(db, user, tenant_id)
    rows = db.execute(select(LogEventMeta.event_action, func.count()).where(LogEventMeta.tenant_id.in_(tenant_ids), LogEventMeta.event_category == "network").group_by(LogEventMeta.event_action)).all()
    top_ports = search_logs(db, tenant_ids=tenant_ids, filters={"event_category": "network"}, size=0).get("aggregations", {})
    return {"allow_deny": dict(rows), "aggregations": top_ports}


@router.get("/endpoint")
def endpoint(tenant_id: str | None = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    tenant_ids = accessible_tenant_ids(db, user, tenant_id)
    rows = db.execute(select(LogEventMeta.event_action, func.count()).where(LogEventMeta.tenant_id.in_(tenant_ids), LogEventMeta.event_category.in_(["endpoint", "malware", "process"])).group_by(LogEventMeta.event_action)).all()
    return {"endpoint_findings": dict(rows)}


@router.get("/compliance")
def compliance(tenant_id: str | None = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    tenant_ids = accessible_tenant_ids(db, user, tenant_id)
    audit_count = db.scalar(select(func.count(AuditLog.id)).where(AuditLog.tenant_id.in_(tenant_ids))) or 0
    source_count = db.scalar(select(func.count(LogSource.id)).where(LogSource.tenant_id.in_(tenant_ids))) or 0
    return {"audit_events": audit_count, "log_sources": source_count}
