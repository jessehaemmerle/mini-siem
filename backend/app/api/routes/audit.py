from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import accessible_tenant_ids, require_permission
from app.db.session import get_db
from app.models import AuditLog, User
from app.schemas import AuditRead

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=list[AuditRead])
def list_audit(tenant_id: str | None = None, action: str | None = None, limit: int = Query(default=200, le=1000), db: Session = Depends(get_db), user: User = Depends(require_permission("audit:read"))):
    tenant_ids = accessible_tenant_ids(db, user, tenant_id)
    stmt = select(AuditLog).where((AuditLog.tenant_id.in_(tenant_ids)) | (AuditLog.tenant_id.is_(None))).order_by(AuditLog.timestamp.desc())
    if action:
        stmt = stmt.where(AuditLog.action == action)
    return db.scalars(stmt.limit(limit)).all()
