from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import accessible_tenant_ids, require_permission, resolve_tenant_id
from app.db.session import get_db
from app.models import IOC, User
from app.schemas import IOCCreate, IOCRead, IOCUpdate
from app.services.audit_service import audit

router = APIRouter(prefix="/iocs", tags=["threat-intelligence"])


@router.get("", response_model=list[IOCRead])
def list_iocs(tenant_id: str | None = None, db: Session = Depends(get_db), user: User = Depends(require_permission("iocs:read"))):
    return db.scalars(select(IOC).where(IOC.tenant_id.in_(accessible_tenant_ids(db, user, tenant_id))).order_by(IOC.type, IOC.value)).all()


@router.post("", response_model=IOCRead, status_code=status.HTTP_201_CREATED)
def create_ioc(payload: IOCCreate, request: Request, db: Session = Depends(get_db), user: User = Depends(require_permission("iocs:write"))):
    tenant_id = resolve_tenant_id(db, user, tenant_id=payload.tenant_id)
    ioc = IOC(tenant_id=tenant_id, **payload.model_dump(exclude={"tenant_id"}))
    db.add(ioc)
    audit(db, action="ioc_created", entity_type="ioc", entity_id=ioc.id, tenant_id=tenant_id, actor=user, new_value=payload.model_dump(mode="json"), request=request)
    db.commit()
    db.refresh(ioc)
    return ioc


@router.put("/{ioc_id}", response_model=IOCRead)
def update_ioc(ioc_id: str, payload: IOCUpdate, request: Request, db: Session = Depends(get_db), user: User = Depends(require_permission("iocs:write"))):
    ioc = db.get(IOC, ioc_id)
    if not ioc or ioc.tenant_id not in accessible_tenant_ids(db, user):
        raise HTTPException(status_code=404, detail="IOC not found")
    old = {"value": ioc.value, "type": ioc.type, "severity": ioc.severity}
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(ioc, key, value)
    audit(db, action="ioc_updated", entity_type="ioc", entity_id=ioc.id, tenant_id=ioc.tenant_id, actor=user, old_value=old, new_value=payload.model_dump(mode="json", exclude_unset=True), request=request)
    db.commit()
    db.refresh(ioc)
    return ioc


@router.delete("/{ioc_id}")
def delete_ioc(ioc_id: str, request: Request, db: Session = Depends(get_db), user: User = Depends(require_permission("iocs:write"))):
    ioc = db.get(IOC, ioc_id)
    if not ioc or ioc.tenant_id not in accessible_tenant_ids(db, user):
        raise HTTPException(status_code=404, detail="IOC not found")
    audit(db, action="ioc_deleted", entity_type="ioc", entity_id=ioc.id, tenant_id=ioc.tenant_id, actor=user, request=request)
    db.delete(ioc)
    db.commit()
    return {"ok": True}
