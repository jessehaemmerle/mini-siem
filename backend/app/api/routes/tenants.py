from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import accessible_tenant_ids, require_permission
from app.core.permissions import SUPER_ADMIN
from app.db.session import get_db
from app.models import RetentionPolicy, Tenant, User
from app.schemas import TenantCreate, TenantRead, TenantUpdate
from app.services.audit_service import audit

router = APIRouter(prefix="/tenants", tags=["tenants"])


@router.get("", response_model=list[TenantRead])
def list_tenants(db: Session = Depends(get_db), actor: User = Depends(require_permission("tenants:read"))):
    if actor.role == SUPER_ADMIN:
        return db.scalars(select(Tenant).order_by(Tenant.name)).all()
    return db.scalars(select(Tenant).where(Tenant.id.in_(accessible_tenant_ids(db, actor))).order_by(Tenant.name)).all()


@router.post("", response_model=TenantRead, status_code=status.HTTP_201_CREATED)
def create_tenant(payload: TenantCreate, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_permission("tenants:write"))):
    tenant = Tenant(**payload.model_dump())
    db.add(tenant)
    db.flush()
    db.add(RetentionPolicy(tenant_id=tenant.id, online_days=tenant.retention_days))
    audit(db, action="tenant_created", entity_type="tenant", entity_id=tenant.id, tenant_id=tenant.id, actor=actor, new_value=payload.model_dump(), request=request)
    db.commit()
    db.refresh(tenant)
    return tenant


@router.get("/{tenant_id}", response_model=TenantRead)
def get_tenant(tenant_id: str, db: Session = Depends(get_db), actor: User = Depends(require_permission("tenants:read"))):
    if actor.role != SUPER_ADMIN and tenant_id not in accessible_tenant_ids(db, actor):
        raise HTTPException(status_code=403, detail="Tenant access denied")
    tenant = db.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant


@router.put("/{tenant_id}", response_model=TenantRead)
def update_tenant(tenant_id: str, payload: TenantUpdate, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_permission("tenants:write"))):
    tenant = get_tenant(tenant_id, db, actor)
    old = {key: getattr(tenant, key) for key in payload.model_fields}
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(tenant, key, value)
    policy = db.scalar(select(RetentionPolicy).where(RetentionPolicy.tenant_id == tenant.id))
    if policy and payload.retention_days is not None:
        policy.online_days = payload.retention_days
    audit(db, action="tenant_updated", entity_type="tenant", entity_id=tenant.id, tenant_id=tenant.id, actor=actor, old_value=old, new_value=payload.model_dump(exclude_unset=True), request=request)
    db.commit()
    db.refresh(tenant)
    return tenant


@router.delete("/{tenant_id}")
def delete_tenant(tenant_id: str, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_permission("tenants:write"))):
    tenant = get_tenant(tenant_id, db, actor)
    tenant.status = "inactive"
    audit(db, action="tenant_deactivated", entity_type="tenant", entity_id=tenant.id, tenant_id=tenant.id, actor=actor, request=request)
    db.commit()
    return {"ok": True}
