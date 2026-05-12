from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.api.deps import accessible_tenant_ids, require_permission, resolve_tenant_id
from app.core.security import api_key_prefix, generate_api_key, hash_api_key
from app.db.session import get_db
from app.models import ApiKey, LogSource, User
from app.schemas import LogSourceCreate, LogSourceCreateResponse, LogSourceRead, LogSourceUpdate
from app.services.audit_service import audit

router = APIRouter(prefix="/log-sources", tags=["log-sources"])


@router.get("", response_model=list[LogSourceRead])
def list_sources(tenant_id: str | None = None, db: Session = Depends(get_db), user: User = Depends(require_permission("sources:read"))):
    tenant_ids = accessible_tenant_ids(db, user, tenant_id)
    return db.scalars(select(LogSource).options(selectinload(LogSource.api_keys)).where(LogSource.tenant_id.in_(tenant_ids)).order_by(LogSource.name)).all()


@router.post("", response_model=LogSourceCreateResponse, status_code=status.HTTP_201_CREATED)
def create_source(payload: LogSourceCreate, request: Request, db: Session = Depends(get_db), user: User = Depends(require_permission("sources:write"))):
    tenant_id = resolve_tenant_id(db, user, tenant_id=payload.tenant_id)
    source = LogSource(tenant_id=tenant_id, **payload.model_dump(exclude={"tenant_id"}))
    db.add(source)
    db.flush()
    raw_key = generate_api_key()
    key = ApiKey(tenant_id=tenant_id, source_id=source.id, name=f"{source.name} key", key_hash=hash_api_key(raw_key), key_prefix=api_key_prefix(raw_key))
    db.add(key)
    audit(db, action="log_source_created", entity_type="log_source", entity_id=source.id, tenant_id=tenant_id, actor=user, new_value=payload.model_dump(), request=request)
    db.commit()
    source = db.scalar(select(LogSource).options(selectinload(LogSource.api_keys)).where(LogSource.id == source.id))
    return {"source": source, "api_key": raw_key}


@router.get("/{source_id}", response_model=LogSourceRead)
def get_source(source_id: str, db: Session = Depends(get_db), user: User = Depends(require_permission("sources:read"))):
    source = db.scalar(select(LogSource).options(selectinload(LogSource.api_keys)).where(LogSource.id == source_id))
    if not source or source.tenant_id not in accessible_tenant_ids(db, user):
        raise HTTPException(status_code=404, detail="Log source not found")
    return source


@router.put("/{source_id}", response_model=LogSourceRead)
def update_source(source_id: str, payload: LogSourceUpdate, request: Request, db: Session = Depends(get_db), user: User = Depends(require_permission("sources:write"))):
    source = get_source(source_id, db, user)
    old = {key: getattr(source, key) for key in payload.model_fields}
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(source, key, value)
    audit(db, action="log_source_updated", entity_type="log_source", entity_id=source.id, tenant_id=source.tenant_id, actor=user, old_value=old, new_value=payload.model_dump(exclude_unset=True), request=request)
    db.commit()
    db.refresh(source)
    return source


@router.delete("/{source_id}")
def delete_source(source_id: str, request: Request, db: Session = Depends(get_db), user: User = Depends(require_permission("sources:write"))):
    source = get_source(source_id, db, user)
    source.status = "disabled"
    audit(db, action="log_source_disabled", entity_type="log_source", entity_id=source.id, tenant_id=source.tenant_id, actor=user, request=request)
    db.commit()
    return {"ok": True}


@router.post("/{source_id}/rotate-key")
def rotate_key(source_id: str, request: Request, db: Session = Depends(get_db), user: User = Depends(require_permission("sources:write"))):
    source = get_source(source_id, db, user)
    for key in source.api_keys:
        key.active = False
    raw_key = generate_api_key()
    key = ApiKey(tenant_id=source.tenant_id, source_id=source.id, name=f"{source.name} rotated key", key_hash=hash_api_key(raw_key), key_prefix=api_key_prefix(raw_key))
    db.add(key)
    audit(db, action="api_key_rotated", entity_type="log_source", entity_id=source.id, tenant_id=source.tenant_id, actor=user, request=request)
    db.commit()
    return {"api_key": raw_key, "key_prefix": key.key_prefix}
