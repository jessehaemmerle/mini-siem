from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import accessible_tenant_ids, require_permission, resolve_tenant_id, serialize_user
from app.core.permissions import SUPER_ADMIN
from app.core.security import hash_password
from app.db.session import get_db
from app.models import User, UserTenantMembership
from app.schemas import UserCreate, UserRead, UserUpdate
from app.services.audit_service import audit

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=list[UserRead])
def list_users(db: Session = Depends(get_db), actor: User = Depends(require_permission("users:read"))):
    if actor.role == SUPER_ADMIN:
        users = db.scalars(select(User).order_by(User.email)).unique().all()
    else:
        tenant_ids = accessible_tenant_ids(db, actor)
        users = db.scalars(select(User).join(UserTenantMembership).where(UserTenantMembership.tenant_id.in_(tenant_ids)).order_by(User.email)).unique().all()
    return [serialize_user(user) for user in users]


@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(payload: UserCreate, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_permission("users:write"))):
    if db.scalar(select(User).where(User.email == payload.email.lower())):
        raise HTTPException(status_code=409, detail="User already exists")
    tenant_ids = payload.tenant_ids or accessible_tenant_ids(db, actor)[:1]
    for tenant_id in tenant_ids:
        resolve_tenant_id(db, actor, tenant_id=tenant_id)
    user = User(email=payload.email.lower(), full_name=payload.full_name, password_hash=hash_password(payload.password), role=payload.role, is_active=payload.is_active, mfa_enabled=payload.mfa_enabled)
    db.add(user)
    db.flush()
    for tenant_id in tenant_ids:
        db.add(UserTenantMembership(user_id=user.id, tenant_id=tenant_id, role=payload.role))
    audit(db, action="user_created", entity_type="user", entity_id=user.id, tenant_id=tenant_ids[0] if tenant_ids else None, actor=actor, new_value=payload.model_dump(exclude={"password"}), request=request)
    db.commit()
    db.refresh(user)
    return serialize_user(user)


@router.get("/{user_id}", response_model=UserRead)
def get_user(user_id: str, db: Session = Depends(get_db), actor: User = Depends(require_permission("users:read"))):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if actor.role != SUPER_ADMIN and not set(accessible_tenant_ids(db, actor)).intersection({m.tenant_id for m in user.memberships}):
        raise HTTPException(status_code=403, detail="Tenant access denied")
    return serialize_user(user)


@router.put("/{user_id}", response_model=UserRead)
def update_user(user_id: str, payload: UserUpdate, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_permission("users:write"))):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    old = serialize_user(user)
    data = payload.model_dump(exclude_unset=True)
    tenant_ids = data.pop("tenant_ids", None)
    password = data.pop("password", None)
    if "email" in data and data["email"]:
        data["email"] = data["email"].lower()
    for key, value in data.items():
        setattr(user, key, value)
    if password:
        user.password_hash = hash_password(password)
    if tenant_ids is not None:
        for tenant_id in tenant_ids:
            resolve_tenant_id(db, actor, tenant_id=tenant_id)
        user.memberships.clear()
        db.flush()
        for tenant_id in tenant_ids:
            db.add(UserTenantMembership(user_id=user.id, tenant_id=tenant_id, role=user.role))
    audit(db, action="user_updated", entity_type="user", entity_id=user.id, tenant_id=(tenant_ids or [None])[0], actor=actor, old_value=old, new_value=payload.model_dump(exclude_unset=True, exclude={"password"}), request=request)
    db.commit()
    db.refresh(user)
    return serialize_user(user)


@router.delete("/{user_id}")
def delete_user(user_id: str, request: Request, db: Session = Depends(get_db), actor: User = Depends(require_permission("users:write"))):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_active = False
    audit(db, action="user_deactivated", entity_type="user", entity_id=user.id, tenant_id=user.memberships[0].tenant_id if user.memberships else None, actor=actor, request=request)
    db.commit()
    return {"ok": True}
