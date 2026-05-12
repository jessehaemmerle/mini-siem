from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, Header, HTTPException, Query, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.permissions import SUPER_ADMIN, has_permission
from app.core.security import decode_access_token
from app.db.session import get_db
from app.models import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def serialize_user(user: User) -> dict:
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "is_active": user.is_active,
        "mfa_enabled": user.mfa_enabled,
        "last_login_at": user.last_login_at,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
        "tenant_ids": [membership.tenant_id for membership in user.memberships],
    }


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    try:
        payload = decode_access_token(token)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc
    user_id = payload.get("sub")
    user = db.get(User, user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive or missing user")
    return user


def require_permission(permission: str) -> Callable[[User], User]:
    def dependency(user: User = Depends(get_current_user)) -> User:
        if not has_permission(user.role, permission):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user

    return dependency


def tenant_ids_for_user(user: User) -> list[str]:
    if user.role == SUPER_ADMIN:
        return []
    return [membership.tenant_id for membership in user.memberships]


def resolve_tenant_id(
    db: Session,
    user: User,
    tenant_id: str | None = None,
    x_tenant_id: str | None = None,
) -> str:
    requested = tenant_id or x_tenant_id
    memberships = [membership.tenant_id for membership in user.memberships]
    if user.role == SUPER_ADMIN:
        if requested:
            return requested
        first = db.execute(select(User).where(User.id == user.id)).scalar_one()
        if first.memberships:
            return first.memberships[0].tenant_id
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No tenant selected")
    if requested and requested not in memberships:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tenant access denied")
    if requested:
        return requested
    if memberships:
        return memberships[0]
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User has no tenant membership")


def accessible_tenant_ids(db: Session, user: User, tenant_id: str | None = None) -> list[str]:
    if user.role == SUPER_ADMIN:
        if tenant_id:
            return [tenant_id]
        from app.models import Tenant

        return [row.id for row in db.scalars(select(Tenant)).all()]
    memberships = [membership.tenant_id for membership in user.memberships]
    if tenant_id:
        if tenant_id not in memberships:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tenant access denied")
        return [tenant_id]
    return memberships


def selected_tenant(
    tenant_id: str | None = Query(default=None),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> str:
    return resolve_tenant_id(db, user, tenant_id=tenant_id, x_tenant_id=x_tenant_id)
