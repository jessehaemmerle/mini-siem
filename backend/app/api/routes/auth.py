from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, serialize_user
from app.core.config import get_settings
from app.core.rate_limit import rate_limiter
from app.core.security import create_access_token, verify_password
from app.db.session import get_db
from app.models import User
from app.schemas import LoginRequest, TokenResponse, UserRead
from app.services.audit_service import audit

settings = get_settings()
router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse, dependencies=[Depends(rate_limiter("login", settings.login_rate_limit, 60))])
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == payload.email.lower()))
    if not user or not user.is_active or not verify_password(payload.password, user.password_hash):
        audit(db, action="login_failed", entity_type="user", tenant_id=None, new_value={"email": payload.email}, request=request)
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    user.last_login_at = datetime.now(UTC)
    token = create_access_token(user.id, {"role": user.role})
    first_tenant = user.memberships[0].tenant_id if user.memberships else None
    audit(db, action="login_success", entity_type="user", entity_id=user.id, tenant_id=first_tenant, actor=user, request=request)
    db.commit()
    return {"access_token": token, "user": serialize_user(user)}


@router.post("/logout")
def logout(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    tenant_id = user.memberships[0].tenant_id if user.memberships else None
    audit(db, action="logout", entity_type="user", entity_id=user.id, tenant_id=tenant_id, actor=user, request=request)
    db.commit()
    return {"ok": True}


@router.get("/me", response_model=UserRead)
def me(user: User = Depends(get_current_user)):
    return serialize_user(user)
