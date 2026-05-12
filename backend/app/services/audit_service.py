from __future__ import annotations

from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from app.models import AuditLog, User


def audit(
    db: Session,
    *,
    action: str,
    entity_type: str,
    entity_id: str | None = None,
    tenant_id: str | None = None,
    actor: User | None = None,
    old_value: dict[str, Any] | None = None,
    new_value: dict[str, Any] | None = None,
    request: Request | None = None,
) -> AuditLog:
    ip_address = request.client.host if request and request.client else ""
    user_agent = request.headers.get("user-agent", "") if request else ""
    row = AuditLog(
        tenant_id=tenant_id,
        actor_user_id=actor.id if actor else None,
        actor_username=actor.email if actor else "system",
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        old_value=old_value,
        new_value=new_value,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.add(row)
    return row
