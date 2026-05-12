from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import require_permission
from app.db.session import get_db
from app.models import RetentionPolicy, SystemSetting, User

router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("")
def settings(db: Session = Depends(get_db), user: User = Depends(require_permission("dashboards:read"))):
    values = db.scalars(select(SystemSetting).order_by(SystemSetting.key)).all()
    retention = db.scalars(select(RetentionPolicy)).all()
    return {
        "settings": [{"key": row.key, "value": row.value, "description": row.description} for row in values],
        "retention": [{"tenant_id": row.tenant_id, "online_days": row.online_days, "archive_enabled": row.archive_enabled, "last_status": row.last_status} for row in retention],
    }
