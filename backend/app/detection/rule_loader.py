from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import DetectionRule


def load_enabled_rules(db: Session) -> list[DetectionRule]:
    return list(db.scalars(select(DetectionRule).where(DetectionRule.enabled.is_(True))).all())
