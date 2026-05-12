from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select

from app.db.session import SessionLocal
from app.detection.engine import run_detection_once
from app.models import LogEventMeta, RetentionPolicy
from app.workers.celery_app import celery_app


@celery_app.task(name="app.workers.tasks.run_detection_task")
def run_detection_task():
    db = SessionLocal()
    try:
        return run_detection_once(db)
    finally:
        db.close()


@celery_app.task(name="app.workers.tasks.run_retention_task")
def run_retention_task():
    db = SessionLocal()
    deleted = 0
    try:
        policies = db.scalars(select(RetentionPolicy)).all()
        now = datetime.now(UTC)
        for policy in policies:
            cutoff = now - timedelta(days=policy.online_days)
            result = db.execute(delete(LogEventMeta).where(LogEventMeta.tenant_id == policy.tenant_id, LogEventMeta.timestamp < cutoff))
            deleted += result.rowcount or 0
            policy.last_run_at = now
            policy.last_status = "ok"
        db.commit()
        return {"deleted_log_metadata": deleted}
    finally:
        db.close()
