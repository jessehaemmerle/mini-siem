from sqlalchemy import select

from app.db.session import SessionLocal
from app.detection.engine import run_detection_once
from app.models import Alert, AuditLog, IOC, LogEventMeta, User
from app.services.audit_service import audit
from app.services.ingestion_service import ingest_events
from scripts.demo_content import DEMO_API_KEY, demo_events
from scripts.seed_demo_data import seed


def test_demo_seed_login_and_roles():
    seed()
    db = SessionLocal()
    try:
        admin = db.scalar(select(User).where(User.email == "admin@example.com"))
        analyst = db.scalar(select(User).where(User.email == "analyst@example.com"))
        assert admin and admin.role == "super_admin"
        assert analyst and analyst.role == "security_analyst"
        assert admin.memberships
    finally:
        db.close()


def test_ingestion_detection_ioc_and_audit():
    result = seed()
    db = SessionLocal()
    try:
        events = demo_events(result["tenant_id"])
        response = ingest_events(db, api_key=DEMO_API_KEY, events=events)
        assert response["accepted"] >= 500
        assert db.scalar(select(LogEventMeta)) is not None
        detection = run_detection_once(db)
        assert detection["rules_evaluated"] >= 10
        assert db.scalar(select(Alert)) is not None
        audit(db, action="test_action", entity_type="test", tenant_id=result["tenant_id"])
        db.commit()
        assert db.scalar(select(AuditLog).where(AuditLog.action == "test_action")) is not None
        assert db.scalar(select(IOC)) is not None
    finally:
        db.close()
