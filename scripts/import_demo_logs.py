from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from sqlalchemy import select

from app.db.session import SessionLocal
from app.models import ApiKey, Tenant
from app.services.ingestion_service import ingest_events
from scripts.demo_content import DEMO_API_KEY, DEMO_TENANT_NAME, demo_events
from scripts.seed_demo_data import seed


def main() -> None:
    seed()
    db = SessionLocal()
    try:
        tenant = db.scalar(select(Tenant).where(Tenant.name == DEMO_TENANT_NAME))
        events = demo_events(tenant.id)
        result = ingest_events(db, api_key=DEMO_API_KEY, events=events)
        print(f"Imported {result['accepted']} demo events, IOC alerts created during ingestion: {result['alerts_created']}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
