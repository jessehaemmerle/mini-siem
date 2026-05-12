from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends
from redis import Redis
from sqlalchemy import func, text, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import get_db
from app.models import LogEventMeta, LogSource
from app.schemas import HealthResponse
from app.services.opensearch_service import _client

router = APIRouter(prefix="/health", tags=["health"])


@router.get("", response_model=HealthResponse)
def health():
    return {"status": "ok", "components": {"backend": "ok"}}


@router.get("/deep", response_model=HealthResponse)
def deep_health(db: Session = Depends(get_db)):
    settings = get_settings()
    components = {"backend": "ok"}
    try:
        db.execute(text("select 1"))
        components["postgres"] = "ok"
    except Exception as exc:
        components["postgres"] = f"error: {exc}"
    try:
        Redis.from_url(settings.redis_url, socket_connect_timeout=1).ping()
        components["redis"] = "ok"
    except Exception as exc:
        components["redis"] = f"error: {exc}"
    try:
        client = _client()
        components["opensearch"] = "ok" if client and client.ping() else "unavailable"
    except Exception as exc:
        components["opensearch"] = f"error: {exc}"
    try:
        one_hour = datetime.now(UTC) - timedelta(hours=1)
        components["ingestion_rate_1h"] = str(db.scalar(select(func.count(LogEventMeta.id)).where(LogEventMeta.received_at >= one_hour)) or 0)
        stale_cutoff = datetime.now(UTC) - timedelta(hours=24)
        components["sources_without_logs_24h"] = str(db.scalar(select(func.count(LogSource.id)).where((LogSource.last_seen.is_(None)) | (LogSource.last_seen < stale_cutoff))) or 0)
        components["worker"] = "scheduled"
    except Exception as exc:
        components["telemetry"] = f"error: {exc}"
    critical = ["backend", "postgres", "redis", "opensearch"]
    overall = "ok" if all(components.get(name) == "ok" for name in critical) else "degraded"
    return {"status": overall, "components": components}
