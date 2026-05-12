from typing import Any

from fastapi import APIRouter, Depends, Header
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.rate_limit import rate_limiter
from app.db.session import get_db
from app.schemas import IngestEventIn, IngestResponse, SyslogIngestRequest
from app.services.ingestion_service import ingest_events, ingest_syslog_line

settings = get_settings()
router = APIRouter(prefix="/ingest", tags=["ingestion"])


@router.post("/logs", response_model=IngestResponse, dependencies=[Depends(rate_limiter("ingestion", settings.ingestion_rate_limit, 60))])
def ingest_logs(payload: IngestEventIn | list[IngestEventIn] | dict[str, Any] | list[dict[str, Any]], x_api_key: str = Header(alias="X-API-Key"), db: Session = Depends(get_db)):
    if isinstance(payload, list):
        events = [item.model_dump() if hasattr(item, "model_dump") else item for item in payload]
    else:
        events = [payload.model_dump() if hasattr(payload, "model_dump") else payload]
    return ingest_events(db, api_key=x_api_key, events=events)


@router.post("/syslog", response_model=IngestResponse)
def ingest_syslog(payload: SyslogIngestRequest, x_api_key: str = Header(alias="X-API-Key"), db: Session = Depends(get_db)):
    return ingest_syslog_line(db, api_key=x_api_key, line=payload.line, source_name=payload.source_name)


@router.get("/status")
def ingestion_status():
    return {"status": "ready", "formats": ["json", "array", "syslog", "fluent-bit-http"], "header": "X-API-Key"}
