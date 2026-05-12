from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import hash_api_key
from app.models import ApiKey, IOC, LogEventMeta, LogSource, Tenant
from app.services.alert_service import create_alert
from app.services.normalization_service import normalize_event, parse_datetime, parse_syslog_line
from app.services.opensearch_service import index_log


def get_api_key_record(db: Session, api_key: str) -> ApiKey:
    key_hash = hash_api_key(api_key)
    row = db.scalar(select(ApiKey).where(ApiKey.key_hash == key_hash, ApiKey.active.is_(True)))
    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid ingestion API key")
    tenant = db.get(Tenant, row.tenant_id)
    if not tenant or tenant.status != "active":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tenant is inactive")
    return row


def _log_meta(event: dict[str, Any], index: str) -> LogEventMeta:
    return LogEventMeta(
        id=event["id"],
        tenant_id=event["tenant_id"],
        opensearch_index=index,
        timestamp=parse_datetime(event.get("timestamp")),
        received_at=parse_datetime(event.get("received_at")),
        source_type=event.get("source_type") or "",
        source_name=event.get("source_name") or "",
        hostname=event.get("hostname") or "",
        severity=event.get("severity") or "informational",
        event_category=event.get("event_category") or "application",
        event_action=event.get("event_action") or "",
        user_name=event.get("user_name") or "",
        src_ip=event.get("src_ip") or "",
        dst_ip=event.get("dst_ip") or "",
        message=event.get("message") or "",
    )


def match_iocs(db: Session, event: dict[str, Any]) -> int:
    values = {
        "ip": {event.get("src_ip"), event.get("dst_ip")},
        "domain": set(),
        "url": set(),
        "hash": set(),
        "email": {event.get("user_name")} if "@" in str(event.get("user_name")) else set(),
    }
    text = " ".join(str(event.get(field) or "") for field in ["message", "raw_log", "command_line"]).lower()
    created = 0
    iocs = db.scalars(select(IOC).where(IOC.tenant_id == event["tenant_id"])).all()
    for ioc in iocs:
        if ioc.expires_at and ioc.expires_at < datetime.now(UTC):
            continue
        direct = ioc.value in values.get(ioc.type, set())
        textual = ioc.type in {"domain", "url", "hash"} and ioc.value.lower() in text
        if not direct and not textual:
            continue
        dedup = f"ioc:{event['tenant_id']}:{ioc.id}:{event.get('id')}"
        _, was_created = create_alert(
            db,
            tenant_id=event["tenant_id"],
            title=f"Threat intel IOC matched: {ioc.value}",
            description=ioc.description or f"Event matched IOC {ioc.value} from {ioc.source}",
            severity=ioc.severity,
            risk_score=max(60, ioc.confidence),
            dedup_key=dedup,
            matched_events=[event],
            mitre_tactic="Command and Control",
            mitre_technique="Indicator Removal or IOC Match",
            response_recommendation="Validate the IOC, isolate affected host if needed, and review related events.",
        )
        created += int(was_created)
    return created


def ingest_events(db: Session, *, api_key: str, events: list[dict[str, Any]]) -> dict[str, Any]:
    key = get_api_key_record(db, api_key)
    source = db.get(LogSource, key.source_id)
    accepted = 0
    alerts_created = 0
    ids: list[str] = []
    for raw in events:
        normalized = normalize_event(raw, tenant_id=key.tenant_id, source=source)
        idx = index_log(normalized)
        db.merge(_log_meta(normalized, idx))
        alerts_created += match_iocs(db, normalized)
        ids.append(normalized["id"])
        accepted += 1
    now = datetime.now(UTC)
    key.last_used_at = now
    if source:
        source.last_seen = now
        source.events_last_24h = (source.events_last_24h or 0) + accepted
    db.commit()
    return {"accepted": accepted, "rejected": 0, "alerts_created": alerts_created, "ids": ids}


def ingest_syslog_line(db: Session, *, api_key: str, line: str, source_name: str = "syslog") -> dict[str, Any]:
    event = parse_syslog_line(line)
    event["source_name"] = source_name or event.get("source_name") or "syslog"
    return ingest_events(db, api_key=api_key, events=[event])
