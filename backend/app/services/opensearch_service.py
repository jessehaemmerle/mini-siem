from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import LogEventMeta

try:
    from opensearchpy import OpenSearch
except Exception:  # pragma: no cover
    OpenSearch = None


def _client():
    settings = get_settings()
    if OpenSearch is None:
        return None
    http_auth = None
    if settings.opensearch_user and settings.opensearch_password:
        http_auth = (settings.opensearch_user, settings.opensearch_password)
    return OpenSearch(hosts=[settings.opensearch_url], http_auth=http_auth, timeout=10, max_retries=2, retry_on_timeout=True)


def index_name(tenant_id: str, timestamp: datetime | str | None = None) -> str:
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            timestamp = None
    ts = timestamp or datetime.now(UTC)
    return f"siem-logs-{tenant_id}-{ts.strftime('%Y.%m.%d')}"


def create_index_template() -> None:
    client = _client()
    if client is None:
        return
    body = {
        "index_patterns": ["siem-logs-*"],
        "template": {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {
                "dynamic": True,
                "properties": {
                    "tenant_id": {"type": "keyword"},
                    "timestamp": {"type": "date"},
                    "received_at": {"type": "date"},
                    "source_type": {"type": "keyword"},
                    "source_name": {"type": "keyword"},
                    "hostname": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "event_category": {"type": "keyword"},
                    "event_action": {"type": "keyword"},
                    "event_outcome": {"type": "keyword"},
                    "user_name": {"type": "keyword"},
                    "src_ip": {"type": "ip", "ignore_malformed": True},
                    "dst_ip": {"type": "ip", "ignore_malformed": True},
                    "tags": {"type": "keyword"},
                    "message": {"type": "text"},
                    "raw_log": {"type": "text"},
                    "command_line": {"type": "text"},
                    "risk_score": {"type": "integer"},
                    "mitre_tactic": {"type": "keyword"},
                    "mitre_technique": {"type": "keyword"},
                    "mitre_technique_id": {"type": "keyword"},
                }
            },
        },
    }
    try:
        client.indices.put_index_template(name="siem-logs-template", body=body)
    except Exception:
        pass


def index_log(event: dict[str, Any]) -> str:
    client = _client()
    idx = index_name(event["tenant_id"], event.get("timestamp"))
    if client is None:
        return idx
    try:
        client.index(index=idx, id=event["id"], body=event, refresh=False)
    except Exception:
        pass
    return idx


def _fallback_search(
    db: Session,
    *,
    tenant_ids: list[str],
    q: str | None,
    start_time: datetime | None,
    end_time: datetime | None,
    filters: dict[str, Any],
    page: int,
    size: int,
    sort: str,
) -> dict[str, Any]:
    stmt = select(LogEventMeta).where(LogEventMeta.tenant_id.in_(tenant_ids))
    if start_time:
        stmt = stmt.where(LogEventMeta.timestamp >= start_time)
    if end_time:
        stmt = stmt.where(LogEventMeta.timestamp <= end_time)
    for field, value in filters.items():
        if value in (None, "", []):
            continue
        column = getattr(LogEventMeta, field, None)
        if column is not None:
            stmt = stmt.where(column == value)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(LogEventMeta.message.ilike(like), LogEventMeta.hostname.ilike(like), LogEventMeta.user_name.ilike(like)))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    order_col = LogEventMeta.timestamp.desc() if sort != "asc" else LogEventMeta.timestamp.asc()
    rows = db.scalars(stmt.order_by(order_col).offset((page - 1) * size).limit(size)).all()
    items = [
        {
            "id": row.id,
            "tenant_id": row.tenant_id,
            "timestamp": row.timestamp.isoformat(),
            "received_at": row.received_at.isoformat(),
            "source_type": row.source_type,
            "source_name": row.source_name,
            "hostname": row.hostname,
            "severity": row.severity,
            "event_category": row.event_category,
            "event_action": row.event_action,
            "user_name": row.user_name,
            "src_ip": row.src_ip,
            "dst_ip": row.dst_ip,
            "message": row.message,
        }
        for row in rows
    ]
    return {"total": total, "items": items, "aggregations": {}}


def search_logs(
    db: Session,
    *,
    tenant_ids: list[str],
    q: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    filters: dict[str, Any] | None = None,
    page: int = 1,
    size: int = 50,
    sort: str = "desc",
) -> dict[str, Any]:
    filters = filters or {}
    client = _client()
    if client is None:
        return _fallback_search(db, tenant_ids=tenant_ids, q=q, start_time=start_time, end_time=end_time, filters=filters, page=page, size=size, sort=sort)
    must: list[dict[str, Any]] = [{"terms": {"tenant_id": tenant_ids}}]
    if q:
        must.append({"multi_match": {"query": q, "fields": ["message", "raw_log", "command_line", "hostname", "user_name"]}})
    if start_time or end_time:
        range_query: dict[str, Any] = {}
        if start_time:
            range_query["gte"] = start_time.isoformat()
        if end_time:
            range_query["lte"] = end_time.isoformat()
        must.append({"range": {"timestamp": range_query}})
    keyword_fields = {"source_type", "source_name", "severity", "hostname", "user_name", "src_ip", "dst_ip", "event_category", "event_action", "tags"}
    for field, value in filters.items():
        if value in (None, "", []):
            continue
        if field in keyword_fields:
            if isinstance(value, list):
                must.append({"terms": {field: value}})
            else:
                must.append({"term": {field: value}})
    body = {
        "query": {"bool": {"must": must}},
        "from": (page - 1) * size,
        "size": size,
        "sort": [{"timestamp": {"order": sort}}],
        "aggs": {
            "severity": {"terms": {"field": "severity", "size": 10}},
            "top_hosts": {"terms": {"field": "hostname", "size": 10}},
            "top_users": {"terms": {"field": "user_name", "size": 10}},
            "top_source_ips": {"terms": {"field": "src_ip", "size": 10}},
            "events_over_time": {"date_histogram": {"field": "timestamp", "fixed_interval": "1h"}},
        },
    }
    try:
        result = client.search(index="siem-logs-*", body=body)
        hits = result.get("hits", {})
        items = [hit.get("_source", {}) | {"_index": hit.get("_index")} for hit in hits.get("hits", [])]
        total = hits.get("total", {}).get("value", 0) if isinstance(hits.get("total"), dict) else hits.get("total", 0)
        return {"total": total, "items": items, "aggregations": result.get("aggregations", {})}
    except Exception:
        return _fallback_search(db, tenant_ids=tenant_ids, q=q, start_time=start_time, end_time=end_time, filters=filters, page=page, size=size, sort=sort)


def get_log(db: Session, *, tenant_ids: list[str], event_id: str) -> dict[str, Any] | None:
    client = _client()
    if client is not None:
        try:
            result = client.search(index="siem-logs-*", body={"query": {"bool": {"must": [{"terms": {"tenant_id": tenant_ids}}, {"term": {"id": event_id}}]}}, "size": 1})
            hits = result.get("hits", {}).get("hits", [])
            if hits:
                return hits[0].get("_source", {})
        except Exception:
            pass
    row = db.get(LogEventMeta, event_id)
    if not row or row.tenant_id not in tenant_ids:
        return None
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "timestamp": row.timestamp.isoformat(),
        "source_type": row.source_type,
        "source_name": row.source_name,
        "hostname": row.hostname,
        "severity": row.severity,
        "event_category": row.event_category,
        "event_action": row.event_action,
        "user_name": row.user_name,
        "src_ip": row.src_ip,
        "dst_ip": row.dst_ip,
        "message": row.message,
    }
