import csv
import io
import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.api.deps import accessible_tenant_ids, require_permission
from app.db.session import get_db
from app.models import User
from app.schemas import LogSearchResponse
from app.services.opensearch_service import get_log, search_logs

router = APIRouter(prefix="/logs", tags=["logs"])


def _filters(
    source_type: str | None,
    severity: str | None,
    hostname: str | None,
    user_name: str | None,
    ip: str | None,
    event_category: str | None,
    tags: list[str] | None,
) -> dict:
    filters = {
        "source_type": source_type,
        "severity": severity,
        "hostname": hostname,
        "user_name": user_name,
        "event_category": event_category,
        "tags": tags,
    }
    if ip:
        filters["src_ip"] = ip
    return filters


@router.get("/search", response_model=LogSearchResponse)
def search(
    tenant_id: str | None = None,
    q: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    source_type: str | None = None,
    severity: str | None = None,
    hostname: str | None = None,
    user_name: str | None = None,
    ip: str | None = None,
    event_category: str | None = None,
    tags: list[str] | None = Query(default=None),
    page: int = 1,
    size: int = Query(default=50, le=500),
    sort: str = "desc",
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("logs:read")),
):
    tenant_ids = accessible_tenant_ids(db, user, tenant_id)
    result = search_logs(db, tenant_ids=tenant_ids, q=q, start_time=start_time, end_time=end_time, filters=_filters(source_type, severity, hostname, user_name, ip, event_category, tags), page=page, size=size, sort=sort)
    return {"page": page, "size": size, **result}


@router.get("/aggregations")
def aggregations(tenant_id: str | None = None, db: Session = Depends(get_db), user: User = Depends(require_permission("logs:read"))):
    tenant_ids = accessible_tenant_ids(db, user, tenant_id)
    return search_logs(db, tenant_ids=tenant_ids, size=0).get("aggregations", {})


@router.get("/{event_id}")
def get_event(event_id: str, tenant_id: str | None = None, db: Session = Depends(get_db), user: User = Depends(require_permission("logs:read"))):
    event = get_log(db, tenant_ids=accessible_tenant_ids(db, user, tenant_id), event_id=event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Log event not found")
    return event


@router.post("/export")
def export_logs(format: str = "csv", tenant_id: str | None = None, db: Session = Depends(get_db), user: User = Depends(require_permission("logs:read"))):
    result = search_logs(db, tenant_ids=accessible_tenant_ids(db, user, tenant_id), size=1000)
    if format == "json":
        return Response(json.dumps(result["items"], default=str, indent=2), media_type="application/json")
    buffer = io.StringIO()
    fieldnames = sorted({key for item in result["items"] for key in item.keys()}) or ["id"]
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(result["items"])
    return Response(buffer.getvalue(), media_type="text/csv")
