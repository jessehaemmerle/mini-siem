from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Alert, AuditLog, LogEventMeta, Report


def generate_report(
    db: Session,
    *,
    tenant_id: str,
    report_type: str,
    title: str | None,
    created_by: str | None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    file_type: str = "json",
) -> Report:
    end = end_time or datetime.now(UTC)
    start = start_time or end - timedelta(days=1)
    event_count = db.scalar(
        select(func.count(LogEventMeta.id)).where(LogEventMeta.tenant_id == tenant_id, LogEventMeta.timestamp >= start, LogEventMeta.timestamp <= end)
    ) or 0
    alert_rows = db.execute(
        select(Alert.severity, func.count(Alert.id)).where(Alert.tenant_id == tenant_id, Alert.created_at >= start, Alert.created_at <= end).group_by(Alert.severity)
    ).all()
    audit_count = db.scalar(select(func.count(AuditLog.id)).where(AuditLog.tenant_id == tenant_id, AuditLog.timestamp >= start, AuditLog.timestamp <= end)) or 0
    content: dict[str, Any] = {
        "period": {"start": start.isoformat(), "end": end.isoformat()},
        "summary": {"events": event_count, "alerts": sum(count for _, count in alert_rows), "audit_events": audit_count},
        "alerts_by_severity": {severity: count for severity, count in alert_rows},
        "recommendations": [
            "Review high and critical alerts first.",
            "Validate log source coverage and ingestion gaps.",
            "Tune noisy detection rules and document false positives.",
        ],
    }
    report = Report(
        tenant_id=tenant_id,
        report_type=report_type,
        title=title or report_type.replace("_", " ").title(),
        parameters={"start_time": start.isoformat(), "end_time": end.isoformat()},
        content=content,
        file_type=file_type,
        created_by=created_by,
    )
    db.add(report)
    db.flush()
    return report
