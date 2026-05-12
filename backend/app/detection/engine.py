from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.detection.evaluators import evaluate_match, evaluate_regex, evaluate_sequence, evaluate_threshold
from app.detection.rule_loader import load_enabled_rules
from app.models import DetectionRule
from app.services.alert_service import create_alert
from app.services.notification_service import send_alert_notifications
from app.services.opensearch_service import search_logs


def _evaluate(rule: DetectionRule, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if rule.condition_type == "match":
        return evaluate_match(events, rule.query_definition or {})
    if rule.condition_type == "regex":
        return evaluate_regex(events, rule.query_definition or {})
    if rule.condition_type == "threshold":
        return evaluate_threshold(events, rule.query_definition or {}, threshold=rule.threshold, group_by=rule.group_by or [])
    if rule.condition_type == "sequence":
        return evaluate_sequence(events, rule.query_definition or {}, group_by=rule.group_by or [])
    if rule.condition_type == "query":
        return [{"group": "query", "events": events}] if events else []
    return []


def _rule_filters(rule: DetectionRule) -> dict[str, Any]:
    definition = rule.query_definition or {}
    fields = definition.get("fields") if isinstance(definition.get("fields"), dict) else {}
    filters = {}
    for field in ["source_type", "severity", "hostname", "user_name", "src_ip", "dst_ip", "event_category", "event_action"]:
        if field in fields:
            filters[field] = fields[field]
    return filters


def run_rule(db: Session, rule: DetectionRule) -> int:
    end = datetime.now(UTC)
    start = end - timedelta(minutes=rule.timeframe_minutes or 5)
    result = search_logs(
        db,
        tenant_ids=[rule.tenant_id],
        start_time=start,
        end_time=end,
        filters=_rule_filters(rule),
        size=1000,
    )
    events = result["items"]
    matches = _evaluate(rule, events)
    created = 0
    window = end.strftime("%Y%m%d%H%M")
    for match in matches:
        matched_events: list[dict[str, Any]] = match.get("events", [])
        group = str(match.get("group") or "all")
        event_ids = ",".join(sorted(str(event.get("id")) for event in matched_events[:10]))
        dedup = f"rule:{rule.id}:{group}:{window}:{event_ids[:128]}"
        alert, was_created = create_alert(
            db,
            tenant_id=rule.tenant_id,
            title=rule.name,
            description=rule.description,
            severity=rule.severity,
            risk_score=rule.risk_score,
            rule_id=rule.id,
            dedup_key=dedup,
            matched_events=matched_events[:50],
            mitre_tactic=rule.mitre_tactic,
            mitre_technique=rule.mitre_technique,
            mitre_technique_id=rule.mitre_technique_id,
            response_recommendation=rule.response_recommendation,
        )
        if was_created:
            send_alert_notifications(db, alert)
            created += 1
    db.commit()
    return created


def run_detection_once(db: Session) -> dict[str, Any]:
    total = 0
    rules = load_enabled_rules(db)
    for rule in rules:
        total += run_rule(db, rule)
    return {"rules_evaluated": len(rules), "alerts_created": total, "timestamp": datetime.now(UTC).isoformat()}
