from __future__ import annotations

import json
import smtplib
from email.message import EmailMessage

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import Alert, NotificationDelivery, NotificationRule

SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _passes(rule: NotificationRule, alert: Alert) -> bool:
    if SEVERITY_RANK.get(alert.severity, 0) < SEVERITY_RANK.get(rule.severity_min, 0):
        return False
    filters = rule.filters or {}
    if filters.get("rule_id") and filters["rule_id"] != alert.rule_id:
        return False
    return True


def send_alert_notifications(db: Session, alert: Alert) -> list[NotificationDelivery]:
    settings = get_settings()
    rules = db.scalars(select(NotificationRule).where(NotificationRule.tenant_id == alert.tenant_id, NotificationRule.enabled.is_(True))).all()
    if not rules:
        rules = [NotificationRule(tenant_id=alert.tenant_id, name="Local demo notification", channel="demo", target="stdout", severity_min="high")]
    deliveries: list[NotificationDelivery] = []
    for rule in rules:
        if not _passes(rule, alert):
            continue
        delivery = NotificationDelivery(tenant_id=alert.tenant_id, alert_id=alert.id, rule_id=getattr(rule, "id", None), channel=rule.channel, target=rule.target, attempts=1)
        try:
            if rule.channel in {"webhook", "teams", "json_webhook"} and rule.target:
                payload = {"title": alert.title, "severity": alert.severity, "status": alert.status, "risk_score": alert.risk_score, "alert_id": alert.id}
                response = httpx.post(rule.target, json=payload, timeout=settings.webhook_timeout_seconds)
                response.raise_for_status()
                delivery.status = "sent"
                delivery.response = response.text[:1000]
            elif rule.channel == "email" and settings.smtp_host and rule.target:
                message = EmailMessage()
                message["From"] = settings.smtp_from
                message["To"] = rule.target
                message["Subject"] = f"[{alert.severity.upper()}] {alert.title}"
                message.set_content(json.dumps({"description": alert.description, "alert_id": alert.id}, indent=2))
                with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
                    smtp.starttls()
                    if settings.smtp_username and settings.smtp_password:
                        smtp.login(settings.smtp_username, settings.smtp_password)
                    smtp.send_message(message)
                delivery.status = "sent"
            else:
                delivery.status = "sent"
                delivery.response = f"demo notification: {alert.severity} {alert.title}"
        except Exception as exc:
            delivery.status = "failed"
            delivery.last_error = str(exc)
        db.add(delivery)
        deliveries.append(delivery)
    return deliveries
