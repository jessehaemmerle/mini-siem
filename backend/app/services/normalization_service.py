from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any

from app.models import LogSource

SYSLOG_RE = re.compile(r"^(?:<(?P<pri>\d+)>)?(?P<ts>\w{3}\s+\d+\s+[\d:]+)?\s*(?P<host>[\w.-]+)?\s*(?P<app>[\w./-]+)?(?:\[\d+\])?:?\s*(?P<msg>.*)$")


def parse_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str) and value:
        try:
            normalized = value.replace("Z", "+00:00")
            parsed = datetime.fromisoformat(normalized)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            pass
    return datetime.now(UTC)


def normalize_severity(value: Any, message: str = "") -> str:
    if isinstance(value, int):
        if value >= 9:
            return "critical"
        if value >= 7:
            return "high"
        if value >= 4:
            return "medium"
        if value >= 2:
            return "low"
        return "informational"
    text = str(value or "").lower()
    if text in {"critical", "crit", "fatal", "emergency"}:
        return "critical"
    if text in {"high", "error", "err", "alert"}:
        return "high"
    if text in {"medium", "warning", "warn"}:
        return "medium"
    if text in {"low", "notice"}:
        return "low"
    lower_message = message.lower()
    if any(term in lower_message for term in ["malware", "ransomware", "eventlog cleared", "encodedcommand"]):
        return "critical"
    if any(term in lower_message for term in ["failed", "denied", "blocked", "sudo"]):
        return "medium"
    return "informational"


def parse_syslog_line(line: str) -> dict[str, Any]:
    match = SYSLOG_RE.match(line.strip())
    if not match:
        return {"raw_log": line, "message": line, "source_type": "syslog"}
    data = match.groupdict()
    return {
        "raw_log": line,
        "message": data.get("msg") or line,
        "hostname": data.get("host") or "",
        "source_name": data.get("app") or "syslog",
        "source_type": "syslog",
        "metadata": {"syslog_priority": data.get("pri"), "syslog_timestamp": data.get("ts")},
    }


def _category_action_outcome(event: dict[str, Any]) -> tuple[str, str, str]:
    source_type = str(event.get("source_type") or "").lower()
    event_id = str(event.get("event_id") or "")
    message = str(event.get("message") or event.get("raw_log") or "").lower()
    action = str(event.get("action") or "").lower()

    if event_id == "4625" or "failed password" in message or "failed login" in message:
        return "authentication", "login_failed", "failure"
    if event_id == "4624" or "accepted password" in message or "login success" in message:
        return "authentication", "login_success", "success"
    if event_id == "4720" or "new user" in message or "account created" in message:
        return "identity", "account_created", "success"
    if event_id in {"4728", "4732"} or "admin group" in message or "domain admins" in message:
        return "identity", "group_membership_changed", "success"
    if event_id == "1102" or "eventlog cleared" in message or "audit log cleared" in message:
        return "audit", "eventlog_cleared", "success"
    if "encodedcommand" in message or "-enc" in message:
        return "process", "powershell_encoded_command", "success"
    if "malware" in message or "virus" in message or source_type in {"edr", "antivirus"} and "detected" in message:
        return "malware", "malware_detected", "success"
    if "edr disabled" in message or "antivirus disabled" in message:
        return "endpoint", "security_tool_disabled", "success"
    if source_type in {"firewall", "network"} or action in {"allow", "deny", "blocked"}:
        outcome = "failure" if action in {"deny", "blocked", "drop"} or "blocked" in message else "success"
        return "network", action or "network_connection", outcome
    if "sudo" in message:
        return "authorization", "sudo", "success"
    if source_type == "vpn":
        return "authentication", "vpn_login", "success"
    return "application", action or "event", "unknown"


def _mitre(category: str, action: str) -> tuple[str, str, str]:
    mapping = {
        "login_failed": ("Credential Access", "Brute Force", "T1110"),
        "login_success": ("Initial Access", "Valid Accounts", "T1078"),
        "powershell_encoded_command": ("Execution", "PowerShell", "T1059.001"),
        "eventlog_cleared": ("Defense Evasion", "Clear Windows Event Logs", "T1070.001"),
        "account_created": ("Persistence", "Create Account", "T1136"),
        "group_membership_changed": ("Privilege Escalation", "Account Manipulation", "T1098"),
        "malware_detected": ("Impact", "Data Encrypted for Impact", "T1486"),
        "security_tool_disabled": ("Defense Evasion", "Impair Defenses", "T1562"),
    }
    return mapping.get(action, ("", "", ""))


def _risk_score(severity: str, action: str) -> int:
    base = {"informational": 10, "low": 25, "medium": 50, "high": 75, "critical": 90}.get(severity, 30)
    if action in {"eventlog_cleared", "powershell_encoded_command", "malware_detected", "security_tool_disabled"}:
        return max(base, 85)
    return base


def normalize_event(raw_event: dict[str, Any], *, tenant_id: str, source: LogSource | None = None) -> dict[str, Any]:
    event = dict(raw_event)
    if event.get("raw_log") and not event.get("message") and not event.get("source_type"):
        event.update(parse_syslog_line(str(event["raw_log"])))
    message = str(event.get("message") or event.get("raw_log") or "")
    severity = normalize_severity(event.get("severity"), message)
    category, action, outcome = _category_action_outcome({**event, "severity": severity})
    tactic, technique, technique_id = _mitre(category, action)
    now = datetime.now(UTC)
    timestamp = parse_datetime(event.get("timestamp"))
    normalized = {
        "id": str(event.get("id") or uuid.uuid4()),
        "tenant_id": tenant_id,
        "timestamp": timestamp.isoformat(),
        "received_at": now.isoformat(),
        "source_type": event.get("source_type") or (source.source_type if source else "custom"),
        "source_name": event.get("source_name") or (source.name if source else "api"),
        "hostname": event.get("hostname") or (source.hostname if source else ""),
        "severity": severity,
        "event_category": event.get("event_category") or category,
        "event_action": event.get("event_action") or action,
        "event_outcome": event.get("event_outcome") or outcome,
        "user_name": event.get("user_name") or event.get("user") or "",
        "src_ip": event.get("src_ip") or event.get("ip_address") or "",
        "dst_ip": event.get("dst_ip") or "",
        "src_port": event.get("src_port"),
        "dst_port": event.get("dst_port"),
        "protocol": event.get("protocol") or "",
        "action": event.get("action") or action,
        "geo_country": event.get("geo_country") or "",
        "process_name": event.get("process_name") or "",
        "command_line": event.get("command_line") or "",
        "message": message,
        "raw_log": event.get("raw_log") or message,
        "tags": event.get("tags") or [],
        "metadata": event.get("metadata") or {},
        "mitre_tactic": event.get("mitre_tactic") or tactic,
        "mitre_technique": event.get("mitre_technique") or technique,
        "mitre_technique_id": event.get("mitre_technique_id") or technique_id,
        "risk_score": event.get("risk_score") or _risk_score(severity, action),
    }
    return normalized
