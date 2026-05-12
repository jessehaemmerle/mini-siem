SEVERITIES = ("informational", "low", "medium", "high", "critical")
EVENT_CATEGORIES = (
    "authentication",
    "authorization",
    "network",
    "endpoint",
    "malware",
    "process",
    "file",
    "dns",
    "cloud",
    "identity",
    "system",
    "audit",
    "application",
)
ALERT_STATUSES = ("new", "acknowledged", "investigating", "resolved", "false_positive", "suppressed")
INCIDENT_STATUSES = ("open", "triage", "contained", "eradicated", "recovered", "closed")
SOURCE_TYPES = (
    "windows",
    "linux",
    "firewall",
    "vpn",
    "edr",
    "antivirus",
    "m365",
    "entra_id",
    "cloud",
    "application",
    "syslog",
    "custom",
)
