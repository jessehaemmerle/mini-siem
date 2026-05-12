from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta
from typing import Any

DEMO_TENANT_NAME = "Demo Company"
DEMO_API_KEY = "siem_demo_ingest_key_change_me"

USERS = [
    ("admin@example.com", "Admin Example", "Admin123!", "super_admin"),
    ("analyst@example.com", "Security Analyst", "Analyst123!", "security_analyst"),
    ("auditor@example.com", "Audit User", "Auditor123!", "auditor"),
    ("viewer@example.com", "Read Only Viewer", "Viewer123!", "viewer"),
]

SOURCES = [
    ("DC01 Windows Domain Controller", "windows", "dc01.demo.local", "10.10.1.10"),
    ("FILE01 Windows File Server", "windows", "file01.demo.local", "10.10.1.20"),
    ("FW01 Firewall", "firewall", "fw01.demo.local", "10.10.0.1"),
    ("VPN01 VPN Gateway", "vpn", "vpn01.demo.local", "10.10.0.5"),
    ("LINUX01 Ubuntu Server", "linux", "linux01.demo.local", "10.10.2.20"),
    ("EDR Demo", "edr", "edr.demo.local", "10.10.9.10"),
]

DETECTION_RULES: list[dict[str, Any]] = [
    {
        "name": "Brute Force Login",
        "description": "More than 10 failed logins within 5 minutes per user or source IP.",
        "condition_type": "threshold",
        "severity": "high",
        "risk_score": 80,
        "timeframe_minutes": 15,
        "threshold": 10,
        "group_by": ["user_name", "src_ip"],
        "query_definition": {"fields": {"event_category": "authentication", "event_action": "login_failed"}},
        "mitre_tactic": "Credential Access",
        "mitre_technique": "Brute Force",
        "mitre_technique_id": "T1110",
        "response_recommendation": "Block the source IP, reset the targeted account if needed, and review successful logins after the failures.",
    },
    {
        "name": "Successful Login After Multiple Failures",
        "description": "Failed logins followed by a success for the same user.",
        "condition_type": "sequence",
        "severity": "high",
        "risk_score": 78,
        "timeframe_minutes": 20,
        "threshold": 1,
        "group_by": ["user_name"],
        "query_definition": {"sequence": [{"event_action": "login_failed"}, {"event_action": "login_success"}]},
        "mitre_tactic": "Initial Access",
        "mitre_technique": "Valid Accounts",
        "mitre_technique_id": "T1078",
        "response_recommendation": "Validate the login, force password reset if suspicious, and inspect endpoint activity.",
    },
    {
        "name": "User Added To Administrator Group",
        "description": "User membership changed for an administrator group.",
        "condition_type": "match",
        "severity": "critical",
        "risk_score": 88,
        "query_definition": {"fields": {"event_action": "group_membership_changed"}},
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "Account Manipulation",
        "mitre_technique_id": "T1098",
        "response_recommendation": "Confirm the change owner and remove unauthorized privileges immediately.",
    },
    {
        "name": "New User Account Created",
        "description": "New account creation event detected.",
        "condition_type": "match",
        "severity": "medium",
        "risk_score": 55,
        "query_definition": {"fields": {"event_action": "account_created"}},
        "mitre_tactic": "Persistence",
        "mitre_technique": "Create Account",
        "mitre_technique_id": "T1136",
        "response_recommendation": "Confirm business justification and disable unknown accounts.",
    },
    {
        "name": "Antivirus Or EDR Disabled",
        "description": "Endpoint security control disabled.",
        "condition_type": "match",
        "severity": "critical",
        "risk_score": 90,
        "query_definition": {"fields": {"event_action": "security_tool_disabled"}},
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "Impair Defenses",
        "mitre_technique_id": "T1562",
        "response_recommendation": "Isolate the host, re-enable protection, and inspect recent process activity.",
    },
    {
        "name": "Malware Detected",
        "description": "Malware or EDR detection event.",
        "condition_type": "match",
        "severity": "critical",
        "risk_score": 95,
        "query_definition": {"fields": {"event_action": "malware_detected"}},
        "mitre_tactic": "Impact",
        "mitre_technique": "Data Encrypted for Impact",
        "mitre_technique_id": "T1486",
        "response_recommendation": "Contain host, collect forensic artefacts, and validate whether the file executed.",
    },
    {
        "name": "PowerShell Encoded Command",
        "description": "PowerShell encoded command detected.",
        "condition_type": "regex",
        "severity": "high",
        "risk_score": 84,
        "query_definition": {"pattern": r"(encodedcommand|-enc\s+[A-Za-z0-9+/=]{20,})", "fields": ["message", "command_line", "raw_log"]},
        "mitre_tactic": "Execution",
        "mitre_technique": "PowerShell",
        "mitre_technique_id": "T1059.001",
        "response_recommendation": "Decode the command, review parent process and isolate host if malicious.",
    },
    {
        "name": "Eventlog Cleared",
        "description": "Windows event log or audit log was cleared.",
        "condition_type": "match",
        "severity": "critical",
        "risk_score": 92,
        "query_definition": {"fields": {"event_action": "eventlog_cleared"}},
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "Clear Windows Event Logs",
        "mitre_technique_id": "T1070.001",
        "response_recommendation": "Identify actor and preserve remaining logs from adjacent telemetry.",
    },
    {
        "name": "Many Blocked Firewall Connections",
        "description": "Large amount of blocked firewall traffic from one source.",
        "condition_type": "threshold",
        "severity": "medium",
        "risk_score": 65,
        "timeframe_minutes": 15,
        "threshold": 25,
        "group_by": ["src_ip"],
        "query_definition": {"fields": {"event_category": "network", "event_action": "deny"}},
        "mitre_tactic": "Reconnaissance",
        "mitre_technique": "Active Scanning",
        "mitre_technique_id": "T1595",
        "response_recommendation": "Review source reputation and firewall policy hits.",
    },
    {
        "name": "VPN Login From Unusual Country",
        "description": "VPN login from country outside approved operating regions.",
        "condition_type": "match",
        "severity": "high",
        "risk_score": 76,
        "query_definition": {"fields": {"source_type": "vpn", "geo_country": "RU"}},
        "mitre_tactic": "Initial Access",
        "mitre_technique": "External Remote Services",
        "mitre_technique_id": "T1133",
        "response_recommendation": "Verify user travel, revoke sessions, and require MFA challenge.",
    },
    {
        "name": "Login Outside Business Hours",
        "description": "Authentication event tagged as outside business hours.",
        "condition_type": "match",
        "severity": "medium",
        "risk_score": 58,
        "query_definition": {"fields": {"event_action": "login_success", "metadata.outside_business_hours": True}},
        "mitre_tactic": "Initial Access",
        "mitre_technique": "Valid Accounts",
        "mitre_technique_id": "T1078",
        "response_recommendation": "Check whether after-hours access matches user schedule.",
    },
    {
        "name": "SSH Login As Root",
        "description": "Root SSH login detected.",
        "condition_type": "match",
        "severity": "high",
        "risk_score": 82,
        "query_definition": {"fields": {"source_type": "linux", "user_name": "root", "event_action": "login_success"}},
        "mitre_tactic": "Initial Access",
        "mitre_technique": "Valid Accounts",
        "mitre_technique_id": "T1078",
        "response_recommendation": "Disable direct root login and rotate credentials if suspicious.",
    },
    {
        "name": "Sudo Use By Non Privileged User",
        "description": "sudo usage by user outside expected admin group.",
        "condition_type": "regex",
        "severity": "medium",
        "risk_score": 62,
        "query_definition": {"pattern": r"sudo:.*(intern|guest|temp)", "fields": ["message", "raw_log"]},
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "Sudo and Sudo Caching",
        "mitre_technique_id": "T1548.003",
        "response_recommendation": "Validate sudoers policy and recent commands.",
    },
    {
        "name": "Communication To Known Malicious IP",
        "description": "Network communication involving a known malicious IP.",
        "condition_type": "match",
        "severity": "critical",
        "risk_score": 93,
        "query_definition": {"fields": {"dst_ip": "203.0.113.66"}},
        "mitre_tactic": "Command and Control",
        "mitre_technique": "Application Layer Protocol",
        "mitre_technique_id": "T1071",
        "response_recommendation": "Block destination, inspect host, and search for beaconing patterns.",
    },
    {
        "name": "Mass File Changes Ransomware Indicator",
        "description": "High volume file modification events from a single host.",
        "condition_type": "threshold",
        "severity": "critical",
        "risk_score": 96,
        "timeframe_minutes": 15,
        "threshold": 40,
        "group_by": ["hostname"],
        "query_definition": {"fields": {"event_category": "file", "event_action": "file_modified"}},
        "mitre_tactic": "Impact",
        "mitre_technique": "Data Encrypted for Impact",
        "mitre_technique_id": "T1486",
        "response_recommendation": "Isolate host and restore from protected backup after containment.",
    },
]

IOCS = [
    {"value": "203.0.113.66", "type": "ip", "source": "Demo TI Feed", "confidence": 92, "severity": "critical", "description": "Demo command-and-control address."},
    {"value": "evil.example", "type": "domain", "source": "Demo TI Feed", "confidence": 80, "severity": "high", "description": "Known demo phishing domain."},
    {"value": "44d88612fea8a8f36de82e1278abb02f", "type": "hash", "source": "Demo TI Feed", "confidence": 85, "severity": "high", "description": "EICAR-like demo hash."},
]


def demo_events(tenant_id: str | None = None) -> list[dict[str, Any]]:
    now = datetime.now(UTC)
    hosts = ["dc01.demo.local", "file01.demo.local", "linux01.demo.local", "workstation-07.demo.local", "workstation-12.demo.local"]
    users = ["alice", "bob", "carol", "david", "svc-backup", "intern"]
    src_ips = ["198.51.100.10", "198.51.100.11", "198.51.100.12", "192.0.2.44", "203.0.113.66"]
    events: list[dict[str, Any]] = []

    for index in range(420):
        ts = now - timedelta(minutes=random.randint(1, 1440))
        source = random.choice(SOURCES)
        category = random.choice(["authentication", "network", "application", "system"])
        if category == "authentication":
            success = random.random() > 0.25
            events.append(
                {
                    "tenant_id": tenant_id,
                    "timestamp": ts.isoformat(),
                    "source_type": "windows" if "Windows" in source[0] else "linux",
                    "source_name": source[0],
                    "hostname": random.choice(hosts),
                    "event_id": "4624" if success else "4625",
                    "severity": "informational" if success else "medium",
                    "user": random.choice(users),
                    "src_ip": random.choice(src_ips[:-1]),
                    "message": ("Successful login" if success else "Failed login") + " for demo user",
                    "metadata": {"outside_business_hours": ts.hour < 6 or ts.hour > 20},
                }
            )
        elif category == "network":
            action = "deny" if random.random() < 0.35 else "allow"
            events.append(
                {
                    "tenant_id": tenant_id,
                    "timestamp": ts.isoformat(),
                    "source_type": "firewall",
                    "source_name": "FW01 Firewall",
                    "hostname": "fw01.demo.local",
                    "severity": "medium" if action == "deny" else "informational",
                    "src_ip": random.choice(src_ips),
                    "dst_ip": random.choice(["10.10.1.20", "10.10.2.20", "8.8.8.8", "203.0.113.66"]),
                    "src_port": random.randint(1024, 65000),
                    "dst_port": random.choice([22, 53, 80, 443, 445, 3389]),
                    "protocol": "tcp",
                    "action": action,
                    "message": f"Firewall {action} tcp connection",
                }
            )
        else:
            events.append(
                {
                    "tenant_id": tenant_id,
                    "timestamp": ts.isoformat(),
                    "source_type": "application",
                    "source_name": "Business App",
                    "hostname": random.choice(hosts),
                    "severity": random.choice(["informational", "low", "medium"]),
                    "user": random.choice(users),
                    "message": "Application audit event completed",
                }
            )

    attack_time = now - timedelta(minutes=3)
    for i in range(12):
        events.append({"tenant_id": tenant_id, "timestamp": (attack_time - timedelta(seconds=i * 10)).isoformat(), "source_type": "windows", "source_name": "DC01 Windows Domain Controller", "hostname": "dc01.demo.local", "event_id": "4625", "severity": "medium", "user": "alice", "src_ip": "198.51.100.200", "message": "Failed login for alice from remote host"})
    events.append({"tenant_id": tenant_id, "timestamp": attack_time.isoformat(), "source_type": "windows", "source_name": "DC01 Windows Domain Controller", "hostname": "dc01.demo.local", "event_id": "4624", "severity": "informational", "user": "alice", "src_ip": "198.51.100.200", "message": "Successful login for alice after repeated failures"})
    events.extend(
        [
            {"tenant_id": tenant_id, "timestamp": now.isoformat(), "source_type": "windows", "source_name": "DC01 Windows Domain Controller", "hostname": "dc01.demo.local", "event_id": "4728", "severity": "high", "user": "mallory", "message": "User mallory added to Domain Admins admin group"},
            {"tenant_id": tenant_id, "timestamp": now.isoformat(), "source_type": "windows", "source_name": "DC01 Windows Domain Controller", "hostname": "dc01.demo.local", "event_id": "4720", "severity": "medium", "user": "new-temp", "message": "New user account created: new-temp"},
            {"tenant_id": tenant_id, "timestamp": now.isoformat(), "source_type": "edr", "source_name": "EDR Demo", "hostname": "workstation-07.demo.local", "severity": "critical", "message": "Malware detected: demo-ransomware.exe hash 44d88612fea8a8f36de82e1278abb02f"},
            {"tenant_id": tenant_id, "timestamp": now.isoformat(), "source_type": "edr", "source_name": "EDR Demo", "hostname": "workstation-12.demo.local", "severity": "critical", "message": "EDR disabled by local administrator"},
            {"tenant_id": tenant_id, "timestamp": now.isoformat(), "source_type": "windows", "source_name": "FILE01 Windows File Server", "hostname": "file01.demo.local", "severity": "high", "process_name": "powershell.exe", "command_line": "powershell.exe -NoP -EncodedCommand SQBFAFgA", "message": "PowerShell EncodedCommand execution detected"},
            {"tenant_id": tenant_id, "timestamp": now.isoformat(), "source_type": "windows", "source_name": "DC01 Windows Domain Controller", "hostname": "dc01.demo.local", "event_id": "1102", "severity": "critical", "user": "mallory", "message": "Eventlog cleared by user mallory"},
            {"tenant_id": tenant_id, "timestamp": now.isoformat(), "source_type": "vpn", "source_name": "VPN01 VPN Gateway", "hostname": "vpn01.demo.local", "severity": "high", "user": "carol", "src_ip": "198.51.100.55", "geo_country": "RU", "message": "VPN login success from unusual country"},
            {"tenant_id": tenant_id, "timestamp": now.isoformat(), "source_type": "linux", "source_name": "LINUX01 Ubuntu Server", "hostname": "linux01.demo.local", "severity": "high", "user": "root", "src_ip": "198.51.100.77", "message": "Accepted password for root from 198.51.100.77 port 54231 ssh2"},
            {"tenant_id": tenant_id, "timestamp": now.isoformat(), "source_type": "linux", "source_name": "LINUX01 Ubuntu Server", "hostname": "linux01.demo.local", "severity": "medium", "user": "intern", "raw_log": "sudo: intern : TTY=pts/0 ; PWD=/home/intern ; USER=root ; COMMAND=/bin/cat /etc/shadow", "message": "sudo: intern attempted privileged command"},
            {"tenant_id": tenant_id, "timestamp": now.isoformat(), "source_type": "firewall", "source_name": "FW01 Firewall", "hostname": "fw01.demo.local", "severity": "critical", "src_ip": "10.10.2.20", "dst_ip": "203.0.113.66", "action": "allow", "dst_port": 443, "message": "Firewall allow connection to known malicious IP 203.0.113.66"},
        ]
    )
    for i in range(30):
        events.append({"tenant_id": tenant_id, "timestamp": (now - timedelta(seconds=i * 8)).isoformat(), "source_type": "firewall", "source_name": "FW01 Firewall", "hostname": "fw01.demo.local", "severity": "medium", "src_ip": "198.51.100.250", "dst_ip": f"10.10.1.{i % 20 + 1}", "dst_port": random.choice([22, 445, 3389]), "action": "deny", "message": "Firewall deny tcp connection"})
    for i in range(45):
        events.append({"tenant_id": tenant_id, "timestamp": (now - timedelta(seconds=i * 5)).isoformat(), "source_type": "windows", "source_name": "FILE01 Windows File Server", "hostname": "file01.demo.local", "severity": "high", "event_category": "file", "event_action": "file_modified", "user": "svc-backup", "message": f"File modified at high rate: share/report-{i}.xlsx"})
    return events[: max(500, len(events))]
