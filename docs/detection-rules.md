# Detection Rules

Detection rules are stored per tenant and evaluated by the worker.

## Rule Types

- Match: field equality against recent events.
- Threshold: X matching events in Y minutes grouped by selected fields.
- Sequence: ordered matching conditions within a window.
- Regex: pattern match against message, command line or raw log.
- Query: simplified wrapper for recent events.

## Demo Rules

The seed script creates rules for brute force login, success after failures, admin group changes, account creation, disabled security tooling, malware, PowerShell encoded commands, eventlog clearing, blocked firewall spikes, unusual VPN country, after-hours logins, root SSH, suspicious sudo, malicious IP communication and ransomware-like file modifications.

## Deduplication

Alerts include a deterministic `dedup_key` built from rule, group, time window and event ids. This prevents repeated alerts for the same finding during one window.

## MITRE ATT&CK

Rules and alerts store tactic, technique and technique id. Dashboards and alert details display these fields.
