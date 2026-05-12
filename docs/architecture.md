# Architecture

Mini SIEM trennt interaktive API, Suchspeicher, Metadatenbank und Hintergrundjobs.

## Components

- React Frontend: SOC dashboard, log explorer, alert and incident workflows.
- FastAPI Backend: authentication, RBAC, tenant enforcement, REST API and orchestration.
- PostgreSQL: tenants, users, roles, sources, API key hashes, rules, alerts, incidents, reports, audit trail and log metadata.
- OpenSearch: normalized log events in daily tenant indexes named `siem-logs-{tenant_id}-{yyyy.MM.dd}`.
- Redis and Celery: periodic detection and retention jobs.
- Syslog Receiver: UDP listener that forwards lines to backend ingestion.

## Data Flow

1. A source sends JSON, Fluent Bit HTTP or syslog data.
2. API key is hashed and matched against active source keys.
3. The event is normalized into the internal schema.
4. Full event is indexed in OpenSearch.
5. Metadata is written to PostgreSQL.
6. IOC matching can create immediate alerts.
7. Celery periodically evaluates detection rules against recent OpenSearch data.
8. Alerts feed dashboards, reports, incidents and notifications.

## Tenant Isolation

Tenant isolation is applied in API dependencies. Every relevant query is scoped to the current user's memberships unless the user has `super_admin`.
