# Operations

## Health

Use `/api/health` for shallow checks and `/api/health/deep` for PostgreSQL, Redis and OpenSearch status.

## Backups

- PostgreSQL: `pg_dump` and tested restore.
- OpenSearch: snapshot repository and snapshot lifecycle.
- Configuration: backup `.env`, compose files and reverse-proxy config.

## Retention

Tenant retention defaults to 90 days. The worker deletes old PostgreSQL metadata. Configure OpenSearch ISM policies for index deletion or archival in production.

## Alert Handling

Analysts should triage critical and high alerts first, acknowledge valid findings, create incidents for multi-alert investigations and document timeline entries. False positives should be marked and used to tune rules.

## Log Source Monitoring

Log sources track `last_seen` and `events_last_24h`. Sources with stale `last_seen` should be investigated as telemetry gaps.
