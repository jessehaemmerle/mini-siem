# API

OpenAPI is served at `/api/docs`.

## Main Endpoints

- `POST /api/auth/login`
- `GET /api/auth/me`
- `POST /api/ingest/logs`
- `POST /api/ingest/syslog`
- `GET /api/logs/search`
- `GET /api/logs/{id}`
- `GET /api/dashboard/overview`
- `GET /api/alerts`
- `PUT /api/alerts/{id}`
- `POST /api/incidents`
- `GET /api/detection-rules`
- `POST /api/reports/generate`
- `GET /api/audit`
- `GET /api/health/deep`

## Ingestion Authentication

Use `X-API-Key` with an active source key.

## User Authentication

Use `Authorization: Bearer <token>` with the token returned by login. Most endpoints also accept `X-Tenant-ID` for tenant selection.
