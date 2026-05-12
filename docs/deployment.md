# Deployment

## Local Docker Compose

Run:

```bash
docker compose up --build
```

Services:

- `frontend`
- `backend`
- `worker`
- `postgres`
- `redis`
- `opensearch`
- `opensearch-dashboards`
- `syslog-receiver`
- `demo-init`
- optional `fluent-bit`

## Reverse Proxy

For production, terminate TLS at a reverse proxy and forward:

- `/` to frontend
- `/api` to backend
- optional internal-only OpenSearch Dashboards

## Scaling

Backend can be horizontally scaled behind a load balancer. Worker concurrency can be increased for detection throughput. OpenSearch should move from single-node demo mode to a real cluster before production use.
