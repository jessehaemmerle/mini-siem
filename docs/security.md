# Security

## Authentication

Passwords are hashed with Argon2. The backend issues JWT access tokens signed with `JWT_SECRET` from the environment.

## API Keys

Ingestion API keys are generated as random values and stored only as HMAC-SHA256 hashes with an environment-provided pepper. Cleartext keys are shown only at creation and rotation time.

## RBAC

Roles:

- `super_admin`
- `tenant_admin`
- `security_analyst`
- `auditor`
- `viewer`

Permissions are enforced with FastAPI dependencies. Role-controlled UI is prepared and backend authorization remains the source of truth.

## Audit Trail

Administrative and analyst actions are written to `audit_logs`, including actor, action, entity, tenant, client IP and user agent when available.

## Production Hardening

- Replace all demo secrets.
- Enable OpenSearch authentication and TLS.
- Put the frontend/backend behind HTTPS.
- Restrict CORS origins.
- Configure SMTP and webhooks with secret management.
- Use external backups for PostgreSQL and OpenSearch snapshots.
