# Mini SIEM

Mini SIEM ist eine self-hosted SIEM-Plattform fuer kleine Teams, Labore und produktionsnahe Demos. Die Plattform sammelt Logs per REST, Fluent-Bit-kompatiblem HTTP und Syslog-Demo-Receiver, normalisiert Events, speichert sie in OpenSearch, verwaltet Metadaten in PostgreSQL, erzeugt Alerts ueber Detection Rules und stellt Dashboards, Reports, Audit Trail, Mandanten und Rollen bereit.

## Architektur

- Frontend: React, Vite, TypeScript, Tailwind CSS, Recharts, Lucide Icons
- Backend: Python 3.12, FastAPI, SQLAlchemy, Pydantic, JWT, Argon2
- Datenhaltung: PostgreSQL fuer SIEM-Metadaten, OpenSearch fuer Logs und Suche
- Jobs: Redis und Celery Worker mit periodischer Detection und Retention
- Ingestion: REST API, Syslog UDP Demo-Service, Fluent Bit HTTP Output
- Security: RBAC, Mandantentrennung, API-Key-Hashing, Audit Logging, Rate Limits, sichere Header

## Projektstruktur

```text
backend/              FastAPI, Modelle, Services, Detection Engine, Tests
frontend/             React SOC-Konsole
syslog-receiver/      UDP Syslog Forwarder
scripts/              Demo Seed, Demo Log Import, Detection Run
docs/                 Architektur, Security, API, Deployment, Betrieb
fluent-bit/           Optionale Fluent Bit Demo-Konfiguration
docker-compose.yml    Vollstaendiges lokales Deployment
```

## Lokal starten

1. `.env.example` optional nach `.env` kopieren und Secrets anpassen.
2. Docker starten.
3. Plattform bauen und starten:

```bash
docker compose up --build
```

Die Initialisierung laeuft automatisch ueber den Service `demo-init`: Schema, Demo-Mandant, Demo-User, Quellen, API-Key, IOCs, Detection Rules, Demo-Logs und ein erster Detection-Lauf.

Nach dem Start:

- Frontend: http://localhost:8080
- Backend API Docs: http://localhost:8000/api/docs
- OpenSearch: http://localhost:9200
- OpenSearch Dashboards: http://localhost:5601

## Demo-Logins

- `admin@example.com` / `Admin123!`
- `analyst@example.com` / `Analyst123!`
- `auditor@example.com` / `Auditor123!`
- `viewer@example.com` / `Viewer123!`

Demo Ingestion API-Key:

```text
siem_demo_ingest_key_change_me
```

## Demo-Kommandos

```bash
docker compose run --rm backend python ../scripts/seed_demo_data.py
docker compose run --rm backend python ../scripts/import_demo_logs.py
docker compose run --rm backend python ../scripts/run_detection_once.py
```

## Log-Ingestion

Einzelnes JSON-Event:

```bash
curl -X POST http://localhost:8000/api/ingest/logs \
  -H "Content-Type: application/json" \
  -H "X-API-Key: siem_demo_ingest_key_change_me" \
  -d '{"source_type":"linux","source_name":"manual","hostname":"linux01","severity":"medium","message":"Failed password for alice from 198.51.100.10","user":"alice","src_ip":"198.51.100.10"}'
```

Array von Events:

```bash
curl -X POST http://localhost:8000/api/ingest/logs \
  -H "Content-Type: application/json" \
  -H "X-API-Key: siem_demo_ingest_key_change_me" \
  -d '[{"source_type":"firewall","source_name":"fw01","action":"deny","src_ip":"198.51.100.250","dst_ip":"10.10.1.10","message":"Firewall deny tcp connection"}]'
```

Syslog HTTP-Demo:

```bash
curl -X POST http://localhost:8000/api/ingest/syslog \
  -H "Content-Type: application/json" \
  -H "X-API-Key: siem_demo_ingest_key_change_me" \
  -d '{"line":"<134>May 12 10:30:00 linux01 sshd: Failed password for root from 198.51.100.77 port 50022 ssh2"}'
```

Syslog UDP:

```bash
echo "<134>May 12 10:30:00 linux01 sshd: Failed password for root from 198.51.100.77 port 50022 ssh2" | nc -u -w1 localhost 5514
```

Fluent Bit Demo:

```bash
docker compose --profile fluent-bit up fluent-bit
```

## Detection Rules und Alerts

Die Demo enthaelt Regeln fuer Brute Force, erfolgreichen Login nach Fehlversuchen, Admin-Gruppenaenderung, neue Konten, deaktiviertes EDR/AV, Malware, PowerShell EncodedCommand, geloeschtes Eventlog, Firewall-Block-Spikes, VPN aus ungewoehnlichem Land, Root-SSH, sudo durch nicht privilegierte User, bekannte boesartige IP und Ransomware-Dateiaenderungen. Alerts koennen bestaetigt, untersucht, geloest, zu Incidents verknuepft und als False Positive markiert werden.

## Mandanten und Rollen

Jeder Benutzer ist einem oder mehreren Mandanten zugeordnet. Backend-Dependencies erzwingen Mandantenzugriff fuer Logs, Alerts, Incidents, Reports, IOCs, Quellen und Regeln. `super_admin` darf alle Mandanten sehen, alle anderen Rollen werden auf ihre Memberships begrenzt.

## Reports

Reports werden im Backend erzeugt und gespeichert. Demo-Typen sind Daily Security Report, Weekly Management Report, Monthly Compliance Report und Alert Summary. JSON und CSV-Export sind implementiert; PDF ist als lokale Text-PDF-Demo vorbereitet.

## Retention

Pro Mandant gibt es eine Retention Policy. Der Worker fuehrt periodisch einen Metadaten-Retention-Lauf aus. OpenSearch Index Lifecycle ist ueber Index-Templates vorbereitet; fuer Produktion sollte eine echte ISM/ILM-Policy in OpenSearch aktiviert werden.

## Security-Hinweise

- `JWT_SECRET`, `API_KEY_HASH_SECRET` und Datenbankpasswort in `.env` ersetzen.
- OpenSearch Security Plugin ist in der lokalen Demo deaktiviert. In Produktion aktivieren.
- TLS ueber Reverse Proxy terminieren, z. B. Traefik, Caddy oder Nginx.
- SMTP/Webhook-Ziele nur ueber sichere Kanaele verwenden.
- API-Keys werden gehasht gespeichert und nur bei Erstellung/Rotation angezeigt.

## Backup-Hinweise

- PostgreSQL: regelmaessige `pg_dump` Backups.
- OpenSearch: Snapshot Repository konfigurieren.
- `.env`, Reverse-Proxy-Konfiguration und Docker Compose versionieren, echte Secrets separat verwalten.

## Tests

Backend:

```bash
cd backend
python -m pytest tests -q
```

Frontend:

```bash
cd frontend
npm install
npm test
```

## Troubleshooting

- OpenSearch startet nicht: Docker RAM pruefen und ggf. `vm.max_map_count` erhoehen.
- Keine Demo-Daten: `docker compose run --rm backend python ../scripts/import_demo_logs.py` ausfuehren.
- Login schlaegt fehl: `docker compose logs demo-init backend` pruefen.
- Frontend API-Fehler: Backend unter http://localhost:8000/api/health testen.
