# Betrieb und Wartung

## Installation

```bash
git clone https://github.com/jessehaemmerle/mini-siem.git
cd mini-siem
cp .env.example .env     # Werte anpassen (alle optional)
docker compose up -d --build
docker compose logs siem | grep -A3 "Erstes Admin-Konto"
```

Das Passwort des ersten Kontos steht zusätzlich in `/data/initial-admin-password.txt` im Container.
Die Datei wird gelöscht, sobald das Passwort in der Oberfläche geändert wurde (unten links auf den
eigenen Namen klicken).

**Hardware als Richtwert:** 2 CPU-Kerne, 2 GB RAM, Plattenplatz nach Logmenge (siehe unten).
Eine SSD macht Suchen über lange Zeiträume deutlich schneller.

## Aktualisieren

```bash
cd mini-siem
git pull
docker compose up -d --build
```

Datenbank-Änderungen werden beim Start automatisch eingespielt. Vorher eine Sicherung anzulegen
schadet nie.

## Sicherung und Wiederherstellung

Die Sicherung läuft im laufenden Betrieb und erzeugt konsistente Kopien aller Datenbanken:

```bash
# alles sichern -> /data/backups/siem-backup-<datum>.tar.gz im Volume
docker compose exec siem python -m siem backup

# nur Konfiguration, Alarme und die letzten 7 Tage Events
docker compose exec siem python -m siem backup --tage 7

# Sicherung aus dem Container auf den Host kopieren
docker cp mini-siem:/data/backups/ ./backups/
```

Für eine regelmäßige Sicherung genügt ein Cronjob auf dem Host, z. B. täglich um 2 Uhr:

```
0 2 * * *  cd /opt/mini-siem && docker compose exec -T siem python -m siem backup --tage 2 && docker cp mini-siem:/data/backups/ /srv/backup/mini-siem/
```

**Wiederherstellen:**

```bash
docker compose down
docker run --rm -v mini-siem_siem-data:/data -v "$PWD":/backup alpine \
  sh -c "tar xzf /backup/siem-backup-XXXX.tar.gz -C /data && chown -R 1000:1000 /data"
docker compose up -d
```

(Der Volume-Name lautet `<ordnername>_siem-data`; `docker volume ls` zeigt ihn an.)

## Passwort vergessen

```bash
docker compose exec siem python -m siem passwort admin
```

setzt ein neues zufälliges Passwort, entsperrt das Konto und meldet alle Sitzungen ab.

## Aufbewahrung und Speicherplatz

- Events liegen in einer Datei pro Tag (`/data/events/JJJJ-MM-TT.db`). Ältere Tage als die eingestellte
  Aufbewahrung werden stündlich gelöscht.
- Geschlossene Alarme werden nach der eingestellten Frist (Standard 365 Tage) gelöscht, offene nie.
- Richtwert: **0,5 KB pro Event** inklusive Suchindex.

| Events pro Tag | pro Tag | 30 Tage | 90 Tage | 365 Tage |
|---------------:|--------:|--------:|--------:|---------:|
| 100.000 | 50 MB | 1,5 GB | 4,5 GB | 18 GB |
| 1 Mio. | 0,5 GB | 15 GB | 45 GB | 180 GB |
| 10 Mio. | 5 GB | 150 GB | 450 GB | 1,8 TB |

Die Seite **System** zeigt den tatsächlichen Durchschnitt pro Tag und wie lange der freie Platz noch
reicht. Wird es knapp: Aufbewahrung verkürzen (wirkt sofort) oder laute, unwichtige Quellen an der
Quelle filtern (z. B. Debug-Meldungen in rsyslog nicht weiterleiten: `*.info` statt `*.*`).

## HTTPS

### Mit Reverse-Proxy (empfohlen)

Beispiel mit [Caddy](https://caddyserver.com), der automatisch Zertifikate besorgt.
`docker-compose.override.yml` neben `docker-compose.yml` anlegen:

```yaml
services:
  siem:
    ports: !override
      - "514:1514/udp"
      - "514:1514/tcp"
    environment:
      SIEM_COOKIE_SECURE: "true"
      SIEM_TRUSTED_PROXIES: "*"
  caddy:
    image: caddy:2
    restart: unless-stopped
    ports: ["80:80", "443:443"]
    command: caddy reverse-proxy --from siem.firma.de --to siem:8080
    volumes: [caddy-data:/data]
volumes:
  caddy-data:
```

Im internen Netz ohne öffentlichen Namen statt `--from siem.firma.de` z. B. `--from siem.firma.local --internal-certs`
verwenden und das Caddy-Stammzertifikat auf den Clients hinterlegen.

### Direkt im Container

Mit `SIEM_TLS_CERT=/data/tls/cert.pem` und `SIEM_TLS_KEY=/data/tls/key.pem` spricht die
Weboberfläche direkt HTTPS. Dieselben Dateien verwendet der optionale Syslog-über-TLS-Empfang
(`SIEM_SYSLOG_TLS_PORT=6514`, Port in `docker-compose.yml` freigeben).

## Netzwerk und Firewall

| Richtung | Port | Wofür |
|----------|------|-------|
| Geräte → SIEM | 514/udp, 514/tcp | Syslog |
| Geräte → SIEM | 8080/tcp (bzw. 443) | HTTP-Ingest (Windows/Fluent Bit, Docker, Skripte) |
| Benutzer → SIEM | 8080/tcp (bzw. 443) | Weboberfläche |

Mit `SIEM_SYSLOG_ALLOW=10.0.0.0/8,192.168.0.0/16` nimmt das SIEM Syslog nur aus diesen Netzen an.
HTTP-Ingest ist immer durch ein Token geschützt.

## Fehlersuche

**Es kommen keine Logs an**

1. Seite **Quellen**: Erscheint der Host überhaupt? Wenn ja, stimmt evtl. nur der Suchzeitraum nicht.
2. Auf dem SIEM-Host prüfen, ob Pakete ankommen: `sudo tcpdump -ni any port 514`
3. Firewall des SIEM-Hosts und dazwischenliegender Geräte prüfen.
4. Ist `SIEM_SYSLOG_ALLOW` gesetzt? Dann muss die Absender-IP darin liegen.
5. HTTP-Quellen: Antwort `401` bedeutet falsches oder gesperrtes Token.

**Uhrzeiten sind um Stunden verschoben** – Das Gerät sendet Syslog ohne Zeitzone (RFC 3164).
`TZ` in `.env` auf die Zeitzone der Geräte setzen. Zeitstempel aus der Zukunft ersetzt das SIEM
automatisch durch die Empfangszeit.

**„Das SIEM ist ausgelastet“ / verworfene Events auf der Seite System** – Es kommen mehr Events an,
als verarbeitet werden können. Unwichtige Quellen filtern, mehr CPU zuweisen oder `SIEM_QUEUE_SIZE`
für kurze Spitzen erhöhen.

**Suche dauert lange oder bricht ab** – Zeitraum verkleinern oder ein Feld angeben (`host:…`,
`app:…`); Feldsuchen nutzen Indizes und sind deutlich schneller als reiner Freitext über viele Tage.

## Logs des SIEM selbst

```bash
docker compose logs -f siem
```

Mehr Details mit `SIEM_LOG_LEVEL=DEBUG`, Zugriffslog des Webservers mit `SIEM_ACCESS_LOG=true`.
Alle Änderungen durch Benutzer (Anmeldungen, Regeln, Tokens, Einstellungen) stehen zusätzlich
unter **System → Protokoll der Änderungen**.
