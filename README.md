# Mini-SIEM

Ein schlankes SIEM für kleine und mittlere Unternehmen: Logs von Servern, Netzwerkgeräten,
Windows-Systemen und Docker-Containern zentral sammeln, durchsuchen und bei verdächtigen
Ereignissen alarmieren – in **einem einzigen Docker-Container**, ohne externe Datenbank.

- **Sammeln:** Syslog (UDP/TCP/TLS), HTTP/JSON, Splunk-HEC-kompatibel (Docker-Logtreiber `splunk`),
  Windows-Ereignisprotokolle über Fluent Bit oder NXLog
- **Verstehen:** Erkennt automatisch Benutzer, IP-Adressen, Ports und Aktionen aus sshd, sudo,
  Firewalls (iptables/UFW, key=value) und Windows-Sicherheitsereignissen
- **Suchen:** Volltext und Felder, Zeitverlauf, häufige Werte, CSV-Export
- **Erkennen:** 16 mitgelieferte Regeln (SSH-Brute-Force, Password-Spraying, Portscan, neue Admins,
  gelöschte Ereignisprotokolle …), eigene Regeln mit derselben Syntax wie die Suche, Test gegen
  vorhandene Daten
- **Bearbeiten:** Alarme übernehmen, kommentieren, schließen; Rollen *Nur lesen*, *Analyst*, *Administrator*
- **Warten:** Eine Datei pro Tag, Aufbewahrung = alte Dateien löschen, Sicherung mit einem Befehl

Die Oberfläche ist komplett auf Deutsch, hell und dunkel, und funktioniert auch auf dem Smartphone.

---

## Schnellstart

Voraussetzung: ein Linux-Server (oder VM) mit Docker und Docker Compose.

```bash
git clone https://github.com/jessehaemmerle/mini-siem.git
cd mini-siem
cp .env.example .env        # optional: Zeitzone, Admin-Passwort usw. anpassen
docker compose up -d --build
```

Beim ersten Start wird ein Admin-Konto angelegt. Das Passwort steht im Log:

```bash
docker compose logs siem | grep -A3 "Erstes Admin-Konto"
```

Dann im Browser `http://<server>:8080` öffnen, anmelden und unter **Quellen → Neue Quelle anbinden**
den Schritt-für-Schritt-Anleitungen folgen. Dort stehen fertige, kopierbare Konfigurationen für
Linux (rsyslog), Netzwerkgeräte, Windows, Docker und eigene Anwendungen – bereits mit der richtigen
Adresse und auf Wunsch mit einem frisch erstellten Token.

**Zum Ausprobieren** ohne echte Quellen (sendet normalen Betrieb und einige Angriffe):

```bash
python3 scripts/demo_logs.py --host <server>
```

### Ports

| Port | Zweck |
|------|-------|
| 8080/tcp | Weboberfläche, REST-API, HTTP-Ingest, Splunk-HEC |
| 514/udp, 514/tcp | Syslog (im Container 1514, siehe `docker-compose.yml`) |

---

## Bedienung in Kürze

| Seite | Wofür |
|-------|-------|
| **Übersicht** | Lagebild in einem Satz, Eventverlauf, offene Alarme, aktivste Hosts, stille Quellen |
| **Suche** | Events durchsuchen; Klick auf eine Zeile zeigt alle Felder, Klick auf Werte filtert |
| **Alarme** | Alarme übernehmen, kommentieren, schließen (mit Ergebnis), Sammelaktionen |
| **Regeln** | Erkennungsregeln an-/abschalten, bearbeiten, gegen vorhandene Daten testen |
| **Quellen** | Welche Geräte senden? Wer ist still geworden? Anleitungen und Sende-Tokens |
| **Benutzer** | Konten und Rollen (nur Administratoren) |
| **System** | Zustand, Speicherplatz, Aufbewahrung, Protokoll aller Änderungen |

### Suchsyntax

| Beispiel | Bedeutung |
|----------|-----------|
| `Failed password` | alle Wörter kommen vor |
| `"Failed password"` | genau diese Wortfolge |
| `pass*` | Wortanfang |
| `host:web01` | Feld hat diesen Wert (Groß-/Kleinschreibung egal) |
| `host:web*` | Platzhalter `*` und `?` |
| `src_ip:10.0.0.0/8` | IP-Adresse im Netz |
| `severity:<=warning` | Vergleich (`>`, `>=`, `<`, `<=`) |
| `user:*` | Feld ist vorhanden |
| `-app:cron` oder `NOT app:cron` | ausschließen |
| `host:a OR host:b` | oder, Klammern erlaubt |
| `data.status:500` | Feld aus den Originaldaten (JSON, key=value) |
| `user:~"^adm"` | regulärer Ausdruck |

Felder: `host`, `app`, `severity`, `facility`, `category`, `event_id`, `user`, `src_ip`, `dst_ip`,
`dst_port`, `action`, `input`, `source_ip`, `message`, `data.<name>`. Kurzformen: `ip` (alle IP-Felder),
`port`, `sev`, `msg`. Schweregrade: `emerg`, `alert`, `crit`, `error`, `warning`, `notice`, `info`, `debug` (0–7).

### Regeln

Eine Regel ist eine gespeicherte Suche plus „wann alarmieren“:

- **bei jedem Treffer** – z. B. `event_id:1102` (Sicherheitsprotokoll gelöscht)
- **ab einer Anzahl von Treffern** im Zeitfenster – z. B. 10 fehlgeschlagene SSH-Anmeldungen in 5 Minuten
- **ab einer Anzahl verschiedener Werte** – z. B. 25 verschiedene Zielports von einer IP in 2 Minuten (Portscan)

Mit **Getrennt zählen je** entsteht pro Wert (z. B. je Angreifer-IP) ein eigener Alarm. Weitere Treffer
fließen in den offenen Alarm ein, statt eine Alarmflut zu erzeugen. Jede Suche lässt sich mit
**Als Regel speichern** direkt in eine Regel übernehmen.

### Rollen

| Rolle | Darf |
|-------|------|
| Nur lesen | alles ansehen |
| Analyst | zusätzlich Alarme bearbeiten, Regeln und Quellen pflegen |
| Administrator | zusätzlich Benutzer, Sende-Tokens und Einstellungen verwalten |

---

## Betrieb und Wartung

Die wichtigsten Befehle (Details in [docs/betrieb.md](docs/betrieb.md)):

```bash
docker compose logs -f siem                               # Log ansehen
git pull && docker compose up -d --build                  # Aktualisieren
docker compose exec siem python -m siem backup            # Sicherung nach /data/backups
docker compose exec siem python -m siem passwort admin    # Passwort vergessen
```

**Speicherbedarf:** rund 0,5 KB pro Event inklusive Suchindex. Beispiel: 1 Mio. Events pro Tag
≈ 0,5 GB pro Tag ≈ 45 GB bei 90 Tagen Aufbewahrung. Die Seite **System** zeigt den tatsächlichen
Verbrauch und wie lange der freie Platz noch reicht.

**Leistung:** gemessen im Container auf einem CPU-Kern ca. 7.500 Events pro Sekunde dauerhaft;
Suchen über einen Tag dauern typischerweise unter einer Sekunde. Der Container braucht etwa 200 MB RAM.

**HTTPS:** Die Oberfläche hinter einen Reverse-Proxy (z. B. Caddy, Traefik, nginx) stellen und
`SIEM_COOKIE_SECURE=true` setzen – Beispiel in [docs/betrieb.md](docs/betrieb.md#https).

### Konfiguration

Alle Einstellungen sind optional und werden in `.env` gesetzt. Aufbewahrung, Ruhezeit für
„stille“ Quellen und automatische Abmeldung lassen sich zusätzlich in der Oberfläche ändern.

| Variable | Standard | Bedeutung |
|----------|----------|-----------|
| `TZ` | `Europe/Vienna` | Zeitzone für Syslog-Meldungen ohne Zeitzonenangabe |
| `SIEM_ADMIN_USER` | `admin` | Name des ersten Kontos |
| `SIEM_ADMIN_PASSWORD` | *(erzeugt)* | Passwort des ersten Kontos (nur beim allerersten Start) |
| `SIEM_RETENTION_DAYS` | `90` | Aufbewahrung beim ersten Start |
| `SIEM_SYSLOG_ALLOW` | *(alle)* | Syslog nur aus diesen Netzen, z. B. `10.0.0.0/8,192.168.0.0/16` |
| `SIEM_COOKIE_SECURE` | `false` | `true` bei Betrieb über HTTPS |
| `SIEM_TRUSTED_PROXIES` | `127.0.0.1` | Reverse-Proxys, deren `X-Forwarded-For` vertraut wird |
| `SIEM_PUBLIC_SYSLOG_PORT` | `514` | Syslog-Port in den Anleitungen der Oberfläche |
| `SIEM_SYSLOG_TLS_PORT` | `0` (aus) | Syslog über TLS, benötigt `SIEM_TLS_CERT` und `SIEM_TLS_KEY` |
| `SIEM_QUERY_TIMEOUT` | `30` | maximale Dauer einer Suche in Sekunden |
| `SIEM_QUEUE_SIZE` | `200000` | Puffer für eingehende Events bei Lastspitzen |

---

## Aufbau

```
                    ┌──────────────────────── Container ─────────────────────────┐
 Syslog UDP/TCP ──▶ │ Empfänger ─┐                                                │
 HTTP / HEC ──────▶ │ REST-API ──┴▶ Warteschlange ▶ Parser ▶ Speicher ▶ Erkennung │
 Browser ─────────▶ │ Weboberfläche ◀──────── Suche ◀───┘          │            │
                    │                                    Tagesdateien  Alarme     │
                    └─────────────── /data (Volume) ─────────────────────────────┘
```

- Python 3 mit FastAPI, eine einzige Prozess-Instanz; Oberfläche ohne Build-Schritt (HTML/CSS/JS)
- `data/siem.db` – Benutzer, Regeln, Alarme, Einstellungen, Änderungsprotokoll
- `data/events/JJJJ-MM-TT.db` – Events eines Tages mit Volltextindex (SQLite FTS5)

Hinweise für Entwickler stehen in [docs/entwicklung.md](docs/entwicklung.md).

## Lizenz

MIT, siehe [LICENSE](LICENSE). Die mitgelieferte Schrift *Atkinson Hyperlegible* steht unter der
SIL Open Font License ([siem/static/fonts/OFL.txt](siem/static/fonts/OFL.txt)).
