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
      SIEM_PUBLIC_URL: "https://siem.firma.de"   # für die Installationsbefehle der Agenten
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
verwenden und das Caddy-Stammzertifikat auf den Clients hinterlegen – auch auf den Rechnern mit Agent,
sonst lehnen diese die Verbindung ab (Windows: Zertifikatspeicher „Vertrauenswürdige Stammzertifizierungsstellen“,
Debian/Ubuntu: nach `/usr/local/share/ca-certificates/` kopieren und `update-ca-certificates`).

### Direkt im Container

Mit `SIEM_TLS_CERT=/data/tls/cert.pem` und `SIEM_TLS_KEY=/data/tls/key.pem` spricht die
Weboberfläche direkt HTTPS. Dieselben Dateien verwendet der optionale Syslog-über-TLS-Empfang
(`SIEM_SYSLOG_TLS_PORT=6514`, Port in `docker-compose.yml` freigeben).

## Agenten

### Installation und was dabei passiert

Den Befehl unter **Quellen → Agenten** auf dem Rechner ausführen (Linux mit `sudo`, Windows in einer
PowerShell „Als Administrator“). Er

1. lädt die passende Programmdatei aus dem SIEM-Container und prüft ihre SHA-256-Prüfsumme,
2. meldet den Rechner mit dem Registrierungsschlüssel an – der Agent erhält dabei ein eigenes Token,
3. richtet den Dienst `mini-siem-agent` ein und startet ihn.

| | Linux | Windows |
|---|---|---|
| Programm | `/opt/mini-siem-agent/mini-siem-agent` (Verknüpfung in `/usr/local/bin`) | `C:\Program Files\MiniSIEM\mini-siem-agent.exe` |
| Zugangsdaten | `/etc/mini-siem-agent/agent.json` (nur root) | `C:\ProgramData\MiniSIEM\agent.json` |
| Zustand und Puffer | `/var/lib/mini-siem-agent/` | `C:\ProgramData\MiniSIEM\state\` |
| Dienst | systemd-Unit `mini-siem-agent` | Windows-Dienst `mini-siem-agent` (startet nach Fehlern neu) |
| Protokoll | `journalctl -u mini-siem-agent` | `C:\ProgramData\MiniSIEM\agent.log` |

Der Agent läuft mit Administratorrechten (root bzw. LocalSystem), weil nur so das Sicherheitsprotokoll,
das Journal aller Dienste und der Docker-Socket lesbar sind. Unter Linux ist das Dateisystem für den
Dienst bis auf seine eigenen Verzeichnisse schreibgeschützt. Nach einem Neustart liest der Agent dort
weiter, wo er aufgehört hat. Beim allerersten Start übernimmt er aus Journal, Ereignisprotokollen und
Docker die letzten 10 Minuten, aus Logdateien nur neu hinzukommende Zeilen.

Nachträglich installieren auf vielen Rechnern: Der Befehl lässt sich unverändert per Gruppenrichtlinie
(Startskript), Ansible, Intune o. Ä. verteilen. Eine erneute Ausführung auf demselben Rechner ersetzt
die Installation, der Rechner erscheint nicht doppelt.

### Was gesammelt wird

Die Einstellungen unter **Quellen → Agenten → Was die Agenten sammeln** gelten für alle Agenten;
einzelne Rechner können über **Einstellungen** in ihrer Zeile eigene bekommen.

- **Windows:** Kanäle mit Stufe („Erfassen bis Warnung“ = kritisch, Fehler, Warnung) sowie optional
  nur bestimmte oder ausgenommene Ereignis-IDs. Überwachungsereignisse (Sicherheitsprotokoll) werden
  immer erfasst. Standardmäßig ausgenommen sind sehr häufige, wenig aussagekräftige Ereignisse wie
  Objektzugriffe (4656, 4658, 4662, 4663) und die Filterplattform (5156–5158).
- **Linux:** systemd-Journal ab einem Schweregrad, zusätzlich beliebige Logdateien (Platzhalter
  erlaubt, Logrotation wird erkannt).
- **Docker:** Ausgaben aller Container (JSON-Logs werden zerlegt) und Ereignisse: Start, Stopp, Absturz
  mit Exit-Code, Speichermangel, Healthcheck, `docker exec` mit Befehl und Benutzer. Beim Start wird
  vermerkt, ob ein Container privilegiert läuft, den Docker-Socket eingebunden hat oder das Netzwerk
  bzw. die Prozesse des Hosts nutzt. Healthchecks selbst erscheinen nicht als `docker exec`.

Damit Windows aussagekräftige Anmelde- und Kontoereignisse schreibt, sollte die erweiterte
Überwachungsrichtlinie aktiv sein (Gruppenrichtlinie → Computerkonfiguration → Richtlinien →
Windows-Einstellungen → Sicherheitseinstellungen → Erweiterte Überwachungsrichtlinienkonfiguration),
mindestens: Anmelden/Abmelden, Kontoverwaltung, Kontosperrung, Richtlinienänderung, Systemintegrität.
Für Prozess- und Netzwerkdaten empfiehlt sich zusätzlich [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) –
der Agent liest es automatisch, sobald es installiert ist.

### Laufender Betrieb

- **Liste unter Quellen → Agenten:** „Verbunden“ heißt, der Agent hat sich in den letzten 3 Minuten
  gemeldet (er meldet sich jede Minute). Angezeigt werden außerdem fehlende Kanäle, gepufferte Daten
  und Sendefehler.
- **Puffer:** Ist das SIEM nicht erreichbar, schreibt der Agent bis zu 256 MB auf die Platte und sendet
  sie später nach, die ältesten zuerst. Die Erkennungsregeln werten Agent-Events nach ihrer
  Ereigniszeit aus – nachgelieferte Events lösen also keine falschen Häufungsalarme aus.
- **Updates:** Nach einem Update des SIEM-Containers laden die Agenten die neue Version selbst (Prüfsumme
  wird kontrolliert) und starten neu. Abschaltbar unter **Quellen → Agenten → Updates**.
- **Sperren / Löschen:** Ein gesperrter Agent kann nichts mehr senden, bis er entsperrt wird. Gelöschte
  Agenten müssen neu installiert werden. Auf dem Rechner selbst entfernt `mini-siem-agent uninstall`
  Dienst, Konfiguration und Puffer.
- **Registrierungsschlüssel erneuern**, wenn ein Installationsbefehl in falsche Hände geraten ist.
  Installierte Agenten laufen mit ihrem eigenen Token weiter.
- **Proxy:** Der Agent beachtet die Umgebungsvariable `HTTPS_PROXY`. Für den Dienst unter Linux per
  `systemctl edit mini-siem-agent` (`[Service]` → `Environment=HTTPS_PROXY=http://proxy:3128`) setzen,
  unter Windows als Systemumgebungsvariable.

## Microsoft 365

### Einrichtung

1. **App registrieren:** [entra.microsoft.com](https://entra.microsoft.com) → Identität → Anwendungen →
   App-Registrierungen → *Neue Registrierung*. Name z. B. „Mini-SIEM“, „Nur Konten in diesem
   Organisationsverzeichnis“, keine Umleitungs-URI.
2. **Berechtigungen:** *API-Berechtigungen → Berechtigung hinzufügen*, jeweils **Anwendungsberechtigungen**:
   - *Office 365 Management APIs* → `ActivityFeed.Read` (Anmeldungen, Konten, SharePoint, OneDrive, Teams)
   - *Microsoft Graph* → `SecurityAlert.Read.All` (Defender-Warnungen)
   - *Microsoft Graph* → `AuditLog.Read.All` (nur für die optionalen Anmeldedetails, Entra ID P1)

   Danach **Administratorzustimmung erteilen** – in der Spalte Status muss überall „Gewährt“ stehen.
3. **Geheimer Clientschlüssel:** *Zertifikate & Geheimnisse → Neuer geheimer Clientschlüssel*. Den
   **Wert** kopieren (nicht die Geheimnis-ID). Gültigkeit höchstens 24 Monate – Erinnerung eintragen.
4. Im SIEM unter **Quellen → Microsoft 365** Verzeichnis-ID (Mandant), Anwendungs-ID und Schlüssel
   eintragen, Bereiche wählen, **Verbindung testen**, **Speichern**.
5. Das **Überwachungsprotokoll** muss aktiv sein. In neueren Mandanten ist es das bereits; sonst in
   [purview.microsoft.com](https://purview.microsoft.com) → Überwachung → „Aufzeichnung starten“.

### Was abgerufen wird

| Bereich | Quelle | Beispiele |
|---|---|---|
| Anmeldungen & Konten | Management Activity API, `Audit.AzureActiveDirectory` | erfolgreiche und fehlgeschlagene Anmeldungen, neue/gelöschte Benutzer, Kennwort- und MFA-Änderungen, Administratorrollen, App-Zustimmungen, Domänen-Verbund |
| SharePoint, OneDrive, Teams | Management Activity API, `Audit.SharePoint`, `Audit.General` | Downloads, Löschungen, Freigaben, anonyme Links, Schadsoftware in Dateien, Teams-Mitglieder und Gäste |
| Defender-Warnungen | Microsoft Graph `security/alerts_v2` | Warnungen aus Defender for Endpoint, Office 365, Identity, Cloud Apps, Entra ID Protection |
| Anmeldedetails (optional) | Microsoft Graph `auditLogs/signIns` | Anmeldungen mit Land, Stadt, Gerät, Anwendung und Risiko – ersetzt dann die Anmeldungen aus dem Überwachungsprotokoll |

Fehlgeschlagene Anmeldungen, die nur eine Zwischenabfrage sind (MFA-Aufforderung, „Angemeldet
bleiben?“), werden als `action:interrupted` gespeichert und zählen nicht für die Brute-Force-Regeln.
Häufige Vorgänge ohne Sicherheitswert (Seitenaufrufe, Suchanfragen, Teams-Sitzungen) lassen sich
auslassen (Standard).

Alle Events haben `input:m365` und `host:microsoft365`, die Anwendung steht in `app`
(`entra-id`, `sharepoint`, `onedrive`, `teams`, `defender`), der Vorgang in `event_id`
(z. B. `event_id:FileDeleted`, `event_id:UserLoginFailed`).

### Verzögerung und Grenzen

- Microsoft stellt das Überwachungsprotokoll mit Verzögerung bereit, üblich sind **30 Minuten bis einige
  Stunden**, beim ersten Abonnieren **bis zu 12 Stunden**. Defender-Warnungen und Anmeldedetails
  kommen meist nach wenigen Minuten. Die Erkennungsregeln werten Microsoft-365-Events nach ihrer
  Ereigniszeit aus: Was gesammelt verspätet ankommt, wird zeitlich richtig eingeordnet.
- War das SIEM länger aus, holt es bis zu 7 Tage nach (Grenze der Schnittstelle).
- Doppelte Lieferungen von Microsoft werden erkannt und verworfen.

### Fehlermeldungen

| Meldung | Ursache |
|---|---|
| „Der geheime Clientschlüssel ist falsch“ | Geheimnis-ID statt Wert eingetragen oder Tippfehler |
| „… ist abgelaufen“ | Neuen Schlüssel erstellen und im SIEM eintragen |
| „Zugriff verweigert – Berechtigung … fehlt“ | Berechtigung fehlt, als *Delegiert* statt *Anwendung* angelegt oder Administratorzustimmung fehlt |
| „Entra-ID-P1-Lizenz nötig“ | Anmeldedetails abwählen; die Anmeldungen kommen dann aus dem Überwachungsprotokoll |
| Status „In Ordnung“, aber keine Events | Normal in den ersten Stunden nach der Einrichtung; sonst prüfen, ob das Überwachungsprotokoll aktiv ist |

## Netzwerk und Firewall

| Richtung | Port | Wofür |
|----------|------|-------|
| Geräte → SIEM | 514/udp, 514/tcp | Syslog |
| Geräte → SIEM | 8080/tcp (bzw. 443) | HTTP-Ingest (Fluent Bit, Docker-Logtreiber, Skripte) |
| Agenten → SIEM | 8080/tcp (bzw. 443) | Installation, Anmeldung, Einstellungen, Events |
| Benutzer → SIEM | 8080/tcp (bzw. 443) | Weboberfläche |
| SIEM → Internet | 443/tcp | Microsoft 365: `login.microsoftonline.com`, `manage.office.com`, `graph.microsoft.com` |

Mit `SIEM_SYSLOG_ALLOW=10.0.0.0/8,192.168.0.0/16` nimmt das SIEM Syslog nur aus diesen Netzen an.
HTTP-Ingest ist immer durch ein Token geschützt, jeder Agent hat ein eigenes. Sobald Agenten über
Standorte oder das Internet senden, das SIEM nur per HTTPS erreichbar machen (siehe oben).

## Fehlersuche

**Es kommen keine Logs an**

1. Seite **Quellen**: Erscheint der Host überhaupt? Wenn ja, stimmt evtl. nur der Suchzeitraum nicht.
2. Auf dem SIEM-Host prüfen, ob Pakete ankommen: `sudo tcpdump -ni any port 514`
3. Firewall des SIEM-Hosts und dazwischenliegender Geräte prüfen.
4. Ist `SIEM_SYSLOG_ALLOW` gesetzt? Dann muss die Absender-IP darin liegen.
5. HTTP-Quellen: Antwort `401` bedeutet falsches oder gesperrtes Token.

**Ein Agent erscheint nicht oder zeigt „Keine Verbindung“**

1. Auf dem Rechner `mini-siem-agent status` aufrufen; das Protokoll (siehe Tabelle oben) nennt den Grund.
2. Erreicht der Rechner das SIEM? `curl -I https://siem.firma.local/api/health` bzw.
   `Test-NetConnection siem.firma.local -Port 443`.
3. Steht unter **Quellen → Agenten** die richtige Adresse? Sonst `SIEM_PUBLIC_URL` setzen und den Befehl
   neu kopieren.
4. „Registrierungsschlüssel ist falsch“: Der Schlüssel wurde inzwischen erneuert – Befehl neu kopieren.
5. „Das SIEM kennt diesen Agenten nicht (mehr)“: Agent wurde im SIEM gelöscht oder gesperrt – entsperren
   oder neu installieren.

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
