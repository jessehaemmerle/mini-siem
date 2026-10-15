# Hinweise für Entwickler

## Lokal starten

```bash
pip install -r requirements-dev.txt
SIEM_DATA_DIR=./data SIEM_ADMIN_PASSWORD=ein-sicheres-passwort python -m siem
# Oberfläche: http://localhost:8080   Syslog: Port 1514   API-Doku: http://localhost:8080/api/docs
python3 scripts/demo_logs.py --port 1514
```

Den Agenten zum Ausprobieren für die lokale Instanz bereitstellen (Go 1.24):

```bash
mkdir -p agent-dist && (cd agent && go build -ldflags "-X main.version=dev" -o ../agent-dist/mini-siem-agent-linux-amd64 .)
echo dev > agent-dist/VERSION
SIEM_AGENT_DIST=./agent-dist SIEM_DATA_DIR=./data python -m siem
```

## Tests

```bash
python -m pytest                       # SIEM
(cd agent && go vet ./... && GOOS=windows go vet ./... && go test ./...)   # Agent
```

Die Python-Tests decken Abfragesprache (SQL und Python liefern dieselben Treffer), Parser, Erkennung,
Agent-Schnittstelle, den Microsoft-365-Connector (gegen ein nachgebildetes Microsoft) und die
REST-API ab. GitHub Actions führt bei jedem Push zusätzlich aus:

- die Go-Tests unter Linux und **auf einem Windows-Runner** – dort mit echten Ereignisprotokollen
  (Lesen, Meldungstexte, ein mit `eventcreate` geschriebenes Ereignis wird erfasst),
- `scripts/ci-windows-agent.ps1`: SIEM starten, Agent mit dem Einzeiler aus der Oberfläche in
  Windows PowerShell 5.1 installieren, Ereignis erzeugen und im SIEM wiederfinden, Dienst und
  Deinstallation prüfen,
- `scripts/ci-linux-agent.sh`: Docker-Image bauen, Linux-Agent per Einzeiler mit systemd
  installieren, Journal-Meldung, Container-Ausgabe und Docker-Ereignis wiederfinden.

## Aufbau des Codes

| Datei | Aufgabe |
|-------|---------|
| `siem/config.py` | Einstellungen aus Umgebungsvariablen (`SIEM_*`) |
| `siem/parsers.py` | Syslog (RFC 3164/5424), JSON, Windows, HEC → einheitliches Event; Feld-Extraktion |
| `siem/query.py` | Abfragesprache: Parser, Übersetzung nach SQL, Auswertung in Python |
| `siem/storage.py` | Tagesdateien (SQLite + FTS5), Suche, Histogramm, Statistik |
| `siem/pipeline.py` | Warteschlange und Verarbeitungs-Thread, Wartung (Aufbewahrung) |
| `siem/detection.py` | Erkennungs-Engine (Schwellen, Zeitfenster, Gruppierung, Zusammenfassen) |
| `siem/rules_default.py` | Mitgelieferte Regeln |
| `siem/receivers.py` | Syslog-Empfang UDP/TCP/TLS |
| `siem/db.py` | Haupt-Datenbank mit versionierten Migrationen |
| `siem/auth.py` | Passwörter (scrypt), Sitzungen, Tokens, Rollen |
| `siem/agents.py` | Agenten: Registrierung, zentrale Konfiguration, Auslieferung, Installationsskripte |
| `siem/agent_events.py` | Aufbereitung der Agent-Events (Journal, Windows, Docker, Dateien) |
| `siem/m365.py` | Microsoft-365-Connector: Token, Management Activity API, Graph, Abrufstand |
| `siem/m365_events.py` | Aufbereitung der Microsoft-365-Datensätze (deutsche Meldungen, Kategorien) |
| `siem/api/*.py` | REST-Endpunkte |
| `siem/cli.py` | `python -m siem [backup|passwort]` |
| `siem/static/` | Oberfläche: `index.html`, `app.css`, `js/app.js` und eine Datei pro Seite |
| `agent/` | Agent in Go: `agent.go` (Ablauf, Check-in, Update), `sender.go` (Stapel, Puffer), `collect_*.go` (Sammler), `platform_*.go` (Dienst unter systemd bzw. Windows) |

## Das Event-Schema

Jedes Event hat dieselben Felder: `ts` (Ereigniszeit), `received`, `input` (syslog/http/hec/agent/m365),
`source_ip` (Absender), `host`, `app`, `severity` (0–7 wie Syslog), `facility`, `category`,
`event_id`, `user`, `src_ip`, `dst_ip`, `dst_port`, `action`, `message`, `data` (alle weiteren
Felder als JSON) und `raw` (Originalzeile, falls abweichend).

Die Erkennung zählt Zeitfenster für `input:agent` und `input:m365` nach der Ereigniszeit (verspätete,
gesammelte Lieferung), für alle anderen Eingänge nach der Empfangszeit (Geräteuhren sind oft falsch).

## Agent: Ablauf und Schnittstelle

1. `POST /api/agent/enroll` mit Registrierungsschlüssel → eigenes Token (`agt_…`, nur als Hash gespeichert)
2. jede Minute `POST /api/agent/checkin` → Konfiguration, deren Version und ggf. ein Update-Angebot
   (Version, SHA-256, Download-Pfad); Statistik der Sammler geht in die andere Richtung
3. alle 2 Sekunden bzw. ab 500 Events `POST /api/agent/events` (gzip-JSON-Liste); Fehlschläge landen im
   Puffer auf der Platte

Ein Lock in `agent.lock` verhindert, dass zwei Agenten gleichzeitig laufen. Ein Update wird nach
Prüfung der SHA-256-Summe eingespielt; der Prozess beendet sich mit Code 3, systemd bzw. die
Wiederherstellungsoptionen des Windows-Dienstes starten ihn neu.

## Typische Erweiterungen

**Neues Log-Format erkennen** – In `siem/parsers.py` ein Muster zu `_PATTERNS` hinzufügen
(regulärer Ausdruck + welche Gruppe welches Feld füllt) und einen Test in `tests/test_parsers.py`
ergänzen.

**Neue mitgelieferte Regel** – Eintrag in `siem/rules_default.py` mit eindeutigem `key`. Beim
nächsten Start wird sie bei bestehenden Installationen automatisch ergänzt; vom Benutzer gelöschte
Regeln kommen nicht zurück. Ändert sich die Abfrage einer mitgelieferten Regel, den Schritt in
`RULE_UPGRADES` eintragen – übernommen wird er nur, wenn die Regel noch unverändert ist.

**Neuer Microsoft-365-Vorgang** – Bezeichnung, Kategorie, Aktion und Schweregrad in `OPERATIONS`
(`siem/m365_events.py`) ergänzen, Test in `tests/test_m365.py`.

**Datenbank-Schema ändern** – Neues SQL-Skript ans Ende von `MIGRATIONS` in `siem/db.py` anhängen,
niemals bestehende Einträge ändern. Für die Tagesdateien gilt: Spalten nur mit
`ALTER TABLE … ADD COLUMN` ergänzen, weil alte Dateien bis zum Ablauf der Aufbewahrung bestehen bleiben.

## Gestaltung der Oberfläche

- **Tokens** stehen am Anfang von `siem/static/app.css`: Farben (hell und dunkel), Schriftgrößen,
  4-px-Abstandsraster, Radien. Neue Komponenten verwenden nur diese Tokens, keine festen Werte.
- **Farbe ist knapp:** Petrol (`--accent`) für Bedienung, die vier `--sev-*`-Farben ausschließlich
  für Schweregrade – immer zusammen mit Text und dem Pegel-Symbol (1–4 Balken, `pegel()` in `ui.js`),
  damit Schweregrade auch ohne Farbsehen unterscheidbar sind.
- **Kontraste** sind auf WCAG 2.1 AA geprüft (Text ≥ 4,5:1, Bedienelemente und Grafik ≥ 3:1),
  die Diagrammfarben zusätzlich auf Unterscheidbarkeit bei Farbsehschwächen. Wer Farben ändert,
  sollte beides erneut prüfen.
- **Diagramme** (`timeChart`, `barList` in `ui.js`): schmale Säulen mit 2 px Abstand, durchgezogene
  Hilfslinien, Tooltip per Maus und Tastatur (Pfeiltasten), darunter immer eine Tabellenansicht.
- **Texte:** Begriffe einheitlich verwenden – Event, Alarm, Regel, Quelle, Sende-Token;
  Buttons nennen die Aktion („Alarm schließen“, nicht „OK“).

## Sicherheitsgrundsätze

- Logdaten stammen potenziell von Angreifern: Die Oberfläche setzt sie ausschließlich als Text ein
  (`textContent`), nie als HTML. Die Content-Security-Policy erlaubt nur eigene Skripte.
- In SQL werden nur feste Spaltennamen eingesetzt; alle Werte sind gebundene Parameter.
- Schreibende API-Aufrufe brauchen den Header `X-SIEM: 1` (Schutz vor CSRF) und ein
  `SameSite=Strict`-Cookie.
- Passwörter mit scrypt, Sitzungs-, Sende- und Agent-Tokens werden nur als SHA-256-Hash gespeichert.
- Der geheime Clientschlüssel für Microsoft 365 wird von der API nie zurückgegeben; Folge-URLs aus
  Microsoft-Antworten erhalten das Zugriffstoken nur, wenn sie auf den erwarteten Microsoft-Host zeigen.
- Agent-Updates werden nur nach erfolgreicher SHA-256-Prüfung installiert.
- Der Container läuft als unprivilegierter Benutzer (UID 1000).
