# Hinweise für Entwickler

## Lokal starten

```bash
pip install -r requirements-dev.txt
SIEM_DATA_DIR=./data SIEM_ADMIN_PASSWORD=ein-sicheres-passwort python -m siem
# Oberfläche: http://localhost:8080   Syslog: Port 1514   API-Doku: http://localhost:8080/api/docs
python3 scripts/demo_logs.py --port 1514
```

## Tests

```bash
python -m pytest
```

Die Tests decken Abfragesprache (SQL und Python liefern dieselben Treffer), Parser, Erkennung und die
REST-API ab. GitHub Actions führt sie bei jedem Push aus und baut das Docker-Image.

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
| `siem/api/*.py` | REST-Endpunkte |
| `siem/cli.py` | `python -m siem [backup|passwort]` |
| `siem/static/` | Oberfläche: `index.html`, `app.css`, `js/app.js` und eine Datei pro Seite |

## Das Event-Schema

Jedes Event hat dieselben Felder: `ts` (Ereigniszeit), `received`, `input` (syslog/http/hec),
`source_ip` (Absender), `host`, `app`, `severity` (0–7 wie Syslog), `facility`, `category`,
`event_id`, `user`, `src_ip`, `dst_ip`, `dst_port`, `action`, `message`, `data` (alle weiteren
Felder als JSON) und `raw` (Originalzeile, falls abweichend).

## Typische Erweiterungen

**Neues Log-Format erkennen** – In `siem/parsers.py` ein Muster zu `_PATTERNS` hinzufügen
(regulärer Ausdruck + welche Gruppe welches Feld füllt) und einen Test in `tests/test_parsers.py`
ergänzen.

**Neue mitgelieferte Regel** – Eintrag in `siem/rules_default.py` mit eindeutigem `key`. Beim
nächsten Start wird sie bei bestehenden Installationen automatisch ergänzt; vom Benutzer gelöschte
Regeln kommen nicht zurück.

**Datenbank-Schema ändern** – Neues SQL-Skript ans Ende von `MIGRATIONS` in `siem/db.py` anhängen,
niemals bestehende Einträge ändern. Für die Tagesdateien gilt: Spalten nur mit
`ALTER TABLE … ADD COLUMN` ergänzen, weil alte Dateien bis zum Ablauf der Aufbewahrung bestehen bleiben.

## Sicherheitsgrundsätze

- Logdaten stammen potenziell von Angreifern: Die Oberfläche setzt sie ausschließlich als Text ein
  (`textContent`), nie als HTML. Die Content-Security-Policy erlaubt nur eigene Skripte.
- In SQL werden nur feste Spaltennamen eingesetzt; alle Werte sind gebundene Parameter.
- Schreibende API-Aufrufe brauchen den Header `X-SIEM: 1` (Schutz vor CSRF) und ein
  `SameSite=Strict`-Cookie.
- Passwörter mit scrypt, Sitzungs- und Ingest-Tokens werden nur als SHA-256-Hash gespeichert.
- Der Container läuft als unprivilegierter Benutzer (UID 1000).
