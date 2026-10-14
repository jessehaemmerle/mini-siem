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
- Passwörter mit scrypt, Sitzungs- und Sende-Tokens werden nur als SHA-256-Hash gespeichert.
- Der Container läuft als unprivilegierter Benutzer (UID 1000).
