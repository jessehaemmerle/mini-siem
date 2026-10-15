"""Einlesen und Normalisieren von Logs.

Jede Quelle (Syslog, HTTP/JSON, Splunk-HEC, Windows-Events, Docker) wird in
ein einheitliches Event übersetzt::

    ts, received, input, source_ip, host, app, severity, facility, category,
    event_id, user, src_ip, dst_ip, dst_port, action, message, data, raw

Zusätzlich werden aus bekannten Meldungen (sshd, sudo, Firewalls, ...) die
wichtigsten Felder wie Benutzer und IP-Adressen extrahiert.
"""

from __future__ import annotations

import calendar
import ipaddress
import json
import re
import time
from datetime import datetime, timezone
from typing import Any

from .query import SEVERITY_NAMES

EVENT_FIELDS = (
    "ts", "received", "input", "source_ip", "host", "app", "severity", "facility",
    "category", "event_id", "user", "src_ip", "dst_ip", "dst_port", "action",
    "message", "data", "raw",
)

MAX_FIELD_LEN = 512

_MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}


def new_event(input_name: str, source_ip: str | None, received: float | None = None) -> dict:
    ev = dict.fromkeys(EVENT_FIELDS)
    ev["received"] = received if received is not None else time.time()
    ev["input"] = input_name
    ev["source_ip"] = source_ip
    return ev


# ---------------------------------------------------------------------------
# Zeitstempel
# ---------------------------------------------------------------------------

_ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?"
)


def parse_iso(s: str) -> float | None:
    m = _ISO_RE.match(s.strip())
    if not m:
        return None
    try:
        y, mo, d, h, mi, se = (int(m.group(i)) for i in range(1, 7))
        frac = float(m.group(7)) if m.group(7) else 0.0
        tz = m.group(8)
        if tz and tz != "Z":
            sign = 1 if tz[0] == "+" else -1
            tz = tz[1:].replace(":", "")
            offset = sign * (int(tz[:2]) * 3600 + int(tz[2:4]) * 60)
        else:
            offset = 0
        if tz is None:
            # ohne Zeitzone: lokale Zeit des Containers (Variable TZ)
            base = time.mktime((y, mo, d, h, mi, se, 0, 0, -1))
            return base + frac
        return calendar.timegm((y, mo, d, h, mi, se, 0, 0, 0)) - offset + frac
    except (ValueError, OverflowError):
        return None


def parse_any_time(value: Any) -> float | None:
    """Zeit aus JSON: Epoch (s/ms/µs/ns), ISO-8601 oder ``/Date(..)/``."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, dict):
        # Windows: {"SystemTime": "..."}
        for k in ("SystemTime", "#text", "$date"):
            if k in value:
                return parse_any_time(value[k])
        return None
    if isinstance(value, (int, float)):
        v = float(value)
    else:
        s = str(value).strip()
        if not s:
            return None
        m = re.match(r"^/Date\((\d+)\)/$", s)
        if m:
            return int(m.group(1)) / 1000.0
        try:
            v = float(s)
        except ValueError:
            return parse_iso(s)
    if v > 1e17:
        v /= 1e9
    elif v > 1e14:
        v /= 1e6
    elif v > 1e11:
        v /= 1e3
    return v if v > 0 else None


def _bsd_time(mon: str, day: str, hms: str, year: str | None, now: float) -> float | None:
    month = _MONTHS.get(mon.lower()[:3])
    if not month:
        return None
    try:
        frac = 0.0
        if "." in hms:
            hms, f = hms.split(".", 1)
            frac = float("0." + f)
        h, mi, se = (int(x) for x in hms.split(":"))
        yr = int(year) if year else time.localtime(now).tm_year
        ts = time.mktime((yr, month, int(day), h, mi, se, 0, 0, -1)) + frac
        # Syslog nach RFC 3164 kennt kein Jahr: Jahreswechsel berücksichtigen
        if not year and ts > now + 86400 * 2:
            ts = time.mktime((yr - 1, month, int(day), h, mi, se, 0, 0, -1)) + frac
        return ts
    except (ValueError, OverflowError):
        return None


# ---------------------------------------------------------------------------
# Syslog
# ---------------------------------------------------------------------------

_PRI_RE = re.compile(r"^<(\d{1,3})>")
_5424_RE = re.compile(r"^1 (\S+) (\S+) (\S+) (\S+) (\S+) ")
_BSD_TS_RE = re.compile(
    r"^(?:\*|\.)?([A-Za-z]{3})\s+(\d{1,2})\s+(?:(\d{4})\s+)?(\d{2}:\d{2}:\d{2}(?:\.\d+)?)(?:\s+[A-Z]{2,5}\b)?:?\s*"
)
_ISO_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+")
_TAG_RE = re.compile(r"^([^\s\[\]:]{1,64})(?:\[([^\]\s]{1,32})\])?:(?:\s|$)")
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-:]{0,253}$")


def _nil(v: str) -> str | None:
    return None if v == "-" else v


def _parse_sd(s: str) -> tuple[dict, str]:
    """Structured Data nach RFC 5424 -> (dict, Rest)."""
    sd: dict = {}
    i = 0
    while i < len(s) and s[i] == "[":
        i += 1
        j = i
        while j < len(s) and s[j] not in " ]":
            j += 1
        sd_id = s[i:j]
        params: dict = {}
        i = j
        while i < len(s) and s[i] == " ":
            i += 1
            eq = s.find("=", i)
            if eq < 0:
                break
            name = s[i:eq]
            i = eq + 1
            if i >= len(s) or s[i] != '"':
                break
            i += 1
            val = []
            while i < len(s):
                c = s[i]
                if c == "\\" and i + 1 < len(s) and s[i + 1] in '"\\]':
                    val.append(s[i + 1])
                    i += 2
                    continue
                if c == '"':
                    i += 1
                    break
                val.append(c)
                i += 1
            params[name] = "".join(val)
        if i < len(s) and s[i] == "]":
            i += 1
        sd[sd_id] = params
    return sd, s[i:]


def parse_syslog(raw: str, source_ip: str | None, received: float | None = None,
                 input_name: str = "syslog") -> dict:
    ev = new_event(input_name, source_ip, received)
    now = ev["received"]
    line = raw.strip("\r\n\x00 ")
    ev["raw"] = line
    rest = line

    m = _PRI_RE.match(rest)
    if m:
        pri = int(m.group(1))
        if pri <= 191:
            ev["facility"], ev["severity"] = divmod(pri, 8)
        rest = rest[m.end():]

    m = _5424_RE.match(rest)
    if m:
        ts_s, host, app, procid, msgid = m.groups()
        ev["ts"] = parse_iso(ts_s) if ts_s != "-" else None
        ev["host"] = _nil(host)
        ev["app"] = _nil(app)
        data: dict = {}
        if _nil(procid):
            data["pid"] = procid
        if _nil(msgid):
            data["msgid"] = msgid
        rest = rest[m.end():]
        if rest.startswith("-"):
            rest = rest[1:]
        elif rest.startswith("["):
            sd, rest = _parse_sd(rest)
            if sd:
                data["sd"] = sd
        msg = rest.lstrip(" ")
        if msg.startswith("﻿"):
            msg = msg[1:]
        ev["message"] = msg
        ev["data"] = data or None
    else:
        # RFC 3164 und verbreitete Abwandlungen
        rest = re.sub(r"^\d+:\s+", "", rest)  # Cisco-Sequenznummer "123: "
        m = _BSD_TS_RE.match(rest)
        if m:
            ev["ts"] = _bsd_time(m.group(1), m.group(2), m.group(4), m.group(3), now)
            rest = rest[m.end():]
        else:
            m = _ISO_TS_RE.match(rest)
            if m:
                ev["ts"] = parse_iso(m.group(1))
                rest = rest[m.end():]
        # Hostname (fehlt bei manchen Geräten)
        parts = rest.split(" ", 1)
        if len(parts) == 2 and _HOST_RE.match(parts[0]) and not _TAG_RE.match(rest) \
                and not parts[0].endswith(":"):
            ev["host"] = parts[0]
            rest = parts[1]
        m = _TAG_RE.match(rest)
        if m:
            ev["app"] = m.group(1)
            if m.group(2):
                ev["data"] = {"pid": m.group(2)}
            rest = rest[m.end():]
        ev["message"] = rest.strip()

    msg = ev["message"] or ""
    stripped = msg.lstrip()
    if stripped.startswith("{") and stripped.rstrip().endswith("}"):
        try:
            obj = json.loads(stripped)
        except ValueError:
            obj = None
        if isinstance(obj, dict):
            apply_json(ev, obj)
    else:
        extract_kv(ev)
    enrich(ev)
    return finalize(ev)


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def get_path(obj: Any, path: str) -> Any:
    """Liest ``a.b.c`` aus verschachtelten oder flachen ("a.b") Schlüsseln."""
    if not isinstance(obj, dict):
        return None
    if path in obj:
        return obj[path]
    head, _, tail = path.partition(".")
    if tail and isinstance(obj.get(head), dict):
        return get_path(obj[head], tail)
    return None


def _first(obj: dict, keys) -> Any:
    for k in keys:
        v = get_path(obj, k)
        if v not in (None, "", [], {}):
            return v
    return None


TS_KEYS = ("@timestamp", "timestamp", "time", "date", "ts", "datetime", "EventTime",
           "TimeCreated", "event.created", "_time", "eventTime")
HOST_KEYS = ("host.name", "host.hostname", "hostname", "Hostname", "host", "Computer", "computer",
             "computer_name", "agent.hostname", "winlog.computer_name", "_HOSTNAME", "device")
APP_KEYS = ("app", "application", "program", "service.name", "service", "ProviderName",
            "SourceName", "winlog.provider_name", "container_name", "container.name", "tag",
            "logger", "logger_name", "SYSLOG_IDENTIFIER", "_COMM", "ident", "source_name")
MSG_KEYS = ("message", "msg", "Message", "log", "line", "short_message", "full_message",
            "MESSAGE", "text", "event.original")
SEV_KEYS = ("severity", "level", "Severity", "log.level", "loglevel", "levelname", "PRIORITY",
            "SeverityValue", "Level", "priority")
SRC_KEYS = ("src_ip", "source_ip", "srcip", "src", "client_ip", "clientip", "remote_addr",
            "remote_ip", "source.ip", "client.ip", "IpAddress", "SourceAddress", "ip")
DST_KEYS = ("dst_ip", "dest_ip", "destination_ip", "dstip", "dst", "destination.ip",
            "server.ip", "DestAddress")
DPORT_KEYS = ("dst_port", "dest_port", "dport", "dstport", "destination_port",
              "destination.port", "DestPort")
USER_KEYS = ("user", "username", "user_name", "user.name", "usr", "TargetUserName",
             "winlog.event_data.TargetUserName", "account", "login")
ACTION_KEYS = ("action", "event.action", "outcome", "event.outcome", "result")
CAT_KEYS = ("category", "event.category", "event.dataset", "type")
EID_KEYS = ("event_id", "EventID", "EventId", "eventId", "winlog.event_id", "event.code")


def _as_str(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, dict):
        for k in ("name", "#text", "value"):
            if k in v and not isinstance(v[k], (dict, list)):
                return str(v[k])
        return None
    if isinstance(v, list):
        return None
    return str(v)


def severity_from(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        iv = int(value)
        return iv if 0 <= iv <= 7 else None
    s = str(value).strip().lower()
    if s.isdigit():
        iv = int(s)
        return iv if 0 <= iv <= 7 else None
    if s in SEVERITY_NAMES:
        return SEVERITY_NAMES[s]
    if s in ("warn", "warning"):
        return 4
    if s in ("trace", "verbose"):
        return 7
    if s in ("audit_failure", "failure audit"):
        return 4
    if s in ("audit_success", "success audit"):
        return 6
    return None


def apply_json(ev: dict, obj: dict) -> None:
    """Überträgt Felder aus einem JSON-Objekt in das Event."""
    if is_windows_event(obj):
        apply_windows(ev, obj)
        return

    ts = parse_any_time(_first(obj, TS_KEYS))
    if ts:
        ev["ts"] = ts
    host = _as_str(_first(obj, HOST_KEYS))
    if host:
        ev["host"] = host
    app = _as_str(_first(obj, APP_KEYS))
    if app:
        ev["app"] = app.lstrip("/")
    sev = severity_from(_first(obj, SEV_KEYS))
    if sev is not None:
        ev["severity"] = sev
    for field, keys in (("src_ip", SRC_KEYS), ("dst_ip", DST_KEYS), ("user", USER_KEYS),
                        ("action", ACTION_KEYS), ("category", CAT_KEYS), ("event_id", EID_KEYS)):
        v = _as_str(_first(obj, keys))
        if v:
            ev[field] = v
    port = _first(obj, DPORT_KEYS)
    if port is not None:
        ev["dst_port"] = port

    msg = _first(obj, MSG_KEYS)
    if isinstance(msg, dict):
        # z. B. Docker-Splunk-Treiber im JSON-Format
        nested = dict(msg)
        apply_json(ev, nested)
        msg = None
    if msg is not None and not isinstance(msg, (dict, list)):
        ev["message"] = str(msg)
    elif not ev.get("message") or ev["message"].lstrip().startswith("{"):
        ev["message"] = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)[:4000]

    data = dict(ev.get("data") or {})
    data.update(obj)
    for k in MSG_KEYS:  # die Nachricht nicht doppelt speichern
        if k in data and data[k] == ev["message"]:
            del data[k]
    ev["data"] = data


def parse_json_event(obj: Any, source_ip: str | None, input_name: str = "http",
                     received: float | None = None) -> dict:
    ev = new_event(input_name, source_ip, received)
    if isinstance(obj, dict):
        apply_json(ev, obj)  # das Original steckt vollständig in "data"
    else:
        ev["raw"] = str(obj)
        ev["message"] = str(obj)
    enrich(ev)
    return finalize(ev)


def parse_text_line(line: str, source_ip: str | None, input_name: str = "http",
                    received: float | None = None) -> dict:
    """Eine Textzeile, die per HTTP geschickt wurde (evtl. selbst Syslog)."""
    if _PRI_RE.match(line) or _BSD_TS_RE.match(line):
        return parse_syslog(line, source_ip, received, input_name)
    ev = new_event(input_name, source_ip, received)
    ev["raw"] = line
    ev["message"] = line
    extract_kv(ev)
    enrich(ev)
    return finalize(ev)


def parse_hec_event(obj: dict, source_ip: str | None, received: float | None = None) -> dict:
    """Splunk-HEC-Format (u. a. Docker-Logging-Treiber ``splunk``)."""
    ev = new_event("hec", source_ip, received)
    event = obj.get("event")
    if isinstance(event, dict):
        line = event.get("line")
        if isinstance(line, dict):
            inner = dict(line)
            apply_json(ev, inner)
        elif isinstance(line, str) and line.lstrip().startswith("{"):
            try:
                inner = json.loads(line)
            except ValueError:
                inner = None
            if isinstance(inner, dict):
                apply_json(ev, inner)
            else:
                ev["message"] = line
        else:
            apply_json(ev, event)
        if event.get("tag"):
            ev["app"] = str(event["tag"]).lstrip("/")
        data = dict(ev.get("data") or {})
        for k in ("source", "tag", "attrs"):
            if k in event:
                data[k] = event[k]
        ev["data"] = data
    elif event is not None:
        text = str(event)
        if _PRI_RE.match(text):
            sub = parse_syslog(text, source_ip, received, "hec")
            ev.update({k: v for k, v in sub.items() if v is not None and k not in ("input", "raw")})
        else:
            ev["message"] = text
            extract_kv(ev)
    ts = parse_any_time(obj.get("time"))
    if ts:
        ev["ts"] = ts
    if obj.get("host"):
        ev["host"] = str(obj["host"])
    data = dict(ev.get("data") or {})
    for k in ("source", "sourcetype", "index"):
        if obj.get(k):
            data["hec_" + k] = obj[k]
    if isinstance(obj.get("fields"), dict):
        data.update(obj["fields"])
    ev["data"] = data or None
    enrich(ev)
    return finalize(ev)


# ---------------------------------------------------------------------------
# Windows-Ereignisse (NXLog, Fluent Bit winevtlog, Winlogbeat, PowerShell)
# ---------------------------------------------------------------------------

WINDOWS_EVENTS: dict[str, tuple[str, str, str | None]] = {
    # ID: (Beschreibung, Kategorie, Aktion)
    "4624": ("Anmeldung erfolgreich", "authentication", "success"),
    "4625": ("Anmeldung fehlgeschlagen", "authentication", "failure"),
    "4634": ("Abmeldung", "authentication", "logoff"),
    "4647": ("Abmeldung durch Benutzer", "authentication", "logoff"),
    "4648": ("Anmeldung mit expliziten Anmeldeinformationen", "authentication", "success"),
    "4672": ("Spezielle Berechtigungen bei Anmeldung zugewiesen", "privilege", "success"),
    "4688": ("Neuer Prozess erstellt", "process", "start"),
    "4697": ("Dienst installiert", "service", "created"),
    "4698": ("Geplanter Task erstellt", "persistence", "created"),
    "4719": ("Überwachungsrichtlinie geändert", "policy", "changed"),
    "4720": ("Benutzerkonto erstellt", "account", "created"),
    "4722": ("Benutzerkonto aktiviert", "account", "enabled"),
    "4723": ("Kennwortänderung versucht", "account", "changed"),
    "4724": ("Kennwort zurückgesetzt", "account", "changed"),
    "4725": ("Benutzerkonto deaktiviert", "account", "disabled"),
    "4726": ("Benutzerkonto gelöscht", "account", "deleted"),
    "4728": ("Mitglied zu globaler Sicherheitsgruppe hinzugefügt", "group", "added"),
    "4732": ("Mitglied zu lokaler Sicherheitsgruppe hinzugefügt", "group", "added"),
    "4756": ("Mitglied zu universeller Sicherheitsgruppe hinzugefügt", "group", "added"),
    "4740": ("Benutzerkonto gesperrt", "account", "locked"),
    "4767": ("Benutzerkonto entsperrt", "account", "unlocked"),
    "4771": ("Kerberos-Vorauthentifizierung fehlgeschlagen", "authentication", "failure"),
    "4776": ("NTLM-Anmeldeinformationen geprüft", "authentication", None),
    "1102": ("Sicherheitsprotokoll wurde gelöscht", "audit", "cleared"),
    "104": ("Ereignisprotokoll wurde gelöscht", "audit", "cleared"),
    "7045": ("Neuer Dienst installiert", "service", "created"),
    "4104": ("PowerShell-Skriptblock ausgeführt", "process", "start"),
}

# Position von Benutzer / IP in "StringInserts" (Fluent Bit winevtlog)
_INSERTS: dict[str, dict[str, int]] = {
    "4624": {"user": 5, "src_ip": 18, "logon_type": 8, "workstation": 11},
    "4625": {"user": 5, "src_ip": 19, "logon_type": 10, "workstation": 13},
    "4648": {"user": 5, "src_ip": 12},
    "4720": {"user": 0, "subject_user": 4},
    "4722": {"user": 0, "subject_user": 4},
    "4724": {"user": 0, "subject_user": 4},
    "4725": {"user": 0, "subject_user": 4},
    "4726": {"user": 0, "subject_user": 4},
    "4740": {"user": 0, "subject_user": 4},
    "4767": {"user": 0, "subject_user": 4},
    "4728": {"user": 0, "group": 2, "subject_user": 6},
    "4732": {"user": 0, "group": 2, "subject_user": 6},
    "4756": {"user": 0, "group": 2, "subject_user": 6},
    "4771": {"user": 0, "src_ip": 6},
    "4776": {"user": 1, "workstation": 2},
}


def is_windows_event(obj: dict) -> bool:
    if "winlog" in obj and isinstance(obj["winlog"], dict):
        return True
    keys = set(obj)
    return bool(keys & {"EventID", "EventId"}) and bool(
        keys & {"Channel", "ProviderName", "SourceName", "Computer", "Hostname", "StringInserts",
                "EventData", "Keywords", "EventType"})


def _win_val(obj: dict, name: str) -> Any:
    for path in (name, f"EventData.{name}", f"winlog.event_data.{name}", f"event_data.{name}"):
        v = get_path(obj, path)
        if v not in (None, "", "-"):
            return v
    return None


def apply_windows(ev: dict, obj: dict) -> None:
    eid = _first(obj, ("EventID", "EventId", "winlog.event_id", "event.code", "event_id"))
    eid_s = _as_str(eid)
    if eid_s:
        eid_s = eid_s.strip()
        ev["event_id"] = eid_s
    ev["host"] = _as_str(_first(obj, ("Computer", "Hostname", "winlog.computer_name",
                                      "host.name", "computer_name"))) or ev.get("host")
    ev["app"] = _as_str(_first(obj, ("ProviderName", "SourceName", "winlog.provider_name",
                                     "Channel", "winlog.channel"))) or ev.get("app")
    ts = parse_any_time(_first(obj, ("EventTime", "TimeCreated", "@timestamp", "TimeGenerated",
                                     "timestamp", "time", "date")))
    if ts:
        ev["ts"] = ts

    data: dict = {}
    inserts = obj.get("StringInserts")
    pos = _INSERTS.get(eid_s or "", {})
    for key, idx in pos.items():
        val = None
        if isinstance(inserts, list) and idx < len(inserts):
            val = inserts[idx]
        if val in (None, "", "-") and key in ("user", "src_ip", "workstation", "subject_user", "group",
                                              "logon_type"):
            name = {"user": "MemberName" if eid_s in ("4728", "4732", "4756") else "TargetUserName",
                    "src_ip": "IpAddress", "workstation": "WorkstationName",
                    "subject_user": "SubjectUserName", "group": "TargetUserName",
                    "logon_type": "LogonType"}[key]
            val = _win_val(obj, name)
        if val in (None, "", "-"):
            continue
        if key in ("user", "src_ip"):
            ev[key] = str(val)
        else:
            data[key] = val
    if not ev.get("user"):
        u = _win_val(obj, "TargetUserName")
        if u:
            ev["user"] = str(u)
    if not ev.get("src_ip"):
        ip = _win_val(obj, "IpAddress")
        if ip:
            ev["src_ip"] = str(ip)
    if ev.get("src_ip") and ev["src_ip"].startswith("::ffff:"):
        ev["src_ip"] = ev["src_ip"][7:]

    # Schweregrad
    level = _first(obj, ("Level", "winlog.level", "log.level"))
    sev = None
    if isinstance(level, (int, float)) or (isinstance(level, str) and level.isdigit()):
        sev = {0: 6, 1: 2, 2: 3, 3: 4, 4: 6, 5: 7}.get(int(level))
    elif level is not None:
        sev = severity_from(level)
    etype = str(_first(obj, ("EventType", "Keywords", "winlog.keywords")) or "").lower()
    if "failure" in etype or "fehler" in etype:
        sev = 4 if sev is None or sev > 4 else sev
        ev["action"] = "failure"
    if sev is None:
        sev = severity_from(_first(obj, ("Severity", "SeverityValue")))
    ev["severity"] = sev if sev is not None else 6

    info = WINDOWS_EVENTS.get(eid_s or "")
    if info:
        desc, cat, action = info
        ev["category"] = cat
        if action and not ev.get("action"):
            ev["action"] = action
        data["description"] = desc
    channel = _first(obj, ("Channel", "winlog.channel"))
    if channel:
        data["channel"] = channel

    msg = _first(obj, ("Message", "message", "winlog.message"))
    if msg:
        ev["message"] = str(msg)
    elif info:
        ev["message"] = f"{info[0]} (Ereignis {eid_s})"
    else:
        ev["message"] = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)[:4000]

    full = dict(obj)
    merge_keys(full, data, on_conflict="skip")  # z. B. „channel“ nicht neben dem Original „Channel“
    ev["data"] = full


def merge_keys(target: dict, extra: dict, on_conflict: str = "skip") -> dict:
    """Übernimmt Schlüssel, ohne dass zwei sich nur in Groß-/Kleinschreibung unterscheiden.

    Solches JSON ist zwar gültig, viele Programme (z. B. PowerShell) können es aber nicht
    lesen. Bei einem Konflikt wird der neue Wert übersprungen (``skip``) oder unter
    ``<Name>_data`` abgelegt (``rename``). Gleich geschriebene Schlüssel werden überschrieben.
    """
    lower = {k.lower(): k for k in target}
    for k, v in extra.items():
        existing = lower.get(k.lower())
        if existing is None or existing == k:
            target[k] = v
            lower[k.lower()] = k
        elif on_conflict == "rename":
            alt = f"{k}_data"
            while alt.lower() in lower:
                alt += "_"
            target[alt] = v
            lower[alt.lower()] = alt
    return target


# ---------------------------------------------------------------------------
# Feld-Extraktion aus Klartext-Meldungen
# ---------------------------------------------------------------------------

_KV_RE = re.compile(r'(?:(?<=\s)|^)([A-Za-z][\w.\-]{0,40})=("([^"]*)"|\'([^\']*)\'|[^\s,;]*)')

_KV_MAP = {
    "src_ip": ("src", "srcip", "src_ip", "source", "sip", "client", "rhost", "srcaddr", "remip"),
    "dst_ip": ("dst", "dstip", "dst_ip", "dip", "destination", "dstaddr", "locip"),
    "dst_port": ("dpt", "dport", "dstport", "dst_port", "destport", "dest_port", "dpt"),
    "user": ("user", "usr", "username", "suser", "duser", "user_name", "acct"),
    "action": ("action", "act", "disposition"),
}


def extract_kv(ev: dict) -> None:
    msg = ev.get("message") or ""
    if "=" not in msg:
        return
    pairs = {}
    for m in _KV_RE.finditer(msg):
        key = m.group(1)
        val = m.group(3) if m.group(3) is not None else m.group(4) if m.group(4) is not None else m.group(2)
        if key not in pairs:
            pairs[key] = val
        if len(pairs) >= 40:
            break
    if len(pairs) < 2:
        return
    lower = {k.lower(): v for k, v in pairs.items()}
    for field, keys in _KV_MAP.items():
        if ev.get(field):
            continue
        for k in keys:
            v = lower.get(k)
            if v:
                if field.endswith("_ip") and not _is_ip(v):
                    continue
                ev[field] = v
                break
    data = dict(ev.get("data") or {})
    for k, v in pairs.items():
        data.setdefault(k, v)
    ev["data"] = data


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


_PATTERNS: list[tuple[re.Pattern, dict]] = [
    (re.compile(r"Failed (?:password|publickey|none|keyboard-interactive(?:/pam)?) for (?:invalid user )?(\S+) from (\S+)(?: port (\d+))?"),
     {"groups": ("user", "src_ip", None), "category": "authentication", "action": "failure"}),
    (re.compile(r"Accepted (?:password|publickey|keyboard-interactive(?:/pam)?|gssapi-with-mic) for (\S+) from (\S+)(?: port (\d+))?"),
     {"groups": ("user", "src_ip", None), "category": "authentication", "action": "success"}),
    (re.compile(r"[Ii]nvalid user (\S*) from (\S+)"),
     {"groups": ("user", "src_ip"), "category": "authentication", "action": "failure"}),
    (re.compile(r"authentication failure;.*?rhost=(\S*)(?:\s+user=(\S+))?"),
     {"groups": ("src_ip", "user"), "category": "authentication", "action": "failure"}),
    (re.compile(r"maximum authentication attempts exceeded for (?:invalid user )?(\S+) from (\S+)"),
     {"groups": ("user", "src_ip"), "category": "authentication", "action": "failure"}),
    (re.compile(r"^\s*(\S+) : (?:\d+ )?incorrect password attempts?"),
     {"groups": ("user",), "category": "privilege", "action": "failure"}),
    (re.compile(r"^\s*(\S+) : .*COMMAND=(.*)$"),
     {"groups": ("user", "data.command"), "category": "privilege", "action": "success"}),
    (re.compile(r"new user: name=([^,\s]+)"),
     {"groups": ("user",), "category": "account", "action": "created"}),
    (re.compile(r"delete user '([^']+)'"),
     {"groups": ("user",), "category": "account", "action": "deleted"}),
    (re.compile(r"session opened for user (\S+?)(?:\(uid=\d+\))? by"),
     {"groups": ("user",), "category": "session", "action": "opened"}),
    (re.compile(r"\[UFW (BLOCK|ALLOW|AUDIT)\]"),
     {"groups": ("action_raw",), "category": "network"}),
    (re.compile(r"Out of memory: Killed process \d+ \(([^)]+)\)|oom-kill"),
     {"groups": ("data.process",), "category": "system", "action": "oom"}),
]

_FROM_IP_RE = re.compile(r"\bfrom\s+\[?(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,39})\]?")


def enrich(ev: dict) -> None:
    msg = ev.get("message") or ""
    if not msg:
        return
    for rx, spec in _PATTERNS:
        m = rx.search(msg)
        if not m:
            continue
        for name, value in zip(spec["groups"], m.groups()):
            if not name or not value:
                continue
            if name == "action_raw":
                if not ev.get("action"):
                    ev["action"] = value.lower()
                continue
            if name.startswith("data."):
                data = dict(ev.get("data") or {})
                data.setdefault(name[5:], value.strip())
                ev["data"] = data
                continue
            if name == "src_ip" and not _is_ip(value):
                continue
            if not ev.get(name):
                ev[name] = value
        if spec.get("category") and not ev.get("category"):
            ev["category"] = spec["category"]
        if spec.get("action") and not ev.get("action"):
            ev["action"] = spec["action"]
        break
    if not ev.get("src_ip"):
        m = _FROM_IP_RE.search(msg)
        if m and _is_ip(m.group(1)):
            ev["src_ip"] = m.group(1)


# ---------------------------------------------------------------------------
# Abschluss: Typen prüfen, kürzen, Zeit plausibilisieren
# ---------------------------------------------------------------------------


def _clip(v: Any, n: int = MAX_FIELD_LEN) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    return s[:n]


def finalize(ev: dict, max_message: int = 65_536) -> dict:
    received = ev["received"]
    ts = ev.get("ts")
    # Uhrzeit aus der Zukunft (falsche Uhr am Gerät) -> Empfangszeit verwenden
    if not isinstance(ts, (int, float)) or ts <= 0 or ts > received + 300:
        ts = received
    ev["ts"] = float(ts)
    for f in ("host", "app", "category", "event_id", "user", "src_ip", "dst_ip", "action",
              "source_ip", "input"):
        ev[f] = _clip(ev.get(f))
    if ev["host"]:
        ev["host"] = ev["host"].lower() if ev["host"].isascii() else ev["host"]
    if not ev["host"]:
        ev["host"] = ev.get("source_ip")
    for f in ("src_ip", "dst_ip"):
        if ev[f] and not _is_ip(ev[f]):
            ev[f] = None
    for f in ("severity", "facility", "dst_port"):
        v = ev.get(f)
        try:
            ev[f] = int(v) if v is not None and str(v).strip() != "" else None
        except (TypeError, ValueError):
            ev[f] = None
    if ev["severity"] is None:
        ev["severity"] = 6
    if not 0 <= ev["severity"] <= 7:
        ev["severity"] = 6
    if ev["dst_port"] is not None and not 0 <= ev["dst_port"] <= 65535:
        ev["dst_port"] = None
    if ev["action"]:
        ev["action"] = ev["action"].lower()
    msg = ev.get("message")
    ev["message"] = (str(msg) if msg is not None else "")[:max_message]
    raw = ev.get("raw")
    ev["raw"] = str(raw)[:max_message] if raw is not None else None
    if ev.get("raw") == ev["message"]:
        ev["raw"] = None  # spart Platz; die Nachricht ist bereits die Rohzeile
    ev.pop("_tokens", None)
    return ev


def utc_day(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")
