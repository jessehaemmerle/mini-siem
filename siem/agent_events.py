"""Aufbereitung der Events, die der Mini-SIEM-Agent schickt.

Der Agent sendet kompakte JSON-Objekte; ``src`` gibt die Herkunft an:

* ``journald`` – Linux-Journal (``msg``, ``prio``, ``ident``, ``unit``, ``pid`` …)
* ``winlog``   – Windows-Ereignisprotokoll (``channel``, ``provider``, ``event_id``,
  ``level``, ``keywords``, ``record_id``, ``computer``, ``data`` = EventData, ``msg``)
* ``docker``   – Container-Ausgabe (``kind=log``) oder Docker-Ereignis (``kind=event``)
* ``file``     – Zeile aus einer Logdatei (``path``, ``msg``)

Als Host wird immer der Name des Agenten eingetragen, damit ein Rechner in
der Quellenliste genau einmal erscheint.
"""

from __future__ import annotations

import json
import posixpath

from . import parsers

DOCKER_ACTIONS = {
    "create": ("Container erstellt", 6),
    "start": ("Container gestartet", 6),
    "restart": ("Container neu gestartet", 5),
    "stop": ("Container gestoppt", 6),
    "kill": ("Container beendet (kill)", 5),
    "die": ("Container beendet", 6),
    "oom": ("Container wegen Speichermangel beendet", 3),
    "destroy": ("Container gelöscht", 6),
    "pause": ("Container angehalten", 6),
    "unpause": ("Container fortgesetzt", 6),
    "exec_create": ("Befehl im Container vorbereitet", 6),
    "exec_start": ("Befehl im Container ausgeführt", 5),
    "exec_die": ("Befehl im Container beendet", 7),
    "health_status": ("Healthcheck", 6),
    "rename": ("Container umbenannt", 6),
    "update": ("Container-Einstellungen geändert", 5),
    "attach": ("Mit Container verbunden", 6),
    "copy": ("Dateien in/aus Container kopiert", 5),
}


def _base(input_host: str, source_ip: str | None, received: float | None) -> dict:
    ev = parsers.new_event("agent", source_ip, received)
    ev["host"] = input_host
    return ev


def _num(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _journald(ev: dict, obj: dict) -> None:
    ev["ts"] = parsers.parse_any_time(obj.get("t"))
    ev["app"] = obj.get("ident") or obj.get("comm") or (obj.get("unit") or "").removesuffix(".service") or None
    prio = _num(obj.get("prio"))
    ev["severity"] = prio if prio is not None and 0 <= prio <= 7 else 6
    ev["facility"] = _num(obj.get("facility"))
    msg = obj.get("msg")
    if isinstance(msg, list):  # journald liefert Binärdaten als Zahlenliste
        try:
            msg = bytes(msg).decode("utf-8", errors="replace")
        except (TypeError, ValueError):
            msg = str(msg)
    ev["message"] = "" if msg is None else str(msg)
    data = {k: obj[k] for k in ("unit", "pid", "transport", "comm", "exe", "uid", "boot") if obj.get(k) not in (None, "")}
    data["src"] = "journald"
    ev["data"] = data
    stripped = ev["message"].lstrip()
    if stripped.startswith("{") and stripped.rstrip().endswith("}"):
        try:
            inner = json.loads(stripped)
        except ValueError:
            inner = None
        if isinstance(inner, dict):
            app = ev["app"]
            parsers.apply_json(ev, inner)
            ev["app"] = app or ev.get("app")
            return
    parsers.extract_kv(ev)


def _winlog(ev: dict, obj: dict, agent_host: str) -> None:
    win = {
        "EventID": obj.get("event_id"),
        "Channel": obj.get("channel"),
        "ProviderName": obj.get("provider"),
        "Computer": obj.get("computer"),
        "Level": obj.get("level"),
        "Keywords": obj.get("keywords") or "",
        "EventRecordID": obj.get("record_id"),
        "TimeCreated": obj.get("t"),
        "EventData": obj.get("data") if isinstance(obj.get("data"), dict) else {},
    }
    if obj.get("task"):
        win["Task"] = obj["task"]
    if obj.get("msg"):
        win["Message"] = obj["msg"]
    parsers.apply_windows(ev, win)
    ev["host"] = agent_host
    # Eigene, schlanke Struktur statt der Rohform: Metadaten klein geschrieben, EventData flach,
    # keine doppelten Schlüssel (siehe parsers.merge_keys)
    derived = {k: v for k, v in (ev.get("data") or {}).items() if k not in win}
    data = {"src": "winlog"}
    for key, value in (("channel", obj.get("channel")), ("provider", obj.get("provider")),
                       ("record_id", obj.get("record_id")), ("keywords", obj.get("keywords")),
                       ("task", obj.get("task"))):
        if value not in (None, ""):
            data[key] = value
    parsers.merge_keys(data, derived, on_conflict="skip")
    parsers.merge_keys(data, win["EventData"], on_conflict="rename")
    ev["data"] = data


def _docker(ev: dict, obj: dict) -> None:
    ev["ts"] = parsers.parse_any_time(obj.get("t"))
    container = str(obj.get("container") or "").lstrip("/") or None
    data = {k: obj[k] for k in ("container_id", "image", "stream", "exit_code", "privileged", "docker_socket",
                                 "network_host", "pid_host", "cap_add", "exec_cmd", "exec_user", "health",
                                 "compose_project", "compose_service") if obj.get(k) not in (None, "")}
    data["src"] = "docker"
    if container:
        data["container"] = container
    ev["category"] = "container"
    if obj.get("kind") == "event":
        action = str(obj.get("action") or "").split(":", 1)[0].strip()
        label, sev = DOCKER_ACTIONS.get(action, (f"Docker-Ereignis {action}", 6))
        parts = [f"{label}: {container or obj.get('container_id', '?')}"]
        if obj.get("image"):
            parts.append(f"(Image {obj['image']})")
        if action == "die" and obj.get("exit_code") not in (None, "", "0", 0):
            parts.append(f"mit Exit-Code {obj['exit_code']}")
            sev = 4
        if action == "health_status" and obj.get("health"):
            parts.append(f"→ {obj['health']}")
            if obj["health"] == "unhealthy":
                sev = 4
        if obj.get("exec_cmd"):
            parts.append(f"– {obj['exec_cmd']}")
        if action == "start" and (obj.get("privileged") or obj.get("docker_socket")):
            parts.append("– privilegiert" if obj.get("privileged") else "– mit Zugriff auf den Docker-Socket")
            sev = 4
        ev["message"] = " ".join(parts)
        ev["action"] = action
        ev["event_id"] = "docker." + action if action else None
        ev["severity"] = sev
        ev["app"] = "docker"
        ev["user"] = obj.get("exec_user") or None
        ev["data"] = data
        return
    # Ausgabe eines Containers
    ev["app"] = container or "docker"
    ev["message"] = str(obj.get("msg") or "")
    ev["severity"] = 6
    ev["data"] = data
    stripped = ev["message"].lstrip()
    if stripped.startswith("{") and stripped.rstrip().endswith("}"):
        try:
            inner = json.loads(stripped)
        except ValueError:
            inner = None
        if isinstance(inner, dict):
            parsers.apply_json(ev, inner)
            ev["app"] = container or ev.get("app")
            ev["category"] = ev.get("category") or "container"
            return
    if parsers._PRI_RE.match(stripped) or parsers._BSD_TS_RE.match(stripped):  # noqa: SLF001
        sub = parsers.parse_syslog(stripped, ev.get("source_ip"), ev["received"], "agent")
        for k in ("severity", "facility", "user", "src_ip", "dst_ip", "dst_port", "action", "message"):
            if sub.get(k) is not None:
                ev[k] = sub[k]
        return
    parsers.extract_kv(ev)


def _file(ev: dict, obj: dict) -> None:
    path = str(obj.get("path") or "")
    line = str(obj.get("msg") or "")
    sub = parsers.parse_text_line(line, ev.get("source_ip"), "agent", ev["received"])
    for k in parsers.EVENT_FIELDS:
        if k in ("host", "input", "source_ip", "received"):
            continue
        if sub.get(k) is not None:
            ev[k] = sub[k]
    if obj.get("t") and ev.get("ts") in (None, ev["received"]):
        ev["ts"] = parsers.parse_any_time(obj.get("t"))
    if not ev.get("app"):
        ev["app"] = posixpath.basename(path.replace("\\", "/")) or None
    data = dict(ev.get("data") or {})
    data["src"] = "file"
    data["path"] = path
    ev["data"] = data


def parse_agent_event(obj: dict, agent_host: str, source_ip: str | None, received: float | None = None) -> dict:
    ev = _base(agent_host, source_ip, received)
    src = obj.get("src") if isinstance(obj, dict) else None
    if src == "journald":
        _journald(ev, obj)
    elif src == "winlog":
        _winlog(ev, obj, agent_host)
    elif src == "docker":
        _docker(ev, obj)
    elif src == "file":
        _file(ev, obj)
    else:
        ev["message"] = json.dumps(obj, ensure_ascii=False, default=str)[:4000] if not isinstance(obj, str) else obj
        ev["data"] = {"src": str(src or "unbekannt")}
    parsers.enrich(ev)
    ev["host"] = agent_host
    return parsers.finalize(ev)
