"""Erkennungs-Engine.

Eine Regel besteht aus

* ``query``     – eine Suchabfrage (gleiche Syntax wie in der Suche),
* ``threshold`` – ab wie vielen Treffern alarmiert wird (1 = jeder Treffer),
* ``window``    – Zeitfenster in Sekunden,
* ``group_by``  – optional: getrennt zählen je Wert dieses Feldes (z. B. src_ip),
* ``distinct_field`` – optional: verschiedene Werte statt Treffer zählen
  (z. B. verschiedene Ports pro Quell-IP = Portscan).

Weitere Treffer derselben Regel und Gruppe werden in den bestehenden, noch
offenen Alarm einsortiert, solange sie innerhalb des Zeitfensters auftreten.
So entsteht aus einem andauernden Angriff genau ein Alarm mit wachsender
Trefferzahl statt einer Alarmflut.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable

from . import query as q

log = logging.getLogger("siem.detection")

SEVERITIES = ("low", "medium", "high", "critical")
GROUP_FIELDS = tuple(f for f in q.FIELDS if f != "message")
MAX_SAMPLES = 20
MAX_KEYS_PER_RULE = 100_000

SAMPLE_FIELDS = ("ref", "ts", "host", "app", "severity", "user", "src_ip", "dst_ip", "dst_port",
                 "event_id", "action", "input")


def sample_of(ev: dict) -> dict:
    s = {k: ev.get(k) for k in SAMPLE_FIELDS if ev.get(k) is not None}
    s["message"] = (ev.get("message") or "")[:500]
    return s


def validate_rule(rule: dict) -> dict:
    """Prüft eine Regel (aus API/Datenbank) und gibt eine bereinigte Kopie zurück."""
    out = {}
    name = str(rule.get("name") or "").strip()
    if not name:
        raise ValueError("Bitte einen Namen angeben")
    out["name"] = name[:200]
    out["description"] = str(rule.get("description") or "")[:2000]
    query_s = str(rule.get("query") or "").strip()
    if not query_s:
        raise ValueError("Bitte eine Abfrage angeben")
    q.parse(query_s)  # wirft QueryError
    out["query"] = query_s
    sev = rule.get("severity") or "medium"
    if sev not in SEVERITIES:
        raise ValueError("Ungültiger Schweregrad")
    out["severity"] = sev
    try:
        out["threshold"] = max(1, min(1_000_000, int(rule.get("threshold") or 1)))
        out["window"] = max(10, min(7 * 86400, int(rule.get("window") or 300)))
    except (TypeError, ValueError):
        raise ValueError("Schwelle und Zeitfenster müssen Zahlen sein") from None
    for key in ("group_by", "distinct_field"):
        v = rule.get(key) or None
        if v is not None and v not in GROUP_FIELDS and not str(v).startswith("data."):
            raise ValueError(f"Unbekanntes Feld '{v}'")
        out[key] = v
    out["enabled"] = bool(rule.get("enabled", True))
    return out


@dataclass
class CompiledRule:
    id: int
    name: str
    severity: str
    threshold: int
    window: int
    group_by: str | None
    distinct_field: str | None
    matcher: Callable[[dict], bool]

    @classmethod
    def from_row(cls, row: dict) -> "CompiledRule":
        return cls(
            id=row["id"], name=row["name"], severity=row["severity"],
            threshold=int(row["threshold"]), window=int(row["window"]),
            group_by=row.get("group_by"), distinct_field=row.get("distinct_field"),
            matcher=q.compile_matcher(q.parse(row["query"])),
        )


@dataclass
class _GroupState:
    hits: deque = field(default_factory=deque)       # (zeit, distinct-wert)
    samples: deque = field(default_factory=lambda: deque(maxlen=MAX_SAMPLES))
    hosts: set = field(default_factory=set)
    active_until: float = float("-inf")  # nach dem Auslösen zählt jeder weitere Treffer sofort


@dataclass
class Firing:
    rule: CompiledRule
    group_value: str
    count: int
    first_seen: float
    last_seen: float
    samples: list
    hosts: set


def _value(ev: dict, fieldname: str | None):
    if not fieldname:
        return None
    if fieldname.startswith("data."):
        cur = ev.get("data")
        for part in fieldname[5:].split("."):
            if not isinstance(cur, dict):
                return None
            cur = cur.get(part)
        return cur
    return ev.get(fieldname)


class Detector:
    """Reine Logik ohne Datenbank – wird live und für Regeltests verwendet."""

    def __init__(self, rules: list[CompiledRule], clock_field: str = "received"):
        self.rules = rules
        self.clock_field = clock_field
        self.state: dict[tuple, _GroupState] = {}
        self._last_prune = 0.0

    def process(self, events: list[dict]) -> list[Firing]:
        firings: dict[tuple, Firing] = {}
        for ev in events:
            now = ev.get(self.clock_field)
            if now is None:
                now = ev.get("ts") if ev.get("ts") is not None else time.time()
            for rule in self.rules:
                try:
                    if not rule.matcher(ev):
                        continue
                except Exception:  # noqa: BLE001 - eine defekte Regel darf nichts blockieren
                    log.exception("Regel %s fehlerhaft", rule.name)
                    continue
                gv = _value(ev, rule.group_by)
                if rule.group_by and gv in (None, ""):
                    gv = "(unbekannt)"
                key = (rule.id, "" if gv is None else str(gv))
                st = self.state.get(key)
                if st is None:
                    if len(self.state) > MAX_KEYS_PER_RULE * max(1, len(self.rules)):
                        continue
                    st = self.state[key] = _GroupState()
                dv = _value(ev, rule.distinct_field) if rule.distinct_field else None
                if rule.distinct_field and dv in (None, ""):
                    continue
                if now <= st.active_until:
                    # Alarm läuft bereits: Treffer direkt hinzurechnen
                    st.active_until = now + rule.window
                    f = firings.get(key)
                    if f is None:
                        firings[key] = Firing(rule, key[1], 1, now, now, [sample_of(ev)],
                                              {ev["host"]} if ev.get("host") else set())
                    else:
                        f.count += 1
                        f.last_seen = now
                        f.samples = (f.samples + [sample_of(ev)])[-MAX_SAMPLES:]
                        if ev.get("host"):
                            f.hosts.add(ev["host"])
                    continue
                st.hits.append((now, dv))
                st.samples.append(sample_of(ev))
                if ev.get("host"):
                    st.hosts.add(ev["host"])
                limit = now - rule.window
                while st.hits and st.hits[0][0] < limit:
                    st.hits.popleft()
                if rule.distinct_field:
                    reached = len({d for _, d in st.hits}) >= rule.threshold
                else:
                    reached = len(st.hits) >= rule.threshold
                if not reached:
                    continue
                f = firings.get(key)
                if f is None:
                    firings[key] = Firing(rule, key[1], len(st.hits), st.hits[0][0], now,
                                          list(st.samples), set(st.hosts))
                else:
                    f.count += len(st.hits)
                    f.last_seen = now
                    f.samples = (f.samples + list(st.samples))[-MAX_SAMPLES:]
                    f.hosts |= st.hosts
                st.hits.clear()
                st.samples.clear()
                st.hosts = set()
                st.active_until = now + rule.window
            if now - self._last_prune > 60:
                self._prune(now)
        return list(firings.values())

    def _prune(self, now: float) -> None:
        self._last_prune = now
        windows = {r.id: r.window for r in self.rules}
        for key in list(self.state):
            st = self.state[key]
            w = windows.get(key[0])
            if w is None or (st.active_until < now and (not st.hits or st.hits[-1][0] < now - w)):
                del self.state[key]


class DetectionEngine:
    """Live-Erkennung: lädt Regeln aus der Datenbank und schreibt Alarme."""

    def __init__(self, db):
        self.db = db
        self._lock = threading.Lock()
        self._reload = True
        self.detector = Detector([])
        # (rule_id, gruppe) -> (alarm_id, letzte_aktualisierung)
        self.active: dict[tuple, tuple[int, float]] = {}
        self.alerts_created = 0
        self._restored = False

    def request_reload(self) -> None:
        self._reload = True

    def _load(self) -> None:
        rows = self.db.all("SELECT * FROM rules WHERE enabled = 1 ORDER BY id")
        rules = []
        for row in rows:
            try:
                rules.append(CompiledRule.from_row(row))
            except q.QueryError as exc:
                log.warning("Regel '%s' wird übersprungen: %s", row["name"], exc)
        old_state = self.detector.state
        self.detector = Detector(rules)
        ids = {r.id for r in rules}
        self.detector.state = {k: v for k, v in old_state.items() if k[0] in ids}
        self._reload = False
        if not self._restored:
            # offene Alarme nach einem Neustart weiterführen
            for row in self.db.all(
                "SELECT id, rule_id, group_value, last_seen FROM alerts "
                "WHERE status != 'closed' AND rule_id IS NOT NULL AND last_seen > ?",
                (time.time() - 7 * 86400,),
            ):
                self.active[(row["rule_id"], row["group_value"] or "")] = (row["id"], row["last_seen"])
            self._restored = True
        log.info("%d Erkennungsregel(n) aktiv", len(rules))

    def process(self, events: list[dict]) -> int:
        with self._lock:
            if self._reload:
                self._load()
            if not self.detector.rules:
                return 0
            firings = self.detector.process(events)
            for f in firings:
                self._store(f)
            return len(firings)

    def _store(self, f: Firing) -> None:
        key = (f.rule.id, f.group_value)
        now = time.time()
        active = self.active.get(key)
        with self.db.tx() as conn:
            if active and f.first_seen - active[1] <= f.rule.window:
                row = conn.execute(
                    "SELECT samples, hosts FROM alerts WHERE id = ? AND status != 'closed'",
                    (active[0],),
                ).fetchone()
                if row is not None:
                    samples = (json.loads(row["samples"]) + f.samples)[-MAX_SAMPLES:]
                    hosts = sorted(set(json.loads(row["hosts"] or "[]")) | f.hosts)[:20]
                    conn.execute(
                        "UPDATE alerts SET count = count + ?, last_seen = ?, samples = ?, hosts = ?, "
                        "updated = ? WHERE id = ?",
                        (f.count, f.last_seen, json.dumps(samples, default=str), json.dumps(hosts),
                         now, active[0]),
                    )
                    self.active[key] = (active[0], f.last_seen)
                    return
            cur = conn.execute(
                "INSERT INTO alerts(rule_id, rule_name, severity, group_value, count, first_seen, "
                "last_seen, status, hosts, samples, created, updated) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?)",
                (f.rule.id, f.rule.name, f.rule.severity, f.group_value or None, f.count,
                 f.first_seen, f.last_seen, json.dumps(sorted(f.hosts)[:20]),
                 json.dumps(f.samples, default=str), now, now),
            )
            self.active[key] = (cur.lastrowid, f.last_seen)
            self.alerts_created += 1
            log.info("Neuer Alarm #%s: %s [%s]", cur.lastrowid, f.rule.name, f.group_value or "-")
        if len(self.active) > 50_000:
            cutoff = now - 7 * 86400
            self.active = {k: v for k, v in self.active.items() if v[1] > cutoff}


def simulate(rule: dict, events) -> list[dict]:
    """Spielt eine Regel gegen historische Events ab (für "Regel testen")."""
    compiled = CompiledRule.from_row({"id": 0, **rule})
    det = Detector([compiled], clock_field="ts")
    current: dict[str, dict] = {}
    result: list[dict] = []
    for ev in events:
        for f in det.process([ev]):
            a = current.get(f.group_value)
            if a and f.first_seen - a["last_seen"] <= compiled.window:
                a["count"] += f.count
                a["last_seen"] = f.last_seen
                a["samples"] = (a["samples"] + f.samples)[-5:]
                continue
            a = {"group_value": f.group_value, "count": f.count, "first_seen": f.first_seen,
                 "last_seen": f.last_seen, "samples": f.samples[-5:]}
            current[f.group_value] = a
            result.append(a)
    return sorted(result, key=lambda a: -a["last_seen"])
