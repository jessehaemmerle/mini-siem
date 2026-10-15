"""Verarbeitungs-Pipeline: Warteschlange -> Parsen -> Speichern -> Erkennen.

Empfänger (Syslog, HTTP, Agenten, Microsoft-365-Connector) legen Rohdaten nur in die Warteschlange. Ein
einzelner Hintergrund-Thread parst sie in Stapeln, schreibt sie in die
Tagesdateien, wertet die Erkennungsregeln aus und pflegt die Quellenliste.
Damit bleibt die Weboberfläche auch unter Last reaktionsschnell.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from collections import defaultdict, deque

from . import parsers
from .agent_events import parse_agent_event
from .m365_events import parse_m365

log = logging.getLogger("siem.pipeline")

MAINTENANCE_INTERVAL = 3600


class Pipeline:
    def __init__(self, settings, db, store, engine):
        self.settings = settings
        self.db = db
        self.store = store
        self.engine = engine
        self.queue: queue.Queue = queue.Queue(maxsize=settings.queue_size)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.started = time.time()
        # Kennzahlen
        self.total = 0
        self.dropped_full = 0
        self.dropped_old = 0
        self.parse_errors = 0
        self._rate: deque = deque()
        self._last_maintenance = 0.0
        self._idle = True
        self.hooks: list = []          # werden höchstens alle 10 s im Pipeline-Thread aufgerufen
        self._last_hooks = 0.0
        self.token_usage: dict[int, int] = defaultdict(int)
        self._token_lock = threading.Lock()
        self.retention_days = int(db.get_setting("retention_days") or settings.default_retention_days)

    # ------------------------------------------------------------------ Eingang

    def submit(self, kind: str, payload, source_ip: str | None, received: float | None = None) -> bool:
        try:
            self.queue.put_nowait((kind, payload, source_ip, received or time.time()))
            return True
        except queue.Full:
            self.dropped_full += 1
            return False

    def has_capacity(self, n: int) -> bool:
        return self.queue.qsize() + n <= self.settings.queue_size

    def count_token(self, token_id: int, n: int) -> None:
        with self._token_lock:
            self.token_usage[token_id] += n

    # ------------------------------------------------------------------ Thread

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="siem-pipeline", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 10) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout)
        self.store.close()

    def _run(self) -> None:
        log.info("Pipeline gestartet")
        while not self._stop.is_set() or not self.queue.empty():
            batch = self._collect()
            if batch:
                try:
                    self.process(batch)
                except Exception:  # noqa: BLE001 - die Pipeline muss weiterlaufen
                    log.exception("Fehler bei der Verarbeitung von %d Events", len(batch))
            if time.time() - self._last_maintenance > MAINTENANCE_INTERVAL:
                self.maintenance()
            self._flush_tokens()
            if time.time() - self._last_hooks > 10:
                self._last_hooks = time.time()
                for hook in self.hooks:
                    try:
                        hook()
                    except Exception:  # noqa: BLE001
                        log.exception("Fehler in periodischer Aufgabe")
        for hook in self.hooks:
            try:
                hook()
            except Exception:  # noqa: BLE001
                log.exception("Fehler in periodischer Aufgabe")
        log.info("Pipeline beendet")

    def _collect(self) -> list:
        try:
            first = self.queue.get(timeout=0.5)
        except queue.Empty:
            return []
        batch = [first]
        deadline = time.monotonic() + 0.25
        while len(batch) < self.settings.batch_size and time.monotonic() < deadline:
            try:
                batch.append(self.queue.get(timeout=0.05))
            except queue.Empty:
                if self.queue.empty():
                    break
        return batch

    def drain(self, timeout: float = 5) -> None:
        """Wartet, bis die Warteschlange abgearbeitet ist (für Tests)."""
        end = time.time() + timeout
        while time.time() < end:
            if self.queue.empty() and getattr(self, "_idle", True):
                time.sleep(0.05)
                if self.queue.empty() and getattr(self, "_idle", True):
                    return
            time.sleep(0.02)

    # ------------------------------------------------------------------ Verarbeitung

    def parse(self, item) -> dict | None:
        kind, payload, source_ip, received = item
        try:
            if kind == "syslog":
                return parsers.parse_syslog(payload, source_ip, received)
            if kind == "json":
                return parsers.parse_json_event(payload, source_ip, "http", received)
            if kind == "text":
                return parsers.parse_text_line(payload, source_ip, "http", received)
            if kind == "hec":
                return parsers.parse_hec_event(payload, source_ip, received)
            if kind == "agent":
                obj, agent_host = payload
                return parse_agent_event(obj, agent_host, source_ip, received)
            if kind == "m365":
                sub, record = payload
                return parse_m365(sub, record, received)
            if kind == "event":
                return parsers.finalize(payload)
        except Exception:  # noqa: BLE001
            self.parse_errors += 1
            log.debug("Parserfehler", exc_info=True)
            ev = parsers.new_event(kind, source_ip, received)
            ev["message"] = str(payload)[:4000]
            return parsers.finalize(ev)
        return None

    def process(self, items: list) -> None:
        self._idle = False
        try:
            min_ts = time.time() - self.retention_days * 86400
            events = []
            for item in items:
                ev = self.parse(item)
                if ev is None:
                    continue
                if ev["ts"] < min_ts:
                    self.dropped_old += 1
                    continue
                events.append(ev)
            if not events:
                return
            self.store.write_batch(events)
            self.engine.process(events)
            self._update_sources(events)
            self.total += len(events)
            now = time.time()
            self._rate.append((now, len(events)))
            while self._rate and self._rate[0][0] < now - 60:
                self._rate.popleft()
        finally:
            self._idle = True

    def _update_sources(self, events: list[dict]) -> None:
        agg: dict[tuple, list] = {}
        for ev in events:
            key = (ev.get("host") or "?", ev.get("input") or "?")
            a = agg.get(key)
            if a is None:
                agg[key] = [1, ev["received"], ev.get("source_ip")]
            else:
                a[0] += 1
                a[1] = max(a[1], ev["received"])
                a[2] = ev.get("source_ip") or a[2]
        with self.db.tx() as conn:
            conn.executemany(
                "INSERT INTO sources(host, input, source_ip, first_seen, last_seen, events) "
                "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(host, input) DO UPDATE SET "
                "last_seen = MAX(last_seen, excluded.last_seen), events = events + excluded.events, "
                "source_ip = COALESCE(excluded.source_ip, source_ip)",
                [(h, i, ip, ts, ts, n) for (h, i), (n, ts, ip) in agg.items()],
            )

    @property
    def rate(self) -> float:
        now = time.time()
        n = sum(c for t, c in self._rate if t >= now - 60)
        return round(n / 60.0, 2)

    # ------------------------------------------------------------------ Wartung

    def _flush_tokens(self) -> None:
        if not self.token_usage:
            return
        with self._token_lock:
            usage, self.token_usage = dict(self.token_usage), defaultdict(int)
        now = time.time()
        with self.db.tx() as conn:
            conn.executemany(
                "UPDATE api_tokens SET events = events + ?, last_used = ? WHERE id = ?",
                [(n, now, tid) for tid, n in usage.items()],
            )

    def request_maintenance(self, retention_days: int | None = None) -> None:
        """Aufräumen beim nächsten Durchlauf des Pipeline-Threads."""
        if retention_days:
            self.retention_days = retention_days
        self._last_maintenance = 0.0

    def maintenance(self) -> None:
        self._last_maintenance = time.time()
        try:
            self.retention_days = int(self.db.get_setting("retention_days") or self.retention_days)
            self.store.delete_older_than(self.retention_days)
            now = time.time()
            alert_days = int(self.db.get_setting("alert_retention_days") or 365)
            with self.db.tx() as conn:
                conn.execute("DELETE FROM sessions WHERE expires < ?", (now,))
                conn.execute("DELETE FROM alerts WHERE status = 'closed' AND updated < ?",
                             (now - alert_days * 86400,))
                conn.execute("DELETE FROM audit_log WHERE ts < ?", (now - 400 * 86400,))
                conn.execute("DELETE FROM sources WHERE last_seen < ?",
                             (now - self.retention_days * 86400,))
        except Exception:  # noqa: BLE001
            log.exception("Fehler bei der Wartung")
