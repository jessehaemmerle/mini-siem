"""Speicherung der Events: eine SQLite-Datei pro Tag (UTC).

* ``data/events/2026-10-14.db`` enthält alle Events dieses Tages
  (nach Ereigniszeit), einen Volltextindex (FTS5) und eine kleine
  Statistik-Tabelle pro Minute für schnelle Dashboards.
* Aufbewahrung = alte Tagesdateien löschen. Backup = Ordner kopieren.
* Geschrieben wird nur von einem einzigen Thread (siehe ``pipeline.py``),
  gelesen wird parallel (WAL-Modus).

Sicherheit: In SQL-Texte werden ausschließlich feste Spaltennamen aus
``query.FIELDS`` und die vom Abfrage-Compiler erzeugten Bedingungen
eingesetzt. Alle Werte aus Benutzereingaben werden als Parameter gebunden.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import threading
import time
from collections import OrderedDict, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import query as q
from .parsers import utc_day

log = logging.getLogger("siem.storage")

COLUMNS = (
    "ts", "received", "input", "source_ip", "host", "app", "severity", "facility", "category",
    "event_id", "user", "src_ip", "dst_ip", "dst_port", "action", "message", "data", "raw",
)
_DATA_IDX = COLUMNS.index("data")
_INSERT_SQL = "INSERT INTO events (" + ",".join(COLUMNS) + ") VALUES (" + ",".join("?" * len(COLUMNS)) + ")"

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    received REAL NOT NULL,
    input TEXT, source_ip TEXT, host TEXT, app TEXT,
    severity INTEGER, facility INTEGER, category TEXT, event_id TEXT,
    user TEXT, src_ip TEXT, dst_ip TEXT, dst_port INTEGER, action TEXT,
    message TEXT, data TEXT, raw TEXT
);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_events_host ON events(host COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS ix_events_app ON events(app COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS ix_events_src ON events(src_ip COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS ix_events_user ON events(user COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS ix_events_eid ON events(event_id COLLATE NOCASE);
CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
    message, content='events', content_rowid='id',
    tokenize='unicode61 remove_diacritics 2'
);
CREATE TABLE IF NOT EXISTS stats (
    minute INTEGER NOT NULL, host TEXT NOT NULL, severity INTEGER NOT NULL, input TEXT NOT NULL,
    n INTEGER NOT NULL,
    PRIMARY KEY (minute, host, severity, input)
) WITHOUT ROWID;
"""

_DAY_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})\.db$")

TOP_FIELDS = tuple(f for f in q.FIELDS if f != "message")


class QueryTimeout(Exception):
    pass


def _connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), timeout=30, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=30000")
    q.register_functions(conn)
    return conn


def _days_between(t_from: float, t_to: float) -> list[str]:
    start = datetime.fromtimestamp(t_from, tz=timezone.utc).date()
    end = datetime.fromtimestamp(max(t_from, t_to), tz=timezone.utc).date()
    out = []
    d = start
    while d <= end:
        out.append(d.isoformat())
        d += timedelta(days=1)
    return out


def _row_to_event(day: str, row: sqlite3.Row) -> dict:
    ev = dict(row)
    ev["ref"] = day + ":" + str(ev.pop("id"))
    if ev.get("data"):
        try:
            ev["data"] = json.loads(ev["data"])
        except ValueError:
            pass
    return ev


class EventStore:
    def __init__(self, events_dir: Path, query_timeout: int = 30):
        self.dir = Path(events_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.query_timeout = query_timeout
        self._writers: OrderedDict[str, sqlite3.Connection] = OrderedDict()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ Dateien

    def path(self, day: str) -> Path:
        return self.dir / (day + ".db")

    def days(self) -> list[str]:
        out = []
        for name in os.listdir(self.dir):
            m = _DAY_RE.match(name)
            if m:
                out.append(m.group(1))
        return sorted(out)

    def partitions(self) -> list[dict]:
        out = []
        for day in self.days():
            size = 0
            for suffix in ("", "-wal", "-shm"):
                p = Path(str(self.path(day)) + suffix)
                if p.exists():
                    size += p.stat().st_size
            out.append({"day": day, "bytes": size})
        return out

    def total_bytes(self) -> int:
        return sum(p["bytes"] for p in self.partitions())

    # ------------------------------------------------------------------ Schreiben

    def _writer(self, day: str) -> sqlite3.Connection:
        conn = self._writers.get(day)
        if conn is not None:
            self._writers.move_to_end(day)
            return conn
        conn = _connect(self.path(day))
        conn.executescript(SCHEMA)
        self._writers[day] = conn
        while len(self._writers) > 4:
            _, old = self._writers.popitem(last=False)
            old.close()
        return conn

    def write_batch(self, events: list[dict]) -> None:
        by_day: dict[str, list[dict]] = defaultdict(list)
        for ev in events:
            by_day[utc_day(ev["ts"])].append(ev)
        with self._lock:
            for day, evs in by_day.items():
                conn = self._writer(day)
                stats: dict[tuple, int] = defaultdict(int)
                with conn:
                    cur = conn.cursor()
                    for ev in evs:
                        data = ev.get("data")
                        row = [ev.get(c) for c in COLUMNS]
                        row[_DATA_IDX] = (
                            json.dumps(data, ensure_ascii=False, default=str, separators=(",", ":"))
                            if data else None
                        )
                        cur.execute(_INSERT_SQL, row)
                        rowid = cur.lastrowid
                        cur.execute("INSERT INTO events_fts(rowid, message) VALUES (?, ?)",
                                    (rowid, ev.get("message") or ""))
                        ev["ref"] = day + ":" + str(rowid)
                        key = (int(ev["ts"] // 60), ev.get("host") or "", ev.get("severity") or 0,
                               ev.get("input") or "")
                        stats[key] += 1
                    cur.executemany(
                        "INSERT INTO stats(minute, host, severity, input, n) VALUES (?,?,?,?,?) "
                        "ON CONFLICT(minute, host, severity, input) DO UPDATE SET n = n + excluded.n",
                        [(*k, n) for k, n in stats.items()],
                    )

    def close(self) -> None:
        with self._lock:
            for conn in self._writers.values():
                conn.close()
            self._writers.clear()

    # ------------------------------------------------------------------ Aufbewahrung

    def delete_older_than(self, days: int) -> list[str]:
        cutoff = (datetime.now(timezone.utc).date() - timedelta(days=days)).isoformat()
        removed = []
        with self._lock:
            for day in self.days():
                if day >= cutoff:
                    continue
                conn = self._writers.pop(day, None)
                if conn:
                    conn.close()
                for suffix in ("", "-wal", "-shm"):
                    p = Path(str(self.path(day)) + suffix)
                    try:
                        p.unlink()
                    except FileNotFoundError:
                        pass
                removed.append(day)
        if removed:
            log.info("Aufbewahrung: %d Tagesdatei(en) gelöscht (%s)", len(removed), ", ".join(removed))
        return removed

    # ------------------------------------------------------------------ Lesen

    def _reader(self, day: str, deadline: float | None) -> sqlite3.Connection | None:
        path = self.path(day)
        if not path.exists():
            return None
        conn = sqlite3.connect(str(path), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=1")
        q.register_functions(conn)
        if deadline is not None:
            conn.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 20_000)
        return conn

    def _deadline(self) -> float:
        return time.monotonic() + self.query_timeout

    def _query(self, day: str, deadline: float, sql: str, params) -> list:
        conn = self._reader(day, deadline)
        if conn is None:
            return []
        try:
            return conn.execute(sql, params).fetchall()
        except sqlite3.OperationalError as exc:
            if "interrupted" in str(exc):
                raise QueryTimeout() from None
            if "no such table" in str(exc):
                return []
            raise
        finally:
            conn.close()

    def _existing_days(self, t_from: float, t_to: float) -> list[str]:
        wanted = set(_days_between(t_from, t_to))
        return [d for d in self.days() if d in wanted]

    def search(self, node, t_from: float, t_to: float, limit: int = 100,
               cursor: str | None = None) -> tuple[list[dict], str | None]:
        """Neueste Events zuerst. ``cursor`` setzt eine vorherige Seite fort."""
        where, params = q.to_sql(node)
        cur_ts = cur_day = None
        cur_id = 0
        if cursor:
            try:
                ts_s, cur_day, id_s = cursor.split("|")
                cur_ts, cur_id = float(ts_s), int(id_s)
            except ValueError:
                cursor = None
        deadline = self._deadline()
        results: list[dict] = []
        for day in reversed(self._existing_days(t_from, t_to)):
            if cursor and day > cur_day:
                continue
            sql = "SELECT * FROM events e WHERE e.ts >= ? AND e.ts < ? AND " + where
            p: list = [t_from, t_to, *params]
            if cursor and day == cur_day:
                sql += " AND (e.ts < ? OR (e.ts = ? AND e.id < ?))"
                p += [cur_ts, cur_ts, cur_id]
            sql += " ORDER BY e.ts DESC, e.id DESC LIMIT ?"
            p.append(limit - len(results) + 1)
            for r in self._query(day, deadline, sql, p):
                results.append(_row_to_event(day, r))
            if len(results) > limit:
                break
        next_cursor = None
        if len(results) > limit:
            results = results[:limit]
            last = results[-1]
            day, rid = last["ref"].split(":")
            next_cursor = "|".join((repr(last["ts"]), day, rid))
        return results, next_cursor

    def iter_matching(self, node, t_from: float, t_to: float, max_events: int = 50_000):
        """Alle passenden Events in zeitlicher Reihenfolge (für Regeltests)."""
        where, params = q.to_sql(node)
        deadline = self._deadline()
        count = 0
        sql = ("SELECT * FROM events e WHERE e.ts >= ? AND e.ts < ? AND " + where
               + " ORDER BY e.ts, e.id LIMIT ?")
        for day in self._existing_days(t_from, t_to):
            for r in self._query(day, deadline, sql, [t_from, t_to, *params, max_events - count]):
                yield _row_to_event(day, r)
                count += 1
            if count >= max_events:
                return

    @staticmethod
    def bucket_size(t_from: float, t_to: float, target: int = 60) -> int:
        span = max(60.0, t_to - t_from)
        for size in (60, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400):
            if span / size <= target:
                return size
        return 86400 * 7

    def histogram(self, node, t_from: float, t_to: float) -> dict:
        size = self.bucket_size(t_from, t_to)
        start = int(t_from // size * size)
        n_buckets = int((t_to - start) // size) + 1
        counts = [0] * n_buckets
        deadline = self._deadline()
        if node is None:
            # schneller Weg über die Minuten-Statistik
            sql = ("SELECT (minute * 60 - ?) / ? AS b, SUM(n) FROM stats "
                   "WHERE minute >= ? AND minute < ? GROUP BY b")
            params = [start, size, int(t_from // 60), int(-(-t_to // 60))]
        else:
            where, wparams = q.to_sql(node)
            sql = ("SELECT CAST((e.ts - ?) / ? AS INTEGER) AS b, COUNT(*) FROM events e "
                   "WHERE e.ts >= ? AND e.ts < ? AND " + where + " GROUP BY b")
            params = [start, size, t_from, t_to, *wparams]
        for day in self._existing_days(t_from, t_to):
            for b, n in self._query(day, deadline, sql, params):
                if 0 <= b < n_buckets:
                    counts[int(b)] += n
        return {"bucket": size, "start": start, "counts": counts, "total": sum(counts)}

    def top_values(self, node, field: str, t_from: float, t_to: float, limit: int = 10) -> list[dict]:
        if field not in TOP_FIELDS:
            raise q.QueryError("Feld '" + field + "' kann nicht ausgewertet werden")
        where, params = q.to_sql(node)
        deadline = self._deadline()
        col = "e." + field  # aus der festen Liste TOP_FIELDS
        sql = ("SELECT " + col + " AS v, COUNT(*) FROM events e WHERE e.ts >= ? AND e.ts < ? AND "
               + where + " AND " + col + " IS NOT NULL GROUP BY v ORDER BY 2 DESC LIMIT 200")
        totals: dict = defaultdict(int)
        for day in self._existing_days(t_from, t_to):
            for v, n in self._query(day, deadline, sql, [t_from, t_to, *params]):
                totals[v] += n
        top = sorted(totals.items(), key=lambda kv: -kv[1])[:limit]
        return [{"value": v, "count": n} for v, n in top]

    def stats_overview(self, t_from: float, t_to: float) -> dict:
        """Kennzahlen für das Dashboard aus der Minuten-Statistik."""
        size = self.bucket_size(t_from, t_to, target=48)
        start = int(t_from // size * size)
        n_buckets = int((t_to - start) // size) + 1
        series = [0] * n_buckets
        series_err = [0] * n_buckets
        by_sev: dict[int, int] = defaultdict(int)
        by_host: dict[str, int] = defaultdict(int)
        by_input: dict[str, int] = defaultdict(int)
        deadline = self._deadline()
        sql = ("SELECT (minute * 60 - ?) / ? AS b, host, severity, input, SUM(n) FROM stats "
               "WHERE minute >= ? AND minute < ? GROUP BY b, host, severity, input")
        params = [start, size, int(t_from // 60), int(-(-t_to // 60))]
        for day in self._existing_days(t_from, t_to):
            for b, host, sev, inp, n in self._query(day, deadline, sql, params):
                if 0 <= b < n_buckets:
                    series[int(b)] += n
                    if sev <= 3:
                        series_err[int(b)] += n
                by_sev[sev] += n
                by_host[host] += n
                by_input[inp] += n
        return {
            "bucket": size,
            "start": start,
            "series": series,
            "series_errors": series_err,
            "total": sum(series),
            "by_severity": {str(k): v for k, v in sorted(by_sev.items())},
            "top_hosts": [{"value": h, "count": n}
                          for h, n in sorted(by_host.items(), key=lambda kv: -kv[1])[:10]],
            "by_input": [{"value": i, "count": n}
                         for i, n in sorted(by_input.items(), key=lambda kv: -kv[1])],
        }
