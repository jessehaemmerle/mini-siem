import json
import sqlite3
import time

import pytest

from siem import query as q
from siem.parsers import finalize, new_event
from siem.storage import _INSERT_SQL, COLUMNS, SCHEMA

EVENTS = [
    dict(host="web01", app="sshd", severity=6, user="root", src_ip="10.0.0.5",
         message="Failed password for root from 10.0.0.5 port 22 ssh2", data={"status": 500, "ok": True}),
    dict(host="web02", app="nginx", severity=3, user=None, src_ip="192.168.1.20", dst_port=443,
         message='GET /index.html HTTP/1.1 "Mozilla"', data={"status": 200, "path": {"x": "a-b"}}),
    dict(host="DC01", app="Microsoft-Windows-Security-Auditing", severity=4, user="Administrator",
         event_id="4625", message="Anmeldung fehlgeschlagen für Müller", data=None),
    dict(host="fw", app="kernel", severity=4, src_ip="8.8.8.8", dst_port=22,
         message="[UFW BLOCK] IN=eth0 SRC=8.8.8.8 DST=10.0.0.1 DPT=22", data={"PROTO": "TCP"}),
]


def _events():
    out = []
    for e in EVENTS:
        ev = new_event("test", "127.0.0.1", time.time())
        ev.update(e)
        ev["ts"] = ev["received"]
        out.append(finalize(ev))
    return out


@pytest.fixture(scope="module")
def db():
    conn = sqlite3.connect(":memory:")
    conn.executescript(SCHEMA)
    q.register_functions(conn)
    for ev in _events():
        row = [ev.get(c) for c in COLUMNS]
        row[COLUMNS.index("data")] = json.dumps(ev["data"]) if ev["data"] else None
        cur = conn.execute(_INSERT_SQL, row)
        conn.execute("INSERT INTO events_fts(rowid, message) VALUES (?, ?)", (cur.lastrowid, ev["message"]))
    return conn


CASES = [
    ("", {0, 1, 2, 3}),
    ("failed", {0}),
    ("Failed password", {0}),
    ('"password for"', {0}),
    ('"for password"', set()),
    ("pass*", {0}),
    ("host:web01", {0}),
    ("host:WEB*", {0, 1}),
    ("host:dc01", {2}),
    ("-host:web*", {2, 3}),
    ("NOT host:web*", {2, 3}),
    ("severity:<=warning", {1, 2, 3}),
    ("severity:error", {1}),
    ("sev:>4", {0}),
    ("src_ip:10.0.0.0/8", {0}),
    ("ip:8.8.8.8", {3}),
    ("user:*", {0, 2}),
    ("-user:*", {1, 3}),
    ("dst_port:>=100", {1}),
    ("port:22", {3}),
    ("event_id:4625", {2}),
    ("muller", {2}),
    ("host:web01 OR host:fw", {0, 3}),
    ("(host:web01 OR host:fw) severity:4", {3}),
    ("host:web01 AND severity:4", set()),
    ("data.status:500", {0}),
    ("data.status:>=300", {0}),
    ("data.ok:true", {0}),
    ("data.path.x:a-b", {1}),
    ("data.PROTO:tcp", {3}),
    ('user:~"^adm"', {2}),
    ('message:~"UFW (BLOCK|ALLOW)"', {3}),
    ('"/index.html"', {1}),
    ('"../"', set()),
    ("ufw block", {3}),
]


@pytest.mark.parametrize("query,expected", CASES)
def test_sql_and_python_agree(db, query, expected):
    node = q.parse(query)
    where, params = q.to_sql(node)
    rows = db.execute("SELECT id FROM events e WHERE " + where + " ORDER BY id", params).fetchall()
    sql_ids = {r[0] - 1 for r in rows}
    matcher = q.compile_matcher(node)
    py_ids = {i for i, ev in enumerate(_events()) if matcher(ev)}
    assert sql_ids == expected, "SQL: " + query
    assert py_ids == expected, "Python: " + query


@pytest.mark.parametrize("bad", [
    "foo:bar", '"offen', "(host:a", "host:a)", "severity:hoch", "src_ip:1.2.3.4/99",
    'user:~"(("', "OR host:a", "host:",
])
def test_errors(bad):
    with pytest.raises(q.QueryError):
        q.parse(bad)
