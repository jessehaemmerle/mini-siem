from siem.detection import CompiledRule, Detector, simulate, validate_rule

import pytest


def rule(**kw):
    base = dict(id=1, name="r", severity="high", query="action:failure", threshold=3, window=60,
                group_by="src_ip", distinct_field=None)
    base.update(kw)
    return CompiledRule.from_row(base)


def ev(t, **kw):
    e = dict(received=t, ts=t, host="h", message="x", action="failure", src_ip="1.1.1.1")
    e.update(kw)
    return e


def test_threshold_per_group():
    d = Detector([rule()])
    assert d.process([ev(0), ev(1), ev(2, src_ip="2.2.2.2")]) == []
    fired = d.process([ev(3)])
    assert len(fired) == 1
    assert fired[0].group_value == "1.1.1.1" and fired[0].count == 3


def test_window_expires():
    d = Detector([rule()])
    d.process([ev(0), ev(1)])
    assert d.process([ev(100)]) == []  # die ersten beiden sind außerhalb des Fensters


def test_distinct_count():
    d = Detector([rule(query="dst_port:*", threshold=3, distinct_field="dst_port")])
    out = d.process([ev(0, dst_port=22), ev(1, dst_port=22), ev(2, dst_port=80)])
    assert out == []
    out = d.process([ev(3, dst_port=443)])
    assert len(out) == 1


def test_match_rule_without_group():
    d = Detector([rule(threshold=1, group_by=None)])
    out = d.process([ev(0), ev(1)])
    assert len(out) == 1 and out[0].count == 2 and out[0].group_value == ""


def test_simulation_merges_within_window():
    r = dict(name="t", query="action:failure", severity="low", threshold=2, window=60,
             group_by="src_ip", distinct_field=None)
    events = [ev(t) for t in (0, 1, 10, 11, 500, 501)]
    alerts = simulate(r, events)
    assert len(alerts) == 2
    assert sum(a["count"] for a in alerts) == 6


def test_validate_rule():
    ok = validate_rule({"name": "x", "query": "host:a", "severity": "low"})
    assert ok["threshold"] == 1 and ok["window"] == 300
    with pytest.raises(ValueError):
        validate_rule({"name": "", "query": "host:a"})
    with pytest.raises(ValueError):
        validate_rule({"name": "x", "query": "host:a", "group_by": "nope"})
    with pytest.raises(Exception):
        validate_rule({"name": "x", "query": "unbekannt:a"})


def test_hits_after_firing_are_added():
    d = Detector([rule()])
    first = d.process([ev(t) for t in (0, 1, 2)])
    assert first[0].count == 3
    more = d.process([ev(5), ev(6)])
    assert len(more) == 1 and more[0].count == 2
    # nach Ablauf des Fensters muss die Schwelle wieder erreicht werden
    assert d.process([ev(200)]) == []


def test_delayed_batch_uses_event_time():
    """Microsoft 365 liefert stundenweise verspätet: 100 Löschungen über zwei Stunden, die
    gemeinsam ankommen, sind kein Massenlöschen – 100 in fünf Minuten schon."""
    r = rule(query="action:deleted", threshold=100, window=600, group_by="user")
    spread = [ev(1000 + i * 72, received=9000, input="m365", action="deleted", user="a") for i in range(100)]
    assert Detector([r]).process(spread) == []
    burst = [ev(1000 + i * 3, received=9000, input="m365", action="deleted", user="a") for i in range(100)]
    fired = Detector([r]).process(burst)
    assert len(fired) == 1 and fired[0].first_seen == 1000 and fired[0].last_seen == 1000 + 99 * 3


def test_unsorted_batch_and_late_events():
    r = rule(threshold=3, window=60)
    d = Detector([r])
    # absteigend geliefert (wie Microsoft Graph) – wird nach Zeit sortiert ausgewertet
    fired = d.process([ev(30, input="agent", received=500), ev(20, input="agent", received=500),
                       ev(10, input="agent", received=500)])
    assert len(fired) == 1 and fired[0].first_seen == 10
    # ein noch älteres Event danach stört die Gruppe nicht (Uhr läuft je Gruppe nur vorwärts)
    out = d.process([ev(5, input="agent", received=600)])
    assert len(out) == 1 and out[0].last_seen == 30


def test_syslog_keeps_receive_time():
    """Geräte mit falscher Zeitzone: Für Syslog zählt weiter die Empfangszeit."""
    r = rule(threshold=3, window=60)
    events = [ev(t, received=1000 + i, input="syslog") for i, t in enumerate((0, 7200, 14400))]
    assert len(Detector([r]).process(events)) == 1
