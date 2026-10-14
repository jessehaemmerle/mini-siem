import calendar
import time

from siem.parsers import parse_hec_event, parse_json_event, parse_syslog, parse_text_line


def test_rfc3164_sshd():
    ev = parse_syslog("<38>Oct 14 09:10:11 web01 sshd[1234]: Failed password for invalid user bob "
                      "from 203.0.113.9 port 51234 ssh2", "10.0.0.1")
    assert ev["host"] == "web01"
    assert ev["app"] == "sshd"
    assert ev["facility"] == 4 and ev["severity"] == 6
    assert ev["user"] == "bob"
    assert ev["src_ip"] == "203.0.113.9"
    assert ev["category"] == "authentication" and ev["action"] == "failure"
    assert ev["data"]["pid"] == "1234"
    assert ev["message"].startswith("Failed password")
    assert ev["ts"] <= ev["received"] + 300


def test_rfc5424_with_structured_data():
    ev = parse_syslog('<165>1 2026-10-14T08:00:00.123Z host1 myapp 42 ID47 '
                      '[exampleSDID@32473 iut="3" eventSource="App\\"lication"] ﻿Hallo Welt', "10.0.0.2")
    assert ev["host"] == "host1" and ev["app"] == "myapp"
    assert ev["severity"] == 5 and ev["facility"] == 20
    assert ev["data"]["sd"]["exampleSDID@32473"]["eventSource"] == 'App"lication'
    assert ev["message"] == "Hallo Welt"
    assert abs(ev["ts"] - (calendar.timegm((2026, 10, 14, 8, 0, 0)) + 0.123)) < 0.001


def test_missing_hostname_and_pri():
    ev = parse_syslog("sudo:  alice : 3 incorrect password attempts ; TTY=pts/0 ; COMMAND=/bin/ls", "192.0.2.7")
    assert ev["host"] == "192.0.2.7"
    assert ev["app"] == "sudo"
    assert ev["user"] == "alice"
    assert ev["action"] == "failure"


def test_iptables_kv():
    ev = parse_syslog("<4>Oct 14 10:00:00 fw kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.4 "
                      "DST=10.0.0.1 PROTO=TCP SPT=4444 DPT=3389", "10.0.0.254")
    assert ev["src_ip"] == "198.51.100.4"
    assert ev["dst_ip"] == "10.0.0.1"
    assert ev["dst_port"] == 3389
    assert ev["action"] == "block"
    assert ev["data"]["PROTO"] == "TCP"


def test_future_timestamp_is_clamped():
    ev = parse_syslog("<13>2099-01-01T00:00:00Z host app: test", "1.2.3.4")
    assert ev["ts"] == ev["received"]


def test_json_in_syslog_nxlog_windows():
    msg = ('<14>Oct 14 10:00:00 DC01 Security: {"EventTime":"2026-10-14 10:00:00","Hostname":"DC01.corp.local",'
           '"EventID":4625,"SourceName":"Microsoft-Windows-Security-Auditing","Channel":"Security",'
           '"EventType":"AUDIT_FAILURE","TargetUserName":"jdoe","IpAddress":"10.1.1.50",'
           '"Message":"An account failed to log on."}')
    ev = parse_syslog(msg, "10.0.0.10")
    assert ev["event_id"] == "4625"
    assert ev["host"] == "dc01.corp.local"
    assert ev["user"] == "jdoe"
    assert ev["src_ip"] == "10.1.1.50"
    assert ev["category"] == "authentication" and ev["action"] == "failure"
    assert ev["severity"] == 4
    assert ev["data"]["description"] == "Anmeldung fehlgeschlagen"


def test_fluentbit_winevtlog_string_inserts():
    inserts = [""] * 21
    inserts[5] = "admin"
    inserts[19] = "172.16.0.9"
    obj = {"ProviderName": "Microsoft-Windows-Security-Auditing", "EventID": 4625, "Level": 0,
           "Computer": "SRV01", "Channel": "Security", "Message": "Fehler", "StringInserts": inserts,
           "Keywords": "0x8010000000000000 Audit Failure", "TimeCreated": "2026-10-14 08:00:00 +0000"}
    ev = parse_json_event(obj, "10.0.0.3")
    assert ev["user"] == "admin" and ev["src_ip"] == "172.16.0.9"
    assert ev["host"] == "srv01" and ev["event_id"] == "4625"
    assert ev["action"] == "failure"


def test_winlogbeat_style():
    obj = {"@timestamp": "2026-10-14T08:00:00.000Z", "winlog": {"event_id": "4720", "computer_name": "DC02",
           "provider_name": "Microsoft-Windows-Security-Auditing", "event_data": {"TargetUserName": "neu"}},
           "message": "A user account was created."}
    ev = parse_json_event(obj, "10.0.0.4")
    assert ev["event_id"] == "4720" and ev["host"] == "dc02" and ev["user"] == "neu"
    assert ev["category"] == "account" and ev["action"] == "created"


def test_generic_json_fluentbit_docker():
    obj = {"date": time.time() - 5, "log": "GET / 200", "stream": "stdout", "container_name": "/web",
           "level": "warn"}
    ev = parse_json_event(obj, "10.0.0.5")
    assert ev["app"] == "web"
    assert ev["message"] == "GET / 200"
    assert ev["severity"] == 4
    assert "log" not in ev["data"]


def test_hec_docker_splunk_driver():
    obj = {"event": {"line": "Accepted publickey for deploy from 10.9.8.7 port 2222 ssh2", "source": "stdout",
                     "tag": "ssh-gateway"}, "time": "%.3f" % (time.time() - 1), "host": "docker01"}
    ev = parse_hec_event(obj, "10.0.0.6")
    assert ev["input"] == "hec"
    assert ev["host"] == "docker01"
    assert ev["app"] == "ssh-gateway"
    assert ev["user"] == "deploy" and ev["action"] == "success"


def test_hec_string_event():
    ev = parse_hec_event({"event": "hello world", "sourcetype": "test"}, "10.0.0.6")
    assert ev["message"] == "hello world"
    assert ev["data"]["hec_sourcetype"] == "test"


def test_text_line():
    ev = parse_text_line("user=alice action=login src=10.2.3.4 result=ok", "10.0.0.7")
    assert ev["user"] == "alice" and ev["src_ip"] == "10.2.3.4"
    ev2 = parse_text_line("<13>Oct 14 10:00:00 h1 app: hi", "10.0.0.7")
    assert ev2["host"] == "h1" and ev2["input"] == "http"


def test_garbage_does_not_crash():
    for raw in ["", "<999>", "<12>1 - - - - -", "\x00\x01\x02", "{not json", "<13>Feb 30 25:61:61 x y: z"]:
        ev = parse_syslog(raw, "1.1.1.1")
        assert isinstance(ev["message"], str)
        assert 0 <= ev["severity"] <= 7
