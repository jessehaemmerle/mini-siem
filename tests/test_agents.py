import gzip
import json
import time

from conftest import login, wait_processed

from siem.agent_events import parse_agent_event
from siem.agents import DEFAULT_AGENT_CONFIG, validate_config

import pytest


# --------------------------------------------------------------------------- Aufbereitung


def test_journald_sshd():
    ev = parse_agent_event({"src": "journald", "t": time.time(), "prio": 6, "ident": "sshd-session",
                            "unit": "ssh.service", "pid": "812",
                            "msg": "Failed password for invalid user oracle from 203.0.113.7 port 4242 ssh2"},
                           "web01", "10.0.0.5")
    assert ev["host"] == "web01" and ev["input"] == "agent"
    assert ev["app"] == "sshd-session"
    assert ev["user"] == "oracle" and ev["src_ip"] == "203.0.113.7"
    assert ev["action"] == "failure" and ev["data"]["unit"] == "ssh.service"


def test_journald_binary_message():
    ev = parse_agent_event({"src": "journald", "t": time.time(), "prio": 3, "comm": "x",
                            "msg": list("hallo".encode())}, "h", None)
    assert ev["message"] == "hallo" and ev["severity"] == 3 and ev["app"] == "x"


def test_winlog_4625():
    ev = parse_agent_event({
        "src": "winlog", "t": time.time(), "channel": "Security",
        "provider": "Microsoft-Windows-Security-Auditing", "event_id": 4625, "level": 0,
        "keywords": "0x8010000000000000 Audit Failure", "record_id": 991, "computer": "DC01.firma.local",
        "data": {"TargetUserName": "j.mueller", "IpAddress": "10.1.2.3", "LogonType": "3"},
        "msg": "Fehler beim Anmelden eines Kontos.",
    }, "dc01", "10.0.0.2")
    assert ev["host"] == "dc01" and ev["event_id"] == "4625"
    assert ev["user"] == "j.mueller" and ev["src_ip"] == "10.1.2.3"
    assert ev["action"] == "failure" and ev["category"] == "authentication"
    assert ev["data"]["src"] == "winlog" and ev["data"]["channel"] == "Security"


def test_docker_events_and_logs():
    start = parse_agent_event({"src": "docker", "kind": "event", "t": time.time(), "action": "start",
                               "container": "/web", "image": "nginx:1.27", "privileged": True}, "docker01", None)
    assert start["category"] == "container" and start["action"] == "start"
    assert start["data"]["privileged"] is True and start["severity"] == 4
    assert "privilegiert" in start["message"]

    die = parse_agent_event({"src": "docker", "kind": "event", "t": time.time(), "action": "die",
                             "container": "web", "exit_code": "137"}, "docker01", None)
    assert die["severity"] == 4 and "137" in die["message"]

    exe = parse_agent_event({"src": "docker", "kind": "event", "t": time.time(), "action": "exec_start: sh -c id",
                             "container": "web", "exec_cmd": "sh -c id"}, "docker01", None)
    assert exe["action"] == "exec_start" and exe["event_id"] == "docker.exec_start"

    log = parse_agent_event({"src": "docker", "kind": "log", "t": time.time(), "container": "api",
                             "stream": "stderr", "msg": '{"level":"error","msg":"db down","user":"svc"}'},
                            "docker01", None)
    assert log["app"] == "api" and log["severity"] == 3 and log["message"] == "db down"
    assert log["data"]["stream"] == "stderr"


def test_file_line():
    ev = parse_agent_event({"src": "file", "t": time.time(), "path": "/var/log/nginx/access.log",
                            "msg": '203.0.113.9 - - "GET /../../etc/passwd HTTP/1.1" 404'}, "web02", None)
    assert ev["app"] == "access.log" and ev["data"]["path"] == "/var/log/nginx/access.log"


def test_validate_config():
    cfg = validate_config({"linux": {"files": ["/var/log/app/*.log"], "min_priority": 9},
                           "windows": {"channels": [{"name": "Security", "max_level": 4, "event_ids": ["4625"]}]},
                           "docker": {"enabled": False}})
    assert cfg["linux"]["min_priority"] == 7 and cfg["linux"]["files"] == ["/var/log/app/*.log"]
    assert cfg["windows"]["channels"][0]["event_ids"] == [4625]
    assert cfg["docker"]["enabled"] is False and cfg["docker"]["logs"] is True
    with pytest.raises(ValueError):
        validate_config({"linux": {"files": ["relativ.log"]}})
    with pytest.raises(ValueError):
        validate_config({"windows": {"channels": [{"name": "x'y"}]}})
    assert validate_config({}) == DEFAULT_AGENT_CONFIG


# --------------------------------------------------------------------------- API


def _enroll(client, key, machine="m-0001-abcdef", host="WEB01"):
    return client.post("/api/agent/enroll", json={"key": key, "machine_id": machine, "hostname": host,
                                                  "os": "linux", "arch": "amd64", "version": "0.9.0"})


def test_agent_lifecycle(admin_client, tmp_path):
    c = admin_client
    settings = c.get("/api/agents-settings").json()
    key = settings["enroll_key"]
    assert key.startswith("enr_") and "install.sh" in settings["commands"]["linux"]

    assert _enroll(c, "falsch").status_code == 403
    r = _enroll(c, key)
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    auth = {"Authorization": f"Bearer {token}"}

    r = c.post("/api/agent/checkin", json={"version": "0.9.0", "stats": {"sent": 0}}, headers=auth)
    assert r.status_code == 200
    body = r.json()
    assert body["config"]["linux"]["journald"] is True and body["config_version"]
    assert body["update"] is None  # keine Programmdateien im Test vorhanden

    events = [
        {"src": "journald", "t": time.time(), "prio": 6, "ident": "sshd",
         "msg": f"Failed password for root from 198.51.100.{i} port 22 ssh2"} for i in range(3)
    ] + [{"src": "docker", "kind": "event", "t": time.time(), "action": "oom", "container": "db"}]
    r = c.post("/api/agent/events", content=gzip.compress(json.dumps(events).encode()),
               headers={**auth, "Content-Encoding": "gzip"})
    assert r.json() == {"accepted": 4}
    assert c.post("/api/agent/events", json=events, headers={"Authorization": "Bearer agt_falsch"}).status_code == 401
    wait_processed(c, 4)

    found = c.get("/api/events", params={"q": "input:agent host:web01"}).json()["events"]
    assert len(found) == 4
    agents = c.get("/api/agents").json()["agents"]
    assert agents[0]["hostname"] == "web01" and agents[0]["online"] is True

    # eigene Einstellungen für diesen Agenten
    aid = agents[0]["id"]
    r = c.patch(f"/api/agents/{aid}", json={"config": {"docker": {"enabled": False}}})
    assert r.status_code == 200
    body = c.post("/api/agent/checkin", json={"version": "0.9.0"}, headers=auth).json()
    assert body["config"]["docker"]["enabled"] is False

    # erneute Registrierung desselben Rechners ersetzt das alte Token
    new_token = _enroll(c, key).json()["token"]
    assert c.post("/api/agent/checkin", json={}, headers=auth).status_code == 401
    assert c.post("/api/agent/checkin", json={}, headers={"Authorization": f"Bearer {new_token}"}).status_code == 200
    assert len(c.get("/api/agents").json()["agents"]) == 1

    # Schlüssel erneuern, Agent sperren und löschen
    new_key = c.post("/api/agents-settings/enroll-key").json()["enroll_key"]
    assert new_key != key and _enroll(c, key, machine="m-0002-xyzxyz").status_code == 403
    c.patch(f"/api/agents/{aid}", json={"disabled": True})
    assert c.post("/api/agent/checkin", json={}, headers={"Authorization": f"Bearer {new_token}"}).status_code == 401
    assert c.delete(f"/api/agents/{aid}").status_code == 200
    assert c.get("/api/agents").json()["agents"] == []


def test_install_scripts_and_downloads(client, settings, tmp_path):
    r = client.get("/api/agent/install.sh")
    assert r.status_code == 200 and 'SERVER="http://testserver"' in r.text
    r = client.get("/api/agent/install.ps1")
    assert r.status_code == 200 and "windows-amd64" in r.text
    assert client.get("/api/agent/download/linux-amd64").status_code == 404
    assert client.get("/api/agent/download/../../etc/passwd").status_code == 404

    # Programmdatei bereitstellen -> Download und Prüfsumme
    dist = settings.agent_dist_dir
    dist.mkdir(parents=True, exist_ok=True)
    (dist / "mini-siem-agent-linux-amd64").write_bytes(b"\x7fELF test")
    (dist / "VERSION").write_text("1.2.3\n")
    r = client.get("/api/agent/download/linux-amd64")
    assert r.status_code == 200 and r.content == b"\x7fELF test"
    import hashlib
    assert client.get("/api/agent/download/linux-amd64.sha256").text.strip() == hashlib.sha256(b"\x7fELF test").hexdigest()

    # Update-Angebot an veraltete Agenten
    login(client)
    key = client.get("/api/agents-settings").json()["enroll_key"]
    token = _enroll(client, key).json()["token"]
    upd = client.post("/api/agent/checkin", json={"version": "0.9.0"}, headers={"Authorization": f"Bearer {token}"}).json()["update"]
    assert upd["version"] == "1.2.3" and upd["url"] == "/api/agent/download/linux-amd64"
    client.put("/api/agents-settings", json={"auto_update": False})
    upd = client.post("/api/agent/checkin", json={"version": "0.9.0"}, headers={"Authorization": f"Bearer {token}"}).json()["update"]
    assert upd is None


# --------------------------------------------------------------------------- Erkennungsregeln Docker


def _docker_rule(key):
    from siem.detection import validate_rule
    from siem.rules_default import DEFAULT_RULES

    return validate_rule(next(r for r in DEFAULT_RULES if r["key"] == key))


def test_docker_rules():
    from siem.detection import simulate

    t = time.time() - 600

    def ev(action, **kw):
        return parse_agent_event({"src": "docker", "kind": "event", "t": t + kw.pop("dt", 0), "action": action,
                                  "container": "web", **kw}, "docker01", None)

    assert simulate(_docker_rule("docker-privileged"), [ev("start", docker_socket=True)])
    assert not simulate(_docker_rule("docker-privileged"), [ev("start")])
    assert simulate(_docker_rule("docker-exec"), [ev("exec_start: sh", exec_cmd="sh")])
    loop = [ev("die", exit_code="1", dt=i * 30) for i in range(5)]
    hits = simulate(_docker_rule("docker-restart-loop"), loop)
    assert len(hits) == 1 and hits[0]["group_value"] == "web"
    assert not simulate(_docker_rule("docker-restart-loop"), loop[:4])
    assert simulate(_docker_rule("docker-oom"), [ev("oom")])
    assert simulate(_docker_rule("docker-unhealthy"), [ev("health_status: unhealthy", health="unhealthy")])


def test_ssh_rules_cover_sshd_session():
    from siem.detection import simulate

    evs = [parse_agent_event({"src": "journald", "t": time.time() - 60 + i, "prio": 6, "ident": "sshd-session",
                              "msg": f"Failed password for root from 203.0.113.7 port {4000 + i} ssh2"}, "web01", None)
           for i in range(10)]
    assert simulate(_docker_rule("ssh-bruteforce"), evs)


def test_builtin_rule_upgrade(settings):
    from siem.core import Core

    core = Core(settings)
    core.db.execute("UPDATE rules SET query = 'app:sshd category:authentication action:failure' "
                    "WHERE key = 'ssh-bruteforce'")
    core.db.execute("UPDATE rules SET query = 'app:sshd action:success user:root AND host:web*' "
                    "WHERE key = 'ssh-root-login'")
    core._seed_rules()
    rows = {r["key"]: r["query"] for r in core.db.all("SELECT key, query FROM rules")}
    assert rows["ssh-bruteforce"] == "app:sshd* category:authentication action:failure"
    assert rows["ssh-root-login"].endswith("host:web*"), "selbst geänderte Regeln bleiben unangetastet"


def _no_case_duplicates(d: dict) -> bool:
    keys = [k.lower() for k in d]
    return len(keys) == len(set(keys))


def test_winlog_data_has_no_case_duplicates():
    """PowerShell (ConvertFrom-Json) scheitert an Schlüsseln, die sich nur in der Schreibung unterscheiden."""
    ev = parse_agent_event({
        "src": "winlog", "t": time.time(), "channel": "System", "provider": "Microsoft-Windows-Eventlog",
        "event_id": 104, "level": 4, "keywords": "0x8000000000000000", "record_id": 77, "computer": "dc01",
        # Ereignis 104 nennt in den Nutzdaten das geleerte Protokoll – ebenfalls „Channel“
        "data": {"SubjectUserName": "admin", "Channel": "Application", "UserSID": "S-1-5-21-1"},
        "msg": "Das Protokoll „Application“ wurde gelöscht.",
    }, "dc01", None)
    d = ev["data"]
    assert _no_case_duplicates(d), d
    assert d["channel"] == "System" and d["Channel_data"] == "Application"
    assert d["SubjectUserName"] == "admin" and d["record_id"] == 77 and "EventData" not in d


def test_http_windows_event_keeps_original_without_duplicates():
    from siem.parsers import parse_json_event

    ev = parse_json_event({"EventID": 4625, "Channel": "Security", "Computer": "PC1", "Level": 0,
                           "Keywords": "Audit Failure", "TargetUserName": "bob", "IpAddress": "10.0.0.9"}, "10.0.0.1")
    assert _no_case_duplicates(ev["data"]), ev["data"]
    assert ev["data"]["Channel"] == "Security" and ev["user"] == "bob"
