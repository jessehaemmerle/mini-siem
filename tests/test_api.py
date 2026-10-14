import gzip
import json
import time

from conftest import ADMIN_PW, login, wait_processed


def _token(client, name="test"):
    r = client.post("/api/tokens", json={"name": name})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def test_health_and_index(client):
    assert client.get("/api/health").json()["status"] == "ok"
    r = client.get("/")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    assert "Content-Security-Policy" in r.headers


def test_login_required_and_csrf(client):
    assert client.get("/api/alerts").status_code == 401
    r = client.post("/api/auth/login", json={"username": "admin", "password": "falsch"})
    assert r.status_code == 401
    login(client)
    assert client.get("/api/auth/me").json()["role"] == "admin"
    # ohne Sicherheits-Header werden schreibende Anfragen abgelehnt
    del client.headers["X-SIEM"]
    assert client.post("/api/tokens", json={"name": "x"}).status_code == 403


def test_login_throttle(client):
    for _ in range(10):
        client.post("/api/auth/login", json={"username": "admin", "password": "falsch"})
    r = client.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PW})
    assert r.status_code == 429


def test_ingest_search_and_bruteforce_alert(admin_client):
    c = admin_client
    token = _token(c)
    assert c.post("/api/ingest", json={"message": "x"}).status_code == 401
    lines = "\n".join(
        f"<38>Oct 14 09:10:{i:02d} web01 sshd[99]: Failed password for root from 203.0.113.50 port {4000 + i} ssh2"
        for i in range(12)
    )
    r = c.post("/api/ingest", content=lines, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200 and r.json()["accepted"] == 12
    batch = [{"message": "GET /shop?id=1 UNION SELECT password FROM users", "host": "shop", "src_ip": "198.51.100.1"},
             {"msg": "hallo", "level": "error", "hostname": "app1"}]
    r = c.post("/api/ingest", content=gzip.compress(json.dumps(batch).encode()),
               headers={"X-API-Key": token, "Content-Encoding": "gzip", "Content-Type": "application/json"})
    assert r.json()["accepted"] == 2
    wait_processed(c, 14)

    now = time.time()
    r = c.get("/api/events", params={"q": "host:web01 failed", "from": now - 365 * 86400, "to": now + 60})
    assert r.status_code == 200
    assert len(r.json()["events"]) == 12
    page = c.get("/api/events", params={"q": "app:sshd", "limit": 5, "from": now - 365 * 86400}).json()
    assert len(page["events"]) == 5 and page["next_cursor"]
    page2 = c.get("/api/events", params={"q": "app:sshd", "limit": 5, "cursor": page["next_cursor"],
                                          "from": now - 365 * 86400}).json()
    assert {e["ref"] for e in page2["events"]}.isdisjoint({e["ref"] for e in page["events"]})

    assert c.get("/api/events", params={"q": "foo:bar"}).status_code == 400
    hist = c.get("/api/events/histogram", params={"from": now - 3600}).json()
    assert hist["total"] >= 2
    top = c.get("/api/events/top", params={"field": "host", "from": now - 365 * 86400}).json()
    assert top["values"][0]["value"] == "web01"

    alerts = c.get("/api/alerts").json()["alerts"]
    names = {a["rule_name"] for a in alerts}
    assert "SSH: Brute-Force-Angriff" in names
    assert "Web: Typische Angriffsmuster" in names
    bf = next(a for a in alerts if a["rule_name"] == "SSH: Brute-Force-Angriff")
    assert bf["group_value"] == "203.0.113.50"

    detail = c.get(f"/api/alerts/{bf['id']}").json()
    assert detail["samples"] and detail["rule"]["query"]
    r = c.patch(f"/api/alerts/{bf['id']}", json={"status": "ack", "assignee": "admin"})
    assert r.json()["status"] == "ack"
    r = c.post(f"/api/alerts/{bf['id']}/comments", json={"text": "Prüfe ich"})
    assert any(cm["text"] == "Prüfe ich" for cm in r.json()["comments"])
    r = c.post("/api/alerts/bulk", json={"ids": [bf["id"]], "status": "closed"})
    assert r.json()["updated"] == 1

    dash = c.get("/api/dashboard", params={"from": now - 86400}).json()
    assert dash["sources"]["total"] >= 1
    srcs = c.get("/api/sources").json()["sources"]
    assert any(s["host"] == "web01" for s in srcs)


def test_hec_endpoint(admin_client):
    c = admin_client
    token = _token(c, "docker")
    assert c.options("/services/collector/event/1.0").status_code == 200
    body = "".join(json.dumps({"event": {"line": f"line {i}", "source": "stdout", "tag": "web"},
                               "host": "docker01", "time": str(time.time())}) for i in range(3))
    r = c.post("/services/collector/event/1.0", content=body, headers={"Authorization": f"Splunk {token}"})
    assert r.json() == {"text": "Success", "code": 0}
    r = c.post("/services/collector/event", content=body, headers={"Authorization": "Splunk falsch"})
    assert r.status_code == 401 and r.json()["code"] == 4
    wait_processed(c, 3)
    evs = c.get("/api/events", params={"q": "app:web input:hec"}).json()["events"]
    assert len(evs) == 3 and evs[0]["host"] == "docker01"


def test_rules_crud_and_test(admin_client):
    c = admin_client
    rules = c.get("/api/rules").json()["rules"]
    assert len(rules) >= 10
    r = c.post("/api/rules", json={"name": "Test", "query": "unbekannt:x"})
    assert r.status_code == 400
    r = c.post("/api/rules", json={"name": "Fehler auf web", "query": "host:web* severity:<=error",
                                   "severity": "low", "threshold": 2, "window": 600, "group_by": "host"})
    assert r.status_code == 200, r.text
    rid = r.json()["id"]
    r = c.put(f"/api/rules/{rid}", json={**r.json(), "enabled": False})
    assert r.json()["enabled"] == 0
    token = _token(c)
    c.post("/api/ingest", json=[{"message": "boom", "host": "web9", "level": "error"}] * 3,
           headers={"Authorization": f"Bearer {token}"})
    wait_processed(c, 3)
    t = c.post("/api/rules/test", json={"query": "host:web* severity:<=error", "threshold": 2, "window": 600,
                                        "group_by": "host"}).json()
    assert t["matched"] == 3 and t["alert_count"] == 1
    assert c.delete(f"/api/rules/{rid}").status_code == 200


def test_roles(admin_client):
    c = admin_client
    r = c.post("/api/users", json={"username": "leser", "password": "kurz", "role": "viewer"})
    assert r.status_code == 400
    r = c.post("/api/users", json={"username": "leser", "password": "ein-langes-passwort", "role": "viewer"})
    assert r.status_code == 200
    users = c.get("/api/users").json()["users"]
    me = next(u for u in users if u["username"] == "admin")
    assert c.delete(f"/api/users/{me['id']}").status_code == 400
    assert c.put(f"/api/users/{me['id']}", json={"role": "viewer"}).status_code == 400

    c.post("/api/auth/logout")
    login(c, "leser", "ein-langes-passwort")
    assert c.get("/api/alerts").status_code == 200
    assert c.get("/api/system").status_code == 200
    assert c.post("/api/rules", json={"name": "x", "query": "host:a"}).status_code == 403
    assert c.get("/api/users").status_code == 403
    assert c.put("/api/settings", json={"retention_days": 5}).status_code == 403
    r = c.post("/api/auth/password", json={"current": "ein-langes-passwort", "new": "noch-ein-langes-pw"})
    assert r.status_code == 200


def test_settings_and_audit(admin_client):
    c = admin_client
    r = c.put("/api/settings", json={"retention_days": 30, "source_silent_minutes": 15})
    assert r.json()["retention_days"] == 30
    entries = c.get("/api/audit").json()["entries"]
    assert any(e["action"] == "settings.update" for e in entries)
    sysinfo = c.get("/api/system").json()
    assert sysinfo["retention_days"] == 30
