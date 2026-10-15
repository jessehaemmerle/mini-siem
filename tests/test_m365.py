import json
import time
import urllib.parse
from datetime import datetime, timezone

from conftest import login, wait_processed

from siem.m365 import HttpResponse, M365Error, validate_m365
from siem.m365_events import clean_ip, parse_m365

import pytest

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
SECRET = "geheim~123"


def iso(ts, z=True):
    s = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    return s + "Z" if z else s


# --------------------------------------------------------------------------- Aufbereitung


def test_clean_ip():
    assert clean_ip("203.0.113.9:51234") == "203.0.113.9"
    assert clean_ip("[2001:db8::1]:443") == "2001:db8::1"
    assert clean_ip("2001:db8::2") == "2001:db8::2"
    assert clean_ip("::ffff:10.0.0.1") == "10.0.0.1"
    assert clean_ip("kaputt") is None and clean_ip(None) is None


def test_audit_login_failed_and_interrupt():
    now = time.time()
    ev = parse_m365("audit", {
        "Id": "a1", "CreationTime": iso(now - 60, z=False), "Operation": "UserLoginFailed", "RecordType": 15,
        "Workload": "AzureActiveDirectory", "UserId": "j.mueller@firma.at", "ClientIP": "203.0.113.9:4444",
        "ErrorCode": "50126", "LogonError": "InvalidUserNameOrPassword",
        "ExtendedProperties": [{"Name": "UserAgent", "Value": "Mozilla/5.0"}],
    })
    assert ev["input"] == "m365" and ev["host"] == "microsoft365" and ev["app"] == "entra-id"
    assert ev["event_id"] == "UserLoginFailed" and ev["action"] == "failure"
    assert ev["category"] == "authentication" and ev["user"] == "j.mueller@firma.at"
    assert ev["src_ip"] == "203.0.113.9" and ev["data"]["error_code"] == 50126
    assert abs(ev["ts"] - (now - 60)) < 2, "CreationTime ohne Zeitzone ist UTC"
    assert "Benutzername oder Kennwort falsch" in ev["message"]

    kmsi = parse_m365("audit", {"Operation": "UserLoginFailed", "Workload": "AzureActiveDirectory",
                                "CreationTime": iso(now), "UserId": "x@firma.at", "ErrorCode": "50140"})
    assert kmsi["action"] == "interrupted" and kmsi["severity"] == 6

    ok = parse_m365("audit", {"Operation": "UserLoggedIn", "Workload": "AzureActiveDirectory",
                              "CreationTime": iso(now), "UserId": "x@firma.at", "ErrorCode": "0"})
    assert ok["event_id"] == "UserLoggedIn" and ok["action"] == "success"


def test_audit_admin_role_and_mfa():
    ev = parse_m365("audit", {
        "Operation": "Add member to role.", "Workload": "AzureActiveDirectory", "CreationTime": iso(time.time()),
        "UserId": "admin@firma.at", "ObjectId": "neu@firma.at",
        "Target": [{"ID": "User_123", "Type": 2}, {"ID": "neu@firma.at", "Type": 5}],
        "ModifiedProperties": [{"Name": "Role.DisplayName", "NewValue": "Global Administrator", "OldValue": ""}],
    })
    assert ev["category"] == "role" and ev["action"] == "added" and ev["severity"] == 4
    assert ev["data"]["role"] == "Global Administrator" and ev["data"]["target_user"] == "neu@firma.at"
    assert "Global Administrator" in ev["message"]

    mfa = parse_m365("audit", {
        "Operation": "Update user.", "Workload": "AzureActiveDirectory", "CreationTime": iso(time.time()),
        "UserId": "admin@firma.at", "ObjectId": "j.mueller@firma.at",
        "ModifiedProperties": [{"Name": "StrongAuthenticationMethod", "NewValue": "[]", "OldValue": "[...]"}],
    })
    assert mfa["category"] == "mfa" and mfa["action"] == "modified"


def test_audit_sharepoint_and_teams():
    dl = parse_m365("audit", {
        "Operation": "FileDownloaded", "Workload": "SharePoint", "CreationTime": iso(time.time()),
        "UserId": "j.mueller@firma.at", "ClientIP": "198.51.100.4", "SiteUrl": "https://firma.sharepoint.com/sites/fin/",
        "SourceRelativeUrl": "Shared Documents/Bilanz", "SourceFileName": "2026.xlsx",
    })
    assert dl["app"] == "sharepoint" and dl["category"] == "file" and dl["action"] == "downloaded"
    assert "Shared Documents/Bilanz/2026.xlsx" in dl["message"] and dl["data"]["file"] == "2026.xlsx"

    link = parse_m365("audit", {"Operation": "AnonymousLinkCreated", "Workload": "OneDrive",
                                "CreationTime": iso(time.time()), "UserId": "x@firma.at",
                                "ObjectId": "https://firma-my.sharepoint.com/personal/x/Documents/a.pdf"})
    assert link["app"] == "onedrive" and link["category"] == "sharing" and link["action"] == "anonymous_link"

    guest = parse_m365("audit", {
        "Operation": "MemberAdded", "Workload": "MicrosoftTeams", "CreationTime": iso(time.time()),
        "UserId": "owner@firma.at", "TeamName": "Vertrieb",
        "Members": [{"UPN": "partner_extern.at#EXT#@firma.onmicrosoft.com", "Role": 2, "DisplayName": "Partner"}],
    })
    assert guest["app"] == "teams" and guest["category"] == "guest" and guest["action"] == "added"
    assert guest["data"]["team"] == "Vertrieb" and guest["data"]["guests"]


def test_graph_signin_and_defender_alert():
    s = parse_m365("signin", {
        "id": "s1", "createdDateTime": iso(time.time() - 30), "userPrincipalName": "j.mueller@firma.at",
        "appDisplayName": "Office 365 Exchange Online", "ipAddress": "185.220.101.5",
        "status": {"errorCode": 0}, "riskLevelDuringSignIn": "high", "riskState": "atRisk",
        "location": {"city": "Moskau", "countryOrRegion": "RU"},
        "deviceDetail": {"operatingSystem": "Linux", "browser": "Firefox"},
    })
    assert s["event_id"] == "UserLoggedIn" and s["action"] == "success" and s["severity"] == 3
    assert s["data"]["country"] == "RU" and s["data"]["risk_level"] == "high" and s["data"]["src"] == "graph"
    assert "Moskau" in s["message"]

    a = parse_m365("alert", {
        "id": "da1", "createdDateTime": iso(time.time() - 10), "title": "Verdächtige PowerShell-Befehlszeile",
        "severity": "high", "status": "new", "serviceSource": "microsoftDefenderForEndpoint",
        "category": "Execution", "alertWebUrl": "https://security.microsoft.com/alerts/da1",
        "evidence": [{"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "pc-12.firma.local",
                      "loggedOnUsers": [{"accountName": "j.mueller"}]},
                     {"@odata.type": "#microsoft.graph.security.ipEvidence", "ipAddress": "10.0.0.12"}],
    })
    assert a["app"] == "defender" and a["category"] == "alert" and a["severity"] == 3
    assert a["user"] == "j.mueller" and a["src_ip"] == "10.0.0.12"
    assert a["data"]["device"] == "pc-12.firma.local" and a["data"]["severity"] == "high"
    assert "Defender for Endpoint" in a["message"]


def test_validate_config():
    with pytest.raises(ValueError):
        validate_m365({"tenant_id": "firma.onmicrosoft.com"})
    with pytest.raises(ValueError):
        validate_m365({"enabled": True, "tenant_id": TENANT, "client_id": CLIENT})
    cfg = validate_m365({"enabled": True, "tenant_id": TENANT.upper(), "client_id": CLIENT, "client_secret": SECRET})
    assert cfg["tenant_id"] == TENANT and cfg["sources"]["graph_signins"] is False
    kept = validate_m365({"client_secret": ""}, cfg)
    assert kept["client_secret"] == SECRET and kept["enabled"] is True


# --------------------------------------------------------------------------- Connector gegen simuliertes Microsoft


class FakeMicrosoft:
    """Bildet Token-Endpunkt, Management Activity API und Graph nach."""

    def __init__(self, now):
        self.now = now
        self.calls = []
        self.subscriptions = set()
        self.blobs = {
            "Audit.AzureActiveDirectory": [("blob-aad-1", [
                {"Id": "r1", "CreationTime": iso(now - 600, z=False), "Operation": "UserLoginFailed",
                 "RecordType": 15, "Workload": "AzureActiveDirectory", "UserId": "j.mueller@firma.at",
                 "ClientIP": "203.0.113.9", "ErrorCode": "50126"},
                {"Id": "r2", "CreationTime": iso(now - 590, z=False), "Operation": "Add member to role.",
                 "RecordType": 8, "Workload": "AzureActiveDirectory", "UserId": "admin@firma.at",
                 "ModifiedProperties": [{"Name": "Role.DisplayName", "NewValue": "Global Administrator"}],
                 "Target": [{"ID": "neu@firma.at", "Type": 5}]},
            ]), ("blob-aad-2", [
                # doppelte Lieferung desselben Datensatzes in einem zweiten Paket
                {"Id": "r1", "CreationTime": iso(now - 600, z=False), "Operation": "UserLoginFailed",
                 "RecordType": 15, "Workload": "AzureActiveDirectory", "UserId": "j.mueller@firma.at",
                 "ClientIP": "203.0.113.9", "ErrorCode": "50126"},
            ])],
            "Audit.SharePoint": [("blob-sp-1", [
                {"Id": "r3", "CreationTime": iso(now - 500, z=False), "Operation": "FileDownloaded",
                 "RecordType": 6, "Workload": "SharePoint", "UserId": "j.mueller@firma.at",
                 "SourceRelativeUrl": "Shared Documents", "SourceFileName": "kunden.xlsx"},
                {"Id": "r4", "CreationTime": iso(now - 500, z=False), "Operation": "PageViewed",
                 "RecordType": 4, "Workload": "SharePoint", "UserId": "j.mueller@firma.at"},
            ])],
            "Audit.General": [],
        }
        self.alerts = [{"id": "al1", "createdDateTime": iso(now - 120), "title": "Ransomware-Verhalten erkannt",
                        "severity": "high", "status": "new", "serviceSource": "microsoftDefenderForEndpoint"},
                       {"id": "al2", "createdDateTime": iso(now - 100), "title": "Verdächtige Anmeldung",
                        "severity": "medium", "status": "new", "serviceSource": "azureAdIdentityProtection"}]
        self.evil_next = False

    def __call__(self, method, url, headers, body, timeout):
        parts = urllib.parse.urlsplit(url)
        q = dict(urllib.parse.parse_qsl(parts.query))
        self.calls.append((method, parts.hostname, parts.path, q, headers.get("Authorization")))
        if parts.hostname == "login.microsoftonline.com":
            form = dict(urllib.parse.parse_qsl(body.decode()))
            assert parts.path == f"/{TENANT}/oauth2/v2.0/token"
            if form["client_secret"] != SECRET:
                return HttpResponse(401, {}, json.dumps({
                    "error": "invalid_client",
                    "error_description": "AADSTS7000215: Invalid client secret provided.\r\nTrace ID: x"}).encode())
            return HttpResponse(200, {}, json.dumps({"access_token": "tok:" + form["scope"],
                                                     "expires_in": 3599}).encode())
        if parts.hostname == "manage.office.com":
            assert headers["Authorization"] == "Bearer tok:https://manage.office.com/.default"
            assert q.get("PublisherIdentifier") == TENANT, url
            base = f"/api/v1.0/{TENANT}/activity/feed"
            if parts.path == base + "/subscriptions/list":
                return self._json([{"contentType": ct, "status": "enabled"} for ct in sorted(self.subscriptions)])
            if parts.path == base + "/subscriptions/start":
                self.subscriptions.add(q["contentType"])
                return self._json({"contentType": q["contentType"], "status": "enabled"})
            if parts.path == base + "/subscriptions/content":
                ct = q["contentType"]
                if ct not in self.subscriptions:
                    return self._json({"error": {"code": "AF20022", "message": "No subscription found"}}, 400)
                start = datetime.strptime(q["startTime"], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
                end = datetime.strptime(q["endTime"], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
                assert (end - start).total_seconds() <= 86400
                items = [{"contentType": ct, "contentId": cid, "contentCreated": iso(self.now - 300),
                          "contentUri": f"https://manage.office.com{base}/audit/{cid}"}
                         for cid, _ in self.blobs[ct]]
                page = int(q.get("page", "0"))
                headers_out = {}
                if page == 0 and len(items) > 1:
                    nxt = (f"https://manage.office.com{base}/subscriptions/content?contentType={ct}"
                           f"&startTime={q['startTime']}&endTime={q['endTime']}&page=1")
                    if self.evil_next:
                        nxt = "https://evil.example/steal"
                    headers_out["nextpageuri"] = nxt
                    items = items[:1]
                elif page == 1:
                    items = items[1:]
                return HttpResponse(200, headers_out, json.dumps(items).encode())
            if parts.path.startswith(base + "/audit/"):
                cid = parts.path.rsplit("/", 1)[1]
                for blobs in self.blobs.values():
                    for bid, records in blobs:
                        if bid == cid:
                            return self._json(records)
                return self._json({"error": {"code": "AF20051", "message": "not found"}}, 404)
        if parts.hostname == "graph.microsoft.com":
            assert headers["Authorization"] == "Bearer tok:https://graph.microsoft.com/.default"
            if parts.path == "/v1.0/security/alerts_v2":
                if "$filter" in q:
                    assert q["$filter"].startswith("createdDateTime ge ") and q["$filter"].endswith("Z")
                if "$skiptoken" in q:
                    return self._json({"value": self.alerts[1:]})
                return self._json({"value": self.alerts[:1],
                                   "@odata.nextLink": "https://graph.microsoft.com/v1.0/security/alerts_v2?"
                                                      "$skiptoken=abc"})
            if parts.path == "/v1.0/auditLogs/signIns":
                return self._json({"error": {"code": "Authentication_RequestFromNonPremiumTenantOrB2CTenant",
                                             "message": "Neither tenant is B2C or tenant doesn't have premium license"}},
                                  403)
        return HttpResponse(404, {}, b"{}")

    @staticmethod
    def _json(obj, status=200):
        return HttpResponse(status, {}, json.dumps(obj).encode())


def use_fake(c, fake):
    """Hintergrund-Thread anhalten, damit nur der Test abruft."""
    c.core.m365.stop()
    c.core.m365._stop.clear()  # Thread ist beendet; poll_once() soll im Test trotzdem arbeiten
    c.core.m365.http = fake
    return c.core.m365


def configure(c, **extra):
    body = {"enabled": True, "tenant_id": TENANT, "client_id": CLIENT, "client_secret": SECRET, **extra}
    r = c.put("/api/m365", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def test_m365_settings_api(admin_client):
    c = admin_client
    data = c.get("/api/m365").json()
    assert data["config"]["enabled"] is False and data["config"]["secret_set"] is False
    assert {s["key"] for s in data["sources"]} == {"entra", "files_teams", "defender", "graph_signins"}
    assert c.put("/api/m365", json={"tenant_id": "kein-guid"}).status_code == 400
    assert c.put("/api/m365", json={"enabled": True, "tenant_id": TENANT}).status_code == 400
    data = configure(c)
    assert data["config"]["secret_set"] is True and "client_secret" not in data["config"]
    assert SECRET not in json.dumps(data)
    # Speichern ohne Schlüssel behält den bisherigen
    data = c.put("/api/m365", json={"sources": {"graph_signins": True}}).json()
    assert data["config"]["secret_set"] is True and data["config"]["sources"]["graph_signins"] is True
    assert c.core.m365.config()["client_secret"] == SECRET
    # Leserechte genügen nicht für die Zugangsdaten
    c.post("/api/users", json={"username": "leser", "role": "viewer", "password": "Leser-Passwort-1"})
    c.post("/api/auth/logout")
    login(c, "leser", "Leser-Passwort-1")
    assert c.get("/api/m365").status_code == 403
    assert c.get("/api/m365/status").status_code == 200
    assert c.post("/api/m365/test", json={}).status_code == 403


def test_m365_connection_test(admin_client):
    c = admin_client
    fake = FakeMicrosoft(time.time())
    use_fake(c, fake)
    configure(c, sources={"entra": True, "files_teams": True, "defender": True, "graph_signins": True})
    res = c.post("/api/m365/test", json={}).json()
    by = {r["source"]: r for r in res["results"]}
    assert by["audit"]["ok"] and "12 Stunden" in by["audit"]["message"]
    assert by["defender"]["ok"]
    assert not by["graph_signins"]["ok"] and "P1" in by["graph_signins"]["message"]
    assert res["ok"] is False
    # falscher Schlüssel (noch nicht gespeichert) wird verständlich gemeldet
    res = c.post("/api/m365/test", json={"client_secret": "falsch"}).json()
    assert all("Clientschlüssel ist falsch" in r["message"] for r in res["results"])
    assert c.core.m365.config()["client_secret"] == SECRET
    assert not fake.subscriptions, "der Test darf keine Abonnements starten"


def test_m365_poll_end_to_end(admin_client):
    c = admin_client
    now = time.time()
    fake = FakeMicrosoft(now)
    m = use_fake(c, fake)
    configure(c, sources={"entra": True, "files_teams": True, "defender": True, "graph_signins": False})
    status = m.poll_once()
    assert all(s["ok"] for s in status["sources"].values()), status
    assert fake.subscriptions == {"Audit.AzureActiveDirectory", "Audit.SharePoint", "Audit.General"}
    # 2 Entra (Duplikat r1 verworfen) + 1 SharePoint (PageViewed verworfen) + 2 Defender
    assert status["sources"]["entra"]["last_events"] == 2
    assert status["sources"]["files_teams"]["last_events"] == 1
    assert status["sources"]["defender"]["last_events"] == 2
    wait_processed(c, 5)
    t = {"from": now - 86400, "to": now + 60}
    evs = c.get("/api/events", params={"q": "input:m365", **t}).json()["events"]
    assert len(evs) == 5
    assert {e["app"] for e in evs} == {"entra-id", "sharepoint", "defender"}
    assert all(e["host"] == "microsoft365" for e in evs)

    # zweiter Abruf: keine Duplikate
    status = m.poll_once()
    assert sum(s["last_events"] for s in status["sources"].values()) == 0
    # Token wurde je Dienst nur einmal geholt
    logins = [x for x in fake.calls if x[1] == "login.microsoftonline.com"]
    assert len(logins) == 2
    # Status übersteht einen Neustart (wird gespeichert)
    assert c.core.m365._load_status()["sources"]["defender"]["events"] == 2
    src = {(s["host"], s["input"]) for s in c.get("/api/sources").json()["sources"]}
    assert ("microsoft365", "m365") in src


def test_m365_token_only_sent_to_microsoft(admin_client):
    c = admin_client
    fake = FakeMicrosoft(time.time())
    fake.evil_next = True
    use_fake(c, fake)
    configure(c, sources={"entra": True, "files_teams": False, "defender": False})
    status = c.core.m365.poll_once()
    assert status["sources"]["entra"]["ok"] is False
    assert "Unerwartete Adresse" in status["sources"]["entra"]["error"]
    assert not any(x[1] == "evil.example" for x in fake.calls)


def test_m365_graph_signins_replace_audit_logins(admin_client):
    c = admin_client
    fake = FakeMicrosoft(time.time())
    signins = [{"id": "g1", "createdDateTime": iso(time.time() - 60), "userPrincipalName": "j.mueller@firma.at",
                "ipAddress": "203.0.113.9", "status": {"errorCode": 50126},
                "location": {"countryOrRegion": "AT"}}]
    original = fake.__call__

    def http(method, url, headers, body, timeout):
        if "/auditLogs/signIns" in url:
            return HttpResponse(200, {}, json.dumps({"value": signins}).encode())
        return original(method, url, headers, body, timeout)

    use_fake(c, http)
    configure(c, sources={"entra": True, "files_teams": False, "defender": False, "graph_signins": True})
    status = c.core.m365.poll_once()
    assert status["sources"]["graph_signins"]["last_events"] == 1
    # aus dem Audit-Log kommt nur noch die Rollenzuweisung, die Anmeldung nicht doppelt
    assert status["sources"]["entra"]["last_events"] == 1


def test_m365_error_messages():
    from siem.m365 import _api_error

    e = _api_error(HttpResponse(403, {}, json.dumps({"error": {"code": "AF10001", "message": "x"}}).encode()),
                   "Office 365 Management APIs → ActivityFeed.Read")
    assert isinstance(e, M365Error) and "ActivityFeed.Read" in e.message
    e = _api_error(HttpResponse(429, {"retry-after": "60"}, b""), "x")
    assert e.retry_after == 60


# --------------------------------------------------------------------------- Erkennungsregeln


def _rule(key):
    from siem.detection import validate_rule
    from siem.rules_default import DEFAULT_RULES

    return validate_rule(next(r for r in DEFAULT_RULES if r["key"] == key))


def _fires(key, events) -> list[dict]:
    from siem.detection import simulate

    return simulate(_rule(key), events)


def _login(user, ip, code, ts):
    return parse_m365("audit", {"Operation": "UserLoginFailed" if code else "UserLoggedIn", "RecordType": 15,
                                "Workload": "AzureActiveDirectory", "CreationTime": iso(ts), "UserId": user,
                                "ClientIP": ip, "ErrorCode": str(code)})


def test_rules_m365_logins():
    t = time.time() - 3000
    spray = [_login(f"user{i}@firma.at", "198.51.100.66", 50126, t + i) for i in range(6)]
    hits = _fires("m365-password-spray", spray)
    assert len(hits) == 1 and hits[0]["group_value"] == "198.51.100.66"
    brute = [_login("chef@firma.at", f"203.0.113.{i}", 50126, t + i) for i in range(10)]
    assert _fires("m365-login-failures", brute)
    # MFA-Zwischenabfragen und „Angemeldet bleiben?“ sind keine Fehlanmeldungen
    noise = [_login("chef@firma.at", "203.0.113.1", code, t + i) for i, code in enumerate([50140, 50074] * 10)]
    assert not _fires("m365-login-failures", noise)
    fatigue = [_login("chef@firma.at", "203.0.113.1", 500121, t + i) for i in range(3)]
    assert _fires("m365-mfa-fatigue", fatigue)


def test_rules_m365_admin_files_defender():
    now = time.time()
    role = parse_m365("audit", {"Operation": "Add member to role.", "Workload": "AzureActiveDirectory",
                                "CreationTime": iso(now), "UserId": "admin@firma.at",
                                "ModifiedProperties": [{"Name": "Role.DisplayName", "NewValue": "Global Administrator"}]})
    assert _fires("m365-admin-role", [role])
    consent = parse_m365("audit", {"Operation": "Consent to application.", "Workload": "AzureActiveDirectory",
                                   "CreationTime": iso(now), "UserId": "j.mueller@firma.at"})
    assert _fires("m365-app-consent", [consent])
    fed = parse_m365("audit", {"Operation": "Set federation settings on domain.", "Workload": "AzureActiveDirectory",
                               "CreationTime": iso(now), "UserId": "admin@firma.at"})
    assert _fires("m365-federation", [fed])
    mfa = parse_m365("audit", {"Operation": "User deleted security info", "Workload": "AzureActiveDirectory",
                               "CreationTime": iso(now), "UserId": "j.mueller@firma.at"})
    assert _fires("m365-mfa-change", [mfa])

    deletes = [parse_m365("audit", {"Operation": "FileDeleted", "Workload": "OneDrive", "CreationTime": iso(now - 300 + i),
                                    "UserId": "j.mueller@firma.at", "SourceFileName": f"d{i}.docx"})
               for i in range(100)]
    assert _fires("m365-mass-delete", deletes) and not _fires("m365-mass-delete", deletes[:50])
    link = parse_m365("audit", {"Operation": "AnonymousLinkCreated", "Workload": "SharePoint",
                                "CreationTime": iso(now), "UserId": "x@firma.at"})
    assert _fires("m365-anonymous-link", [link])

    high = parse_m365("alert", {"id": "1", "createdDateTime": iso(now), "title": "Ransomware", "severity": "high"})
    low = parse_m365("alert", {"id": "2", "createdDateTime": iso(now), "title": "Test", "severity": "low"})
    assert _fires("defender-high", [high]) and not _fires("defender-high", [low])
    assert _fires("defender-low", [low])
    # Defender-Warnungen lösen nicht zusätzlich die allgemeine Regel „Kritische Meldungen“ aus
    assert not _fires("critical-messages", [high])

    foreign = parse_m365("signin", {"id": "s", "createdDateTime": iso(now), "userPrincipalName": "x@firma.at",
                                    "status": {"errorCode": 0}, "location": {"countryOrRegion": "BR"}})
    home = parse_m365("signin", {"id": "t", "createdDateTime": iso(now), "userPrincipalName": "x@firma.at",
                                 "status": {"errorCode": 0}, "location": {"countryOrRegion": "AT"}})
    assert _fires("m365-foreign-login", [foreign]) and not _fires("m365-foreign-login", [home])
    assert _rule("m365-foreign-login")["enabled"] is False
