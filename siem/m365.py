"""Microsoft-365-Connector.

Holt in regelmäßigen Abständen (Standard: alle 5 Minuten) Ereignisse aus dem
Microsoft-365-Mandanten und gibt sie in die Pipeline:

* **Office 365 Management Activity API** – einheitliches Überwachungsprotokoll:
  ``Audit.AzureActiveDirectory`` (Anmeldungen, Konten, Rollen, Apps) sowie
  ``Audit.SharePoint`` und ``Audit.General`` (SharePoint, OneDrive, Teams).
  Berechtigung: *Office 365 Management APIs → ActivityFeed.Read* (Anwendung).
* **Microsoft Graph** ``security/alerts_v2`` – Defender-Warnungen.
  Berechtigung: *SecurityAlert.Read.All* (Anwendung).
* optional **Microsoft Graph** ``auditLogs/signIns`` – Anmeldungen mit Land,
  Gerät und Risiko (benötigt Entra ID P1). Berechtigung: *AuditLog.Read.All*.

Die Anmeldung erfolgt über eine App-Registrierung mit geheimem Clientschlüssel
(OAuth2 Client Credentials). Der Schlüssel liegt nur in der SIEM-Datenbank und
wird über die API nie zurückgegeben.

Doppelte Lieferungen sind bei Microsoft vorgesehen; der Connector merkt sich
deshalb bereits verarbeitete Inhaltspakete bzw. IDs (Tabelle ``connector_seen``)
und den Stand jedes Abrufs (Tabelle ``connector_state``).
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .m365_events import NOISY_OPERATIONS, utc_time

log = logging.getLogger("siem.m365")

CONNECTOR = "m365"
MANAGE_HOST = "manage.office.com"
MANAGE_SCOPE = "https://manage.office.com/.default"
GRAPH_HOST = "graph.microsoft.com"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"

SOURCES: dict[str, dict] = {
    "entra": {
        "label": "Anmeldungen & Konten (Entra ID)",
        "content_types": ["Audit.AzureActiveDirectory"],
        "permission": "Office 365 Management APIs → ActivityFeed.Read",
    },
    "files_teams": {
        "label": "SharePoint, OneDrive & Teams",
        "content_types": ["Audit.SharePoint", "Audit.General"],
        "permission": "Office 365 Management APIs → ActivityFeed.Read",
    },
    "defender": {
        "label": "Defender-Warnungen",
        "permission": "Microsoft Graph → SecurityAlert.Read.All",
    },
    "graph_signins": {
        "label": "Anmeldedetails mit Land und Risiko (Entra ID P1)",
        "permission": "Microsoft Graph → AuditLog.Read.All",
    },
}
AUDIT_PERMISSION = SOURCES["entra"]["permission"]

DEFAULT_M365: dict = {
    "enabled": False,
    "tenant_id": "",
    "client_id": "",
    "client_secret": "",
    "sources": {"entra": True, "files_teams": True, "defender": True, "graph_signins": False},
    "skip_noise": True,
    "interval": 300,
}

GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")

INITIAL_AUDIT_BACKFILL = 24 * 3600     # erster Abruf: bis zu 24 h zurück (sofern schon abonniert)
AUDIT_OVERLAP = 1800                   # Überlappung zwischen zwei Abrufen (Pakete erscheinen verzögert)
MAX_AUDIT_AGE = 7 * 86400 - 900        # die API liefert höchstens 7 Tage zurück
INITIAL_GRAPH_BACKFILL = 6 * 3600
GRAPH_OVERLAP = 3600
MAX_GRAPH_PAGES = 200
SEEN_DAYS = 8
SUBSCRIPTION_CHECK = 6 * 3600
MAX_BODY = 256 << 20


def login_url(tenant: str) -> str:
    return "https://login.microsoftonline.com/" + urllib.parse.quote(tenant) + "/oauth2/v2.0/token"


def manage_url(tenant: str, path: str) -> str:
    return "https://" + MANAGE_HOST + "/api/v1.0/" + urllib.parse.quote(tenant) + "/activity/feed" + path


class M365Error(Exception):
    """Fehler mit einer Meldung für die Oberfläche."""

    def __init__(self, message: str, retry_after: float | None = None):
        super().__init__(message)
        self.message = message
        self.retry_after = retry_after


# --------------------------------------------------------------------------- Konfiguration


def validate_m365(cfg: dict, existing: dict | None = None) -> dict:
    """Prüft und vervollständigt die Einstellungen. Ein leerer Schlüssel behält den bisherigen."""
    existing = existing or {}
    out = json.loads(json.dumps(DEFAULT_M365))
    for key in ("tenant_id", "client_id"):
        raw = cfg.get(key) if cfg.get(key) is not None else existing.get(key)
        v = str(raw or "").strip()
        if v and not GUID_RE.match(v):
            name = "Verzeichnis-ID (Mandant)" if key == "tenant_id" else "Anwendungs-ID (Client)"
            raise ValueError(f"{name}: bitte die GUID aus der App-Registrierung eintragen "
                             "(Format 00000000-0000-0000-0000-000000000000)")
        out[key] = v.lower()
    secret = cfg.get("client_secret")
    out["client_secret"] = str(secret).strip() if secret else str(existing.get("client_secret") or "")
    if len(out["client_secret"]) > 512:
        raise ValueError("Der geheime Clientschlüssel ist zu lang")
    sources = cfg.get("sources") if isinstance(cfg.get("sources"), dict) else existing.get("sources") or {}
    for key in SOURCES:
        if key in sources:
            out["sources"][key] = bool(sources[key])
    out["skip_noise"] = bool(cfg.get("skip_noise", existing.get("skip_noise", True)))
    try:
        out["interval"] = max(60, min(3600, int(cfg.get("interval") or existing.get("interval") or 300)))
    except (TypeError, ValueError):
        raise ValueError("Das Abrufintervall muss eine Zahl (Sekunden) sein") from None
    out["enabled"] = bool(cfg.get("enabled", existing.get("enabled", False)))
    if out["enabled"]:
        missing = [n for k, n in (("tenant_id", "Verzeichnis-ID"), ("client_id", "Anwendungs-ID"),
                                  ("client_secret", "geheimer Clientschlüssel")) if not out[k]]
        if missing:
            raise ValueError("Zum Aktivieren fehlt: " + ", ".join(missing))
        if not any(out["sources"].values()):
            raise ValueError("Bitte mindestens einen Bereich auswählen")
    return out


def public_config(cfg: dict) -> dict:
    out = {k: v for k, v in cfg.items() if k != "client_secret"}
    out["secret_set"] = bool(cfg.get("client_secret"))
    return out


def is_ready(cfg: dict) -> bool:
    return bool(cfg.get("enabled") and cfg.get("tenant_id") and cfg.get("client_id") and cfg.get("client_secret"))


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


# --------------------------------------------------------------------------- HTTP


@dataclass
class HttpResponse:
    status: int
    headers: dict = field(default_factory=dict)
    body: bytes = b""

    def json(self):
        try:
            return json.loads(self.body.decode("utf-8-sig") or "null")
        except ValueError:
            return None


def urllib_transport(method: str, url: str, headers: dict, body: bytes | None, timeout: float) -> HttpResponse:
    """Standard-HTTP über die Python-Bibliothek (beachtet HTTPS_PROXY)."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - nur https-URLs von Microsoft
            return HttpResponse(resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read(MAX_BODY))
    except urllib.error.HTTPError as exc:
        return HttpResponse(exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()}, exc.read(1 << 20))
    except (urllib.error.URLError, OSError) as exc:
        host = urllib.parse.urlsplit(url).hostname
        reason = getattr(exc, "reason", exc)
        raise M365Error(f"Keine Verbindung zu {host}: {reason}") from None


def _check_url(url: str, host: str) -> str:
    """Folge-URLs aus Antworten nur an den erwarteten Microsoft-Dienst senden (Schutz des Tokens)."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname != host:
        raise M365Error(f"Unerwartete Adresse in der Antwort von Microsoft: {parts.hostname}")
    return url


def _with_param(url: str, name: str, value: str) -> str:
    if (name + "=") in url:
        return url
    return url + ("&" if "?" in url else "?") + urllib.parse.urlencode({name: value})


def _error_code(resp: HttpResponse) -> str | None:
    data = resp.json()
    if isinstance(data, dict) and isinstance(data.get("error"), dict):
        return str(data["error"].get("code") or "") or None
    return None


def _token_error(data) -> str:
    desc = ""
    if isinstance(data, dict):
        desc = str(data.get("error_description") or data.get("error") or "")
    known = {
        "AADSTS7000215": "Der geheime Clientschlüssel ist falsch – bitte den Wert des Schlüssels eintragen, "
                         "nicht die Geheimnis-ID.",
        "AADSTS7000222": "Der geheime Clientschlüssel ist abgelaufen – bitte in der App-Registrierung "
                         "einen neuen erstellen.",
        "AADSTS700016": "Die Anwendungs-ID wurde in diesem Mandanten nicht gefunden.",
        "AADSTS90002": "Der Mandant (Verzeichnis-ID) wurde nicht gefunden.",
        "AADSTS900023": "Die Verzeichnis-ID ist ungültig.",
        "AADSTS700024": "Der Client-Nachweis ist ungültig oder abgelaufen.",
        "AADSTS53003": "Die Anmeldung der Anwendung wurde durch bedingten Zugriff blockiert.",
    }
    for code, text in known.items():
        if code in desc:
            return text
    first = desc.splitlines()[0] if desc else "unbekannter Fehler"
    return f"Anmeldung bei Microsoft fehlgeschlagen: {first[:300]}"


def _api_error(resp: HttpResponse, permission: str) -> M365Error:
    data = resp.json()
    code = message = ""
    if isinstance(data, dict):
        err = data.get("error")
        if isinstance(err, dict):
            code = str(err.get("code") or "")
            message = str(err.get("message") or "")
        elif isinstance(err, str):
            code, message = err, str(data.get("error_description") or data.get("message") or "")
        else:
            message = str(data.get("Message") or data.get("message") or "")
    if resp.status == 429 or code == "AF429":
        try:
            retry = float(resp.headers.get("retry-after") or 120)
        except ValueError:
            retry = 120.0
        return M365Error("Microsoft drosselt die Abfragen (zu viele Anfragen) – nächster Versuch später.", retry)
    if code == "Authentication_RequestFromNonPremiumTenantOrB2CTenant":
        return M365Error("Für Anmeldedetails über Graph ist eine Entra-ID-P1-Lizenz nötig "
                         "(z. B. in Microsoft 365 Business Premium enthalten).")
    if code == "AF10001" or resp.status in (401, 403):
        detail = f" ({code or resp.status}: {message[:200]})" if message else f" ({code or resp.status})"
        return M365Error(f"Zugriff verweigert – Berechtigung „{permission}“ fehlt oder die "
                         f"Administratorzustimmung wurde nicht erteilt.{detail}")
    if code == "AF20013":
        return M365Error("Die Verzeichnis-ID ist keine gültige GUID.")
    if code == "AF20011":
        return M365Error("Der Mandant ist bei der Office 365 Management API nicht bekannt.")
    text = message or resp.body[:200].decode("utf-8", errors="replace")
    return M365Error(f"Fehler {resp.status}{' ' + code if code else ''}: {text[:300]}")


# --------------------------------------------------------------------------- Connector


class M365Connector:
    def __init__(self, db, pipeline, http=None, clock=None):
        self.db = db
        self.pipeline = pipeline
        self.http = http or urllib_transport
        self.now = clock or time.time
        self._tokens: dict[tuple, tuple[str, float]] = {}
        self._subscribed: dict[str, float] = {}
        self._recent: OrderedDict = OrderedDict()
        self._lock = threading.Lock()
        self._status_lock = threading.Lock()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._retry_after = 0.0
        self.running = False
        self.status = self._load_status()

    # ---------------------------------------------------------------- Einstellungen & Zustand

    def config(self) -> dict:
        stored = self.db.get_setting("m365") or {}
        try:
            return validate_m365(stored, stored)
        except ValueError:
            return validate_m365({**stored, "enabled": False}, stored)

    def save_config(self, cfg: dict) -> None:
        old = self.db.get_setting("m365") or {}
        self.db.set_setting("m365", cfg)
        if (old.get("tenant_id"), old.get("client_id"), old.get("client_secret")) != (
                cfg.get("tenant_id"), cfg.get("client_id"), cfg.get("client_secret")):
            self._tokens.clear()
            self._subscribed.clear()
        if old.get("tenant_id") != cfg.get("tenant_id"):
            self.reset_state()
        self.wake()

    def reset_state(self) -> None:
        """Anderer Mandant: Abrufstand und Status verwerfen."""
        with self.db.tx() as conn:
            conn.execute("DELETE FROM connector_state WHERE connector = ?", (CONNECTOR,))
            conn.execute("DELETE FROM connector_seen WHERE connector LIKE ?", (CONNECTOR + "-%",))
        self._recent.clear()
        with self._status_lock:
            self.status = {"last_run": None, "sources": {}}

    def snapshot(self) -> dict:
        with self._status_lock:
            out = json.loads(json.dumps(self.status))
        out["running"] = self.running
        return out

    def _state(self, key: str, default=None):
        row = self.db.one("SELECT value FROM connector_state WHERE connector = ? AND key = ?", (CONNECTOR, key))
        if row is None:
            return default
        try:
            return json.loads(row["value"])
        except ValueError:
            return default

    def _set_state(self, key: str, value) -> None:
        self.db.execute(
            "INSERT INTO connector_state(connector, key, value, updated) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(connector, key) DO UPDATE SET value = excluded.value, updated = excluded.updated",
            (CONNECTOR, key, json.dumps(value), time.time()),
        )

    def _load_status(self) -> dict:
        st = self._state("status") or {}
        st.setdefault("last_run", None)
        st.setdefault("sources", {})
        return st

    def _seen(self, kind: str, items: list[str]) -> set[str]:
        found: set[str] = set()
        name = CONNECTOR + "-" + kind
        for i in range(0, len(items), 500):
            chunk = items[i:i + 500]
            marks = ",".join("?" * len(chunk))
            rows = self.db.all("SELECT item FROM connector_seen WHERE connector = ? AND item IN (" + marks + ")",
                               [name, *chunk])
            found.update(r["item"] for r in rows)
        return found

    def _mark_seen(self, kind: str, items: list[str]) -> None:
        if not items:
            return
        now = time.time()
        with self.db.tx() as conn:
            conn.executemany("INSERT OR IGNORE INTO connector_seen(connector, item, ts) VALUES (?, ?, ?)",
                             [(CONNECTOR + "-" + kind, it, now) for it in items])

    def _prune_seen(self) -> None:
        self.db.execute("DELETE FROM connector_seen WHERE connector LIKE ? AND ts < ?",
                        (CONNECTOR + "-%", time.time() - SEEN_DAYS * 86400))

    # ---------------------------------------------------------------- HTTP-Grundlagen

    def token(self, cfg: dict, scope: str) -> str:
        key = (cfg["tenant_id"], cfg["client_id"], cfg["client_secret"], scope)
        cached = self._tokens.get(key)
        if cached and cached[1] > time.time() + 120:
            return cached[0]
        body = urllib.parse.urlencode({
            "client_id": cfg["client_id"], "client_secret": cfg["client_secret"],
            "grant_type": "client_credentials", "scope": scope,
        }).encode()
        resp = self.http("POST", login_url(cfg["tenant_id"]),
                         {"Content-Type": "application/x-www-form-urlencoded"}, body, 30)
        data = resp.json()
        if resp.status != 200 or not isinstance(data, dict) or not data.get("access_token"):
            raise M365Error(_token_error(data))
        try:
            lifetime = float(data.get("expires_in") or 3600)
        except (TypeError, ValueError):
            lifetime = 3600.0
        self._tokens[key] = (data["access_token"], time.time() + lifetime)
        return data["access_token"]

    def _request(self, cfg: dict, method: str, url: str, scope: str) -> HttpResponse:
        headers = {"Authorization": "Bearer " + self.token(cfg, scope), "Accept": "application/json"}
        body = None
        if method == "POST":
            headers["Content-Type"] = "application/json"
            body = b""
        resp = self.http(method, url, headers, body, 120)
        if resp.status == 401:
            # Token evtl. widerrufen: einmal neu anmelden
            self._tokens.pop((cfg["tenant_id"], cfg["client_id"], cfg["client_secret"], scope), None)
            headers["Authorization"] = "Bearer " + self.token(cfg, scope)
            resp = self.http(method, url, headers, body, 120)
        return resp

    def _manage(self, cfg: dict, method: str, path_or_url: str, params: dict | None = None) -> HttpResponse:
        tenant = cfg["tenant_id"]
        if path_or_url.startswith("https://"):
            url = _check_url(path_or_url, MANAGE_HOST)
        else:
            url = manage_url(tenant, path_or_url)
            if params:
                url += "?" + urllib.parse.urlencode(params)
        return self._request(cfg, method, _with_param(url, "PublisherIdentifier", tenant), MANAGE_SCOPE)

    def _graph(self, cfg: dict, url: str, permission: str) -> dict:
        resp = self._request(cfg, "GET", _check_url(url, GRAPH_HOST), GRAPH_SCOPE)
        if resp.status != 200:
            raise _api_error(resp, permission)
        data = resp.json()
        if not isinstance(data, dict):
            raise M365Error("Unerwartete Antwort von Microsoft Graph")
        return data

    # ---------------------------------------------------------------- Überwachungsprotokoll

    def _ensure_subscriptions(self, cfg: dict, content_types: list[str]) -> None:
        now = time.time()
        if all(now - self._subscribed.get(ct, 0) < SUBSCRIPTION_CHECK for ct in content_types):
            return
        resp = self._manage(cfg, "GET", "/subscriptions/list")
        if resp.status != 200:
            raise _api_error(resp, AUDIT_PERMISSION)
        enabled = {s.get("contentType") for s in (resp.json() or []) if isinstance(s, dict)
                   and str(s.get("status") or "").lower() == "enabled"}
        for ct in content_types:
            if ct not in enabled:
                r = self._manage(cfg, "POST", "/subscriptions/start", {"contentType": ct})
                if r.status not in (200, 201) and _error_code(r) != "AF20024":  # AF20024 = bereits aktiv
                    raise _api_error(r, AUDIT_PERMISSION)
                log.info("Microsoft 365: Abonnement %s gestartet – erste Daten können bis zu 12 Stunden dauern", ct)
            self._subscribed[ct] = now

    def _list_content(self, cfg: dict, ct: str, start: float, end: float) -> list[dict]:
        blobs: list[dict] = []
        resp = self._manage(cfg, "GET", "/subscriptions/content",
                            {"contentType": ct, "startTime": _iso(start), "endTime": _iso(end)})
        for _ in range(1000):
            if resp.status != 200:
                if _error_code(resp) in ("AF20022", "AF20023"):  # kein bzw. abgeschaltetes Abonnement
                    self._subscribed.pop(ct, None)
                raise _api_error(resp, AUDIT_PERMISSION)
            page = resp.json() or []
            blobs.extend(b for b in page if isinstance(b, dict))
            nxt = resp.headers.get("nextpageuri")
            if not nxt:
                break
            resp = self._manage(cfg, "GET", nxt)
        return blobs

    def _remember(self, record_id) -> bool:
        """True, wenn der Datensatz neu ist (Microsoft liefert gelegentlich doppelt)."""
        if not record_id:
            return True
        if record_id in self._recent:
            return False
        self._recent[record_id] = None
        if len(self._recent) > 200_000:
            self._recent.popitem(last=False)
        return True

    def _submit(self, kind: str, records: list[dict]) -> int:
        if not records:
            return 0
        deadline = time.time() + 120
        while not self.pipeline.has_capacity(len(records)) and time.time() < deadline and not self._stop.is_set():
            time.sleep(0.5)
        received = time.time()
        return sum(1 for r in records if self.pipeline.submit("m365", (kind, r), None, received))

    def _audit_filter(self, cfg: dict, records) -> list[dict]:
        graph_logins = bool(cfg["sources"].get("graph_signins")) and bool(
            (self.status["sources"].get("graph_signins") or {}).get("ok"))
        out = []
        for r in records if isinstance(records, list) else []:
            if not isinstance(r, dict):
                continue
            op = r.get("Operation")
            if cfg.get("skip_noise") and op in NOISY_OPERATIONS:
                continue
            # Anmeldungen kommen dann ausführlicher über Graph – nicht doppelt speichern
            if graph_logins and op in ("UserLoggedIn", "UserLoginFailed") and r.get("RecordType") == 15:
                continue
            if self._remember(r.get("Id")):
                out.append(r)
        return out

    def poll_audit(self, cfg: dict, content_types: list[str]) -> int:
        self._ensure_subscriptions(cfg, content_types)
        total = 0
        now = self.now()
        for ct in content_types:
            last = self._state("audit:" + ct + ":end")
            start = (float(last) - AUDIT_OVERLAP) if last else now - INITIAL_AUDIT_BACKFILL
            start = max(start, now - MAX_AUDIT_AGE)
            while start < now - 30 and not self._stop.is_set():
                end = min(start + 86400, now)
                blobs = self._list_content(cfg, ct, start, end)
                done = self._seen("audit", [str(b.get("contentId")) for b in blobs if b.get("contentId")])
                for blob in blobs:
                    cid = str(blob.get("contentId") or "")
                    uri = blob.get("contentUri")
                    if not cid or not uri or cid in done:
                        continue
                    resp = self._manage(cfg, "GET", str(uri))
                    if resp.status != 200:
                        raise _api_error(resp, AUDIT_PERMISSION)
                    total += self._submit("audit", self._audit_filter(cfg, resp.json()))
                    self._mark_seen("audit", [cid])
                    done.add(cid)
                self._set_state("audit:" + ct + ":end", end)
                start = end
        return total

    # ---------------------------------------------------------------- Graph

    def _poll_graph(self, cfg: dict, key: str, path: str, kind: str) -> int:
        permission = SOURCES[key]["permission"]
        now = self.now()
        last = self._state(key + ":last")
        since = (float(last) - GRAPH_OVERLAP) if last else now - INITIAL_GRAPH_BACKFILL
        url = GRAPH_BASE + path + "?" + urllib.parse.urlencode(
            {"$filter": "createdDateTime ge " + _iso(since) + "Z", "$top": "500"})
        newest = float(last) if last else 0.0
        total = 0
        for _ in range(MAX_GRAPH_PAGES):
            data = self._graph(cfg, url, permission)
            items = [r for r in data.get("value") or [] if isinstance(r, dict) and r.get("id")]
            done = self._seen(key, [str(r["id"]) for r in items])
            fresh = [r for r in items if str(r["id"]) not in done]
            total += self._submit(kind, fresh)
            self._mark_seen(key, [str(r["id"]) for r in fresh])
            for r in fresh:
                ts = utc_time(r.get("createdDateTime"))
                if ts and ts > newest:
                    newest = min(ts, now)
            url = data.get("@odata.nextLink")
            if not url or self._stop.is_set():
                break
        if newest:
            self._set_state(key + ":last", newest)
        return total

    def poll_signins(self, cfg: dict) -> int:
        return self._poll_graph(cfg, "graph_signins", "/auditLogs/signIns", "signin")

    def poll_alerts(self, cfg: dict) -> int:
        return self._poll_graph(cfg, "defender", "/security/alerts_v2", "alert")

    # ---------------------------------------------------------------- Ablauf

    def poll_once(self, cfg: dict | None = None) -> dict:
        cfg = cfg or self.config()
        src = cfg["sources"]
        # Graph-Anmeldungen zuerst: davon hängt ab, ob das Audit-Log Anmeldungen liefern muss
        jobs = [
            ("graph_signins", lambda: self.poll_signins(cfg)),
            ("entra", lambda: self.poll_audit(cfg, SOURCES["entra"]["content_types"])),
            ("files_teams", lambda: self.poll_audit(cfg, SOURCES["files_teams"]["content_types"])),
            ("defender", lambda: self.poll_alerts(cfg)),
        ]
        with self._lock:
            self.running = True
            try:
                for key, job in jobs:
                    if not src.get(key):
                        with self._status_lock:
                            self.status["sources"].pop(key, None)
                        continue
                    try:
                        n = job()
                        update = {"ok": True, "last_success": time.time(), "last_events": n, "error": None}
                    except M365Error as exc:
                        n, update = 0, {"ok": False, "error": exc.message, "error_at": time.time()}
                        if exc.retry_after:
                            self._retry_after = max(self._retry_after, time.time() + exc.retry_after)
                        log.warning("Microsoft 365 (%s): %s", SOURCES[key]["label"], exc.message)
                    except Exception as exc:  # noqa: BLE001 - der Connector läuft weiter
                        n, update = 0, {"ok": False, "error": f"Interner Fehler: {exc}", "error_at": time.time()}
                        log.exception("Microsoft 365 (%s): Abruf fehlgeschlagen", key)
                    with self._status_lock:
                        st = self.status["sources"].setdefault(key, {"events": 0})
                        st.update(update)
                        st["events"] = int(st.get("events") or 0) + n
                with self._status_lock:
                    self.status["last_run"] = time.time()
                    saved = json.loads(json.dumps(self.status))
                self._set_state("status", saved)
                self._prune_seen()
            finally:
                self.running = False
        return self.snapshot()

    def test(self, cfg: dict) -> list[dict]:
        """Prüft Anmeldung und Berechtigungen, ohne Daten zu übernehmen."""
        src = cfg["sources"]
        checks = []
        if src.get("entra") or src.get("files_teams"):
            checks.append(("audit", "Überwachungsprotokoll (Management Activity API)"))
        if src.get("defender"):
            checks.append(("defender", SOURCES["defender"]["label"]))
        if src.get("graph_signins"):
            checks.append(("graph_signins", SOURCES["graph_signins"]["label"]))
        results = []
        for key, label in checks:
            try:
                if key == "audit":
                    resp = self._manage(cfg, "GET", "/subscriptions/list")
                    if resp.status != 200:
                        raise _api_error(resp, AUDIT_PERMISSION)
                    active = sorted(str(s.get("contentType")) for s in (resp.json() or [])
                                    if isinstance(s, dict) and str(s.get("status")).lower() == "enabled")
                    msg = "Zugriff funktioniert."
                    if active:
                        msg += " Aktive Abonnements: " + ", ".join(active) + "."
                    else:
                        msg += (" Die Abonnements werden beim ersten Abruf gestartet – erste Daten können bis zu "
                                "12 Stunden dauern. Das Überwachungsprotokoll muss in Microsoft Purview "
                                "aktiviert sein.")
                elif key == "defender":
                    self._graph(cfg, GRAPH_BASE + "/security/alerts_v2?$top=1", SOURCES[key]["permission"])
                    msg = "Zugriff auf Defender-Warnungen funktioniert."
                else:
                    self._graph(cfg, GRAPH_BASE + "/auditLogs/signIns?$top=1", SOURCES[key]["permission"])
                    msg = "Zugriff auf die Anmeldeprotokolle funktioniert."
                results.append({"source": key, "label": label, "ok": True, "message": msg})
            except M365Error as exc:
                results.append({"source": key, "label": label, "ok": False, "message": exc.message})
        return results

    def wake(self) -> None:
        self._wake.set()

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="siem-m365", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 10) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout)

    def _run(self) -> None:
        self._wake.wait(5)
        while not self._stop.is_set():
            self._wake.clear()
            cfg = self.config()
            delay = 3600.0
            if is_ready(cfg) and time.time() >= self._retry_after:
                try:
                    self.poll_once(cfg)
                except Exception:  # noqa: BLE001
                    log.exception("Microsoft 365: Abruf fehlgeschlagen")
                delay = float(cfg["interval"])
            if self._retry_after > time.time():
                delay = max(delay, self._retry_after - time.time())
            self._wake.wait(delay)
