"""Annahme von Logs über HTTP.

* ``POST /api/ingest`` – JSON-Objekt, JSON-Array, NDJSON oder Textzeilen
  (geeignet für Fluent Bit, Vector, NXLog, Skripte, curl …)
* ``POST /services/collector/event`` – Splunk-HEC-kompatibel, u. a. für den
  Docker-Logging-Treiber ``splunk`` (ganz ohne zusätzlichen Agenten)

Authentifizierung mit einem Ingest-Token aus der Oberfläche (Quellen → Tokens):
``Authorization: Bearer <token>``, ``Authorization: Splunk <token>``,
``X-API-Key: <token>``, HTTP-Basic (Passwort = Token) oder ``?token=<token>``.
"""

from __future__ import annotations

import base64
import gzip
import json
import time
import zlib

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from .deps import client_ip, get_core

router = APIRouter(tags=["Ingest"])

MAX_BODY = 20 * 1024 * 1024
MAX_EVENTS_PER_REQUEST = 100_000


class IngestError(Exception):
    def __init__(self, status: int, message: str, hec_code: int = 6):
        self.status = status
        self.message = message
        self.hec_code = hec_code


def _token_from(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth:
        scheme, _, value = auth.partition(" ")
        scheme = scheme.lower()
        if scheme in ("bearer", "splunk", "token"):
            return value.strip()
        if scheme == "basic":
            try:
                decoded = base64.b64decode(value.strip()).decode()
                return decoded.partition(":")[2] or decoded.partition(":")[0]
            except (ValueError, UnicodeDecodeError):
                return None
    return (request.headers.get("x-api-key") or request.headers.get("x-siem-token")
            or request.query_params.get("token"))


async def _read_body(request: Request) -> bytes:
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > MAX_BODY:
        raise IngestError(413, "Anfrage zu groß (max. 20 MB)", 6)
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_BODY:
            raise IngestError(413, "Anfrage zu groß (max. 20 MB)", 6)
    data = bytes(body)
    enc = request.headers.get("content-encoding", "").lower()
    try:
        if enc == "gzip" or data[:2] == b"\x1f\x8b":
            data = gzip.decompress(data)
        elif enc == "deflate":
            data = zlib.decompress(data)
    except (OSError, zlib.error):
        raise IngestError(400, "Komprimierte Daten konnten nicht gelesen werden", 6) from None
    if len(data) > MAX_BODY * 5:
        raise IngestError(413, "Entpackte Daten zu groß", 6)
    return data


def _iter_json_values(text: str):
    """Liest aneinandergereihte JSON-Werte (NDJSON oder ohne Trennzeichen)."""
    dec = json.JSONDecoder()
    i, n = 0, len(text)
    while i < n:
        while i < n and text[i] in " \t\r\n,":
            i += 1
        if i >= n:
            break
        value, i = dec.raw_decode(text, i)
        yield value


def _items_generic(data: bytes) -> list[tuple[str, object]]:
    text = data.decode("utf-8", errors="replace")
    stripped = text.lstrip()
    items: list[tuple[str, object]] = []
    if stripped[:1] in ("{", "["):
        try:
            for value in _iter_json_values(stripped):
                values = value if isinstance(value, list) else [value]
                for v in values:
                    items.append(("json", v) if isinstance(v, dict) else ("text", str(v)))
            return items
        except ValueError:
            items = []  # kein gültiges JSON -> als Text behandeln
    for line in text.splitlines():
        if line.strip():
            items.append(("text", line))
    return items


def _items_hec(data: bytes) -> list[tuple[str, object]]:
    text = data.decode("utf-8", errors="replace")
    items = []
    try:
        for value in _iter_json_values(text):
            if isinstance(value, dict):
                items.append(("hec", value))
    except ValueError:
        raise IngestError(400, "Ungültiges JSON", 6) from None
    return items


def _items_raw(data: bytes) -> list[tuple[str, object]]:
    return [("text", line) for line in data.decode("utf-8", errors="replace").splitlines() if line.strip()]


async def _ingest(request: Request, core, parser) -> int:
    token_id = core.tokens.lookup(_token_from(request))
    if token_id is None:
        raise IngestError(401, "Ungültiges oder fehlendes Ingest-Token", 4)
    data = await _read_body(request)
    if not data.strip():
        raise IngestError(400, "Keine Daten", 5)
    items = await run_in_threadpool(parser, data)
    if len(items) > MAX_EVENTS_PER_REQUEST:
        raise IngestError(413, "Zu viele Events in einer Anfrage", 6)
    if not core.pipeline.has_capacity(len(items)):
        raise IngestError(503, "Das SIEM ist ausgelastet – bitte später erneut senden", 9)
    ip = client_ip(request)
    now = time.time()
    accepted = sum(1 for kind, payload in items if core.pipeline.submit(kind, payload, ip, now))
    core.pipeline.count_token(token_id, accepted)
    return accepted


@router.post("/api/ingest")
async def ingest(request: Request, core=Depends(get_core)):
    try:
        n = await _ingest(request, core, _items_generic)
    except IngestError as exc:
        return JSONResponse({"detail": exc.message}, status_code=exc.status)
    return {"accepted": n}


HEC_PATHS = ("/services/collector", "/services/collector/event", "/services/collector/event/1.0")
HEC_RAW_PATHS = ("/services/collector/raw", "/services/collector/raw/1.0")


async def _hec(request: Request, core, parser):
    try:
        await _ingest(request, core, parser)
    except IngestError as exc:
        return JSONResponse({"text": exc.message, "code": exc.hec_code}, status_code=exc.status)
    return {"text": "Success", "code": 0}


async def hec_event(request: Request, core=Depends(get_core)):
    return await _hec(request, core, _items_hec)


async def hec_raw(request: Request, core=Depends(get_core)):
    return await _hec(request, core, _items_raw)


for _path in HEC_PATHS:
    router.add_api_route(_path, hec_event, methods=["POST"], include_in_schema=_path == HEC_PATHS[1])
for _path in HEC_RAW_PATHS:
    router.add_api_route(_path, hec_raw, methods=["POST"], include_in_schema=False)


@router.api_route("/services/collector/health", methods=["GET", "POST"], include_in_schema=False)
@router.api_route("/services/collector/health/1.0", methods=["GET", "POST"], include_in_schema=False)
def hec_health():
    return {"text": "HEC is healthy", "code": 17}


@router.options("/services/collector/{rest:path}", include_in_schema=False)
def hec_options():
    # Der Docker-Splunk-Treiber prüft die Verbindung per OPTIONS-Anfrage
    return Response(status_code=200)
