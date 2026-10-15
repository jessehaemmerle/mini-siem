"""Einstiegspunkt: Web-App + Syslog-Empfänger + Pipeline in einem Prozess.

Start: ``python -m siem``
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .api import admin, agents, alerts, auth_routes, events, ingest, m365, rules
from .config import Settings
from .core import Core
from .receivers import start_receivers, stop_receivers

STATIC_DIR = Path(__file__).parent / "static"

log = logging.getLogger("siem")

CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    core = Core(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        core.pipeline.start()
        core.m365.start()
        servers = await start_receivers(settings, core.pipeline)
        log.info("Mini-SIEM %s bereit – Weboberfläche auf Port %d", __version__, settings.http_port)
        try:
            yield
        finally:
            await stop_receivers(servers)
            core.m365.stop()
            core.pipeline.stop()

    app = FastAPI(
        title="Mini-SIEM",
        version=__version__,
        description="REST-API des Mini-SIEM. Anmeldung über die Weboberfläche (Cookie) "
                    "bzw. Sende-Token für die Log-Annahme.",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.core = core

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        h = response.headers
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("Referrer-Policy", "same-origin")
        h.setdefault("X-Frame-Options", "DENY")
        if not request.url.path.startswith("/api/docs"):
            h.setdefault("Content-Security-Policy", CSP)
        if request.url.path.startswith("/api/"):
            h.setdefault("Cache-Control", "no-store")
        return response

    for module in (auth_routes, events, alerts, rules, admin, ingest, agents, m365):
        app.include_router(module.router)

    @app.get("/api/health", tags=["System"])
    def health():
        return {"status": "ok", "version": __version__, "queue": core.pipeline.queue.qsize()}

    @app.exception_handler(404)
    async def not_found(request: Request, exc):
        if request.url.path.startswith("/api/"):
            detail = getattr(exc, "detail", None) or "Nicht gefunden"
            return JSONResponse({"detail": detail}, status_code=404)
        return FileResponse(STATIC_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-cache"})

    return app


def run() -> None:
    import uvicorn

    level = os.environ.get("SIEM_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    settings = Settings()
    app = create_app(settings)
    ssl_kwargs = {}
    if settings.tls_cert and settings.tls_key:
        ssl_kwargs = {"ssl_certfile": settings.tls_cert, "ssl_keyfile": settings.tls_key}
    uvicorn.run(
        app,
        host=settings.http_host,
        port=settings.http_port,
        log_level=level.lower(),
        access_log=os.environ.get("SIEM_ACCESS_LOG", "").lower() in ("1", "true", "yes"),
        proxy_headers=True,
        forwarded_allow_ips=os.environ.get("SIEM_TRUSTED_PROXIES", "127.0.0.1"),
        server_header=False,
        **ssl_kwargs,
    )
