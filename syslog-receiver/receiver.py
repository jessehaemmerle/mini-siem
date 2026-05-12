from __future__ import annotations

import os
import socketserver
from typing import Any

import httpx

BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")
API_KEY = os.getenv("SYSLOG_API_KEY", "siem_demo_ingest_key_change_me")
UDP_PORT = int(os.getenv("SYSLOG_UDP_PORT", "5514"))


def forward(line: str) -> None:
    payload: dict[str, Any] = {"line": line, "source_name": "syslog-receiver"}
    try:
        httpx.post(f"{BACKEND_URL}/api/ingest/syslog", headers={"X-API-Key": API_KEY}, json=payload, timeout=5)
    except Exception as exc:
        print(f"syslog forward failed: {exc}")


class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = self.request[0].strip()
        forward(data.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    print(f"Syslog UDP receiver listening on 0.0.0.0:{UDP_PORT}")
    with socketserver.UDPServer(("0.0.0.0", UDP_PORT), SyslogUDPHandler) as server:
        server.serve_forever()
