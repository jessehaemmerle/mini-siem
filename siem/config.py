"""Konfiguration über Umgebungsvariablen.

Alle Variablen beginnen mit ``SIEM_``. Werte, die sich im Betrieb ändern
sollen (z. B. Aufbewahrungsdauer), werden in der Datenbank gespeichert und
in der Oberfläche gepflegt – hier stehen nur die Start-Parameter.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str = "") -> str:
    return os.environ.get(f"SIEM_{name}", default).strip()


def _env_int(name: str, default: int) -> int:
    raw = _env(name)
    return int(raw) if raw else default


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name).lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "ja", "on")


def _networks(raw: str) -> list:
    nets = []
    for part in raw.replace(";", ",").split(","):
        part = part.strip()
        if part:
            nets.append(ipaddress.ip_network(part, strict=False))
    return nets


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(_env("DATA_DIR", "./data")))

    # Web-Oberfläche & API
    http_host: str = field(default_factory=lambda: _env("HTTP_HOST", "0.0.0.0"))
    http_port: int = field(default_factory=lambda: _env_int("HTTP_PORT", 8080))
    tls_cert: str = field(default_factory=lambda: _env("TLS_CERT"))
    tls_key: str = field(default_factory=lambda: _env("TLS_KEY"))

    # Syslog-Empfänger (0 = deaktiviert)
    syslog_udp_port: int = field(default_factory=lambda: _env_int("SYSLOG_UDP_PORT", 1514))
    syslog_tcp_port: int = field(default_factory=lambda: _env_int("SYSLOG_TCP_PORT", 1514))
    syslog_tls_port: int = field(default_factory=lambda: _env_int("SYSLOG_TLS_PORT", 0))
    syslog_allow: list = field(default_factory=lambda: _networks(_env("SYSLOG_ALLOW")))

    # Port, unter dem Geräte das SIEM per Syslog erreichen (nur für die Anleitungen
    # in der Oberfläche – entspricht der Port-Freigabe in docker-compose.yml)
    public_syslog_port: int = field(default_factory=lambda: _env_int("PUBLIC_SYSLOG_PORT", 514))

    # Öffentliche Adresse des SIEM (für Installationsbefehle der Agenten), z. B.
    # https://siem.firma.local – leer = Adresse, unter der die Oberfläche aufgerufen wird
    public_url: str = field(default_factory=lambda: _env("PUBLIC_URL").rstrip("/"))

    # Verzeichnis mit den Agent-Programmdateien (im Container: /app/agent-dist)
    agent_dist_dir: Path = field(default_factory=lambda: Path(_env("AGENT_DIST", "/app/agent-dist")))

    # Erstes Admin-Konto (nur beim allerersten Start relevant)
    admin_user: str = field(default_factory=lambda: _env("ADMIN_USER", "admin"))
    admin_password: str = field(default_factory=lambda: _env("ADMIN_PASSWORD"))

    # Sitzungs-Cookie nur über HTTPS senden (bei Betrieb hinter TLS-Proxy: true)
    cookie_secure: bool = field(default_factory=lambda: _env_bool("COOKIE_SECURE", False))

    # Leistung / Schutz
    queue_size: int = field(default_factory=lambda: _env_int("QUEUE_SIZE", 200_000))
    batch_size: int = field(default_factory=lambda: _env_int("BATCH_SIZE", 2_000))
    query_timeout: int = field(default_factory=lambda: _env_int("QUERY_TIMEOUT", 30))
    max_message_bytes: int = field(default_factory=lambda: _env_int("MAX_MESSAGE_BYTES", 65_536))

    # Standardwert für die Aufbewahrung (in der Oberfläche änderbar)
    default_retention_days: int = field(default_factory=lambda: _env_int("RETENTION_DAYS", 90))

    @property
    def events_dir(self) -> Path:
        return self.data_dir / "events"

    @property
    def main_db(self) -> Path:
        return self.data_dir / "siem.db"

    def syslog_allowed(self, ip: str) -> bool:
        if not self.syslog_allow:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.syslog_allow)
