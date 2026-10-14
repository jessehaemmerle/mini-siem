"""Syslog-Empfänger für UDP, TCP und TLS (asyncio).

TCP/TLS verstehen beide üblichen Rahmungen: eine Nachricht pro Zeile sowie
"octet counting" nach RFC 6587 (``<Länge> <Nachricht>``).
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import time

log = logging.getLogger("siem.syslog")


class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, pipeline, settings):
        self.pipeline = pipeline
        self.settings = settings

    def datagram_received(self, data: bytes, addr) -> None:
        ip = addr[0]
        if not self.settings.syslog_allowed(ip):
            return
        text = data[: self.settings.max_message_bytes].decode("utf-8", errors="replace")
        now = time.time()
        for line in text.split("\n"):
            if line.strip():
                self.pipeline.submit("syslog", line, ip, now)


def _split_frames(buf: bytearray, max_len: int) -> list[bytes]:
    """Zerlegt den Puffer in vollständige Nachrichten (verändert ``buf``)."""
    out = []
    while buf:
        if buf[:1].isdigit():
            sp = buf.find(b" ", 0, 12)
            if sp > 0 and buf[:sp].isdigit():
                length = int(buf[:sp])
                if len(buf) < sp + 1 + length:
                    break
                out.append(bytes(buf[sp + 1: sp + 1 + length]))
                del buf[: sp + 1 + length]
                continue
        nl = buf.find(b"\n")
        if nl < 0:
            if len(buf) > max_len:
                out.append(bytes(buf[:max_len]))
                del buf[:]
            break
        out.append(bytes(buf[:nl]))
        del buf[: nl + 1]
    return out


async def _handle_stream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                         pipeline, settings) -> None:
    peer = writer.get_extra_info("peername") or ("?", 0)
    ip = peer[0]
    if not settings.syslog_allowed(ip):
        writer.close()
        return
    buf = bytearray()
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            buf.extend(chunk)
            now = time.time()
            for frame in _split_frames(buf, settings.max_message_bytes):
                line = frame.decode("utf-8", errors="replace").strip("\r\n\x00")
                if line.strip():
                    pipeline.submit("syslog", line[: settings.max_message_bytes], ip, now)
        if buf.strip():
            pipeline.submit("syslog", bytes(buf).decode("utf-8", errors="replace"), ip, time.time())
    except (ConnectionError, asyncio.IncompleteReadError, ssl.SSLError):
        pass
    finally:
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass


async def start_receivers(settings, pipeline) -> list:
    loop = asyncio.get_running_loop()
    servers: list = []

    def handler(r, w):
        return _handle_stream(r, w, pipeline, settings)

    if settings.syslog_udp_port:
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _UDPProtocol(pipeline, settings),
                local_addr=("0.0.0.0", settings.syslog_udp_port),
            )
            servers.append(transport)
            log.info("Syslog UDP lauscht auf Port %d", settings.syslog_udp_port)
        except OSError as exc:
            log.error("Syslog UDP Port %d nicht verfügbar: %s", settings.syslog_udp_port, exc)

    if settings.syslog_tcp_port:
        try:
            srv = await asyncio.start_server(handler, "0.0.0.0", settings.syslog_tcp_port,
                                             limit=settings.max_message_bytes * 2)
            servers.append(srv)
            log.info("Syslog TCP lauscht auf Port %d", settings.syslog_tcp_port)
        except OSError as exc:
            log.error("Syslog TCP Port %d nicht verfügbar: %s", settings.syslog_tcp_port, exc)

    if settings.syslog_tls_port:
        if not (settings.tls_cert and settings.tls_key):
            log.error("Syslog TLS benötigt SIEM_TLS_CERT und SIEM_TLS_KEY")
        else:
            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ctx.load_cert_chain(settings.tls_cert, settings.tls_key)
            try:
                srv = await asyncio.start_server(handler, "0.0.0.0", settings.syslog_tls_port, ssl=ctx,
                                                 limit=settings.max_message_bytes * 2)
                servers.append(srv)
                log.info("Syslog TLS lauscht auf Port %d", settings.syslog_tls_port)
            except OSError as exc:
                log.error("Syslog TLS Port %d nicht verfügbar: %s", settings.syslog_tls_port, exc)
    return servers


async def stop_receivers(servers: list) -> None:
    for s in servers:
        s.close()
        if hasattr(s, "wait_closed"):
            try:
                await asyncio.wait_for(s.wait_closed(), 2)
            except (asyncio.TimeoutError, Exception):  # noqa: BLE001
                pass
