import time

import pytest
from fastapi.testclient import TestClient

from siem.config import Settings
from siem.main import create_app

ADMIN_PW = "Test-Passwort-123"


@pytest.fixture
def settings(tmp_path):
    s = Settings()
    s.data_dir = tmp_path / "data"
    s.syslog_udp_port = 0
    s.syslog_tcp_port = 0
    s.syslog_tls_port = 0
    s.admin_user = "admin"
    s.admin_password = ADMIN_PW
    return s


@pytest.fixture
def client(settings):
    app = create_app(settings)
    with TestClient(app) as c:
        c.core = app.state.core
        yield c


def login(client, username="admin", password=ADMIN_PW):
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    client.headers["X-SIEM"] = "1"
    return r.json()


@pytest.fixture
def admin_client(client):
    login(client)
    return client


def wait_processed(client, n, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        if client.core.pipeline.total >= n and client.core.pipeline.queue.empty():
            return
        time.sleep(0.05)
    raise AssertionError(f"nur {client.core.pipeline.total} von {n} Events verarbeitet")
