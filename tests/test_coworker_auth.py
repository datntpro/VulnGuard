"""coworker_host: bắt buộc token + kiểm tra Host (vá RCE không-auth + DNS rebinding)."""
import importlib
import os

import pytest


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("COWORKER_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VULNGUARD_COWORKER_TOKEN", "t0ken-xyz")
    import coworker_host.app as m
    importlib.reload(m)   # để middleware đọc token mới
    from fastapi.testclient import TestClient
    return TestClient(m.app)


def test_health_public(client):
    assert client.get("/health", headers={"host": "localhost"}).status_code == 200


def test_requires_token(client):
    assert client.get("/folders", headers={"host": "127.0.0.1"}).status_code == 401
    assert client.get("/folders", headers={"host": "127.0.0.1",
                      "authorization": "Bearer wrong"}).status_code == 401


def test_valid_token_ok(client):
    r = client.get("/folders", headers={"host": "127.0.0.1", "authorization": "Bearer t0ken-xyz"})
    assert r.status_code == 200


def test_exec_blocked_without_token(client):
    # Trước bản vá: ai cũng gọi được /fs/exec (RCE). Giờ phải có token.
    r = client.post("/fs/exec", json={"folder_id": "x", "command": "python3 -c 1"},
                    headers={"host": "127.0.0.1"})
    assert r.status_code == 401


def test_dns_rebinding_host_blocked(client):
    # Host lạ (trang web qua DNS rebinding) → 421 dù có token đúng
    r = client.get("/folders", headers={"host": "attacker.example",
                   "authorization": "Bearer t0ken-xyz"})
    assert r.status_code == 421
