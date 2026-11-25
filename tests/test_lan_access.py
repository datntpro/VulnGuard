"""Truy cập LAN: biến VULNGUARD_BIND thống nhất, startup check, Host/Origin qua IP LAN."""
import logging

import pytest
from fastapi.testclient import TestClient

from api import bind_policy
from api.config import settings
from api.main import app

LAN = "192.168.1.63:8080"


def test_resolve_bind_default_and_alias():
    assert bind_policy.resolve_bind({}) == ("127.0.0.1", False)
    assert bind_policy.resolve_bind({"VULNGUARD_BIND": "0.0.0.0"}) == ("0.0.0.0", False)
    assert bind_policy.resolve_bind({"VULNGUARD_HOST": "0.0.0.0"}) == ("0.0.0.0", True)
    # BIND thắng HOST
    assert bind_policy.resolve_bind({"VULNGUARD_BIND": "127.0.0.1", "VULNGUARD_HOST": "0.0.0.0"})[0] == "127.0.0.1"


@pytest.mark.parametrize("bind", ["0.0.0.0", "192.168.1.63", "::"])
def test_startup_refuses_nonloopback_with_auth_off(bind):
    with pytest.raises(RuntimeError):
        bind_policy.check_startup(bind, False, "", False)


@pytest.mark.parametrize("bind", ["127.0.0.1", "localhost", "::1"])
def test_startup_loopback_ok_even_auth_off(bind):
    bind_policy.check_startup(bind, False, "", False)


def test_startup_warns_open_host_and_plain_http(caplog):
    with caplog.at_level(logging.WARNING, logger="api.bind_policy"):
        bind_policy.check_startup("0.0.0.0", True, "", False)
    text = caplog.text
    assert "ALLOWED_HOSTS" in text and "COOKIE_SECURE" in text


def test_startup_no_warning_when_hardened(caplog):
    with caplog.at_level(logging.WARNING, logger="api.bind_policy"):
        bind_policy.check_startup("0.0.0.0", True, "vulnguard.lan", True)
    assert "ALLOWED_HOSTS" not in caplog.text and "COOKIE_SECURE" not in caplog.text


def test_app_startup_fails_on_lan_bind_with_auth_off(monkeypatch):
    monkeypatch.setenv("VULNGUARD_BIND", "0.0.0.0")
    monkeypatch.setattr(settings, "auth_enabled", False)
    with pytest.raises(RuntimeError):
        with TestClient(app):
            pass


def test_lan_ip_allowed_when_listed(monkeypatch):
    monkeypatch.setattr(settings, "allowed_hosts", "192.168.1.63")
    r = TestClient(app).get("/api/auth/status", headers={"Host": LAN})
    assert r.status_code == 200


def test_lan_ip_rejected_when_not_listed(monkeypatch):
    monkeypatch.setattr(settings, "allowed_hosts", "vulnguard.lan")
    r = TestClient(app).get("/api/auth/status", headers={"Host": LAN})
    assert r.status_code == 421 and r.json()["code"] == "bad_host"


def test_auth_off_lan_host_still_rejected(monkeypatch):
    monkeypatch.setattr(settings, "auth_enabled", False)
    monkeypatch.setattr(settings, "allowed_hosts", "")
    r = TestClient(app).get("/api/auth/status", headers={"Host": LAN})
    assert r.status_code == 421


def test_same_origin_write_via_lan_ip_vs_cross_origin(monkeypatch):
    monkeypatch.setattr(settings, "allowed_hosts", "")
    c = TestClient(app)
    ok = c.post("/api/auth/login", json={"email": "x@t.local", "password": "bad"},
                headers={"Host": LAN, "Origin": f"http://{LAN}"})
    assert ok.status_code != 403            # qua được CSRF check (401 sai mật khẩu)
    bad = c.post("/api/auth/login", json={"email": "x@t.local", "password": "bad"},
                 headers={"Host": LAN, "Origin": "http://evil.example"})
    assert bad.status_code == 403 and bad.json()["code"] == "bad_origin"
