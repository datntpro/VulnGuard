"""M-2: AUTH_ENABLED=false + CORS * → mọi trang web RCE host qua Co-work. Phải khoá."""
import pytest
from fastapi.testclient import TestClient

from api.config import settings
from api.main import app

LOCAL = {"Host": "localhost:8080"}


@pytest.fixture
def off(monkeypatch):
    monkeypatch.setattr(settings, "auth_enabled", False)
    return TestClient(app)


def test_coworker_exec_blocked(off):
    r = off.post("/api/coworker/fs/exec", json={"folder_id": "x", "command": "id"}, headers=LOCAL)
    assert r.status_code == 403 and r.json()["code"] == "auth_required"


def test_coworker_get_blocked(off):
    assert off.get("/api/coworker/folders", headers=LOCAL).status_code == 403


def test_file_assistant_blocked(off):
    r = off.post("/api/file-assistant/sessions", json={}, headers=LOCAL)
    assert r.status_code == 403 and r.json()["code"] == "auth_required"


def test_admin_settings_blocked(off):
    assert off.put("/api/settings/scanners", json={}, headers=LOCAL).status_code == 403


def test_regular_read_still_works(off):
    assert off.get("/api/projects", headers=LOCAL).status_code == 200


def test_no_wildcard_cors(off):
    r = off.options("/api/projects", headers={**LOCAL, "Origin": "https://evil.example",
                                              "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in r.headers


def test_dns_rebinding_host_rejected(off):
    assert off.get("/api/health", headers={"Host": "evil.example"}).status_code == 421
    assert off.get("/", headers={"Host": "evil.example"}).status_code == 421
    assert off.get("/api/health", headers={"Host": "localhost:8080"}).status_code == 200
    assert off.get("/api/health", headers={"Host": "[::1]:8080"}).status_code == 200


def test_allowed_hosts_extends(off, monkeypatch):
    monkeypatch.setattr(settings, "allowed_hosts", "vg.corp.example")
    assert off.get("/api/health", headers={"Host": "vg.corp.example"}).status_code == 200


def test_ws_auth_off_rejected(off):
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect):
        with off.websocket_connect("/api/file-assistant/sessions/x/chat/stream", headers=LOCAL) as ws:
            ws.receive_json()


def test_dev_pseudo_user_not_admin(off):
    from api.routes.auth import current_user
    from starlette.requests import Request
    from api.auth_models import UserRole
    req = Request({"type": "http", "method": "GET", "path": "/", "headers": []})
    assert current_user(req).role != UserRole.ADMIN


# ── Auth BẬT: CSRF / Origin guard ──
def _admin_client():
    from tests._authutil import login, make_user, new_client, bearer
    email, _ = make_user()
    c = new_client()
    t = login(c, email)
    return c, bearer(t)


def test_cross_origin_write_rejected():
    c, h = _admin_client()
    r = c.post("/api/projects", json={"name": "csrf"}, headers={**h, "Origin": "https://evil.example"})
    assert r.status_code == 403 and r.json()["code"] == "bad_origin"


def test_cross_site_fetch_metadata_rejected():
    c, h = _admin_client()
    r = c.post("/api/projects", json={"name": "csrf2"}, headers={**h, "Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403


def test_same_origin_and_no_origin_allowed():
    c, h = _admin_client()
    assert c.post("/api/projects", json={"name": "ok1"}, headers={**h, "Origin": "http://testserver"}).status_code in (200, 201)
    assert c.post("/api/projects", json={"name": "ok2"}, headers=h).status_code in (200, 201)


def test_cors_allowlist_origin_accepted(monkeypatch):
    monkeypatch.setattr(settings, "cors_allow_origins", "https://ok.example")
    c, h = _admin_client()
    r = c.post("/api/projects", json={"name": "ok3"}, headers={**h, "Origin": "https://ok.example"})
    assert r.status_code in (200, 201)


def test_cors_middleware_only_when_configured():
    import importlib, api.main as m
    src = open(m.__file__).read()
    assert "if _cors_origins:" in src
    assert 'allow_origins=["*"]' not in src


def test_setup_blocked_when_auth_off(off):
    r = off.post("/api/auth/setup", json={"email": "a@b.com", "name": "A", "password": "longpass123"}, headers=LOCAL)
    assert r.status_code == 403 and r.json()["code"] == "auth_required"
