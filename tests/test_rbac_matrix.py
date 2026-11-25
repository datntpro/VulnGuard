"""L-1: ANALYST/VIEWER không được gọi endpoint settings/SCM/AI test. L-3, I-1, E.5 gộp ở đây."""
import pytest

from api.auth_models import UserRole
from tests._authutil import PASSWORD, bearer, login, make_user, new_client

ADMIN_ONLY_CALLS = [
    ("POST", "/api/settings/smtp/test"),
    ("POST", "/api/settings/sonarqube/test"),
    ("POST", "/api/settings/report-branding/logo"),
    ("DELETE", "/api/settings/report-branding/logo"),
    ("POST", "/api/scm/connections"),
    ("DELETE", "/api/scm/connections/x"),
    ("GET", "/api/scm/connections/x/remote-repos"),
    ("POST", "/api/ai/test"),
]


def _tok(role):
    email, _ = make_user(role)
    c = new_client()
    return c, bearer(login(c, email))


@pytest.mark.parametrize("role", [UserRole.ANALYST, UserRole.VIEWER])
@pytest.mark.parametrize("method,path", ADMIN_ONLY_CALLS)
def test_non_admin_forbidden(role, method, path):
    c, h = _tok(role)
    assert c.request(method, path, headers=h).status_code == 403


@pytest.mark.parametrize("method,path", ADMIN_ONLY_CALLS)
def test_admin_not_blocked_by_rbac(method, path):
    from fastapi.testclient import TestClient
    from api.main import app
    email, _ = make_user()
    c = TestClient(app, raise_server_exceptions=False)   # handler có thể lỗi môi trường (ghi /app) — chỉ cần không phải 403
    h = bearer(login(c, email))
    assert c.request(method, path, headers=h).status_code != 403


def test_analyst_can_list_connections():
    c, h = _tok(UserRole.ANALYST)
    assert c.get("/api/scm/connections", headers=h).status_code == 200


# ── L-3 must_change_password ──
def test_must_change_password_enforced_in_api():
    email, _ = make_user(must_change_password=True)
    c = new_client()
    t = login(c, email)
    h = bearer(t)
    r = c.get("/api/projects", headers=h)
    assert r.status_code == 403 and r.json()["code"] == "must_change_password"
    assert c.get("/api/auth/me", headers=h).status_code == 200
    r = c.post("/api/auth/change-password", json={"current_password": PASSWORD, "new_password": "brand-new-pass-9"}, headers=h)
    assert r.status_code == 200
    assert c.get("/api/projects", headers=bearer(r.json()["token"])).status_code == 200


def test_admin_created_user_must_change_password():
    c, h = _tok(UserRole.ADMIN)
    email = "n_" + make_user()[0]
    r = c.post("/api/auth/users", json={"email": email, "name": "N", "password": "initial-pass-12", "role": "ANALYST"}, headers=h)
    assert r.status_code == 201 and r.json()["must_change_password"] is True


def test_admin_reset_password_sets_flag():
    c, h = _tok(UserRole.ADMIN)
    _, uid = make_user(UserRole.ANALYST)
    r = c.patch(f"/api/auth/users/{uid}", json={"password": "reset-pass-123456"}, headers=h)
    assert r.status_code == 200 and r.json()["must_change_password"] is True


# ── I-1 docs ──
def test_docs_require_login():
    c = new_client()
    assert c.get("/openapi.json").status_code == 401
    assert c.get("/docs", follow_redirects=False).status_code in (303, 401)
    assert c.get("/redoc", follow_redirects=False).status_code in (303, 401)
    _, h = _tok(UserRole.VIEWER)
    assert c.get("/openapi.json", headers=h).status_code == 200
    assert c.get("/docs", headers=h).status_code == 200


def test_mask_secret():
    from api.security import mask_secret
    assert mask_secret("sk-ant-abcdefghijkl1234") == "…1234"
    assert mask_secret("short") == "…"
    assert mask_secret("") == ""


# ── E.5 headers ──
def test_security_headers():
    c = new_client()
    r = c.get("/login")
    csp = r.headers["content-security-policy"]
    assert "connect-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert r.headers["x-frame-options"] == "DENY"
    r = c.get("/api/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "content-security-policy" not in r.headers
    _, h = _tok(UserRole.ADMIN)
    assert "content-security-policy" not in c.get("/docs", headers=h).headers


# ── B1: VIEWER bị ép đổi mật khẩu phải tự đổi được ──
def test_viewer_created_by_admin_can_change_password():
    ac, ah = _tok(UserRole.ADMIN)
    email = "v_" + make_user()[0]
    r = ac.post("/api/auth/users", json={"email": email, "name": "V", "password": "initial-pass-12", "role": "VIEWER"}, headers=ah)
    assert r.status_code == 201
    vc = new_client()
    t = login(vc, email, "initial-pass-12")
    h = bearer(t)
    assert vc.get("/api/projects", headers=h).status_code == 403
    r = vc.post("/api/auth/change-password", json={"current_password": "initial-pass-12", "new_password": "viewer-new-pass-9"}, headers=h)
    assert r.status_code == 200, r.text
    assert vc.get("/api/projects", headers=bearer(r.json()["token"])).status_code == 200
    # VIEWER vẫn không ghi được các route khác
    assert vc.post("/api/projects", json={"name": "x"}, headers=bearer(r.json()["token"])).status_code == 403
    assert vc.post("/api/auth/logout-all", headers=bearer(r.json()["token"])).status_code == 200


def test_change_password_new_works_old_rejected():
    email, _ = make_user(must_change_password=True)
    c = new_client()
    h = bearer(login(c, email))
    r = c.post("/api/auth/change-password", json={"current_password": PASSWORD, "new_password": "totally-new-pass-9"}, headers=h)
    assert r.status_code == 200
    assert c.get("/api/auth/me", headers=h).status_code == 401            # token cũ bị thu hồi
    c2 = new_client()
    assert c2.post("/api/auth/login", json={"email": email, "password": PASSWORD}).status_code == 401
    assert c2.post("/api/auth/login", json={"email": email, "password": "totally-new-pass-9"}).status_code == 200
    assert c2.get("/api/projects").status_code == 200   # cờ đã xoá


# ── B2: WS must-change-password ──
def test_ws_must_change_password_rejected():
    import pytest
    from starlette.websockets import WebSocketDisconnect
    email, _ = make_user(must_change_password=True)
    c = new_client()
    h = bearer(login(c, email))
    with pytest.raises(WebSocketDisconnect):
        with c.websocket_connect("/api/file-assistant/sessions/x/chat/stream", headers=h) as ws:
            ws.receive_json()
