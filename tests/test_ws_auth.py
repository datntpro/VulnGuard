"""N-2 / M-4: WebSocket File Assistant phải kiểm tra phiên thật (revoke, disable, role, Origin, flag)."""
import pytest
from starlette.websockets import WebSocketDisconnect

from api.auth_models import UserRole
from api.config import settings
from tests._authutil import bearer, login, make_user, new_client

URL = "/api/file-assistant/sessions/nope/chat/stream"


@pytest.fixture(autouse=True)
def _fa_enabled(monkeypatch):
    # File Assistant mặc định tắt (D-8); các test WS cần module bật.
    monkeypatch.setattr(settings, "feature_file_assistant", True)


def _connect(c, token=None, origin=None):
    h = {}
    if token:
        h.update(bearer(token))
    if origin:
        h["Origin"] = origin
    return c.websocket_connect(URL, headers=h)


def _must_reject(c, **kw):
    with pytest.raises(WebSocketDisconnect):
        with _connect(c, **kw) as ws:
            ws.receive_json()


def test_no_token_rejected():
    _must_reject(new_client())


def test_analyst_rejected():
    email, _ = make_user(UserRole.ANALYST)
    c = new_client()
    _must_reject(c, token=login(c, email))


def test_admin_accepted_reaches_handler():
    email, _ = make_user()
    c = new_client()
    t = login(c, email)
    with _connect(c, token=t) as ws:
        assert "not found" in ws.receive_json()["error"]


def test_disabled_admin_rejected():
    email, uid = make_user()
    admin2, _ = make_user()
    c = new_client()
    t = login(c, email)
    c2 = new_client()
    t2 = login(c2, admin2)
    r = c2.patch(f"/api/auth/users/{uid}", json={"is_active": False}, headers=bearer(t2))
    assert r.status_code == 200, r.text
    _must_reject(c, token=t)


def test_demoted_admin_rejected():
    email, uid = make_user()
    admin2, _ = make_user()
    c = new_client()
    t = login(c, email)
    c2 = new_client()
    t2 = login(c2, admin2)
    c2.patch(f"/api/auth/users/{uid}", json={"role": "VIEWER"}, headers=bearer(t2))
    _must_reject(c, token=t)


def test_logged_out_token_rejected():
    email, _ = make_user()
    c = new_client()
    t = login(c, email)
    c.post("/api/auth/logout", headers=bearer(t))
    _must_reject(new_client(), token=t)


def test_revoked_mid_session_closes():
    from api.database import SessionLocal
    from api.file_assistant_models import FileAssistantSession
    db = SessionLocal()
    sess = FileAssistantSession(model_used="x", files_json=[])
    db.add(sess)
    db.commit()
    sid = sess.id
    db.close()
    email, _ = make_user()
    c = new_client()
    t = login(c, email)
    with c.websocket_connect(f"/api/file-assistant/sessions/{sid}/chat/stream", headers=bearer(t)) as ws:
        c.post("/api/auth/logout", headers=bearer(t))     # thu hồi khi socket đang mở
        ws.send_text('{"content": "hi"}')
        msg = ws.receive_json()
        assert msg["type"] == "error"
        with pytest.raises(WebSocketDisconnect):
            ws.receive_json()


def test_cross_origin_rejected():
    email, _ = make_user()
    c = new_client()
    t = login(c, email)
    _must_reject(c, token=t, origin="https://evil.example")


def test_feature_flag_off_rejected(monkeypatch):
    email, _ = make_user()
    c = new_client()
    t = login(c, email)
    monkeypatch.setattr(settings, "feature_file_assistant", False)
    _must_reject(c, token=t)
