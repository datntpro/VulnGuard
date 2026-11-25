"""L-2 (PR-G): /api/auth/setup yêu cầu setup token — kẻ tới trước không chiếm được ADMIN đầu tiên."""
import os
import stat
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from api import database
from api.auth_models import User
from api.config import settings
from api.main import app
from api.routes import auth as auth_mod

TOKEN = "test-setup-token"


def _body(**kw):
    d = {"email": f"{uuid4().hex}@t.local", "name": "A", "password": "Longpass-123"}
    d.update(kw)
    return d


@pytest.fixture
def empty_db(monkeypatch):
    """Giả lập hệ thống chưa có user (không xoá DB thật): User.count() == 0 cho tới khi setup thành công."""
    state = {"done": False}
    monkeypatch.setattr(auth_mod, "_user_count", lambda db: 1 if state["done"] else 0, raising=False)
    auth_mod._LOGIN_FAILS.clear()
    return state


@pytest.fixture
def client(empty_db):
    with TestClient(app) as c:
        yield c


def test_setup_without_token_rejected(client):
    r = client.post("/api/auth/setup", json=_body())
    assert r.status_code in (403, 422)


def test_setup_wrong_token_403(client):
    r = client.post("/api/auth/setup", json=_body(setup_token="nope"))
    assert r.status_code == 403


def test_setup_correct_token_ok_then_409(client, empty_db):
    r = client.post("/api/auth/setup", json=_body(setup_token=TOKEN))
    assert r.status_code == 200 and r.json()["user"]["role"] == "ADMIN"
    empty_db["done"] = True
    r2 = client.post("/api/auth/setup", json=_body(setup_token=TOKEN))
    assert r2.status_code == 409


def test_setup_brute_force_rate_limited(client):
    codes = [client.post("/api/auth/setup", json=_body(setup_token=f"g{i}")).status_code for i in range(12)]
    assert 429 in codes and codes[0] == 403


def test_status_reports_token_required(client):
    st = client.get("/api/auth/status").json()
    assert st["setup_required"] is True and st["setup_token_required"] is True


def test_file_token_created_0600_and_deleted(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "vulnguard_setup_token", "")
    monkeypatch.setattr(auth_mod, "_storage_dir", lambda: str(tmp_path))
    tok = auth_mod._setup_token(0)
    p = tmp_path / "setup_token"
    assert p.exists() and len(tok) >= 24 and p.read_text().strip() == tok
    if os.name == "posix":
        assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert auth_mod._setup_token(0) == tok          # ổn định giữa các lần gọi
    auth_mod._clear_setup_token()
    assert not p.exists()
    # đã có user → không tạo file
    assert auth_mod._setup_token(1) is None
    assert not p.exists()


def test_env_token_takes_precedence(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "vulnguard_setup_token", "from-env-123")
    monkeypatch.setattr(auth_mod, "_storage_dir", lambda: str(tmp_path))
    assert auth_mod._setup_token(0) == "from-env-123"
    assert not (tmp_path / "setup_token").exists()
