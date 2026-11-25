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
    monkeypatch.setattr(settings, "vulnguard_setup_token", "from-env-token-1234567")
    monkeypatch.setattr(auth_mod, "_storage_dir", lambda: str(tmp_path))
    assert auth_mod._setup_token(0) == "from-env-token-1234567"
    assert not (tmp_path / "setup_token").exists()


def test_short_env_token_ignored(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "vulnguard_setup_token", "a")
    monkeypatch.setattr(auth_mod, "_storage_dir", lambda: str(tmp_path))
    tok = auth_mod._setup_token(0)
    assert tok != "a" and (tmp_path / "setup_token").exists()


# ── DB trống thật (engine riêng) ──
@pytest.fixture
def real_empty(monkeypatch, tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    eng = create_engine(f"sqlite:///{tmp_path}/e.db", connect_args={"check_same_thread": False})
    database.Base.metadata.create_all(eng)
    SL = sessionmaker(autocommit=False, autoflush=False, bind=eng)

    def _get_db():
        db = SL()
        try:
            yield db
        finally:
            db.close()
    app.dependency_overrides[database.get_db] = _get_db
    monkeypatch.setattr(auth_mod, "SessionLocal", SL)
    monkeypatch.setattr(auth_mod, "_storage_dir", lambda: str(tmp_path))
    monkeypatch.setattr(settings, "vulnguard_setup_token", "")
    auth_mod._LOGIN_FAILS.clear()
    yield SL, tmp_path
    app.dependency_overrides.pop(database.get_db, None)


def test_startup_creates_token_file_0600(real_empty):
    """M-1: file token có ngay sau khởi động, không cần POST /setup."""
    _, tmp = real_empty
    auth_mod.init_setup_token()
    p = tmp / "setup_token"
    assert p.exists()
    if os.name == "posix":
        assert stat.S_IMODE(p.stat().st_mode) == 0o600


def test_startup_removes_stale_token_when_users_exist(real_empty):
    SL, tmp = real_empty
    db = SL()
    db.add(User(email="x@t.local", name="x", password_hash="h", role=auth_mod.UserRole.ADMIN))
    db.commit(); db.close()
    (tmp / "setup_token").write_text("stale")
    auth_mod.init_setup_token()
    assert not (tmp / "setup_token").exists()


def test_lifecycle_and_concurrent_setup_single_admin(real_empty):
    """M-2: N request đồng thời với token đúng → đúng 1 ADMIN (200), còn lại 409."""
    import threading
    SL, tmp = real_empty
    auth_mod.init_setup_token()
    tok = (tmp / "setup_token").read_text().strip()
    codes, barrier = [], threading.Barrier(16)

    def go(i):
        with TestClient(app) as c:
            barrier.wait()
            r = c.post("/api/auth/setup", json=_body(email=f"r{i}@t.local", setup_token=tok))
            codes.append(r.status_code)
    ts = [threading.Thread(target=go, args=(i,)) for i in range(16)]
    [t.start() for t in ts]; [t.join() for t in ts]
    db = SL()
    assert db.query(User).count() == 1
    db.close()
    assert codes.count(200) == 1 and all(c in (200, 409) for c in codes), codes
    assert not (tmp / "setup_token").exists()      # xoá sau khi setup


def test_correct_token_not_locked_out_by_attacker(real_empty):
    """S-1: 5+ lần sai (cùng NAT IP) không chặn chủ máy có token đúng."""
    _, tmp = real_empty
    auth_mod.init_setup_token()
    tok = (tmp / "setup_token").read_text().strip()
    with TestClient(app) as c:
        codes = [c.post("/api/auth/setup", json=_body(setup_token=f"bad{i}")).status_code for i in range(16)]
        assert 429 in codes
        r = c.post("/api/auth/setup", json=_body(setup_token=tok))
        assert r.status_code == 200


def test_xff_rotation_does_not_bypass_limiter(real_empty):
    """S-2: xoay X-Forwarded-For không né được giới hạn."""
    with TestClient(app) as c:
        codes = [c.post("/api/auth/setup", json=_body(setup_token=f"b{i}"),
                        headers={"X-Forwarded-For": f"10.0.0.{i}"}).status_code for i in range(16)]
    assert 429 in codes
