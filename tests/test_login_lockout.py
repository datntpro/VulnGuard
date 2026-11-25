"""M5: khoá đăng nhập sau nhiều lần sai (chống brute-force)."""
import types

import pytest

from api.routes import auth


def _req(ip="1.2.3.4"):
    return types.SimpleNamespace(client=types.SimpleNamespace(host=ip),
                                 state=types.SimpleNamespace(user=None))


def setup_function():
    auth._LOGIN_FAILS.clear()


def test_lockout_after_max_fails():
    key = auth._login_key(_req(), "a@b.com")
    for _ in range(auth._MAX_FAILS):
        auth._check_lockout(key)     # chưa khoá
        auth._record_fail(key)
    with pytest.raises(Exception) as e:
        auth._check_lockout(key)     # lần thứ _MAX_FAILS+1 → khoá
    assert "429" in str(e.value) or "Quá nhiều" in str(e.value)


def test_key_separates_ip_and_email():
    assert auth._login_key(_req("1.1.1.1"), "x@y") != auth._login_key(_req("2.2.2.2"), "x@y")
    assert auth._login_key(_req(), "A@B") == auth._login_key(_req(), "a@b")  # email hạ chữ


def test_reset_clears_lock():
    key = auth._login_key(_req(), "c@d.com")
    for _ in range(auth._MAX_FAILS):
        auth._record_fail(key)
    auth._LOGIN_FAILS.pop(key, None)   # mô phỏng reset khi đăng nhập đúng
    auth._check_lockout(key)           # không còn raise


# ── N-3: lockout không được khoá nhầm người dùng hợp lệ (device cookie) ──
from tests._authutil import PASSWORD, make_user, new_client  # noqa: E402


def _bad(c, email, n):
    return [c.post("/api/auth/login", json={"email": email, "password": "wrong-pass-xx"}).status_code
            for _ in range(n)]


def test_correct_password_with_device_cookie_during_lockout():
    auth._LOGIN_FAILS.clear()
    email, _ = make_user()
    c1 = new_client()
    r = c1.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    assert r.status_code == 200 and "vg_device" in c1.cookies
    c1.post("/api/auth/logout")
    attacker = new_client()
    codes = _bad(attacker, email, auth._MAX_FAILS + 1)
    assert codes[-1] == 429
    # trình duyệt đã đăng nhập trước đó vẫn vào được
    assert c1.post("/api/auth/login", json={"email": email, "password": PASSWORD}).status_code == 200


def test_untrusted_still_locked():
    auth._LOGIN_FAILS.clear()
    email, _ = make_user()
    a = new_client()
    _bad(a, email, auth._MAX_FAILS)
    r = new_client().post("/api/auth/login", json={"email": email, "password": PASSWORD})
    assert r.status_code == 429


def test_device_cookie_bucket_locks():
    auth._LOGIN_FAILS.clear()
    email, _ = make_user()
    c = new_client()
    c.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    codes = _bad(c, email, auth._MAX_FAILS + 1)
    assert codes[-1] == 429


def test_forged_device_cookie_untrusted():
    auth._LOGIN_FAILS.clear()
    email, _ = make_user()
    _bad(new_client(), email, auth._MAX_FAILS)
    c = new_client()
    c.cookies.set("vg_device", "abc.deadbeef", path="/api/auth")
    assert c.post("/api/auth/login", json={"email": email, "password": PASSWORD}).status_code == 429


def test_device_cookie_other_email_untrusted():
    auth._LOGIN_FAILS.clear()
    e1, _ = make_user()
    e2, _ = make_user()
    c = new_client()
    c.post("/api/auth/login", json={"email": e1, "password": PASSWORD})
    dev = c.cookies.get("vg_device")
    _bad(new_client(), e2, auth._MAX_FAILS)
    c2 = new_client()
    c2.cookies.set("vg_device", dev, path="/api/auth")
    assert c2.post("/api/auth/login", json={"email": e2, "password": PASSWORD}).status_code == 429


def test_store_bounded():
    auth._LOGIN_FAILS.clear()
    for i in range(10_001):
        auth._record_fail(f"k{i}")
    assert len(auth._LOGIN_FAILS) <= 10_000


def test_retry_after_header():
    auth._LOGIN_FAILS.clear()
    email, _ = make_user()
    c = new_client()
    codes = _bad(c, email, auth._MAX_FAILS + 1)
    r = c.post("/api/auth/login", json={"email": email, "password": "wrong-pass-xx"})
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0


# ── Verifier PR #30: F-1, F-2, F-3, F-5, F-7 + logout fallback ──
from concurrent.futures import ThreadPoolExecutor  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402

from api.auth_models import UserRole  # noqa: E402
from api.main import app  # noqa: E402
from tests._authutil import bearer, login  # noqa: E402


def test_f1_pipe_in_email_cannot_mint_trusted_bucket():
    auth._LOGIN_FAILS.clear()
    victim, _ = make_user()
    evil_email = f"{victim}|k"           # email chứa '|' → HMAC cũ: "device|victim|k|N" == "device|victim|" + "k|N"
    from api.auth_models import User
    from api.database import SessionLocal
    from api.security import hash_password
    db = SessionLocal()
    db.add(User(email=evil_email, name="e", password_hash=hash_password(PASSWORD), role=UserRole.VIEWER))
    db.commit()
    db.close()
    ce = new_client()
    assert ce.post("/api/auth/login", json={"email": evil_email, "password": PASSWORD}).status_code == 200
    raw = ce.cookies.get("vg_device")             # "N.sig"
    nonce, sig = raw.split(".")
    forged = f"k|{nonce}.{sig}"                   # cố tình dùng làm cookie của victim
    _bad(new_client(), victim, auth._MAX_FAILS)   # bucket untrusted của victim đã khoá
    c = new_client()
    c.cookies.set("vg_device", forged, path="/api/auth")
    assert c.post("/api/auth/login", json={"email": victim, "password": PASSWORD}).status_code == 429


def test_f2_concurrent_guesses_capped():
    auth._LOGIN_FAILS.clear()
    email, _ = make_user()

    def one(_):
        return TestClient(app).post("/api/auth/login",
                                    json={"email": email, "password": "wrong-pass-xx"}).status_code
    with ThreadPoolExecutor(24) as ex:
        codes = list(ex.map(one, range(24)))
    assert codes.count(401) <= auth._MAX_FAILS, codes
    assert codes.count(429) >= 24 - auth._MAX_FAILS


def test_f3_rotating_client_ip_shares_untrusted_bucket():
    auth._LOGIN_FAILS.clear()
    email, _ = make_user()
    codes = []
    for i in range(auth._MAX_FAILS + 3):
        c = TestClient(app, client=(f"10.1.1.{i}", 5000))
        codes.append(c.post("/api/auth/login", json={"email": email, "password": "wrong-pass-xx"},
                            headers={"X-Forwarded-For": f"8.8.8.{i}"}).status_code)
    assert codes.count(401) == auth._MAX_FAILS and codes[-1] == 429


def test_f5_spray_cannot_evict_locked_bucket(monkeypatch):
    auth._LOGIN_FAILS.clear()
    monkeypatch.setattr(auth, "_MAX_KEYS", 20)
    for _ in range(auth._MAX_FAILS):
        auth._record_fail("untrusted|victim@x")
    for i in range(100):
        auth._record_fail(f"untrusted|junk{i}@x")
    assert "untrusted|victim@x" in auth._LOGIN_FAILS
    assert len(auth._LOGIN_FAILS) <= 20


def test_f7_dummy_hash_precomputed(monkeypatch):
    calls = []
    real = auth.hash_password
    monkeypatch.setattr(auth, "hash_password", lambda p: (calls.append(p), real(p))[1])
    new_client().post("/api/auth/login", json={"email": "nobody@t.local", "password": "wrong-pass-xx"})
    assert calls == []          # không băm lại mỗi lần đăng nhập email lạ


def test_logout_bad_header_still_revokes_cookie_token():
    email, _ = make_user()
    c = new_client()
    t = login(c, email)                     # TestClient giữ cookie vg_session
    assert c.post("/api/auth/logout", headers=bearer("garbage")).status_code == 200
    c2 = new_client()
    c2.cookies.set("vg_session", t)
    assert c2.get("/api/auth/me").status_code == 401
