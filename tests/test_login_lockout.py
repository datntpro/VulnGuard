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
