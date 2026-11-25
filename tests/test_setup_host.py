"""B-5/M-2: native bind defaults to loopback; auth-off refuses a network bind."""
import pytest

from scripts.setup import resolve_bind_host


def test_default_is_loopback():
    assert resolve_bind_host({}) == "127.0.0.1"


def test_explicit_host_with_auth_allowed():
    assert resolve_bind_host({"VULNGUARD_HOST": "0.0.0.0", "AUTH_ENABLED": "true"}) == "0.0.0.0"


@pytest.mark.parametrize("auth", ["false", "FALSE", "0", "off", "no"])
def test_auth_off_non_loopback_refused(auth):
    with pytest.raises(SystemExit):
        resolve_bind_host({"VULNGUARD_HOST": "0.0.0.0", "AUTH_ENABLED": auth})


def test_auth_off_loopback_ok():
    assert resolve_bind_host({"VULNGUARD_HOST": "::1", "AUTH_ENABLED": "false"}) == "::1"
