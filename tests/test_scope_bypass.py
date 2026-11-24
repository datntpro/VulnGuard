"""Regression tests cho các lỗ hổng scope/an toàn của Pentest Agent (PoC B1-B4)."""
import asyncio

import pytest

from api.pentest_models import AutonomyMode
from scanner.pentest import scope, toolbelt
from scanner.pentest.gating import decide_action
from scanner.pentest.scope import check_target, canonicalize_target, ScopeError

def _run(coro):
    # loop riêng, không đụng event-loop policy (các test khác dùng get_event_loop())
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


ONE_IP = [{"type": "ip", "value": "172.18.0.2", "mode": "allow"}]
NET24 = [{"type": "cidr", "value": "10.1.0.0/24", "mode": "allow"}]
DOMAIN = [{"type": "domain", "value": "example.com", "include_subdomains": True, "mode": "allow"}]


# ───── B1: nmap quét cả CIDR khi scope chỉ có 1 IP ─────
@pytest.mark.parametrize("bad", [
    "172.18.0.2/28", "172.18.0.2/8", "172.18.0.0/24", "172.18.0.2/0",
    "172.18.0.2,172.18.0.3", "172.18.0.2 172.18.0.3", "172.18.0.1-5", "172.18.0.2-172.18.0.9",
    "172.18.0.*", "-iL/etc/passwd", "--script=x 172.18.0.2", "172.18.0.2\n10.0.0.1",
    "172.18.0.2/99", "2130706433", "0x7f000001", "127.1",
])
def test_b1_port_scan_rejects_non_single_target(bad):
    d, _ = decide_action(toolbelt.get_tool("port_scan") or _fake_nmap(), {"host": bad},
                         AutonomyMode.AUTONOMOUS_IN_SCOPE, ONE_IP)
    assert d in ("block_scope", "block_unavail")
    assert check_target(bad, ONE_IP)[0] is False


def _fake_nmap():
    t = toolbelt.get_tool("port_scan")
    return t


def test_b1_single_ip_still_ok():
    assert check_target("172.18.0.2", ONE_IP)[0]
    assert check_target("172.18.0.2/32", ONE_IP)[0]


def test_b1_cidr_must_be_subset_of_scope():
    assert check_target("10.1.0.0/25", NET24)[0]
    assert check_target("10.1.0.0/24", NET24)[0]
    assert check_target("10.1.0.0/23", NET24)[0] is False
    assert check_target("10.0.0.0/8", NET24)[0] is False
    # domain rule không bao giờ cho phép một dải
    assert check_target("10.1.0.0/25", DOMAIN)[0] is False


def test_b1_cidr_overlapping_deny_blocked():
    rules = NET24 + [{"type": "ip", "value": "10.1.0.9", "mode": "deny"}]
    assert check_target("10.1.0.0/25", rules)[0] is False
    assert check_target("10.1.0.128/25", rules)[0]


def test_b1_nmap_argv_uses_canonical_target(monkeypatch):
    seen = {}

    async def fake(argv, timeout):
        seen["argv"] = argv
        return {"ran": True}
    monkeypatch.setattr(toolbelt, "_run_argv", fake)
    _run(toolbelt._port_scan({"host": "Example.COM."}))
    assert seen["argv"][-2:] == ["--", "example.com"]
    out = _run(toolbelt._port_scan({"host": "10.0.0.1/8,--script=x"}))
    assert out["ran"] is False


@pytest.mark.parametrize("target,host", [
    ("HTTP://Example.COM:8080/a", "example.com"),
    ("bücher.example.com", "xn--bcher-kva.example.com"),
    ("example.com.", "example.com"),
    ("[2001:db8::1]:443", "2001:db8::1"),
])
def test_canonicalize(target, host):
    assert canonicalize_target(target)["host"] == host


@pytest.mark.parametrize("bad", ["", "  ", "http://user@example.com", "http://example.com\\@evil.com",
                                 "ftp://example.com", "http://[::1%eth0]/", "a b", "exa*mple.com"])
def test_canonicalize_rejects(bad):
    with pytest.raises(ScopeError):
        canonicalize_target(bad)


def test_unparsable_is_out_of_scope_fail_closed():
    assert check_target("http://exa mple.com", DOMAIN)[0] is False
    assert check_target(None, DOMAIN)[0] is False


def test_in_scope_usage_unchanged():
    assert check_target("https://example.com/x?y=1", DOMAIN)[0]
    assert check_target("api.example.com:8443", DOMAIN)[0]
    assert check_target("evil.com", DOMAIN)[0] is False
    assert check_target("http://example.com@evil.com/", DOMAIN)[0] is False


def test_agent_execute_fails_closed_on_scope_check_error(monkeypatch):
    from scanner.pentest.agent import PentestAgent
    monkeypatch.setattr(scope, "check_target_resolved", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    ran = {"v": False}

    async def runner(i, c):
        ran["v"] = True
        return {}
    tool = toolbelt.Tool("t", None, "", {}, runner, target_keys=["host"])
    ag = PentestAgent.__new__(PentestAgent)
    ag.run_id = 1
    ag._scope_rules = ONE_IP
    out = _run(ag._execute(tool, {"host": "172.18.0.2"}))
    assert "BỊ CHẶN" in out and ran["v"] is False
