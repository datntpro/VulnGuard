"""P1-1 — scope follow-ups (issue #29): ghim IP chống DNS rebinding, port-pinned url rule,
active_http/sqlmap qua canonical URL, redirect hop, schema strict (B13). Không mở socket thật."""
import asyncio

import httpcore
import httpx
import pytest

from scanner.pentest import toolbelt
from scanner.pentest.netpin import PinnedBackend, pinned_async_client, resolve_and_pin
from scanner.pentest.scope import ScopeError, allowed_ports, check_target_resolved


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


PUB1, PUB2, EVIL = "93.184.216.34", "93.184.216.35", "127.0.0.1"


def dom(*names):
    return [{"type": "domain", "value": n, "include_subdomains": False, "mode": "allow"} for n in names]


class FakeStream(httpcore.AsyncNetworkStream):
    def __init__(self, resp: bytes):
        self.resp, self.done = resp, False

    async def read(self, max_bytes, timeout=None):
        if self.done:
            return b""
        self.done = True
        return self.resp

    async def write(self, buffer, timeout=None):
        pass

    async def aclose(self):
        pass

    def get_extra_info(self, info):
        return None


class FakeInner(httpcore.AsyncNetworkBackend):
    """Backend giả: ghi (ip, port) được kết nối; trả lần lượt các response (hoặc raise nếu hết)."""
    def __init__(self, responses=()):
        self.calls, self.responses = [], list(responses)

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.calls.append((host, port))
        if not self.responses:
            raise httpcore.ConnectError("fake: no route")
        return FakeStream(self.responses.pop(0))

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise httpcore.ConnectError("no")

    async def sleep(self, seconds):
        pass


def _resp(status, headers=(), body=b"ok"):
    h = "".join(f"{k}: {v}\r\n" for k, v in headers)
    return (f"HTTP/1.1 {status} X\r\n{h}Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body


# ───── DNS rebinding pinning ─────
def test_rebinding_http_probe_connects_to_pinned_ip():
    seq = iter([[PUB1], [EVIL], [EVIL]])
    inner = FakeInner()
    ctx = {"scope_rules": dom("a.test"), "_resolver": lambda h: next(seq), "_pin_inner": inner}
    out = _run(toolbelt._http_probe({"url": "http://a.test/"}, ctx))
    assert inner.calls == [(PUB1, 80)]       # KHÔNG bao giờ tới 127.0.0.1 dù resolver đã đổi
    assert out.get("error")


def test_pinned_backend_rejects_unpinned_host():
    inner = FakeInner()
    be = PinnedBackend({"a.test": (PUB1,)}, inner)
    with pytest.raises(httpcore.ConnectError):
        _run(be.connect_tcp("evil.test", 80))
    assert inner.calls == []


def test_pinned_backend_ipv6_literal_and_fallback():
    class Flaky(FakeInner):
        async def connect_tcp(self, host, port, **kw):
            self.calls.append((host, port))
            if host == "::2":
                raise httpcore.ConnectError("down")
            return FakeStream(b"")
    inner = Flaky()
    _run(PinnedBackend({"::1": ("::1",), "a.test": ("::2", "::3")}, inner).connect_tcp("::1", 80))
    _run(PinnedBackend({"a.test": ("::2", "::3")}, inner).connect_tcp("A.test", 80))
    assert inner.calls == [("::1", 80), ("::2", 80), ("::3", 80)]


def test_pinned_client_private_attrs():
    c = pinned_async_client({"a.test": (PUB1,)}, inner=FakeInner())
    pool = c._transport._pool
    assert isinstance(pool, httpcore.AsyncConnectionPool) and isinstance(pool._network_backend, PinnedBackend)
    # httpx nâng cấp đổi cấu trúc nội bộ → fail ở đây (xem netpin.py)
    assert hasattr(httpx.AsyncHTTPTransport(verify=False)._pool, "_ssl_context")


def test_redirect_to_new_inscope_host_is_pinned():
    mapping = {"a.test": [PUB1], "b.test": [PUB2]}
    inner = FakeInner([_resp(302, [("Location", "http://b.test/x")]), _resp(200)])
    ctx = {"scope_rules": dom("a.test", "b.test"), "_resolver": lambda h: mapping[h], "_pin_inner": inner}
    out = _run(toolbelt._http_probe({"url": "http://a.test/"}, ctx))
    assert out["status_code"] == 200, out
    assert inner.calls == [(PUB1, 80), (PUB2, 80)]
    assert out["redirect_chain"] == ["http://b.test/x"]


def test_redirect_hop_port_change_rechecked_against_url_rule():
    rules = [{"type": "url", "value": "http://a.test:80", "mode": "allow"}]
    inner = FakeInner([_resp(302, [("Location", "https://a.test/")]), _resp(200)])
    ctx = {"scope_rules": rules, "_resolver": lambda h: [PUB1], "_pin_inner": inner}
    out = _run(toolbelt._http_probe({"url": "http://a.test/"}, ctx))
    assert "redirect_blocked" in out and inner.calls == [(PUB1, 80)]


@pytest.mark.parametrize("loc", ["//evil.test/x", "/\\evil.test", "javascript:alert(1)", "relative/path",
                                 "/ok\tbad", "ftp://a.test/", "", "http://a.test/\nX: y"])
def test_next_hop_rejects(loc):
    with pytest.raises(ScopeError):
        toolbelt._next_hop("http://a.test/start", loc)


def test_next_hop_accepts():
    assert toolbelt._next_hop("http://a.test:81/s", "/p?q=1") == "http://a.test:81/p?q=1"
    assert toolbelt._next_hop("http://a.test/s", "https://B.test/x") == "https://B.test/x"


@pytest.mark.parametrize("loc", ["//evil.test/x", "/\\evil.test", "javascript:alert(1)"])
def test_probe_blocks_bad_redirects(loc):
    inner = FakeInner([_resp(302, [("Location", loc)]), _resp(200)])
    ctx = {"scope_rules": dom("a.test"), "_resolver": lambda h: [PUB1], "_pin_inner": inner}
    out = _run(toolbelt._http_probe({"url": "http://a.test/"}, ctx))
    assert "redirect_blocked" in out and len(inner.calls) == 1


def test_resolve_and_pin_denies_and_returns_ips():
    pt = resolve_and_pin("http://a.test:8080/x", dom("a.test"), lambda h: [PUB2, PUB1])
    assert pt.ips == (PUB1, PUB2) and pt.host == "a.test" and pt.port == 8080
    with pytest.raises(ScopeError):
        resolve_and_pin("a.test", dom("a.test"), lambda h: [PUB1, EVIL])      # deny thắng
    with pytest.raises(ScopeError):
        resolve_and_pin("10.0.0.0/24", [{"type": "cidr", "value": "10.0.0.0/24", "mode": "allow"}])
    assert check_target_resolved("a.test", dom("a.test"), lambda h: [PUB1])[0]   # API công khai không đổi


def test_dns_enum_flags_rebinding_risk():
    seq = iter([[PUB1], [PUB2]])
    out = _run(toolbelt._dns_enum({"host": "a.test"}, {"_resolver": lambda h: next(seq), "_rebind_delay": 0}))
    assert out["rebinding_risk"] is True and out["addresses"] == [PUB1, PUB2]
    out = _run(toolbelt._dns_enum({"host": "a.test"}, {"_resolver": lambda h: [PUB1], "_rebind_delay": 0}))
    assert "rebinding_risk" not in out


def test_subprocess_tool_flags_dns_change(monkeypatch):
    seq = iter([[PUB1], [EVIL]])

    async def fake(argv, timeout):
        return {"ran": True}
    monkeypatch.setattr(toolbelt, "_run_argv", fake)
    monkeypatch.setattr(toolbelt.shutil, "which", lambda b: "/bin/" + b)
    monkeypatch.setattr(toolbelt, "resolve_wordlist", lambda p: p)
    ctx = {"scope_rules": dom("a.test"), "_resolver": lambda h: next(seq)}
    out = _run(toolbelt._content_discovery({"url": "http://a.test/"}, ctx))
    assert out["dns_changed_during_run"] is True and "warning" in out


# ───── port-pinned url rules + port_scan ─────
def test_allowed_ports():
    assert allowed_ports("h.test", [{"type": "url", "value": "http://h.test:8080", "mode": "allow"}]) == {8080}
    assert allowed_ports("h.test", [{"type": "url", "value": "https://h.test", "mode": "allow"}]) == {443}
    assert allowed_ports("h.test", dom("h.test")) is None
    assert allowed_ports("h.test", [{"type": "url", "value": "http://h.test:8080", "mode": "allow"}] + dom("h.test")) is None
    assert allowed_ports("other.test", dom("h.test")) == set()
    assert allowed_ports("h.test", [{"type": "url", "value": "http://h.test:8080", "mode": "allow"},
                                    {"type": "url", "value": "https://h.test", "mode": "allow"}]) == {443, 8080}


def _scan(rules, host, monkeypatch, ips=(PUB1,)):
    argvs = []

    async def fake(argv, timeout):
        argvs.append(argv)
        return {"ran": True}
    monkeypatch.setattr(toolbelt, "_run_argv", fake)
    out = _run(toolbelt._port_scan({"host": host}, {"scope_rules": rules, "_resolver": lambda h: list(ips)}))
    return out, argvs


def test_port_scan_url_rule_with_port(monkeypatch):
    out, argvs = _scan([{"type": "url", "value": "http://h.test:8080", "mode": "allow"}], "h.test", monkeypatch)
    a = argvs[0]
    assert a[a.index("-p") + 1] == "8080" and "--top-ports" not in a
    assert a[-2:] == ["--", PUB1] and "--max-hostgroup" in a
    assert out["port_restricted_to"] == [8080] and out["host_ips"] == {"h.test": [PUB1]}


def test_port_scan_url_rule_default_port(monkeypatch):
    _, argvs = _scan([{"type": "url", "value": "https://h.test", "mode": "allow"}], "h.test", monkeypatch)
    assert argvs[0][argvs[0].index("-p") + 1] == "443"


def test_port_scan_domain_rule_keeps_top_ports(monkeypatch):
    out, argvs = _scan(dom("h.test"), "h.test", monkeypatch)
    assert "--top-ports" in argvs[0] and "-p" not in argvs[0] and "port_restricted_to" not in out


def test_port_scan_multi_ip_capped_and_sequential(monkeypatch):
    ips = [f"93.184.216.{i}" for i in range(40, 47)]
    out, argvs = _scan(dom("h.test"), "h.test", monkeypatch, ips=ips)
    assert len(argvs) == 4 and len(out["scans"]) == 4


def test_port_scan_refuses_when_pin_denied(monkeypatch):
    out, argvs = _scan(dom("h.test"), "h.test", monkeypatch, ips=[PUB1, EVIL])
    assert out["ran"] is False and argvs == []


# ───── active_http ─────
def _active(inp, rules=None, extra=None):
    sent = []

    def handler(req):
        sent.append(req)
        return httpx.Response(200, text="ok")
    ctx = {"scope_rules": rules if rules is not None else [{"type": "ip", "value": PUB1, "mode": "allow"}],
           "_transport": httpx.MockTransport(handler)}
    ctx.update(extra or {})
    return _run(toolbelt._active_http(inp, ctx)), sent


def test_active_http_sends_canonical_url_with_array_headers():
    out, sent = _active({"url": f"HTTP://{PUB1}:8080/a?b=1", "method": "POST", "body": "x=1",
                         "headers": [{"name": "X-Test", "value": "1"}]})
    assert out["status_code"] == 200
    assert str(sent[0].url) == f"http://{PUB1}:8080/a?b=1" and sent[0].headers["x-test"] == "1"


@pytest.mark.parametrize("hdrs", [
    [{"name": "Host", "value": "evil"}], [{"name": "host", "value": "evil"}],
    [{"name": "Content-Length", "value": "1"}], [{"name": "Transfer-Encoding", "value": "chunked"}],
    [{"name": "Connection", "value": "close"}], [{"name": "Proxy-Authorization", "value": "x"}],
    [{"name": "X-A", "value": "a\r\nHost: evil"}], [{"name": "X-A", "value": "a\x00"}],
    [{"name": "X A", "value": "a"}], {"Host": "evil"}, [{"name": "X", "value": "v"}] * 31,
    [{"name": "X", "value": "v" * 4097}],
])
def test_active_http_rejects_bad_headers(hdrs):
    out, sent = _active({"url": f"http://{PUB1}/", "headers": hdrs})
    assert out["ran"] is False and sent == []


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://93.184.216.34/", "http://faß.lab/x",
                                 "http://93.184.216.99/", "http://user@93.184.216.34/"])
def test_active_http_rejects_bad_or_out_of_scope_url(url):
    out, sent = _active({"url": url})
    assert out["ran"] is False and sent == []


def test_active_http_body_limit_and_no_scope_fail_closed():
    out, sent = _active({"url": f"http://{PUB1}/", "body": "a" * (64 * 1024 + 1)})
    assert out["ran"] is False and sent == []
    out = _run(toolbelt._active_http({"url": f"http://{PUB1}/"}, {}))
    assert out["ran"] is False


def test_active_http_does_not_follow_redirect():
    sent = []

    def handler(req):
        sent.append(1)
        return httpx.Response(302, headers={"location": "http://127.0.0.1/"})
    ctx = {"scope_rules": [{"type": "ip", "value": PUB1, "mode": "allow"}], "_transport": httpx.MockTransport(handler)}
    out = _run(toolbelt._active_http({"url": f"http://{PUB1}/"}, ctx))
    assert len(sent) == 1 and out["status_code"] == 302


# ───── sqlmap ─────
def _sqlmap(inp, monkeypatch, ctx=None):
    seen = []

    async def fake(argv, timeout):
        seen.append(argv)
        return {"ran": True}
    monkeypatch.setattr(toolbelt, "_run_argv", fake)
    return _run(toolbelt._sqlmap(inp, ctx)), seen


def test_sqlmap_argv_hardened(monkeypatch):
    out, seen = _sqlmap({"url": "HTTP://Example.COM:8080/a?id=1", "technique": "BE"}, monkeypatch)
    a = seen[0]
    assert a[a.index("-u") + 1] == "http://example.com:8080/a?id=1"
    for f in ("--ignore-redirects", "--disable-coloring", "--skip-waf"):
        assert f in a
    assert "--crawl" not in a


@pytest.mark.parametrize("inp", [
    {"url": "http://e.com/", "technique": "B;rm"}, {"url": "http://e.com/", "technique": ""},
    {"url": "http://e.com/", "technique": "BEUSTQB"}, {"url": "http://e.com/", "data": "a\nb"},
    {"url": "http://e.com/", "data": "x" * 8193}, {"url": "file:///etc/passwd"}, {"url": "--version"},
])
def test_sqlmap_rejects(inp, monkeypatch):
    out, seen = _sqlmap(inp, monkeypatch)
    assert out["ran"] is False and seen == []


# ───── B13: strict schema conformance ─────
def _walk(node, path, errs):
    if isinstance(node, dict):
        if node.get("type") == "object":
            if node.get("additionalProperties") is not False:
                errs.append(f"{path}: object thiếu additionalProperties:false")
            props = node.get("properties", {})
            for k in node.get("required", []):
                if k not in props:
                    errs.append(f"{path}: required '{k}' không có trong properties")
        for k, v in node.items():
            _walk(v, f"{path}.{k}", errs)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _walk(v, f"{path}[{i}]", errs)


def test_all_tool_schemas_are_strict_conformant():
    from scanner.pentest.agent import REPORT_FINDING_DEF, UPDATE_PLAN_DEF
    errs = []
    for d in toolbelt.tool_defs_for_llm(include_unavailable=True) + [REPORT_FINDING_DEF, UPDATE_PLAN_DEF]:
        _walk(d["input_schema"], d["name"], errs)
    assert errs == []
