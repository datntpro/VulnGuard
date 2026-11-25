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
    seq = iter([[PUB1], [EVIL], [EVIL], [EVIL]])

    async def fake(argv, timeout):
        return {"ran": True}
    monkeypatch.setattr(toolbelt, "_run_argv", fake)
    monkeypatch.setattr(toolbelt.shutil, "which", lambda b: "/bin/" + b)
    monkeypatch.setattr(toolbelt, "resolve_wordlist", lambda p: p)
    ctx = {"scope_rules": dom("a.test"), "_resolver": lambda h: next(seq)}
    out = _run(toolbelt._content_discovery({"url": "http://a.test/"}, ctx))
    assert out["dns_changed_during_run"] is True


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
    out, seen = _sqlmap({"url": "HTTP://Example.COM:8080/a?id=1", "technique": "BE"}, monkeypatch,
                        {"scope_rules": dom("example.com"), "_resolver": lambda h: [PUB1]})
    a = seen[0]
    assert a[a.index("-u") + 1] == "http://example.com:8080/a?id=1"
    for f in ("--ignore-redirects", "--disable-coloring", "--skip-waf"):
        assert f in a
    assert "--crawl" not in a


@pytest.mark.parametrize("inp", [
    {"url": "http://e.com/", "technique": "B;rm"}, {"url": "http://e.com/", "technique": ""},
    {"url": "http://e.com/", "technique": "BEUSTQB"}, {"url": "http://e.com/", "technique": "B\n"}, {"url": "http://e.com/", "data": "a\nb"},
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


# ═════════ Verifier round (PR #38 review): F1–F5 ═════════
from scanner.pentest.pinproxy import PinProxy  # noqa: E402
from scanner.pentest.scope import check_target  # noqa: E402

HTTPS_ONLY = [{"type": "url", "value": "https://h.test", "mode": "allow"}]
HTTPS_RES = {"scope_rules": HTTPS_ONLY, "_resolver": lambda h: [PUB1]}


# ───── F1: url rule không port = cổng MẶC ĐỊNH của scheme, cho MỌI tool ─────
@pytest.mark.parametrize("target", ["http://h.test:22/", "http://h.test/", "https://h.test:9999/", "h.test:22",
                                    "http://h.test:443/", "https://h.test:80/"])
def test_f1_url_rule_without_port_is_scheme_default_only(target):
    assert check_target(target, HTTPS_ONLY)[0] is False


@pytest.mark.parametrize("target", ["https://h.test/", "https://h.test:443/x", "HTTPS://H.test", "h.test", "h.test:443"])
def test_f1_default_port_still_allowed(target):
    assert check_target(target, HTTPS_ONLY)[0] is True


def test_f1_http_probe_and_active_http_reject_other_ports_and_schemes():
    seen = []

    def handler(req):
        seen.append(str(req.url))
        return httpx.Response(200, text="x")
    ctx = {**HTTPS_RES, "_transport": httpx.MockTransport(handler)}
    for u in ("http://h.test:22/", "http://h.test/", "https://h.test:8443/"):
        assert _run(toolbelt._http_probe({"url": u}, ctx))["ran"] is False
        assert _run(toolbelt._active_http({"url": u.replace("22", "9999")}, ctx))["ran"] is False
    assert seen == []
    assert _run(toolbelt._http_probe({"url": "https://h.test:443/"}, ctx))["status_code"] == 200


def test_f1_redirect_hop_to_http_or_other_port_blocked_under_https_rule():
    for loc in ("http://h.test/", "https://h.test:8443/"):
        inner = FakeInner([_resp(302, [("Location", loc)]), _resp(200)])
        ctx = {**HTTPS_RES, "_pin_inner": inner}
        out = _run(toolbelt._http_probe({"url": "https://h.test/"}, ctx))
        assert "redirect_blocked" in out or out.get("error") is not None
        assert len(inner.calls) <= 1


def test_f1_explicit_port_rule_also_pins_scheme():
    rules = [{"type": "url", "value": "http://h.test:8080", "mode": "allow"}]
    assert check_target("http://h.test:8080/x", rules)[0]
    assert check_target("https://h.test:8080/x", rules)[0] is False    # đổi scheme cùng port
    assert check_target("h.test:8080", rules)[0]


def test_f1_subprocess_tools_reject_other_ports(monkeypatch):
    async def fake(argv, timeout):
        raise AssertionError("must not run")
    monkeypatch.setattr(toolbelt, "_run_argv", fake)
    monkeypatch.setattr(toolbelt.shutil, "which", lambda b: "/bin/" + b)
    monkeypatch.setattr(toolbelt, "resolve_wordlist", lambda p: p)
    assert _run(toolbelt._sqlmap({"url": "http://h.test:8080/?id=1"}, HTTPS_RES))["ran"] is False
    assert _run(toolbelt._content_discovery({"url": "http://h.test:8080/"}, HTTPS_RES))["ran"] is False
    import scanner.crawler.nuclei_runner as nr

    async def no_nuclei(**kw):
        raise AssertionError("must not run")
    monkeypatch.setattr(nr, "run_nuclei", no_nuclei)
    assert _run(toolbelt._web_vuln_scan({"targets": ["http://h.test:8080/"]}, HTTPS_RES))["ran"] is False
    assert _run(toolbelt._nuclei_dast({"targets": ["http://h.test:8080/"]}, HTTPS_RES))["ran"] is False


# ───── F2: IPv6 pins cho nmap ─────
def test_f2_ipv6_pin_gets_dash_6_and_v4_first(monkeypatch):
    out, argvs = _scan(dom("h.test"), "h.test", monkeypatch, ips=["2606:4700:4700::1111", PUB1])
    assert [a[-1] for a in argvs] == [PUB1, "2606:4700:4700::1111"]
    assert "-6" not in argvs[0] and "-6" in argvs[1] and "-n" in argvs[0]
    assert argvs[1].index("-6") < argvs[1].index("--")


def test_f2_cap_is_deterministic_and_skips_reported(monkeypatch):
    ips = [f"2606:4700::{i}" for i in range(1, 4)] + [f"93.184.216.{i}" for i in range(40, 43)]
    out, argvs = _scan(dom("h.test"), "h.test", monkeypatch, ips=ips)
    assert len(argvs) == 4 and [a[-1] for a in argvs[:3]] == [f"93.184.216.{i}" for i in range(40, 43)]
    assert len(out["skipped_ips"]) == 2


def test_f2_ipv6_literal_and_cidr_get_dash_6(monkeypatch):
    argvs = []

    async def fake(argv, timeout):
        argvs.append(argv)
        return {"ran": True, "returncode": 0}
    monkeypatch.setattr(toolbelt, "_run_argv", fake)
    rules = [{"type": "cidr", "value": "2001:db8::/64", "mode": "allow"}]
    _run(toolbelt._port_scan({"host": "2001:db8::5"}, {"scope_rules": rules}))
    _run(toolbelt._port_scan({"host": "2001:db8::/120"}, {"scope_rules": rules}))
    assert all("-6" in a for a in argvs) and len(argvs) == 2


def test_f2_nmap_failure_is_an_error_not_success(monkeypatch):
    async def fake(argv, timeout):
        return {"ran": True, "returncode": 1, "stdout": "", "stderr": "QUITTING!"}
    monkeypatch.setattr(toolbelt, "_run_argv", fake)
    out = _run(toolbelt._port_scan({"host": PUB1}, {"scope_rules": [{"type": "ip", "value": PUB1, "mode": "allow"}]}))
    assert "error" in out and "QUITTING" in out["error"]


# ───── F3: nuclei/ffuf/sqlmap đi qua proxy ghim IP ─────
class Lab:
    """Origin HTTP giả + connector ghi (ip, port): bằng chứng proxy chỉ tới IP đã ghim."""
    def __init__(self):
        self.connects, self.reqs = [], []
        self.server = None

    async def start(self):
        async def origin(r, w):
            head = await r.readuntil(b"\r\n\r\n")
            self.reqs.append(head.decode("latin-1"))
            body = b"hello"
            w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n" + body)
            await w.drain()
            w.close()
        self.server = await asyncio.start_server(origin, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def connect(self, ip, port):
        self.connects.append((ip, port))
        return await asyncio.open_connection("127.0.0.1", self.port)

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()


async def _via_proxy(px, raw: bytes) -> bytes:
    r, w = await asyncio.open_connection("127.0.0.1", px.port)
    w.write(raw)
    await w.drain()
    data = await asyncio.wait_for(r.read(65536), 5)
    w.close()
    return data


def test_f3_pin_proxy_http_forwards_to_pinned_ip_only():
    async def go():
        lab = Lab()
        await lab.start()
        rules = dom("h.test")
        px2 = PinProxy({"h.test": (PUB1,)}, HTTPS_ONLY, connect=lab.connect)   # rule https mặc định → :22 bị chặn
        await px2.__aenter__()
        async with PinProxy({"h.test": (PUB1,)}, rules, connect=lab.connect) as px:
            ok = await _via_proxy(px, b"GET http://h.test/a?b=1 HTTP/1.1\r\nHost: h.test\r\nProxy-Connection: keep-alive\r\n\r\n")
            bad_host = await _via_proxy(px, b"GET http://evil.test/ HTTP/1.1\r\nHost: evil.test\r\n\r\n")
            bad_port_scheme = await _via_proxy(px2, b"CONNECT h.test:22 HTTP/1.1\r\n\r\n")
            non_http = await _via_proxy(px, b"GET ftp://h.test/ HTTP/1.1\r\n\r\n")
        await px2.__aexit__(None, None, None)
        await lab.stop()
        return lab, ok, bad_host, bad_port_scheme, non_http, px
    lab, ok, bad_host, bad_port, non_http, px = _run(go())
    assert b"200 OK" in ok and lab.connects == [(PUB1, 80)]
    assert lab.reqs[0].startswith("GET /a?b=1 HTTP/1.1") and "Proxy-Connection" not in lab.reqs[0]
    assert "Connection: close" in lab.reqs[0] and "Host: h.test" in lab.reqs[0]
    assert b" 403 " in bad_host and b" 403 " in bad_port and b" 403 " in non_http
    assert len(px.blocked) == 2 and len(px.blocked) + 1 == 3


def test_f3_pin_proxy_connect_tunnel_to_pinned_ip():
    async def go():
        lab = Lab()
        await lab.start()
        async with PinProxy({"h.test": (PUB1, PUB2)}, dom("h.test") + [], connect=lab.connect) as px:
            r, w = await asyncio.open_connection("127.0.0.1", px.port)
            w.write(b"CONNECT h.test:80 HTTP/1.1\r\nHost: h.test:80\r\n\r\n")
            await w.drain()
            est = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 5)
            w.write(b"GET / HTTP/1.1\r\nHost: h.test\r\n\r\n")
            body = await asyncio.wait_for(r.read(65536), 5)
            w.close()
        await lab.stop()
        return lab, est, body
    lab, est, body = _run(go())
    assert b"200 Connection established" in est and b"hello" in body and lab.connects == [(PUB1, 80)]


def test_f3_rebinding_cannot_reach_other_ip_through_tools(monkeypatch):
    """Resolver lật sang 127.0.0.1 sau lần kiểm đầu; tool (giả lập subprocess đi qua -x) vẫn chỉ tới IP đã ghim,
    và flip-back không làm mất cờ / không có request nào tới IP khác."""
    calls = {"n": 0}

    def resolver(h):
        calls["n"] += 1
        return [PUB1] if calls["n"] == 1 else [EVIL]       # lần 1 hợp lệ, sau đó rebinding

    async def go():
        lab = Lab()
        await lab.start()

        async def fake_run(argv, timeout):
            px_url = argv[argv.index("-x") + 1]
            port = int(px_url.rsplit(":", 1)[1])
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(b"GET http://h.test/FUZZ HTTP/1.1\r\nHost: h.test\r\n\r\n")
            await w.drain()
            data = await asyncio.wait_for(r.read(65536), 5)
            w.close()
            return {"ran": True, "stdout": data.decode()}
        monkeypatch.setattr(toolbelt, "_run_argv", fake_run)
        monkeypatch.setattr(toolbelt.shutil, "which", lambda b: "/bin/" + b)
        monkeypatch.setattr(toolbelt, "resolve_wordlist", lambda p: p)
        ctx = {"scope_rules": dom("h.test"), "_resolver": resolver, "_pin_connect": lab.connect}
        out = await toolbelt._content_discovery({"url": "http://h.test/"}, ctx)
        await lab.stop()
        return lab, out
    lab, out = _run(go())
    assert "200 OK" in out["stdout"]
    assert lab.connects == [(PUB1, 80)]                      # 0 kết nối tới 127.0.0.1
    assert out["dns_changed_during_run"] is True             # cờ bật với MỌI thay đổi


def test_f3_nuclei_gets_proxy_and_http_only_for_hostnames(monkeypatch):
    import scanner.crawler.nuclei_runner as nr
    seen = []

    async def fake_run_nuclei(**kw):
        seen.append(kw)
        return [], {"error": None}
    monkeypatch.setattr(nr, "run_nuclei", fake_run_nuclei)
    _run(toolbelt._web_vuln_scan({"targets": ["http://h.test/"]}, {"scope_rules": dom("h.test"), "_resolver": lambda h: [PUB1]}))
    assert seen[-1]["proxy"].startswith("http://127.0.0.1:")
    _run(toolbelt._nuclei_dast({"targets": ["http://h.test/"]}, {"scope_rules": dom("h.test"), "_resolver": lambda h: [PUB1]}))
    assert seen[-1]["proxy"].startswith("http://127.0.0.1:")
    # IP literal: không có DNS → chạy thẳng, không proxy
    _run(toolbelt._web_vuln_scan({"targets": [f"http://{PUB1}/"]}, {"scope_rules": [{"type": "ip", "value": PUB1, "mode": "allow"}]}))
    assert seen[-1]["proxy"] is None
    # không scope_rules → từ chối
    out = _run(toolbelt._web_vuln_scan({"targets": ["http://h.test/"]}, {}))
    assert out["ran"] is False and len(seen) == 3


def test_f3_nuclei_command_proxy_flags():
    from scanner.crawler.nuclei_runner import build_command
    a = build_command("t.txt", ["high"], [], False, 50, safe_net=True, proxy="http://127.0.0.1:9")
    assert a[a.index("-proxy") + 1] == "http://127.0.0.1:9" and a[a.index("-pt") + 1] == "http"
    assert "-proxy" not in build_command("t.txt", ["high"], [], False, 50)


def test_f3_sqlmap_and_ffuf_get_proxy_flag(monkeypatch):
    argvs = []

    async def fake(argv, timeout):
        argvs.append(argv)
        return {"ran": True}
    monkeypatch.setattr(toolbelt, "_run_argv", fake)
    monkeypatch.setattr(toolbelt.shutil, "which", lambda b: "/bin/" + b)
    monkeypatch.setattr(toolbelt, "resolve_wordlist", lambda p: p)
    ctx = {"scope_rules": dom("h.test"), "_resolver": lambda h: [PUB1]}
    _run(toolbelt._sqlmap({"url": "http://h.test/?id=1", "data": "--os-shell"}, ctx))
    _run(toolbelt._content_discovery({"url": "http://h.test/"}, ctx))
    assert any(x.startswith("--proxy=http://127.0.0.1:") for x in argvs[0]) and "--data=--os-shell" in argvs[0]
    assert argvs[1][argvs[1].index("-x") + 1].startswith("http://127.0.0.1:")


def test_f3_unpinnable_hostname_refuses_to_run(monkeypatch):
    async def fake(argv, timeout):
        raise AssertionError("must not run")
    monkeypatch.setattr(toolbelt, "_run_argv", fake)
    ctx = {"scope_rules": dom("h.test"), "_resolver": lambda h: [PUB1, EVIL]}
    assert _run(toolbelt._sqlmap({"url": "http://h.test/"}, ctx))["ran"] is False
    assert _run(toolbelt._sqlmap({"url": "http://h.test/"}, {}))["ran"] is False


# ───── F5: Location lạ → redirect_blocked kèm status ─────
@pytest.mark.parametrize("loc", ["http://172.29.38.011/x", "/a b"])
def test_f5_weird_location_is_redirect_blocked_with_status(loc):
    inner = FakeInner([_resp(302, [("Location", loc)])])
    ctx = {"scope_rules": dom("a.test"), "_resolver": lambda h: [PUB1], "_pin_inner": inner}
    out = _run(toolbelt._http_probe({"url": "http://a.test/"}, ctx))
    assert out.get("status_code") == 302 and "redirect_blocked" in out, out
