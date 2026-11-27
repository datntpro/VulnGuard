"""[AI PR-4] SSRF guard: corpus bypass, rebinding, redirect, ghim IP."""
import asyncio

import httpx
import pytest

from api.services import url_guard
from api.services.url_guard import UrlPolicy, UrlRejected, check_url


def _arun(coro):
    """Không dùng asyncio.run: nó bỏ event loop hiện tại của thread và làm hỏng các test dùng get_event_loop()."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()

PUBLIC = "93.184.216.34"
DNS = {
    "example.com": [PUBLIC], "api.openai.com": [PUBLIC], "localhost": ["127.0.0.1"],
    "mixed.example": [PUBLIC, "10.0.0.5"], "meta.example": ["169.254.169.254"],
    "corp.example": ["10.1.2.3"], "evil.corp.example": ["169.254.169.254"], "lan-ollama": ["192.168.1.50"],
    "v6meta.example": ["fd00:ec2::254"], "mapped.example": ["::ffff:127.0.0.1"],
}


def _resolver(host, port):
    if host not in DNS:
        raise UrlRejected("không phân giải được host")
    return list(DNS[host])


def pol(kind="cloud", **kw):
    return UrlPolicy(kind, resolver=_resolver, **kw)


CLOUD_BAD = [
    "https://169.254.169.254/latest/meta-data", "https://[fd00:ec2::254]/", "https://127.0.0.1/", "https://[::1]/",
    # mã hoá IP lạ
    "https://2130706433/", "https://0x7f000001/", "https://0177.0.0.1/", "https://127.1/", "https://0x7f.0.0.1/",
    "https://017700000001/", "https://2852039166/",                         # 169.254.169.254 dạng thập phân
    "https://１２７.０.０.１/",                                              # fullwidth → NFKC
    # IPv6 nhúng IPv4
    "https://[::ffff:127.0.0.1]/", "https://[::ffff:7f00:1]/", "https://[::ffff:169.254.169.254]/",
    "https://[64:ff9b::a9fe:a9fe]/", "https://[::127.0.0.1]/", "https://[2002:a9fe:a9fe::1]/", "https://[fe80::1]/",
    # private / đặc biệt
    "https://10.0.0.1/", "https://192.168.1.1/", "https://172.16.0.1/", "https://100.64.0.1/", "https://100.100.100.200/",
    "https://[fc00::1]/", "https://0.0.0.0/", "https://224.0.0.1/", "https://255.255.255.255/",
    # tên → IP cấm
    "https://localhost/", "https://localhost./", "https://meta.example/", "https://v6meta.example/", "https://mapped.example/",
    "https://mixed.example/",                                              # một trong các A record là private
    # cú pháp
    "https://user:pw@example.com/", "https://example.com@169.254.169.254/", "https://169.254.169.254#@example.com/",
    "https://example.com\\@169.254.169.254/", "https://example.com/?x=1", "https://example.com/#f", "https://exa mple.com/",
    "https://example.com/a/../b",
    # scheme / cổng
    "http://example.com/", "ftp://example.com/", "file:///etc/passwd", "gopher://example.com/", "https://example.com:8443/",
    "https://example.com:22/", "", "   ", "example.com", "https://",
]


@pytest.mark.parametrize("url", CLOUD_BAD)
def test_cloud_bypass_corpus_rejected(url):
    with pytest.raises(UrlRejected):
        check_url(url, "cloud", policy=pol())


def test_cloud_good_urls_normalised():
    p = pol()
    assert check_url("https://api.openai.com/v1/", "cloud", policy=p) == "https://api.openai.com/v1"
    assert check_url("HTTPS://Example.COM:443/openai/v1", "cloud", policy=p) == "https://example.com/openai/v1"
    assert check_url(f"https://{PUBLIC}/v1", "cloud", policy=p) == f"https://{PUBLIC}/v1"


def test_allowlist_opens_private_but_never_metadata_or_loopback():
    p = pol(allowlist=("corp.example", "*.corp.example", "localhost"))
    assert check_url("https://corp.example/v1", "cloud", policy=p) == "https://corp.example/v1"
    with pytest.raises(UrlRejected):
        check_url("https://evil.corp.example/", "cloud", policy=p)       # wildcard khớp nhưng IP là metadata
    with pytest.raises(UrlRejected):
        check_url("https://localhost/", "cloud", policy=p)               # loopback không bao giờ mở được
    with pytest.raises(UrlRejected):
        check_url("https://meta.example/", "cloud", policy=pol(allowlist=("meta.example",)))
    # allowlist không khớp hậu tố giả: "xcorp.example" không khớp "*.corp.example"
    assert not p.host_allowlisted("xcorp.example")


def test_extra_ports_are_admin_opt_in():
    with pytest.raises(UrlRejected):
        check_url("https://example.com:8443/v1", "cloud", policy=pol())
    assert check_url("https://example.com:8443/v1", "cloud", policy=pol(extra_ports=(8443,))).endswith(":8443/v1")


OLLAMA_BAD = [
    "http://169.254.169.254:11434/", "http://[fd00:ec2::254]:11434/", "http://[fe80::1]:11434/", "http://meta.example:11434/",
    "http://100.100.100.200:11434/", "http://2852039166:11434/", "http://0x7f000001:11434/",
    "http://[::ffff:169.254.169.254]:11434/", "http://user@192.168.1.5:11434/", "http://8.8.8.8:11434/",   # http tới public
    "http://example.com:11434/",                                                                           # http tới public
    "http://192.168.1.5:22/", "gopher://127.0.0.1:11434/", "http://0.0.0.0:11434/",
]


@pytest.mark.parametrize("url", OLLAMA_BAD)
def test_ollama_bypass_corpus_rejected(url):
    with pytest.raises(UrlRejected):
        check_url(url, "ollama", policy=pol("ollama"))


@pytest.mark.parametrize("url", ["http://localhost:11434", "http://127.0.0.1:11434", "http://[::1]:11434",
                                 "http://192.168.1.50:11434", "http://lan-ollama:11434", "https://example.com",
                                 "http://[::ffff:127.0.0.1]:11434", "http://10.0.0.7:11434/"])
def test_ollama_good(url):
    check_url(url, "ollama", policy=pol("ollama"))


# ── DNS rebinding + ghim IP + redirect: qua transport thật với inner giả ──────────────────────────
class _Seq:
    """Resolver trả danh sách tuần tự mỗi lần gọi (mô phỏng rebinding)."""
    def __init__(self, *answers): self.answers, self.calls = list(answers), 0
    def __call__(self, host, port):
        a = self.answers[min(self.calls, len(self.answers) - 1)]
        self.calls += 1
        return list(a)


def _client(resolver, handler, kind="cloud"):
    seen = []

    def h(request):
        seen.append(request)
        return handler(request)
    c = url_guard.guarded_async_client(kind, policy=UrlPolicy(kind, resolver=resolver), inner=httpx.MockTransport(h))
    return c, seen


def test_pinned_ip_is_used_with_original_host_header_and_sni():
    r = _Seq([PUBLIC])
    c, seen = _client(r, lambda req: httpx.Response(200, json={"ok": 1}))
    resp = _arun(c.get("https://example.com/v1/models"))
    assert resp.status_code == 200 and r.calls == 1
    req = seen[0]
    assert req.url.host == PUBLIC                          # kết nối tới đúng IP đã kiểm
    assert req.headers["host"] == "example.com"            # Host header giữ nguyên
    assert req.extensions["sni_hostname"] == "example.com"  # verify cert theo hostname


def test_dns_rebinding_second_resolution_private_is_refused():
    r = _Seq([PUBLIC], ["169.254.169.254"])
    c, seen = _client(r, lambda req: httpx.Response(200))
    _arun(c.get("https://example.com/a"))
    with pytest.raises(url_guard.GuardRejected):
        _arun(c.get("https://example.com/b"))
    assert len(seen) == 1                                  # request thứ 2 không bao giờ ra mạng


def test_rebinding_is_one_resolution_per_request_no_second_lookup_for_connect():
    # Cả check lẫn connect dùng CÙNG một kết quả resolve: không có cửa sổ TOCTOU giữa check và connect
    r = _Seq([PUBLIC], ["127.0.0.1"])
    c, seen = _client(r, lambda req: httpx.Response(200))
    _arun(c.get("https://example.com/x"))
    assert r.calls == 1 and seen[0].url.host == PUBLIC


def test_redirect_is_not_followed():
    def h(req):
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/meta-data"})
    c, seen = _client(_Seq([PUBLIC]), h)
    resp = _arun(c.get("https://example.com/"))
    assert resp.status_code == 302 and len(seen) == 1


def test_redirect_to_disallowed_host_blocked_even_if_followed_manually():
    # Nếu caller tự theo redirect, request tiếp theo vẫn đi qua guard và bị chặn
    c, seen = _client(_Seq([PUBLIC]), lambda req: httpx.Response(200))
    with pytest.raises(url_guard.GuardRejected):
        _arun(c.get("https://169.254.169.254/latest"))
    with pytest.raises(url_guard.GuardRejected):
        _arun(c.get("http://example.com/"))        # downgrade http bị chặn (cloud)
    assert seen == []


def test_ollama_http_to_public_ip_blocked_at_call_time():
    c, seen = _client(_Seq(["8.8.8.8"]), lambda req: httpx.Response(200), kind="ollama")
    with pytest.raises(url_guard.GuardRejected):
        _arun(c.get("http://ollama.example:11434/api/tags"))
    assert seen == []


def test_client_flags_no_redirect_no_proxy_env(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    c = url_guard.guarded_async_client("cloud")
    assert c.follow_redirects is False and c.trust_env is False
    assert not c._mounts


def test_sync_client_guard():
    c = url_guard.guarded_client("cloud", policy=UrlPolicy("cloud", resolver=_Seq(["10.0.0.1"])),
                                 inner=httpx.MockTransport(lambda r: httpx.Response(200)))
    with pytest.raises(url_guard.GuardRejected):
        c.get("https://example.com/")


def test_read_capped():
    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"x" * 5000))) as c:
            async with c.stream("GET", "https://example.com/") as r:
                return await url_guard.read_capped(r, cap=1000)
    with pytest.raises(UrlRejected):
        _arun(go())


def test_dns_failure_rejected(monkeypatch):
    monkeypatch.setattr(url_guard.socket, "getaddrinfo", lambda *a, **k: (_ for _ in ()).throw(url_guard.socket.gaierror()))
    with pytest.raises(UrlRejected):
        check_url("https://nonexistent.invalid/", "cloud", policy=UrlPolicy("cloud"))


def test_policy_for_reads_env(monkeypatch):
    monkeypatch.setenv("AI_BASE_URL_ALLOWLIST", "Corp.Example, *.lan.example")
    monkeypatch.setenv("AI_URL_EXTRA_PORTS", "8443,abc,99999")
    p = url_guard.policy_for("cloud")
    assert p.host_allowlisted("corp.example") and p.host_allowlisted("a.lan.example")
    assert 8443 in p.ports() and 99999 not in p.ports()


# ── [fix] httpx2 (SDK anthropic 2.x), cổng 80/443 Ollama, B3 ────────────────────
def test_httpx2_client_is_guarded_too():
    import httpx2
    seen = []
    c = url_guard.guarded_async_client("cloud", lib="httpx2", policy=UrlPolicy("cloud", resolver=_Seq(["10.0.0.1"])),
                                       inner=httpx2.MockTransport(lambda r: seen.append(r) or httpx2.Response(200)))
    assert c.follow_redirects is False and c.trust_env is False
    with pytest.raises(url_guard.GuardRejected):
        _arun(c.get("https://example.com/"))
    assert seen == []


@pytest.mark.parametrize("url", ["http://10.0.0.5", "http://127.0.0.1:80", "https://192.168.1.5", "http://lan-ollama:80"])
def test_ollama_lan_loopback_80_443_only_if_configured(url):
    with pytest.raises(UrlRejected):
        check_url(url, "ollama", policy=pol("ollama"))
    check_url(url, "ollama", policy=pol("ollama", extra_ports=(80, 443)))        # AI_URL_EXTRA_PORTS = opt-in rõ ràng
    from urllib.parse import urlsplit
    sp = urlsplit(url)
    host = sp.hostname
    port = sp.port or (443 if sp.scheme == "https" else 80)
    check_url(url, "ollama", policy=UrlPolicy("ollama", resolver=_resolver, configured=(host, port)))


def test_ollama_public_https_443_still_ok():
    check_url("https://example.com", "ollama", policy=pol("ollama"))


def test_ollama_call_sites_use_guarded_client():
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    for rel in ("scanner/ai_analyzer.py", "api/services/ollama_client.py", "api/routes/ollama.py"):
        src = (root / rel).read_text(encoding="utf-8")
        assert "httpx.AsyncClient(" not in src, rel
        assert "guarded_async_client(\"ollama\"" in src, rel
