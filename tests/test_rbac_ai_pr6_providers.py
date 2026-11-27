"""[AI PR-6] Provider expansion: Azure OpenAI (key + Entra), Gemini, Vertex AI (service account), OpenAI-compatible,
OpenRouter parity. Probe qua stub TLS cục bộ (socket + TLS thật, SDK thật), SSRF corpus qua endpoint/region/location/
project/deployment, key không lọt vào log/lỗi/repr, envelope gắn tham số, bảng giá, mẫu che, driver tool-use."""
import asyncio
import base64
import copy
import importlib
import json
import logging
import re
import shutil
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from api.security import encrypt_secret
from api.services import ai_oauth, ai_probe
from api.services import ai_provider_params as pp
from api.services import url_guard
from api.services.ai_config import DEFAULT_CONFIG
from api.services.llm_resolver import Cloud, cloud_route_for, open_client
from api.services.url_guard import UrlPolicy, UrlRejected

PUBLIC = "93.184.216.34"
KEY_AZ = "az0123456789abcdef0123456789abcdef"            # Azure 32-hex
KEY_GEM = "AIza" + "SyD3x4mpleKeyForTestingOnly0123456789"[:35]
KEY_OR = "sk-or-v1-" + "a1b2c3d4e5f6" * 4
KEY_OAI = "sk-test-0123456789abcdefghij"
ENTRA_SECRET = "abc8Q~" + "Xy9Zq-W.eRtYuIoP1aSdFgHjKlZxCvBn"
TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "99999999-8888-7777-6666-555555555555"


def _arun(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _sa_json(**over):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    d = {"type": "service_account", "project_id": "proj-abc123", "private_key_id": "0123456789abcdef0123456789abcdef01234567",
         "private_key": pem, "client_email": "vg-sa@proj-abc123.iam.gserviceaccount.com",
         "token_uri": "https://evil.example/steal"}
    d.update(over)
    return json.dumps(d), key.public_key(), pem


SA_JSON, SA_PUB, SA_PEM = _sa_json()


def _cfg(provider, **sec):
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    cfg["provider"] = provider
    cfg[provider].update(sec)
    return cfg


def _route(provider, key=None, **sec):
    if key is not None:
        sec["api_key_enc"] = encrypt_secret(key)
    return cloud_route_for(_cfg(provider, **sec))


AZ = dict(endpoint="https://myres.openai.azure.com", deployment="gpt-4o-prod", api_version="2024-10-21")
VX = dict(project="proj-abc123", location="us-central1")


@pytest.fixture(autouse=True)
def _offline_dns(monkeypatch):
    """Không DNS thật: localhost → loopback, mọi host khác → IP public (stub fixture ghi đè khi cần)."""
    monkeypatch.setattr(url_guard, "_system_resolve", lambda host, port: ["127.0.0.1"] if host == "localhost" else [PUBLIC])


# ─────────────────────────────────────────────
# Stub TLS (SDK thật + socket + TLS thật) + transport ghi lại nơi request thật sự được gửi
# ─────────────────────────────────────────────
class Stub:
    def __init__(self):
        self.hits = []        # (method, path, query, headers, body)
        self.pinned = []      # (host trước khi rewrite — IP đã ghim, header Host gốc)
        self.fail = None      # (status, body) cho chat/models
        self.token_fail = False
        self.port = 0

    def find(self, method, suffix):
        return [h for h in self.hits if h[0] == method and h[1].endswith(suffix)]


@pytest.fixture
def stub(tmp_path, monkeypatch):
    if not shutil.which("openssl"):
        pytest.skip("cần openssl")
    crt, key = tmp_path / "c.pem", tmp_path / "k.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(crt),
                    "-subj", "/CN=localhost", "-days", "1", "-addext", "subjectAltName=IP:127.0.0.1"],
                   check=True, capture_output=True)
    st = Stub()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, obj, code=200):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def _rec(self, body=None):
            sp = urlsplit(self.path)
            st.hits.append((self.command, sp.path, parse_qs(sp.query), {k.lower(): v for k, v in self.headers.items()}, body))
            return sp.path

        def do_GET(self):
            path = self._rec()
            if st.fail:
                return self._send(st.fail[1], st.fail[0])
            if path.endswith("/models"):
                return self._send({"object": "list", "data": [{"id": "models/gemini-2.5-flash", "object": "model"},
                                                              {"id": "models/embedding-001", "object": "model"},
                                                              {"id": "gpt-4o", "object": "model"}]})
            self._send({}, 404)

        def do_POST(self):
            n = int(self.headers.get("content-length", 0))
            raw = self.rfile.read(n) or b""
            ctype = self.headers.get("content-type", "")
            body = parse_qs(raw.decode()) if "x-www-form-urlencoded" in ctype else json.loads(raw or b"{}")
            path = self._rec(body)
            if path.endswith("/token"):
                if st.token_fail:
                    return self._send({"error": f"invalid_grant {ENTRA_SECRET} {SA_PEM[:40]}"}, 400)
                return self._send({"access_token": "ya29.TESTACCESSTOKEN" + "z" * 24, "expires_in": 3600})
            if st.fail:
                return self._send(st.fail[1], st.fail[0])
            msg = {"role": "assistant", "content": "ok"}
            fin = "stop"
            if isinstance(body, dict) and body.get("tools"):
                msg = {"role": "assistant", "content": None, "tool_calls": [
                    {"id": "call_1", "type": "function", "function": {"name": "probe", "arguments": "{\"x\": 1}"}}]}
                fin = "tool_calls"
            self._send({"id": "c1", "object": "chat.completion", "created": 1, "model": "m",
                        "choices": [{"index": 0, "finish_reason": fin, "message": msg}],
                        "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}})

    srv = HTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(crt), str(key))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    st.port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def rewriting(lib_mod):
        base = lib_mod.AsyncHTTPTransport(verify=False)

        class T(lib_mod.AsyncBaseTransport):
            async def handle_async_request(self, request):
                st.pinned.append((request.url.host, request.headers.get("host", "")))
                request.url = request.url.copy_with(scheme="https", host="127.0.0.1", port=st.port)
                return await base.handle_async_request(request)

            async def aclose(self):
                await base.aclose()
        return T()

    st.dns = [PUBLIC]
    orig_guarded = url_guard.guarded_async_client

    def guarded(kind="cloud", *, timeout=10.0, policy=None, inner=None, lib="httpx"):
        pol = policy or UrlPolicy(kind, resolver=lambda h, p: list(st.dns))
        return orig_guarded(kind, timeout=timeout, policy=pol, inner=rewriting(url_guard._lib(lib)), lib=lib)

    def plain(lib="httpx", *, timeout=10.0):
        m = url_guard._lib(lib)
        return m.AsyncClient(transport=rewriting(m), trust_env=False, follow_redirects=False, timeout=timeout)

    monkeypatch.setattr(url_guard, "guarded_async_client", guarded)
    monkeypatch.setattr(url_guard, "plain_async_client", plain)
    monkeypatch.setattr(url_guard, "_system_resolve", lambda host, port: ["127.0.0.1"] if host == "localhost" else list(st.dns))
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")      # phải bị bỏ qua (trust_env=False)
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    ai_probe.reset_throttle()
    yield st
    srv.shutdown()


def _probe(route):
    return _arun(ai_probe.probe_cloud(route))


# ─────────────────────────────────────────────
# 1. Probe thành công qua stub TLS — từng provider (đường dẫn, header, ghim IP, không GET /models khi không có)
# ─────────────────────────────────────────────
def test_azure_key_probe_success(stub):
    r = _probe(_route("azure_openai", KEY_AZ, **AZ))
    assert (r.ok, r.code, r.tools, r.model) == (True, "VALID", True, "gpt-4o-prod"), r
    assert not stub.find("GET", "/models")                       # Azure: không có bước liệt kê
    post = stub.find("POST", "/openai/deployments/gpt-4o-prod/chat/completions")
    assert post and post[0][2] == {"api-version": ["2024-10-21"]}
    assert post[0][3]["api-key"] == KEY_AZ
    assert {p[0] for p in stub.pinned} == {PUBLIC}                  # IP đã ghim, không phải hostname
    assert all(p[1].startswith("myres.openai.azure.com") for p in stub.pinned)   # Host header gốc giữ nguyên


def test_azure_entra_probe_success_uses_bearer_from_fixed_host(stub, monkeypatch):
    r = _probe(_route("azure_openai", ENTRA_SECRET, auth_mode="entra", tenant_id=TENANT, client_id=CLIENT, **AZ))
    assert r.ok and r.code == "VALID", r
    tok = stub.find("POST", f"/{TENANT}/oauth2/v2.0/token")
    assert tok and tok[0][4]["client_secret"] == [ENTRA_SECRET] and tok[0][4]["client_id"] == [CLIENT]
    assert tok[0][4]["scope"] == ["https://cognitiveservices.azure.com/.default"]
    chat = stub.find("POST", "/chat/completions")[0]
    assert chat[3]["authorization"].startswith("Bearer ya29.TESTACCESSTOKEN") and "api-key" not in chat[3]
    assert ENTRA_SECRET not in json.dumps(chat[3])


def test_gemini_probe_success(stub):
    r = _probe(_route("gemini", KEY_GEM))
    assert (r.ok, r.code, r.tools, r.model) == (True, "VALID", True, "gemini-2.5-flash"), r
    assert stub.find("GET", "/v1beta/openai/models") and stub.find("POST", "/v1beta/openai/chat/completions")
    assert all(h[3]["authorization"] == f"Bearer {KEY_GEM}" for h in stub.hits)


def test_vertex_probe_success_mints_token_from_fixed_google_host(stub):
    r = _probe(_route("vertex", SA_JSON, **VX))
    assert (r.ok, r.code, r.tools, r.model) == (True, "VALID", True, "google/gemini-2.5-flash"), r
    chat = stub.find("POST", "/v1/projects/proj-abc123/locations/us-central1/endpoints/openapi/chat/completions")
    assert chat and chat[0][3]["authorization"].startswith("Bearer ya29.TESTACCESSTOKEN")
    assert not stub.find("GET", "/models")
    tok = stub.find("POST", "/token")
    assert len(tok) == 1 and tok[0][4]["grant_type"] == ["urn:ietf:params:oauth:grant-type:jwt-bearer"]
    # `token_uri` trong SA JSON (evil.example) bị bỏ qua: không request nào tới host đó
    assert not any("evil" in h[3].get("host", "") for h in stub.hits)
    h64, c64, s64 = tok[0][4]["assertion"][0].split(".")
    pad = lambda s: s + "=" * (-len(s) % 4)   # noqa: E731
    claims = json.loads(base64.urlsafe_b64decode(pad(c64)))
    assert claims["iss"] == "vg-sa@proj-abc123.iam.gserviceaccount.com" and claims["aud"] == ai_oauth.GOOGLE_TOKEN_URL
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    SA_PUB.verify(base64.urlsafe_b64decode(pad(s64)), f"{h64}.{c64}".encode(), padding.PKCS1v15(), hashes.SHA256())


def test_vertex_global_location_uses_global_host(stub):
    assert pp.vertex_base_url("proj-abc123", "global") == \
        "https://aiplatform.googleapis.com/v1/projects/proj-abc123/locations/global/endpoints/openapi"
    assert pp.vertex_base_url("proj-abc123", "europe-west4").startswith("https://europe-west4-aiplatform.googleapis.com/")


def test_openai_compatible_probe_success_and_list_404_tolerated(stub):
    r = _probe(_route("openai_compatible", KEY_OAI, base_url="https://llm.example.com/v1", model="my-model"))
    assert (r.ok, r.code, r.model) == (True, "VALID", "my-model"), r
    assert stub.find("POST", "/v1/chat/completions")[0][3]["authorization"] == f"Bearer {KEY_OAI}"
    assert {p[0] for p in stub.pinned} == {PUBLIC}


def test_openrouter_probe_success_parity(stub):
    r = _probe(_route("openrouter", KEY_OR))
    assert r.ok and r.code == "VALID", r
    assert stub.find("POST", "/api/v1/chat/completions")[0][3]["authorization"] == f"Bearer {KEY_OR}"
    assert stub.find("POST", "/api/v1/chat/completions")[0][3].get("x-title") == "VulnGuard"


def test_open_client_family_and_model_for_every_new_provider():
    cases = [("azure_openai", KEY_AZ, AZ, "gpt-4o-prod"), ("gemini", KEY_GEM, {}, "gemini-2.5-flash"),
             ("vertex", SA_JSON, VX, "google/gemini-2.5-flash"),
             ("openai_compatible", KEY_OAI, dict(base_url="https://llm.example.com/v1", model="m1"), "m1")]
    for prov, key, sec, model in cases:
        route = _route(prov, key, **sec)
        assert isinstance(route, Cloud) and route.family == "openai" and route.model == model, prov


def test_bad_json_or_missing_params_fail_cleanly(stub):
    assert _probe(_route("vertex", "not json", **VX)).code == "BAD_BASE_URL"            # SA JSON hỏng
    assert _probe(_route("openai_compatible", KEY_OAI, base_url="")).code in ("NO_CREDENTIAL", "BAD_BASE_URL")
    assert _probe(_route("azure_openai", None, **AZ)).code == "NO_CREDENTIAL"           # thiếu key
    assert _probe(_route("gemini", None)).code == "NO_CREDENTIAL"


# ─────────────────────────────────────────────
# 2. SSRF corpus qua endpoint / deployment / region / location / project / base_url
# ─────────────────────────────────────────────
AZ_BAD_ENDPOINTS = [
    "https://169.254.169.254", "https://127.0.0.1", "https://[::1]", "https://localhost", "https://evil.com",
    "https://myres.openai.azure.com.evil.com", "https://evil.com/myres.openai.azure.com", "https://myres.openai.azure.com@evil.com",
    "https://evil.com#.openai.azure.com", "https://evil.com?.openai.azure.com", "http://myres.openai.azure.com",
    "https://myres.openai.azure.com:8443", "https://myres.openai.azure.com:22", "https://myres.openai.azure.com/openai",
    "https://myres.openai.azure.com/?x=1", "https://myres.openai.azure.com#f", "https://user:pw@myres.openai.azure.com",
    "https://openai.azure.com", "https://.openai.azure.com", "https://-bad.openai.azure.com", "https://bad-.openai.azure.com",
    "https://a_b.openai.azure.com", "https://a.b.openai.azure.com", "https://my res.openai.azure.com",
    "https://myres.openai.azure.com\\@evil.com", "https://myres.openai.azure.com/../x", "https://２２.openai.azure.com.evil.com",
    "https://2130706433", "https://0x7f000001", "https://[::ffff:127.0.0.1]", "ftp://myres.openai.azure.com", "file:///etc/passwd",
    "", "   ", "myres.openai.azure.com", "https://myres.openai.azure.com\n.evil.com", "https://myres.openai.azure.com\x00.evil.com",
    "https://" + "a" * 64 + ".openai.azure.com", "https://xn--evil.openai.azure.com.evil.com",
]


@pytest.mark.parametrize("ep", AZ_BAD_ENDPOINTS)
def test_azure_endpoint_corpus_rejected_everywhere(ep, stub):
    with pytest.raises(UrlRejected):
        pp.check_azure_endpoint(ep)
    route = _route("azure_openai", KEY_AZ, **{**AZ, "endpoint": ep})
    with pytest.raises(UrlRejected):
        open_client(route)                       # kiểm lại lúc dựng client (hàng DB / body test có thể bị sửa)
    r = _probe(route)
    assert (r.ok, r.code) == (False, "BAD_BASE_URL")
    assert stub.hits == []                       # không request nào ra khỏi tiến trình


def test_azure_good_endpoints_and_sovereign_suffixes():
    for ep in ("https://myres.openai.azure.com", "https://MyRes.openai.azure.com/", "https://x1.cognitiveservices.azure.com",
               "https://gov-res.openai.azure.us", "https://myres.openai.azure.com:443"):
        assert pp.check_azure_endpoint(ep).startswith("https://") and "@" not in pp.check_azure_endpoint(ep)
    assert pp.check_azure_endpoint("https://MyRes.openai.azure.com/") == "https://myres.openai.azure.com"


@pytest.mark.parametrize("dep", ["../../etc", "a/b", "a?b=1", "a b", "", "x" * 65, "-x", "a\nb", "a#b", "http://evil", "a@b", "%2e%2e"])
def test_azure_deployment_corpus(dep):
    with pytest.raises(UrlRejected):
        pp.check_deployment(dep)
    with pytest.raises(UrlRejected):
        open_client(_route("azure_openai", KEY_AZ, **{**AZ, "deployment": dep}))


@pytest.mark.parametrize("ver", ["2024-10-21&x=1", "latest", "2024-1-1", "../x", "2024-10-21\n&x", "2024-10-21-preview2"])
def test_azure_api_version_corpus(ver):
    with pytest.raises(UrlRejected):
        pp.check_api_version(ver)


@pytest.mark.parametrize("loc", ["us-central1.evil.com", "us-central1/../x", "evil.com#", "us central1", "localhost", "a" * 40,
                                 "us-central1:443", "us-central1@evil", "UPPER-1", "169.254.169.254", "-evil-1", "https://x", ""])
def test_vertex_location_corpus(loc, stub):
    if loc == "":
        assert pp.check_gcp_location(loc) == "us-central1"      # trống = mặc định
        return
    with pytest.raises(UrlRejected):
        pp.check_gcp_location(loc)
    r = _probe(_route("vertex", SA_JSON, project="proj-abc123", location=loc))
    assert (r.ok, r.code) == (False, "BAD_BASE_URL") and stub.hits == []


@pytest.mark.parametrize("proj", ["p/../x", "proj?x=1", "Proj-ABC", "a", "proj abc", "p" * 31, "proj-", "1proj-abc", "proj%2fx",
                                  "proj#x", "", "proj@evil"])
def test_vertex_project_corpus(proj, stub):
    with pytest.raises(UrlRejected):
        pp.check_gcp_project(proj)
    r = _probe(_route("vertex", SA_JSON, project=proj, location="us-central1"))
    assert (r.ok, r.code) == (False, "BAD_BASE_URL") and stub.hits == []


@pytest.mark.parametrize("region", ["evil.com", "us-east-1.evil.com", "us-east-1/../x", "US-EAST-1", "us-east-1#", "", "x" * 40])
def test_bedrock_region_corpus_still_rejected(region):
    from api.services.llm_resolver import valid_region
    assert not valid_region(region) or region == ""


@pytest.mark.parametrize("url", [
    "https://169.254.169.254/v1", "https://127.0.0.1/v1", "https://[::1]/v1", "https://2130706433/v1", "https://0x7f000001/v1",
    "https://localhost/v1", "http://llm.example.com/v1", "https://user:pw@llm.example.com/v1", "https://llm.example.com:8443/v1",
    "https://llm.example.com/v1?key=1", "https://10.0.0.5/v1", "https://[::ffff:169.254.169.254]/v1", "file:///etc/passwd",
    "https://llm.example.com/../v1", "https://100.100.100.200/v1", "https://[fd00:ec2::254]/v1",
])
def test_openai_compatible_base_url_corpus(url, stub):
    route = _route("openai_compatible", KEY_OAI, base_url=url, model="m")
    with pytest.raises(UrlRejected):
        open_client(route)
    r = _probe(route)
    assert (r.ok, r.code) == (False, "BAD_BASE_URL") and stub.hits == []


@pytest.mark.parametrize("provider,sec,key", [
    ("azure_openai", AZ, KEY_AZ), ("vertex", VX, SA_JSON),
    ("openai_compatible", dict(base_url="https://llm.example.com/v1", model="m"), KEY_OAI)])
def test_dns_rebinding_blocked_at_call_time(provider, sec, key, stub):
    """Host hợp lệ lúc dựng client nhưng resolve ra IP cấm lúc gọi (rebinding) → chặn, không request nào tới stub."""
    route = _route(provider, key, **sec)
    stub.dns = ["169.254.169.254"]
    chat = lambda: [h for h in stub.hits if h[1].endswith("/chat/completions") or h[1].endswith("/models")]   # noqa: E731
    r = _probe(route)       # (Vertex: token lấy từ host Google CỐ ĐỊNH — không phải đích bị rebinding)
    assert (r.ok, r.code) == (False, "BAD_BASE_URL") and chat() == [], r
    stub.dns = [PUBLIC, "10.0.0.7"]                       # một trong các A record là private
    assert _probe(route).code == "BAD_BASE_URL" and chat() == []


def test_no_redirect_followed_and_proxy_env_ignored(stub, monkeypatch):
    """Proxy env bị bỏ qua (probe vẫn thành công dù HTTPS_PROXY trỏ vào cổng chết) và redirect không được theo."""
    assert _probe(_route("gemini", KEY_GEM)).ok
    for prov in ("azure_openai", "vertex", "openai_compatible"):
        client = url_guard.guarded_async_client("cloud")
        assert client.follow_redirects is False and client.trust_env is False
        _arun(client.aclose())
    plain = url_guard.plain_async_client("httpx")
    assert plain.follow_redirects is False and plain.trust_env is False
    _arun(plain.aclose())


def test_user_cannot_supply_arbitrary_azure_endpoint_only_a_resource_label():
    with pytest.raises(UrlRejected):
        pp.azure_endpoint_from_resource("evil.com/x")
    with pytest.raises(UrlRejected):
        pp.azure_endpoint_from_resource("a.b")
    assert pp.azure_endpoint_from_resource("my-res1") == "https://my-res1.openai.azure.com"


# ─────────────────────────────────────────────
# 3. Key không bao giờ lọt vào log / lỗi / repr / kết quả probe
# ─────────────────────────────────────────────
PROVIDER_CASES = [
    ("azure_openai", KEY_AZ, AZ), ("gemini", KEY_GEM, {}), ("vertex", SA_JSON, VX),
    ("openai_compatible", KEY_OAI, dict(base_url="https://llm.example.com/v1", model="m")), ("openrouter", KEY_OR, {}),
    ("azure_openai", ENTRA_SECRET, dict(auth_mode="entra", tenant_id=TENANT, client_id=CLIENT, **AZ)),
]
_ID = ["azure", "gemini", "vertex", "compat", "openrouter", "entra"]


def _secrets_of(key):
    out = [key, SA_PEM, "ya29.TESTACCESSTOKEN"]
    if key == SA_JSON:
        out += [SA_PEM[30:80], json.loads(SA_JSON)["private_key_id"]]
    return out


@pytest.mark.parametrize("provider,key,sec", PROVIDER_CASES, ids=_ID)
def test_key_never_in_repr_logs_or_probe_result(provider, key, sec, stub, caplog):
    caplog.set_level(logging.DEBUG)
    route = _route(provider, key, **sec)
    for text in (repr(route), str(route), repr(route.credential), str(route.credential), repr(route.credential.public_params())):
        for s in _secrets_of(key):
            assert s not in text
    stub.fail = (401, {"error": {"message": f"Incorrect API key provided: {key} / {SA_PEM[:60]} / Bearer {key}"}})
    r = _probe(route)
    assert (r.ok, r.code) == (False, "INVALID_KEY"), r
    blob = json.dumps(r.to_dict()) + repr(r)
    logs = "\n".join(rec.getMessage() for rec in caplog.records)
    for s in _secrets_of(key):
        assert s not in blob and s not in logs, s
    with pytest.raises(TypeError):
        import pickle
        pickle.dumps(route.credential)
    with pytest.raises(TypeError):
        copy.deepcopy(route.credential)


def test_oauth_failure_is_invalid_key_and_leaks_nothing(stub, caplog):
    caplog.set_level(logging.DEBUG)
    stub.token_fail = True                          # body lỗi của "provider" có chứa secret
    for route in (_route("vertex", SA_JSON, **VX),
                  _route("azure_openai", ENTRA_SECRET, auth_mode="entra", tenant_id=TENANT, client_id=CLIENT, **AZ)):
        r = _probe(route)
        assert (r.ok, r.code) == (False, "INVALID_KEY"), r
        assert ENTRA_SECRET not in json.dumps(r.to_dict()) and SA_PEM[:40] not in json.dumps(r.to_dict())
    logs = "\n".join(rec.getMessage() for rec in caplog.records)
    assert ENTRA_SECRET not in logs and SA_PEM[:40] not in logs
    e = ai_oauth.OAuthError(401)
    assert ENTRA_SECRET not in str(e) and e.status_code == 401


def test_sanitize_error_and_log_filter_mask_new_key_formats():
    from api import log_redaction
    from scanner.cloud_ai import redact, redact_text_basic, sanitize_error
    samples = [KEY_GEM, "ya29.a0AfH6SMBx" + "q" * 30, ENTRA_SECRET, KEY_OR, "api-key: " + KEY_AZ, '"private_key_id": "' + "0123456789abcdef" * 2 + '"',
               "vg-sa@proj-abc123.iam.gserviceaccount.com", "1//0g" + "Ab-_" * 12, json.loads(SA_JSON)["private_key"],
               json.dumps({"private_key": json.loads(SA_JSON)["private_key"]})]
    for s in samples:
        body = f"upstream said: {s} !"
        for fn in (redact, redact_text_basic, log_redaction.mask):
            out = fn(body)
            core = s.split("api-key: ")[-1]
            assert core[:20] not in out or "[REDACTED" in out or "REDACTED" in out, (fn.__name__, s[:20])
            assert core[5:40] not in out, (fn.__name__, s[:20])

    class E(RuntimeError):
        pass
    msg = sanitize_error(E(f"cfg error {KEY_GEM} ya29.{'x' * 30}"))
    assert KEY_GEM not in msg and "ya29." + "x" * 30 not in msg


def test_service_account_hint_is_not_tail_of_json():
    from api.services import ai_credentials as creds
    assert creds._hint(SA_JSON) == "json" and creds._hint(KEY_GEM) == "…" + KEY_GEM[-4:]
    assert _route("vertex", SA_JSON, **VX).credential.hint == "json"


# ─────────────────────────────────────────────
# 4. Envelope gắn tham số (base_url / region / deployment / project / endpoint / tenant…)
# ─────────────────────────────────────────────
@pytest.fixture
def db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    from api import ai_cred_models
    from api.database import Base
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng, tables=[ai_cred_models.AiCredential.__table__, ai_cred_models.AiUsageEvent.__table__])
    s = sessionmaker(bind=eng)()
    yield s
    s.close()


BOUND = [
    ("azure_openai", {**AZ}, "endpoint", "https://evil.openai.azure.com"),
    ("azure_openai", {**AZ}, "deployment", "other-dep"),
    ("azure_openai", {**AZ}, "api_version", "2023-05-15"),
    ("azure_openai", {**AZ, "tenant_id": TENANT, "client_id": CLIENT}, "tenant_id", "00000000-0000-0000-0000-000000000000"),
    ("azure_openai", {**AZ, "tenant_id": TENANT, "client_id": CLIENT}, "client_id", "00000000-0000-0000-0000-000000000000"),
    ("vertex", {**VX}, "project", "evil-project-1"),
    ("vertex", {**VX}, "location", "europe-west4"),
    ("openai_compatible", {"base_url": "https://llm.example.com/v1", "model": "m"}, "base_url", "https://evil.example.com/v1"),
]


@pytest.mark.parametrize("provider,params,field,new", BOUND, ids=[f"{p}-{f}" for p, _, f, _ in BOUND])
def test_envelope_binds_destination_params(provider, params, field, new, db):
    from sqlalchemy import text
    from api.services import ai_credentials as svc
    from api.services.llm_resolver import LLMContext
    m = svc.create(db, scope="user", owner_user_id="u1", provider=provider, label="x", secret="k" * 20, params=dict(params),
                   created_by="u1")
    db.commit()
    ctx = LLMContext(feature="pentest", user_id="u1")
    assert svc.open_for_call(db, m["id"], ctx).provider == provider            # nguyên vẹn thì mở được
    evil = {**params, field: new}
    db.execute(text("update ai_credentials set params=:p where id=:i"), {"p": json.dumps(evil), "i": m["id"]})
    db.commit()
    with pytest.raises(svc.CredentialError) as e:
        svc.open_for_call(db, m["id"], ctx)
    assert e.value.code == "AI_CRED_ENVELOPE_MISMATCH"
    db.execute(text("update ai_credentials set params=:p where id=:i"), {"p": json.dumps(params), "i": m["id"]})
    db.commit()
    svc.update_params(db, m["id"], evil, actor="u1")                          # đường hợp lệ: re-seal với digest mới
    db.commit()
    assert svc.open_for_call(db, m["id"], ctx).public_params()[field] == new


def test_org_params_carry_new_provider_destination_fields():
    from api.services import ai_credentials as svc
    sec = {**copy.deepcopy(DEFAULT_CONFIG["azure_openai"]), **AZ, "auth_mode": "entra", "tenant_id": TENANT, "client_id": CLIENT}
    assert svc._org_params("azure_openai", sec) == {**AZ, "tenant_id": TENANT, "client_id": CLIENT}
    assert svc._org_params("vertex", {**DEFAULT_CONFIG["vertex"], **VX})["project"] == "proj-abc123"
    assert svc._org_params("openai_compatible", {"base_url": "https://llm.example.com/v1", "model": "m"})["base_url"]
    assert svc._org_params("gemini", DEFAULT_CONFIG["gemini"]) == {"model": "gemini-2.5-flash"}
    for k in ("tenant_id", "client_id", "endpoint", "deployment", "project", "location", "api_version", "base_url", "region"):
        assert k in svc._BOUND_PARAMS


def test_org_vertex_sync_keeps_sa_json_secret_and_binds_project(db, tmp_path, monkeypatch):
    monkeypatch.setenv("AI_CONFIG_FILE", str(tmp_path / "ai.json"))
    from api.services import ai_config
    importlib.reload(ai_config)
    from api.services import ai_credentials as svc
    cfg = ai_config.validate_and_save({"provider": "vertex", "vertex": {"api_key": SA_JSON, **VX}})
    ids = svc._sync(db, cfg)
    db.commit()
    from api.services.llm_resolver import LLMContext
    cred = svc.open_for_call(db, ids["vertex"], LLMContext(feature="test", user_id=None))
    assert cred.public_params()["project"] == "proj-abc123" and cred.hint == "json"
    from sqlalchemy import text
    db.execute(text("update ai_credentials set params=:p where id=:i"),
               {"p": json.dumps({**VX, "project": "evil-project-1", "model": "google/gemini-2.5-flash"}), "i": ids["vertex"]})
    db.commit()
    with pytest.raises(svc.CredentialError):
        svc.open_for_call(db, ids["vertex"], LLMContext(feature="test", user_id=None))


# ─────────────────────────────────────────────
# 5. Cấu hình org: validate / mã hoá / public / policy / sk-ant-oat
# ─────────────────────────────────────────────
@pytest.fixture
def ai(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_CONFIG_FILE", str(tmp_path / "ai.json"))
    from api.services import ai_config
    importlib.reload(ai_config)
    return ai_config


def test_config_saves_new_sections_encrypted_and_public_hides_keys(ai):
    ai.validate_and_save({"azure_openai": {**AZ, "api_key": KEY_AZ}, "gemini": {"api_key": KEY_GEM},
                          "vertex": {**VX, "api_key": SA_JSON}, "openai_compatible": {"base_url": "https://llm.example.com/v1", "model": "m", "api_key": KEY_OAI}})
    raw = open(ai._path()).read()
    for s in (KEY_AZ, KEY_GEM, KEY_OAI, SA_PEM[30:80], json.loads(SA_JSON)["private_key_id"]):
        assert s not in raw
    assert ai.get_api_key("vertex") == SA_JSON and ai.get_api_key("azure_openai") == KEY_AZ
    pub = ai.public_config()
    blob = json.dumps(pub)
    for s in (KEY_AZ, KEY_GEM, KEY_OAI, SA_PEM[30:80], "api_key_enc"):
        assert s not in blob
    assert pub["vertex"]["api_key_set"] is True and pub["vertex"]["api_key_hint"] == ""
    assert pub["azure_openai"]["api_key_hint"] == "…" + KEY_AZ[-4:]


@pytest.mark.parametrize("update", [
    {"azure_openai": {"endpoint": "https://evil.com"}}, {"azure_openai": {"endpoint": "http://x.openai.azure.com"}},
    {"azure_openai": {"deployment": "../x"}}, {"azure_openai": {"api_version": "latest"}},
    {"azure_openai": {"auth_mode": "nope"}}, {"azure_openai": {"auth_mode": "entra", "tenant_id": "../x"}},
    {"vertex": {"project": "p/../x"}}, {"vertex": {"location": "evil.com"}}, {"vertex": {"auth_mode": "wif"}},
    {"vertex": {"api_key": "not-json"}}, {"vertex": {"api_key": json.dumps({"type": "authorized_user"})}},
    {"openai_compatible": {"base_url": "http://x.example.com"}}, {"provider": "kiro"}, {"provider": "copilot"},
    {"openai": {"api_key": "sk-ant-oat01-" + "z" * 30}}, {"gemini": {"api_key": "sk-ant-oat01-" + "z" * 30}},
])
def test_config_rejects_bad_new_provider_params(ai, update):
    with pytest.raises(ValueError):
        ai.validate_and_save(update)
    assert not __import__("os").path.exists(ai._path())            # không ghi gì


def test_config_custom_base_url_off_blocks_openai_compatible(ai):
    ai.validate_and_save({"policy": {"custom_base_url": "off"}})
    with pytest.raises(ValueError, match="BAD_BASE_URL"):
        ai.validate_and_save({"openai_compatible": {"base_url": "https://llm.example.com/v1"}})
    ai.validate_and_save({"policy": {"custom_base_url": "admin_only"}, "openai_compatible": {"base_url": "https://llm.example.com/v1"}})
    ai.validate_and_save({"policy": {"custom_base_url": "off"}, "openai_compatible": {"base_url": "https://llm.example.com/v1"}})  # lưu lại URL cũ: được


def test_config_model_defaults_and_providers_tuple(ai):
    cfg = ai.validate_and_save({"gemini": {"model": ""}, "vertex": {"model": " "}})
    assert cfg["gemini"]["model"] == "gemini-2.5-flash" and cfg["vertex"]["model"] == "google/gemini-2.5-flash"
    assert set(ai.PROVIDERS) == {"anthropic", "bedrock", "openai", "openrouter", "azure_openai", "gemini", "vertex", "openai_compatible"}
    assert "kiro" not in ai.PROVIDERS and "copilot" not in ai.PROVIDERS and "github_models" not in ai.PROVIDERS
    from api.ai_cred_models import PROVIDERS
    assert set(ai.PROVIDERS) == set(PROVIDERS)
    assert pp.DEFAULT_AZURE_API_VERSION == ai.DEFAULT_AZURE_API_VERSION and pp.DEFAULT_GEMINI_MODEL == ai.DEFAULT_GEMINI_MODEL


# ─────────────────────────────────────────────
# 6. Meter: bảng giá
# ─────────────────────────────────────────────
def test_pricing_for_new_models_and_conservative_default():
    from api.services.ai_prices import DEFAULT, _lookup, est_cost_usd
    assert _lookup("gemini-2.5-pro") == (2.50, 15.00, 0.625)
    assert _lookup("google/gemini-2.5-flash") == (0.30, 2.50, 0.075)
    assert _lookup("google/gemini-2.5-flash-lite") == (0.10, 0.40, 0.025)
    assert _lookup("gpt-4o-mini") == (0.15, 0.60, 0.075) and _lookup("openai/gpt-4o") == (2.50, 10.00, 1.25)
    assert _lookup("gpt-4o-2024-08-06") == (2.50, 10.00, 1.25)                      # hậu tố ngày được chuẩn hoá
    assert _lookup("gpt-4.1-mini") == (0.40, 1.60, 0.10) and _lookup("gpt-4.1") == (2.00, 8.00, 0.50)
    assert _lookup("o4-mini") == (1.10, 4.40, 0.275) and _lookup("openai/o3") == (2.00, 8.00, 0.50)
    assert _lookup("anthropic/claude-opus-5-5") == (4.00, 20.00, 0.20)               # OpenRouter prefix
    assert _lookup("us.anthropic.claude-opus-5-5-v1:0") == (4.00, 20.00, 0.20)       # Bedrock profile + version
    for unknown in ("prod-chat", "my-model", "foo/bar-o3x", "gpt-o3000", "radio3", "gpt-4o-prod", "gpt-5", "o1", ""):
        assert _lookup(unknown) == DEFAULT, unknown                                  # model lạ KHÔNG miễn phí
    assert est_cost_usd("gemini-2.5-pro", 1_000_000, 1_000_000) == pytest.approx(17.5)
    assert est_cost_usd("prod-chat", 1_000_000, 0) == pytest.approx(DEFAULT[0])


def test_s2_exact_match_o3_pro_and_deep_research_not_priced_as_o3():
    from api.services.ai_prices import _lookup, est_cost_usd
    assert _lookup("o3") == (2.00, 8.00, 0.50)
    assert _lookup("o3-pro") == (20.00, 80.00, 20.00) and _lookup("openai/o3-pro-2025-06-10") == (20.00, 80.00, 20.00)
    assert _lookup("o3-deep-research") == (10.00, 40.00, 2.50)
    assert est_cost_usd("o3-pro", 1_000_000, 1_000_000) == pytest.approx(100.0)       # trước: 10.0 (đếm thiếu 10×)
    for variant in ("o3-pro-x", "o3-mini-high", "o3-preview", "o3.5", "gpt-4o-mini-audio", "gemini-2.5-pro-exp", "claude-opus-5-5-fast"):
        assert _lookup(variant) not in ((2.00, 8.00, 0.50), (2.50, 10.00, 1.25), (0.15, 0.60, 0.075), (2.50, 15.00, 0.625),
                                        (4.00, 20.00, 0.20)), variant                 # không khớp tiền tố/chuỗi con


def test_s2_unknown_model_uses_most_expensive_tier_of_its_provider():
    from api.services.ai_prices import _lookup, default_for, est_cost_usd
    assert _lookup("claude-future-9", "anthropic") == (5.00, 25.00, 5.00) == _lookup("x", "bedrock")
    assert _lookup("gpt-9", "openai") == (20.00, 80.00, 20.00) == _lookup("x", "azure_openai") == _lookup("x", "openrouter")
    assert _lookup("gemini-9", "gemini") == (5.00, 30.00, 1.25) == _lookup("x", "vertex")
    assert default_for(None) == (20.00, 80.00, 20.00)                                  # không rõ provider: đắt nhất toàn bảng
    assert est_cost_usd("gpt-9", 1_000_000, 0, provider="openai") == pytest.approx(20.0)


def test_meter_prices_by_effective_model_for_new_providers():
    from api.services import ai_usage
    for prov, key, sec in PROVIDER_CASES[:4]:
        route = _route(prov, key, **sec)
        m = ai_usage.Meter(route)
        assert m.provider == prov
        assert m.model == (f"unmapped/{route.model}" if prov == "azure_openai" else route.model)    # Azure: chưa ánh xạ
        assert ai_usage.Meter(route, "gemini-2.5-pro").model == (f"unmapped/{route.model}" if prov == "azure_openai" else "gemini-2.5-pro")


# ── S2: Azure deployment name không đáng tin → model thật (ánh xạ ADMIN) cho allowlist + giá ──
def _az_policy(**kw):
    from api.services import ai_policy
    return ai_policy.normalize(kw)


def test_s2_azure_real_model_mapping_and_unmapped_fallback():
    from api.services import ai_policy
    pol = _az_policy(azure_deployment_models={"MyRes/Prod-Chat": "o3-pro"})
    assert ai_policy.azure_real_model(pol, "https://myres.openai.azure.com", "prod-chat") == "o3-pro"
    assert ai_policy.azure_real_model(pol, "https://myres.openai.azure.com", "gpt-4o-mini") == "unmapped/gpt-4o-mini"
    assert ai_policy.azure_real_model(pol, "https://other.openai.azure.com", "prod-chat") == "unmapped/prod-chat"   # khoá theo resource
    assert ai_policy.policy_model(pol, "gemini", None, "gemini-2.5-pro") == "gemini-2.5-pro"
    for bad in ({"noslash": "gpt-4o"}, {"a/b": ""}, {"a/b": "x y"}, {"a/../b": "gpt-4o"}, {"a/b": 3}, ["x"]):
        with pytest.raises(ValueError):
            ai_policy.normalize({"azure_deployment_models": bad})


def test_s2_rename_to_bypass_allowlist_is_refused(db):
    """User đặt tên deployment `gpt-4o-mini` (được allowlist) cho một deployment o3-pro → vẫn bị chặn."""
    from api.services import ai_credentials as svc
    from api.services import ai_policy
    from api.services.llm_resolver import LLMContext, Refuse, _user_cloud
    allow = {"allowed": ["azure_openai:gpt-4o-mini"]}
    params = {**AZ, "deployment": "gpt-4o-mini", "model": "gpt-4o-mini"}
    m = svc.create(db, scope="user", owner_user_id="u1", provider="azure_openai", label="x", secret="k" * 20, params=params, created_by="u1")
    from api.ai_cred_models import AiCredential
    row = db.get(AiCredential, m["id"])
    ctx = LLMContext(feature="pentest", user_id="u1")
    # (1) chưa ánh xạ: allowlist cụ thể không khớp "unmapped/…" ⇒ từ chối (fail closed)
    r = _user_cloud(db, row, ctx, ai_policy.normalize(allow))
    assert isinstance(r, Refuse) and r.code == "AI_NOT_ALLOWED"
    # (2) ADMIN ánh xạ tên đó → o3-pro thật: vẫn không khớp `gpt-4o-mini`
    pol = ai_policy.normalize({**allow, "azure_deployment_models": {"myres/gpt-4o-mini": "o3-pro"}})
    r = _user_cloud(db, row, ctx, pol)
    assert isinstance(r, Refuse) and r.code == "AI_NOT_ALLOWED"
    # (3) ánh xạ đúng sang model được phép → qua check allowlist (chỉ có thể dừng ở bước chủ user vì test DB không có User)
    pol = ai_policy.normalize({**allow, "azure_deployment_models": {"myres/gpt-4o-mini": "gpt-4o-mini"}})
    assert ai_policy.is_allowed(pol, "azure_openai", ai_policy.policy_model(pol, "azure_openai", params, "gpt-4o-mini"))
    # wildcard của admin vẫn cho phép mọi deployment Azure
    assert ai_policy.is_allowed(ai_policy.normalize({"allowed": ["azure_openai:*"]}), "azure_openai",
                                ai_policy.policy_model(ai_policy.normalize({}), "azure_openai", params, "gpt-4o-mini"))


def test_s2_meter_policy_and_price_use_real_model_for_azure(monkeypatch, tmp_path):
    from api.services import ai_config, ai_policy, ai_usage
    monkeypatch.setenv("AI_CONFIG_FILE", str(tmp_path / "ai.json"))
    importlib.reload(ai_config)
    ai_config.validate_and_save({"policy": {"azure_deployment_models": {"myres/gpt-4o-mini": "o3-pro"}}})
    route = _route("azure_openai", KEY_AZ, **{**AZ, "deployment": "gpt-4o-mini"})
    m = ai_usage.Meter(route)
    assert m.model == "o3-pro"                                            # tên cho đẹp không đổi giá/allowlist
    assert ai_usage.Meter(_route("azure_openai", KEY_AZ, **AZ)).model == "unmapped/gpt-4o-prod"
    # Azure báo model nền đắt hơn mức đã cấu hình → tính theo model đắt hơn
    ai_config.validate_and_save({"policy": {"azure_deployment_models": {"myres/gpt-4o-mini": "gpt-4o-mini"}}})
    m2 = ai_usage.Meter(route)
    assert m2.model == "gpt-4o-mini"
    raw = type("R", (), {"model": "o3-pro-2025-06-10"})()
    assert m2._eff_model(raw) == "o3-pro-2025-06-10"
    assert m2._eff_model(type("R", (), {"model": "gpt-4o-mini-2024-07-18"})()) == "gpt-4o-mini"
    assert m2._eff_model(type("R", (), {})()) == "gpt-4o-mini"


def test_s2_probe_refuses_when_real_model_not_allowed_by_policy(stub, monkeypatch, tmp_path):
    from api.services import ai_config
    monkeypatch.setenv("AI_CONFIG_FILE", str(tmp_path / "ai.json"))
    importlib.reload(ai_config)
    ai_config.validate_and_save({"policy": {"allowed": ["azure_openai:gpt-4o-mini"]}})
    r = _probe(_route("azure_openai", KEY_AZ, **AZ))         # stub trả model="m" ≠ gpt-4o-mini
    assert (r.ok, r.code, r.real_model) == (False, "NO_MODEL_ACCESS", "m"), r
    ai_config.validate_and_save({"policy": {"allowed": ["azure_openai:m"]}})
    r = _probe(_route("azure_openai", KEY_AZ, **AZ))
    assert (r.ok, r.code, r.real_model) == (True, "VALID", "m")


# ─────────────────────────────────────────────
# 7. Driver tool-use: round-trip cho các family mới (SDK thật qua stub)
# ─────────────────────────────────────────────
@pytest.mark.parametrize("provider,key,sec", PROVIDER_CASES, ids=_ID)
def test_llmdriver_tool_call_round_trip_parity(provider, key, sec, stub):
    from scanner.pentest.llm import make_driver
    drv = make_driver(_route(provider, key, **sec))
    assert drv.family == "openai" and drv.first_party is False and drv.cache is False
    tools = [{"name": "probe", "description": "d", "input_schema": {"type": "object", "properties": {"x": {"type": "integer"}}}}]
    nat = drv.native_tools(tools)
    assert nat[0]["type"] == "function" and nat[0]["function"]["name"] == "probe"
    raw = _arun(drv.create("sys", [{"role": "user", "content": "go"}], nat))
    res = drv.parse(raw)
    assert [(c.id, c.name, c.input) for c in res.tool_calls] == [("call_1", "probe", {"x": 1})] and not res.end
    assert (res.tokens_in, res.tokens_out) == (3, 2)
    msgs = [{"role": "user", "content": "go"}, drv.assistant_entry(raw)] + drv.tool_result_entries([("call_1", "done", False)])
    assert msgs[1]["tool_calls"][0]["function"]["name"] == "probe" and msgs[2] == {"role": "tool", "tool_call_id": "call_1", "content": "done"}
    body = [h for h in stub.hits if h[0] == "POST" and h[1].endswith("/chat/completions")][-1][4]
    assert body["tool_choice"] == "auto" and body["messages"][0] == {"role": "system", "content": "sys"}
    if provider == "azure_openai":
        assert "model" in body                                    # tên deployment
    _arun(drv.client.close())


def test_cloud_analyzer_label_uses_real_provider_for_openai_family():
    from scanner.cloud_ai import CloudAnalyzer
    for prov, key, sec in PROVIDER_CASES[:5]:
        route = _route(prov, key, **sec)
        a = CloudAnalyzer(route=route, cfg={"privacy": {}})
        assert a.provider_label == f"{prov}:{route.model}"
    a = CloudAnalyzer(route=_route("openai", KEY_OAI), cfg={"privacy": {}})
    assert a.provider_label == "openai:gpt-4o"


# ─────────────────────────────────────────────
# 8. Danh sách model
# ─────────────────────────────────────────────
def test_static_models_and_listing(stub):
    from api.services.ai_models import STATIC_MODELS, list_models
    for p in ("azure_openai", "gemini", "vertex"):
        assert STATIC_MODELS[p]
    assert "openai_compatible" in STATIC_MODELS
    r = _arun(list_models("gemini", _route("gemini", KEY_GEM)))
    assert r["source"] == "api" and r["models"] == ["gemini-2.5-flash"]            # bỏ tiền tố models/, bỏ embedding
    for p, key, sec in (("azure_openai", KEY_AZ, AZ), ("vertex", SA_JSON, VX)):
        stub.hits.clear()
        r = _arun(list_models(p, _route(p, key, **sec)))
        assert r["source"] == "static" and r["models"] == STATIC_MODELS[p] and stub.hits == []
    r = _arun(list_models("openai_compatible", _route("openai_compatible", KEY_OAI, base_url="https://llm.example.com/v1", model="m")))
    assert r["source"] == "api" and "gpt-4o" in r["models"]


# ─────────────────────────────────────────────
# 9. API: user self-service (azure/gemini), admin-only providers, /api/ai/test
# ─────────────────────────────────────────────
@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_CONFIG_FILE", str(tmp_path / "ai.json"))
    from api.ai_cred_models import AiCredential, AiUsageEvent
    from api.database import Base, SessionLocal, engine
    Base.metadata.create_all(bind=engine)
    d = SessionLocal()
    d.query(AiUsageEvent).delete()
    d.query(AiCredential).delete()
    d.commit()
    d.close()
    from api.services import ai_config
    ai_config.validate_and_save({"provider": "anthropic", "mode": "cloud_only", "anthropic": {"api_key": "sk-ant-api03-ORGORGORGORGORG-0rg1"}})

    class P:
        calls = []

        async def __call__(self, route):
            self.calls.append(route)
            return {"ok": True, "code": "VALID", "model": route.model, "latency_ms": 3, "tools": True, "json": None}
    p = P()
    p.calls = []
    monkeypatch.setattr("api.routes.ai_credentials._probe", p)
    monkeypatch.setattr("api.routes.ai_credentials._throttle", lambda uid: None)
    return p


def _who(role):
    from tests._authutil import bearer, login, make_user, new_client
    email, uid = make_user(role)
    c = new_client()
    return c, bearer(login(c, email)), uid


def test_user_azure_credential_endpoint_is_server_built(api):
    from api.ai_cred_models import AiCredential
    from api.auth_models import UserRole
    from api.database import SessionLocal
    c, h, uid = _who(UserRole.ANALYST)
    r = c.post("/api/me/ai-credentials", headers=h, json={
        "provider": "azure_openai", "secret": KEY_AZ, "resource": "MyRes", "deployment": "gpt-4o-prod", "api_version": "2024-10-21",
        "endpoint": "https://evil.com", "base_url": "https://evil.com"})            # trường lạ bị bỏ qua
    assert r.status_code == 201, r.text
    b = r.json()
    assert b["endpoint"] == "https://myres.openai.azure.com" and b["deployment"] == "gpt-4o-prod" and b["model"] == "gpt-4o-prod"
    assert KEY_AZ not in r.text and "evil" not in r.text
    d = SessionLocal()
    row = d.get(AiCredential, b["id"])
    assert row.params["endpoint"] == "https://myres.openai.azure.com" and row.provider == "azure_openai" and row.scope == "user"
    d.close()
    assert api.calls and api.calls[-1].provider == "azure_openai"
    assert api.calls[-1].credential.public_params()["endpoint"] == "https://myres.openai.azure.com"
    # PATCH đổi deployment re-seal envelope, endpoint không đổi được qua PATCH
    r2 = c.patch(f"/api/me/ai-credentials/{b['id']}", headers=h, json={"deployment": "gpt-4.1", "endpoint": "https://evil.com"})
    assert r2.status_code == 200 and r2.json()["endpoint"] == "https://myres.openai.azure.com" and r2.json()["deployment"] == "gpt-4.1"
    from api.services.llm_resolver import LLMContext, route_for_own_credential
    d = SessionLocal()
    rt = route_for_own_credential(d, b["id"], uid)
    d.close()
    assert isinstance(rt, Cloud) and rt.model == "gpt-4.1"                            # envelope re-seal hợp lệ → mở được


@pytest.mark.parametrize("body", [
    {"resource": "evil.com/x", "deployment": "d"}, {"resource": "a.b", "deployment": "d"}, {"resource": "myres.openai.azure.com", "deployment": "d"},
    {"resource": "-x", "deployment": "d"}, {"resource": "myres", "deployment": "../x"}, {"resource": "myres", "deployment": ""},
    {"resource": "myres", "deployment": "d", "api_version": "latest"}, {"resource": "", "deployment": "d"}, {"deployment": "d"},
])
def test_user_azure_bad_params_422(api, body):
    from api.auth_models import UserRole
    c, h, _ = _who(UserRole.ANALYST)
    r = c.post("/api/me/ai-credentials", headers=h, json={"provider": "azure_openai", "secret": KEY_AZ, **body})
    assert r.status_code == 422 and r.json()["detail"] == {"code": "AI_BAD_AZURE_PARAMS"}, r.text
    assert api.calls == []


def test_user_gemini_credential_and_format_rules(api):
    from api.auth_models import UserRole
    c, h, _ = _who(UserRole.ANALYST)
    r = c.post("/api/me/ai-credentials", headers=h, json={"provider": "gemini", "secret": KEY_GEM})
    assert r.status_code == 201 and r.json()["model"] == "gemini-2.5-flash" and r.json()["key_hint"] == "…" + KEY_GEM[-4:]
    assert KEY_GEM not in r.text
    r = c.post("/api/me/ai-credentials", headers=h, json={"provider": "gemini", "secret": SA_JSON.replace("\n", "")[:200] + " "})
    assert r.status_code == 422
    r = c.post("/api/me/ai-credentials", headers=h, json={"provider": "gemini", "secret": '{"type":"service_account","x":"' + "a" * 30 + '"}'})
    assert r.status_code == 422 and r.json()["detail"] == {"code": "AI_KEY_INVALID_FORMAT"}
    for prov in ("gemini", "azure_openai", "openai", "openrouter"):               # token OAuth gói Claude.ai: từ chối cho mọi provider
        r = c.post("/api/me/ai-credentials", headers=h, json={"provider": prov, "secret": "sk-ant-oat01-" + "z" * 30,
                                                              "resource": "myres", "deployment": "d"})
        assert r.status_code == 422 and r.json()["detail"] == {"code": "AI_KEY_UNSUPPORTED"}, prov


@pytest.mark.parametrize("prov", ["vertex", "openai_compatible", "kiro", "copilot", "github_models"])
def test_user_cannot_create_admin_only_or_unsupported_providers(api, prov):
    from api.auth_models import UserRole
    c, h, _ = _who(UserRole.ANALYST)
    r = c.post("/api/me/ai-credentials", headers=h, json={"provider": prov, "secret": "x" * 30, "base_url": "https://evil.com"})
    assert r.status_code == 422 and r.json()["detail"] == {"code": "AI_BAD_PROVIDER"}
    r = c.post("/api/me/ai-credentials/test", headers=h, json={"provider": prov, "secret": "x" * 30})
    assert r.status_code == 422


def test_admin_test_endpoint_rejects_ssrf_in_new_fields_without_network(api):
    from api.auth_models import UserRole
    c, h, _ = _who(UserRole.ADMIN)
    for body in ({"provider": "azure_openai", "endpoint": "https://169.254.169.254", "deployment": "d", "api_key": KEY_AZ},
                 {"provider": "azure_openai", "endpoint": "https://evil.com", "deployment": "d", "api_key": KEY_AZ},
                 {"provider": "vertex", "project": "proj-abc123", "location": "evil.com", "api_key": SA_JSON},
                 {"provider": "openai_compatible", "base_url": "https://127.0.0.1/v1", "model": "m", "api_key": KEY_OAI}):
        r = c.post("/api/ai/test", headers=h, json=body)
        ai_probe.reset_throttle()
        assert r.status_code == 200 and r.json()["code"] == "BAD_BASE_URL" and r.json()["ok"] is False, (body, r.text)
        assert KEY_AZ not in r.text and "BEGIN PRIVATE" not in r.text


def test_admin_put_config_new_provider_ssrf_is_422_and_secret_never_echoed(api):
    from api.auth_models import UserRole
    c, h, _ = _who(UserRole.ADMIN)
    r = c.put("/api/ai/config", headers=h, json={"azure_openai": {"endpoint": "https://evil.com", "api_key": KEY_AZ}})
    assert r.status_code == 422 and KEY_AZ not in r.text
    r = c.put("/api/ai/config", headers=h, json={"azure_openai": {**AZ, "api_key": KEY_AZ}, "vertex": {**VX, "api_key": SA_JSON}})
    assert r.status_code == 200, r.text
    assert KEY_AZ not in r.text and "BEGIN PRIVATE" not in r.text and "api_key_enc" not in r.text
    assert r.json()["azure_openai"]["api_key_set"] is True and r.json()["vertex"]["api_key_set"] is True
    r = c.get("/api/ai/models?provider=gemini", headers=h)           # provider mới hợp lệ cho dropdown (static khi chưa có key)
    assert r.status_code == 200 and r.json()["provider"] == "gemini" and r.json()["models"]


def test_provider_params_unit_edges():
    assert pp.parse_service_account(SA_JSON)["client_email"].endswith("iam.gserviceaccount.com")
    for bad in ("", "{}", "[]", json.dumps({"type": "service_account"}), json.dumps({"type": "service_account", "client_email": "a b", "private_key": "x"}),
                "x" * 20000, json.dumps({"type": "authorized_user", "client_email": "a@b", "private_key": "PRIVATE KEY"})):
        with pytest.raises(UrlRejected):
            pp.parse_service_account(bad)
    with pytest.raises(UrlRejected):
        pp.check_guid("not-a-guid", "tenant_id")
    assert pp.check_guid(TENANT.upper(), "tenant_id") == TENANT


# ─────────────────────────────────────────────
# S1: khoá Azure định dạng mới (84 ký tự base62, "JQQJ99" ở giữa) bị che ở MỌI đường
# ─────────────────────────────────────────────
KEY_AZ84 = "Ab3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5hI7jK9lM1nO3pQ5r" + "JQQJ99" + "BDACYeBjFXJ3w3AAABACOGAbCd"
assert len(KEY_AZ84) == 84


@pytest.mark.parametrize("fmt", ["{k}", "api-key: {k}", "api-key:{k}", "AZURE_OPENAI_API_KEY={k}", "AZURE_OPENAI_API_KEY=\"{k}\"",
                                 '{{"api_key": "{k}"}}', "'api-key': '{k}'", "x {k}.", "(key={k})", "export OPENAI_API_KEY={k}"])
def test_s1_azure84_key_masked_by_shared_engine_everywhere(fmt, caplog):
    from api import log_redaction
    from scanner.cloud_ai import build_user_prompt, redact, redact_text_basic, sanitize_error
    from scanner.pentest import redaction as pr
    text = "cfg: " + fmt.format(k=KEY_AZ84) + " end"
    core = KEY_AZ84[10:70]
    # prompt (triage / pentest / Co-work egress dùng cloud_ai.redact + build_user_prompt)
    assert core not in redact(text) and core not in redact_text_basic(text)
    p = build_user_prompt({"title": text, "description": text, "code_snippet": text}, text, None, do_redact=True)
    assert core not in p
    # log
    assert core not in log_redaction.mask(text)
    # lỗi
    class E(RuntimeError):
        pass
    assert core not in sanitize_error(E(text))
    # transcript / pentest egress (engine redaction riêng của Pentest, dùng chung _SECRET_PATTERNS)
    assert core not in pr.redact_for_llm(text, [])
    from scanner.pentest.compaction import render_transcript
    msgs = [{"role": "user", "content": text},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": text, "is_error": False}]}]
    tr = render_transcript(msgs, lambda t: pr.redact_for_llm(t, []))
    assert core not in tr and "REDACTED" in tr


def test_s1_log_filter_masks_record_message_args_and_traceback(caplog):
    from api import log_redaction
    log_redaction.install()
    lg = logging.getLogger("vg.s1")
    caplog.set_level(logging.DEBUG)
    try:
        raise RuntimeError(f"boom {KEY_AZ84}")
    except RuntimeError:
        lg.exception("call failed with key=%s", KEY_AZ84)
    lg.info("transcript: %s", {"headers": {"api-key": KEY_AZ84}})
    out = "\n".join(r.getMessage() + (r.exc_text or "") for r in caplog.records if r.name == "vg.s1")
    assert KEY_AZ84[10:70] not in out


def test_s1_azure84_patterns_are_linear_and_no_false_positive_on_plain_text():
    import time
    from scanner.cloud_ai import redact_text_basic
    hostile = ("A" * 60 + "JQQJ9") * 4000 + "x" * 200_000 + "api-key=" + "a" * 100_000
    t = time.monotonic()
    redact_text_basic(hostile)
    assert time.monotonic() - t < 2.0
    benign = "The quick brown fox " + "a" * 30 + " jumps; file sha=" + "0" * 64 + " version 1.2.3 JQQJ99 alone"
    assert redact_text_basic(benign) == benign
    assert redact_text_basic("api-key: short") == "api-key: short"


# ─────────────────────────────────────────────
# Re-verify round: probe/Meter normalise Azure's versioned model; mapping removable; unmapped marker survives normalisation
# ─────────────────────────────────────────────
def test_rv1_probe_accepts_versioned_azure_model_against_exact_allowlist(stub, monkeypatch, tmp_path):
    from api.services import ai_config, ai_policy
    monkeypatch.setenv("AI_CONFIG_FILE", str(tmp_path / "ai.json"))
    importlib.reload(ai_config)
    ai_config.validate_and_save({"policy": {"allowed": ["azure_openai:gpt-4o"]}})
    real_probe = ai_probe._openai_chat

    async def chat(client, model, info=None):          # Azure thật trả model nền có hậu tố ngày
        r = await real_probe(client, model, info)
        info["model"] = "gpt-4o-2024-08-06"
        return r
    monkeypatch.setattr(ai_probe, "_openai_chat", chat)
    r = _probe(_route("azure_openai", KEY_AZ, **AZ))
    assert (r.ok, r.code, r.real_model) == (True, "VALID", "gpt-4o-2024-08-06"), r

    async def chat2(client, model, info=None):         # model KHÁC vẫn bị từ chối
        r = await real_probe(client, model, info)
        info["model"] = "o3-pro-2025-06-10"
        return r
    monkeypatch.setattr(ai_probe, "_openai_chat", chat2)
    r = _probe(_route("azure_openai", KEY_AZ, **AZ))
    assert (r.ok, r.code) == (False, "NO_MODEL_ACCESS")
    pol = ai_policy.normalize({"allowed": ["azure_openai:gpt-4o"]})
    assert ai_policy.is_allowed_model(pol, "azure_openai", "gpt-4o-2024-08-06")
    assert not ai_policy.is_allowed_model(pol, "azure_openai", "gpt-4o-mini-2024-07-18")      # không khớp tiền tố
    assert not ai_policy.is_allowed_model(pol, "azure_openai", "unmapped/gpt-4o")              # marker không bao giờ khớp rẻ
    assert not ai_policy.is_allowed_model(pol, "openai", "gpt-4o-2024-08-06")                  # chỉ nới cho Azure


def test_rv1_meter_policy_uses_same_normalisation(monkeypatch, tmp_path):
    from api.services import ai_config, ai_policy, ai_usage
    monkeypatch.setenv("AI_CONFIG_FILE", str(tmp_path / "ai.json"))
    importlib.reload(ai_config)
    ai_config.validate_and_save({"policy": {"allowed": ["azure_openai:gpt-4o"],
                                            "azure_deployment_models": {"myres/gpt-4o-prod": "gpt-4o-2024-08-06"}}})
    m = ai_usage.Meter(_route("azure_openai", KEY_AZ, **AZ))
    assert m.model == "gpt-4o-2024-08-06"
    assert ai_policy.is_allowed_model(ai_policy.get_policy(), "azure_openai", m.model)


def test_rv2_admin_can_remove_or_replace_deployment_mappings(tmp_path, monkeypatch):
    from api.services import ai_config, ai_policy
    monkeypatch.setenv("AI_CONFIG_FILE", str(tmp_path / "ai.json"))
    importlib.reload(ai_config)
    ai_config.validate_and_save({"policy": {"azure_deployment_models": {"a/one": "gpt-4o", "a/two": "o3-pro", "a/three": "gpt-4.1"}}})
    assert set(ai_policy.get_policy()["azure_deployment_models"]) == {"a/one", "a/two", "a/three"}
    ai_config.validate_and_save({"policy": {"azure_deployment_models": {"a/one": "gpt-4o"}}})           # replace: bỏ two, three
    assert ai_policy.get_policy()["azure_deployment_models"] == {"a/one": "gpt-4o"}
    ai_config.validate_and_save({"policy": {"azure_deployment_models": {"a/one": "gpt-4o", "a/two": "o3-pro"}}})
    ai_config.validate_and_save({"policy": {"azure_deployment_models": {"a/two": None, "a/one": "gpt-4o"}}})   # null xoá mục
    assert ai_policy.get_policy()["azure_deployment_models"] == {"a/one": "gpt-4o"}
    ai_config.validate_and_save({"policy": {"azure_deployment_models": {}}})                            # {} xoá hết
    assert ai_policy.get_policy()["azure_deployment_models"] == {}
    ai_config.validate_and_save({"policy": {"azure_deployment_models": {"a/one": "gpt-4o"}}})
    ai_config.validate_and_save({"policy": {"byok": "allowed"}})                                        # không đụng tới key → giữ nguyên
    assert ai_policy.get_policy()["azure_deployment_models"] == {"a/one": "gpt-4o"}
    with pytest.raises(ValueError):
        ai_config.validate_and_save({"policy": {"azure_deployment_models": {"bad key": "gpt-4o"}}})
    assert ai_policy.get_policy()["azure_deployment_models"] == {"a/one": "gpt-4o"}                      # lỗi → không ghi


def test_rv3_unmapped_marker_prices_at_top_tier_even_with_cheap_name():
    from api.services import ai_usage
    from api.services.ai_prices import _lookup, est_cost_usd, normalize_model
    top = (20.00, 80.00, 20.00)
    for cheap in ("gpt-4o-mini", "o3", "x/o3", "gemini-2.5-flash-lite", "claude-haiku-5-5", "gpt-4o-mini-2024-07-18"):
        assert normalize_model(f"unmapped/{cheap}") == f"unmapped/{cheap}".lower()
        assert _lookup(f"unmapped/{cheap}", "azure_openai") == top, cheap
        assert _lookup(f"UNMAPPED/{cheap}", "azure_openai") == top
    assert normalize_model("openai/gpt-4o") == "gpt-4o" and normalize_model("anthropic/claude-opus-5-5") == "claude-opus-5-5"
    assert _lookup("x/o3", "openrouter") == top and _lookup("evil/gpt-4o-mini", "openrouter") == top   # chỉ bỏ tiền tố đã biết
    m = ai_usage.Meter(_route("azure_openai", KEY_AZ, **{**AZ, "deployment": "gpt-4o-mini"}))
    assert m.model == "unmapped/gpt-4o-mini"
    assert est_cost_usd(m.model, 1_000_000, 0, provider="azure_openai") == pytest.approx(20.0)
