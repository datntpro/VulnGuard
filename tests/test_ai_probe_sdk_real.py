"""[AI PR-4 fix] B1: client SDK THẬT (anthropic 2.x = httpx2) dựng được với probe client và probe thành công
qua socket + TLS thật tới stub cục bộ (không mock open_client)."""
import asyncio
import copy
import json
import shutil
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from api.security import encrypt_secret
from api.services import ai_probe, url_guard
from api.services.ai_config import DEFAULT_CONFIG
from api.services.llm_resolver import cloud_route_for, open_client


def _arun(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _cfg(provider, **sec):
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    cfg["provider"] = provider
    cfg[provider].update(sec)
    return cfg


@pytest.mark.parametrize("provider,sec", [
    ("anthropic", {"api_key_enc": encrypt_secret("sk-ant-test-123456789")}),
    ("anthropic", {"auth_mode": "environment"}),
    ("bedrock", {"auth_mode": "bedrock_api_key", "api_key_enc": encrypt_secret("ABSKtest123456789"), "region": "us-east-1"}),
    ("openai", {"api_key_enc": encrypt_secret("sk-test-123456789")}),
    ("openrouter", {"api_key_enc": encrypt_secret("sk-or-v1-test-123456789")}),
])
def test_probe_client_builds_for_every_family_without_mocks(provider, sec):
    client, _m, _f = open_client(cloud_route_for(_cfg(provider, **sec)), probe=True)   # trước đây: TypeError (httpx2)
    assert client is not None
    _arun(client.close())


@pytest.fixture
def tls_stub(tmp_path):
    if not shutil.which("openssl"):
        pytest.skip("cần openssl")
    crt, key = tmp_path / "c.pem", tmp_path / "k.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(crt),
                    "-subj", "/CN=localhost", "-days", "1", "-addext", "subjectAltName=IP:127.0.0.1"],
                   check=True, capture_output=True)
    hits = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def _send(self, obj, code=200):
            b = json.dumps(obj).encode()
            self.send_response(code); self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(b))); self.end_headers(); self.wfile.write(b)

        def do_GET(self):
            hits.append(("GET", self.path, self.headers.get("x-api-key") or self.headers.get("authorization")))
            self._send({"data": [], "first_id": None, "last_id": None, "has_more": False})

        def do_POST(self):
            n = int(self.headers.get("content-length", 0)); body = json.loads(self.rfile.read(n) or b"{}")
            hits.append(("POST", self.path, body))
            self._send({"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-x", "content": [],
                        "stop_reason": "end_turn", "stop_sequence": None,
                        "usage": {"input_tokens": 1, "output_tokens": 1}})
    srv = HTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(str(crt), str(key))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"https://127.0.0.1:{srv.server_address[1]}", str(crt), hits
    srv.shutdown()


def test_anthropic_probe_succeeds_against_local_tls_stub(tls_stub, monkeypatch):
    base, crt, hits = tls_stub
    monkeypatch.setenv("ANTHROPIC_BASE_URL", base)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")          # phải bị bỏ qua (trust_env=False)
    orig = url_guard.plain_async_client

    def with_ca(lib="httpx", *, timeout=10.0):
        m = url_guard._lib(lib)
        return m.AsyncClient(trust_env=False, follow_redirects=False, timeout=timeout, verify=ssl.create_default_context(cafile=crt))
    monkeypatch.setattr(url_guard, "plain_async_client", with_ca)
    r = _arun(ai_probe.probe_cloud(cloud_route_for(_cfg("anthropic", api_key_enc=encrypt_secret("sk-ant-test-123456789")))))
    assert (r.ok, r.code, r.tools) == (True, "VALID", True), r
    assert any(h[0] == "GET" and h[1].startswith("/v1/models") and "sk-ant-test-123456789" in (h[2] or "") for h in hits)
    assert any(h[0] == "POST" and h[2].get("max_tokens") == 1 and h[2].get("tools") for h in hits)
    assert orig is not with_ca
