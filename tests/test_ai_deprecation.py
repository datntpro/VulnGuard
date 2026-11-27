"""[AI PR-7] Header/log deprecation cho endpoint AI cũ; hành vi không đổi; endpoint mới và UI-còn-dùng không bị gắn."""
import logging

import pytest

from api import deprecation
from tests._authutil import new_client


@pytest.mark.parametrize("method,path,succ", [
    ("GET", "/api/ai/config", "/api/ai/settings"),
    ("PUT", "/api/ai/config", "/api/ai/settings"),
    ("GET", "/api/ollama/endpoint", "/api/ai/settings"),
    ("PUT", "/api/ollama/active-model", "/api/ai/settings"),
    ("GET", "/api/ollama/health", "/api/ai/ollama/check"),
])
def test_lookup_deprecated(method, path, succ):
    assert deprecation.lookup(method, path) == succ
    assert deprecation.lookup(method, path + "/") == succ


@pytest.mark.parametrize("method,path", [
    ("GET", "/api/ai/settings"), ("POST", "/api/ai/test"), ("POST", "/api/ai/ollama/check"),
    ("GET", "/api/ollama/models"), ("POST", "/api/ollama/pull"), ("DELETE", "/api/ollama/models/x"),
    ("GET", "/api/me/ai-credentials"), ("POST", "/api/ai/config"),
])
def test_lookup_not_deprecated(method, path):
    assert deprecation.lookup(method, path) is None


def test_apply_sets_headers_and_logs_once(caplog):
    deprecation._seen.clear()
    h1, h2 = {}, {}
    with caplog.at_level(logging.WARNING, logger="vulnguard.deprecation"):
        deprecation.apply("GET", "/api/ai/config", h1)
        deprecation.apply("GET", "/api/ai/config", h2)
    assert h1["Deprecation"] == "true" and h1["Sunset"] == deprecation.SUNSET_HTTP
    assert 'rel="successor-version"' in h1["Link"] and "/api/ai/settings" in h1["Link"]
    assert h2 == h1
    assert len([r for r in caplog.records if r.name == "vulnguard.deprecation"]) == 1
    assert deprecation.SUNSET_DATE in caplog.text


def test_http_headers_present_and_body_unchanged():
    c = new_client()
    r = c.get("/api/ai/config")
    assert r.status_code in (200, 401)       # hành vi cũ giữ nguyên (auth quyết định)
    assert r.headers.get("Deprecation") == "true"
    assert "Sunset" in r.headers
    assert "Deprecation" not in c.get("/api/ai/settings").headers


# ── [PR-7] #109 LOW: base_url_allowlist được kiểm entry ──
from api.services import ai_policy  # noqa: E402


@pytest.mark.parametrize("entry", ["gw.corp.vn", "gw.corp.vn:8443", "*.openai.azure.com", "*.corp.vn:443", "Gateway.Corp.VN"])
def test_allowlist_accepts(entry):
    assert ai_policy.normalize({"base_url_allowlist": [entry]})["base_url_allowlist"] == [entry.lower()]


@pytest.mark.parametrize("entry", ["*", "*.", "a.*.b", "**.x.com", "https://x.com", "x.com/path", "u@x.com", "x.com:0",
                                   "x.com:99999", "x.com:", "*.com.*", "x y.com", "-x.com"])
def test_allowlist_rejects(entry):
    with pytest.raises(ValueError):
        ai_policy.normalize({"base_url_allowlist": [entry]})
