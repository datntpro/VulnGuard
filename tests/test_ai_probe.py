"""[AI PR-4] Probe key/kết nối + Ollama capability check + route + throttle."""
import asyncio
import copy
import json

import httpx
import pytest

from api.services import ai_probe, url_guard
from api.services.ai_config import DEFAULT_CONFIG
from api.services.llm_resolver import cloud_route_for


def _arun(coro):
    """Không dùng asyncio.run: nó bỏ event loop hiện tại của thread và làm hỏng các test dùng get_event_loop()."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()

SECRET = "sk-ant-SECRETKEY1234567890"


@pytest.fixture(autouse=True)
def _reset():
    ai_probe.reset_throttle()
    ai_probe.clear_ollama_cache()
    yield
    ai_probe.reset_throttle()
    ai_probe.clear_ollama_cache()


def run(coro):
    return _arun(coro)


class Err(Exception):
    def __init__(self, status=None, msg=f"Incorrect API key provided: {SECRET}"):
        super().__init__(msg)
        self.status_code = status


def _route(provider="anthropic"):
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    cfg["provider"] = provider
    return cloud_route_for(cfg)


class FakeAnthropic:
    def __init__(self, list_exc=None, tools_exc=None, plain_exc=None, hang=False):
        self.list_exc, self.tools_exc, self.plain_exc, self.hang = list_exc, tools_exc, plain_exc, hang
        self.calls = []
        self.models = self
        self.messages = self

    async def list(self, **kw):
        self.calls.append(("list", kw))
        if self.hang:
            await asyncio.sleep(5)
        if self.list_exc:
            raise self.list_exc

    async def create(self, **kw):
        self.calls.append(("create", kw))
        if "tools" in kw and self.tools_exc:
            raise self.tools_exc
        if "tools" not in kw and self.plain_exc:
            raise self.plain_exc

    async def close(self):
        pass


def _patch(monkeypatch, client, family="anthropic_first", model="m1"):
    from api.services import llm_resolver
    monkeypatch.setattr(llm_resolver, "open_client", lambda route, probe=False: (client, model, family))


def test_anthropic_valid_and_minimal_cost(monkeypatch):
    c = FakeAnthropic(); _patch(monkeypatch, c)
    r = run(ai_probe.probe_cloud(_route()))
    assert (r.ok, r.code, r.tools, r.model) == (True, "VALID", True, "m1")
    creates = [kw for n, kw in c.calls if n == "create"]
    assert len(creates) == 1 and creates[0]["max_tokens"] == 1


def test_tools_rejected_still_valid_with_tools_false(monkeypatch):
    c = FakeAnthropic(tools_exc=Err(400)); _patch(monkeypatch, c)
    r = run(ai_probe.probe_cloud(_route()))
    assert r.ok and r.code == "VALID" and r.tools is False


@pytest.mark.parametrize("kw,code", [
    (dict(list_exc=Err(401)), "INVALID_KEY"), (dict(list_exc=Err(403)), "INVALID_KEY"),
    (dict(tools_exc=Err(403)), "NO_MODEL_ACCESS"), (dict(tools_exc=Err(404)), "NO_MODEL_ACCESS"),
    (dict(tools_exc=Err(400), plain_exc=Err(404)), "NO_MODEL_ACCESS"),
    (dict(list_exc=Err(429)), "RATE_LIMITED"), (dict(list_exc=Err(503)), "PROVIDER_ERROR"),
    (dict(list_exc=httpx.ConnectError("boom " + SECRET)), "NETWORK"),
    (dict(list_exc=httpx.ReadTimeout("t")), "TIMEOUT"),
    (dict(list_exc=url_guard.UrlRejected("x")), "BAD_BASE_URL"),
    (dict(list_exc=Err(302)), "BAD_BASE_URL"),
])
def test_error_codes_and_no_provider_text(monkeypatch, kw, code):
    _patch(monkeypatch, FakeAnthropic(**kw))
    r = run(ai_probe.probe_cloud(_route()))
    assert (r.ok, r.code) == (False, code)
    blob = json.dumps(r.to_dict())
    assert SECRET not in blob and "Incorrect API key" not in blob and "boom" not in blob


def test_probe_timeout(monkeypatch):
    _patch(monkeypatch, FakeAnthropic(hang=True))
    r = run(ai_probe.probe_cloud(_route(), timeout=0.05))
    assert r.code == "TIMEOUT"


def test_bedrock_skips_models_list(monkeypatch):
    c = FakeAnthropic(); _patch(monkeypatch, c, family="bedrock")
    r = run(ai_probe.probe_cloud(_route("bedrock")))
    assert r.ok and not [n for n, _ in c.calls if n == "list"]


class FakeOpenAI:
    def __init__(self, reject_max_completion=False, reject_tools=False):
        self.rmc, self.rt, self.calls = reject_max_completion, reject_tools, []
        self.models = self
        self.chat = self
        self.completions = self

    async def list(self):
        pass

    async def create(self, **kw):
        self.calls.append(kw)
        if self.rmc and "max_completion_tokens" in kw:
            raise Err(400)
        if self.rt and "tools" in kw:
            raise Err(400)

    async def close(self):
        pass


def test_openai_probe_variants(monkeypatch):
    c = FakeOpenAI(reject_max_completion=True); _patch(monkeypatch, c, "openai")
    r = run(ai_probe.probe_cloud(_route("openai")))
    assert r.ok and r.tools is True and any("max_tokens" in k for k in c.calls)
    c = FakeOpenAI(reject_tools=True); _patch(monkeypatch, c, "openai")
    assert run(ai_probe.probe_cloud(_route("openai"))).tools is False


def test_no_credential_is_coded_not_raised():
    from api.services.llm_resolver import Refuse
    assert run(ai_probe.probe_cloud(Refuse("AI_NO_CREDENTIAL"))).code == "NO_CREDENTIAL"
    r = run(ai_probe.probe_cloud(_route("anthropic")))     # DEFAULT_CONFIG: chưa có key → RuntimeError nội bộ
    assert not r.ok and r.code == "NO_CREDENTIAL"


@pytest.mark.parametrize("base", ["https://169.254.169.254/v1", "http://example.com/v1", "https://[::ffff:127.0.0.1]/v1",
                                  "https://2130706433/v1", "https://user@example.com/v1"])
def test_openai_custom_base_url_blocked_without_network(base):
    from api.security import encrypt_secret
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    cfg["provider"] = "openai"
    cfg["openai"].update(base_url=base, api_key_enc=encrypt_secret("sk-test-123456789"))
    r = run(ai_probe.probe_cloud(cloud_route_for(cfg)))
    assert (r.ok, r.code) == (False, "BAD_BASE_URL")


# ── throttle ──────────────────────────────────────────────────────────────────
def test_throttle_per_user_and_global():
    for _ in range(5):
        ai_probe.throttle("u1", now=100.0)
    with pytest.raises(ai_probe.ThrottleError):
        ai_probe.throttle("u1", now=101.0)
    ai_probe.throttle("u1", now=161.5)           # cửa sổ trượt
    ai_probe.reset_throttle()
    for i in range(20):
        ai_probe.throttle(f"u{i}", now=10.0)
    with pytest.raises(ai_probe.ThrottleError):
        ai_probe.throttle("other", now=11.0)


# ── Ollama capability check (server giả) ────────────────────────────────────────
def fake_ollama(tool_calls=True, json_ok=True, installed=("qwen2.5:7b",), hits=None, status=None):
    def handler(req):
        if hits is not None:
            hits.append(req.url.path)
        if status:
            return httpx.Response(status, text="SECRET-BODY-FROM-SERVER")
        if req.url.path == "/api/version":
            return httpx.Response(200, json={"version": "0.9.9"})
        if req.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": n} for n in installed]})
        body = json.loads(req.content)
        if body.get("tools"):
            msg = {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "get_weather", "arguments": {"city": "Hanoi"}}}]} \
                if tool_calls else {"role": "assistant", "content": "It is sunny"}
        else:
            assert body.get("format") == "json"
            msg = {"role": "assistant", "content": '{"ok": true}' if json_ok else "not json"}
        return httpx.Response(200, json={"message": msg})
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


URL = "http://127.0.0.1:11434"


def test_ollama_tool_calls_sets_capability_flag():
    r = run(ai_probe.ollama_check(URL, "qwen2.5:7b", client=fake_ollama(tool_calls=True)))
    assert (r["ok"], r["code"], r["tools"], r["json"], r["model_installed"], r["version"]) == (True, "VALID", True, True, True, "0.9.9")
    r = run(ai_probe.ollama_check(URL, "qwen2.5:7b", force=True, client=fake_ollama(tool_calls=False, json_ok=False)))
    assert r["ok"] and r["tools"] is False and r["json"] is False


def test_ollama_cache_hit_and_force():
    hits = []
    run(ai_probe.ollama_check(URL, "qwen2.5:7b", client=fake_ollama(hits=hits)))
    n = len(hits)
    r = run(ai_probe.ollama_check(URL, "qwen2.5:7b", client=fake_ollama(hits=hits)))
    assert r["cached"] is True and len(hits) == n
    assert ai_probe.cached_capability(URL, "qwen2.5:7b")["tools"] is True
    run(ai_probe.ollama_check(URL, "qwen2.5:7b", force=True, client=fake_ollama(hits=hits)))
    assert len(hits) > n


def test_ollama_model_missing_and_bad_url_and_server_text_never_returned():
    r = run(ai_probe.ollama_check(URL, "llama3.2", client=fake_ollama()))
    assert (r["ok"], r["code"], r["model_installed"]) == (False, "NO_MODEL_ACCESS", False)
    hits = []
    r = run(ai_probe.ollama_check("http://169.254.169.254:11434", "m", client=fake_ollama(hits=hits)))
    assert r["code"] == "BAD_BASE_URL" and hits == []                       # không có request nào ra mạng
    r = run(ai_probe.ollama_check(URL, "m", client=fake_ollama(status=500)))
    assert r["code"] == "PROVIDER_ERROR" and "SECRET-BODY" not in json.dumps(r)
    assert ai_probe.cached_capability(URL, "m") is None                      # lỗi tạm thời không bị cache


def test_ollama_redirect_not_followed():
    def h(req):
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/"})
    r = run(ai_probe.ollama_check(URL, "m", client=httpx.AsyncClient(transport=httpx.MockTransport(h))))
    assert r["code"] == "BAD_BASE_URL"
