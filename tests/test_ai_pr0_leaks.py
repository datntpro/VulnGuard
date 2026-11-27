"""[AI PR-0] rò rỉ secret AI + Ollama URL + sanitise lỗi."""
import asyncio
import importlib
import os
import sys

import pytest

def _run(coro):
    # không dùng asyncio.run: nó xoá event loop mặc định, làm hỏng test khác dùng get_event_loop()
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


BEDROCK_KEY = "ABSKQmVkcm9ja0FQSUtleS1zZWNyZXQtdmFsdWUtMTIzNDU2Nzg5MA"


@pytest.fixture
def ai_cfg(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_CONFIG_FILE", str(tmp_path / "ai.json"))
    from api.services import ai_config
    importlib.reload(ai_config)
    return ai_config


@pytest.fixture
def rt(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNTIME_SETTINGS_FILE", str(tmp_path / "rt.json"))
    from api.services import runtime_settings
    importlib.reload(runtime_settings)
    runtime_settings.set_ollama(url="http://10.9.8.7:11434")
    return runtime_settings


def test_bedrock_build_does_not_touch_environ(ai_cfg, monkeypatch):
    monkeypatch.delenv("AWS_BEARER_TOKEN_BEDROCK", raising=False)
    cfg = ai_cfg.validate_and_save({"provider": "bedrock", "mode": "cloud_only",
                                    "bedrock": {"auth_mode": "bedrock_api_key", "api_key": BEDROCK_KEY,
                                                "region": "us-east-1"}})
    from scanner.cloud_ai import build_client
    before = dict(os.environ)
    client, _model, kind = build_client(cfg)
    assert kind == "bedrock"
    assert dict(os.environ) == before
    assert "AWS_BEARER_TOKEN_BEDROCK" not in os.environ
    assert BEDROCK_KEY not in os.environ.values()
    assert getattr(client, "api_key", None) == BEDROCK_KEY   # token nằm trong client, không trong env


def test_spawn_child_does_not_inherit_provider_secrets(monkeypatch):
    for k, v in {"AWS_BEARER_TOKEN_BEDROCK": BEDROCK_KEY, "ANTHROPIC_API_KEY": "sk-ant-xxxxxxxxxxxx",
                 "OPENAI_API_KEY": "sk-yyyy", "KIRO_API_KEY": "ksk_zzzz", "AZURE_OPENAI_API_KEY": "az",
                 "GOOGLE_APPLICATION_CREDENTIALS": "/x.json", "OPENROUTER_API_KEY": "sk-or-v1-q",
                 "HARMLESS_VAR": "keep-me"}.items():
        monkeypatch.setenv(k, v)
    from scanner.pentest.procs import spawn

    async def run():
        p = await spawn(sys.executable, "-c", "import os,json;print(json.dumps(dict(os.environ)))",
                        run_id="t-env", stdout=asyncio.subprocess.PIPE)
        out, _ = await p.communicate()
        return out.decode()

    out = _run(run())
    assert "HARMLESS_VAR" in out
    for secret in (BEDROCK_KEY, "sk-ant-xxxxxxxxxxxx", "sk-yyyy", "ksk_zzzz", "sk-or-v1-q", "AWS_BEARER_TOKEN_BEDROCK"):
        assert secret not in out


def test_run_command_child_env_scrubbed(monkeypatch):
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", BEDROCK_KEY)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-aaaaaaaaaaaa")
    from scanner.scanners.base import run_command
    rc, out, _ = _run(run_command([sys.executable, "-c", "import os;print(sorted(os.environ))"]))
    assert rc == 0
    assert "AWS_BEARER_TOKEN_BEDROCK" not in out and "ANTHROPIC_API_KEY" not in out


def test_explicit_env_still_passes(monkeypatch):
    from scanner.scanners.base import scrubbed_env
    assert scrubbed_env(extra={"AWS_PROFILE": "p"})["AWS_PROFILE"] == "p"


def test_doc_reviewer_uses_runtime_url(rt):
    from scanner.doc_reviewer import DocReviewer
    assert DocReviewer().ollama_url == "http://10.9.8.7:11434"


def test_file_assistant_client_follows_runtime_url(rt):
    from api.services import ollama_client as oc
    assert oc.get_ollama_client().base_url == "http://10.9.8.7:11434"
    rt.set_ollama(url="http://10.9.8.8:11434")
    assert oc.get_ollama_client().base_url == "http://10.9.8.8:11434"   # không bị singleton giữ URL cũ


def test_coworker_uses_runtime_url(rt, monkeypatch):
    seen = []

    class FakeResp:
        status_code = 200
        def raise_for_status(self): pass
        def json(self): return {"response": "ok", "message": {"content": "ok"}}

    class FakeClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): pass
        async def post(self, url, **k):
            seen.append(url); return FakeResp()

    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    from api.routes import coworker
    try:
        _run(coworker._call_ollama("hi"))
    except Exception:
        pass
    assert seen and seen[0].startswith("http://10.9.8.7:11434/")


def test_openai_401_not_echoed():
    from scanner.cloud_ai import sanitize_error

    class E(Exception):
        status_code = 401
    out = sanitize_error(E("Incorrect API key provided: sk-proj-abcdefghijklmnop1234. https://api.openai.com/v1?key=zzz"))
    assert "sk-proj" not in out and "openai.com" not in out and "auth_failed" in out


def test_sanitize_runtime_error_redacts():
    from scanner.cloud_ai import sanitize_error
    out = sanitize_error(RuntimeError(f"bad {BEDROCK_KEY} at https://x.test/?token=abc Bearer abcdefghijkl"))
    assert BEDROCK_KEY not in out and "x.test" not in out and "abcdefghijkl" not in out


def test_redaction_new_patterns():
    from scanner.cloud_ai import redact
    for s in (BEDROCK_KEY, "ksk_abcdefghijklmnop1234", "sk-or-v1-abcdefghijklmnopqrstu"):
        assert s not in redact(f"key={s} tail")


def test_no_kiro_profile_claim():
    html = open("web/index.html", encoding="utf-8").read()
    assert "tạo bằng kiro-cli login" not in html
    assert "profile do <span class=\"text-mono\">kiro-cli</span>" not in html
