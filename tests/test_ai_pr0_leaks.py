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
    from api.services.llm_resolver import LLMContext, open_client, resolve
    before = dict(os.environ)
    client, _model, kind = open_client(resolve(LLMContext(feature="test")))
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
    assert "HARMLESS_VAR" not in out   # allowlist: biến lạ không được kế thừa
    assert "PATH" in out
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


# ───────────── PR-0 round 2 (verify feedback) ─────────────
SECRET_ENV = {"GITHUB_TOKEN": "ghp_" + "a" * 36, "DATABASE_URL": "postgres://u:dbpass@h/db",
              "AWS_ACCESS_KEY_ID": "AKIAABCDEFGHIJKLMNOP", "AWS_BEARER_TOKEN_BEDROCK": BEDROCK_KEY,
              "ANTHROPIC_API_KEY": "sk-ant-aaaaaaaaaaaa", "MY_SERVICE_SECRET": "s3cr3t", "STRIPE_KEY": "stripe-val-9f3"}
DUMP = "import os,json;print(json.dumps(dict(os.environ)))"


def _assert_clean(out):
    for k, v in SECRET_ENV.items():
        assert v not in out and k not in out, k
    assert "PATH" in out


@pytest.fixture
def secret_env(monkeypatch):
    for k, v in SECRET_ENV.items():
        monkeypatch.setenv(k, v)


def test_spawn_allowlist_env(secret_env):
    from scanner.pentest.procs import spawn

    async def go():
        p = await spawn(sys.executable, "-c", DUMP, run_id="t-al", stdout=asyncio.subprocess.PIPE)
        return (await p.communicate())[0].decode()
    _assert_clean(_run(go()))


def test_spawn_explicit_env_replaces(secret_env):
    from scanner.pentest.procs import spawn

    async def go():
        p = await spawn(sys.executable, "-c", DUMP, run_id="t-rep", env={"FOO": "1"}, stdout=asyncio.subprocess.PIPE)
        return (await p.communicate())[0].decode()
    out = _run(go())
    assert '"FOO": "1"' in out and "GITHUB_TOKEN" not in out and "HOME" not in out


def test_run_command_allowlist_env(secret_env):
    from scanner.scanners.base import run_command
    rc, out, _ = _run(run_command([sys.executable, "-c", DUMP]))
    assert rc == 0
    _assert_clean(out)


def test_katana_style_and_which_env(secret_env):
    import subprocess
    from scanner.scanners.base import scrubbed_env
    out = subprocess.run([sys.executable, "-c", DUMP], capture_output=True, text=True, env=scrubbed_env()).stdout
    _assert_clean(out)


def test_git_clone_child_env_scrubbed(secret_env, tmp_path, monkeypatch):
    """scm_service.clone chạy git với env sạch: dùng `git` giả in env ra file."""
    import stat
    from api.services import scm_service
    fake = tmp_path / "bin"
    fake.mkdir()
    dump = tmp_path / "env.json"
    g = fake / "git"
    g.write_text(f"#!{sys.executable}\nimport os,json\nopen({str(dump)!r},'w').write(json.dumps(dict(os.environ)))\n")
    g.chmod(g.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{fake}:{os.environ['PATH']}")
    import types
    monkeypatch.setattr(scm_service.providers, "check_base_url", lambda u: None)
    monkeypatch.setattr(scm_service.providers, "clone_url", lambda *a, **k: "https://example.test/r.git")
    monkeypatch.setattr(scm_service, "decrypt_secret", lambda x: "tok")
    conn = types.SimpleNamespace(base_url="https://example.test", token_enc="x", provider=types.SimpleNamespace(value="github"))
    repo = types.SimpleNamespace(repo_full_name="o/r", default_branch="main")
    try:
        scm_service._clone(conn, repo, str(tmp_path / "d"))
    except Exception:
        pass
    _assert_clean(dump.read_text())


def test_tool_check_child_env_scrubbed(secret_env, tmp_path):
    from api.routes.settings import _check_tool_sync
    _check_tool_sync({"tool": "x", "check_cmd": [sys.executable, "-c", f"import os;open({str(tmp_path/'e')!r},'w').write(str(dict(os.environ)))"]}, {})
    _assert_clean((tmp_path / "e").read_text())


RAW = "Incorrect API key provided: sk-proj-abcdefghijklmnop1234 https://api.openai.com/v1/x?key=zz"


class _E401(Exception):
    status_code = 401


def test_agent_in_loop_llm_error_sanitised():
    src = open("scanner/pentest/agent.py", encoding="utf-8").read()
    assert "Lỗi gọi LLM ({driver.family}/{driver.model}): {e}" not in src
    assert "sanitize_error(e)" in src and "logger.exception(\"LLM call lỗi\")" not in src


def test_ai_analyzer_cloud_error_sanitised(monkeypatch):
    import scanner.cloud_ai as cai
    from scanner.ai_analyzer import AIAnalyzer

    class Boom:
        def __init__(self, *a, **k): pass
        async def analyze_finding(self, *a, **k): raise _E401(RAW)
    monkeypatch.setattr(cai, "CloudAnalyzer", Boom)
    out = _run(AIAnalyzer().analyze_cloud({"title": "t"}, cfg={}))
    blob = repr(out)
    assert "sk-proj" not in blob and "openai.com" not in blob and "auth_failed" in out["error"]


def test_ai_analyzer_crawl_error_sanitised(monkeypatch):
    from scanner.ai_analyzer import AIAnalyzer
    a = AIAnalyzer()

    async def boom(*_a, **_k): raise _E401(RAW)
    monkeypatch.setattr(a, "_call_ollama_crawl", boom, raising=False)
    out = _run(a.analyze_crawl("http://x.test", [{"path": "/", "methods": ["GET"]}]))
    assert "sk-proj" not in repr(out)


def test_scans_domains_routes_use_sanitizer():
    for p, needle in (("api/routes/scans.py", 's["ai_error"] = sanitize_error(e)'),
                      ("api/routes/domains.py", "crawl.ai_error = sanitize_error(e)")):
        src = open(p, encoding="utf-8").read()
        assert needle in src and "ai_error = str(e)" not in src.replace('s["ai_error"] = str(e)', 'ai_error = str(e)')


def test_bad_request_bucket():
    from scanner.cloud_ai import sanitize_error

    class E(Exception):
        status_code = 400
    assert "bad_request" in sanitize_error(E("model foo: prompt too long sk-ant-aaaaaaaaaaaaa"))


# ───────────── PR-0 round 3 ─────────────
def test_tool_config_env_passes_but_secrets_do_not(monkeypatch):
    from scanner.scanners.base import scrubbed_env
    ok = {"SEMGREP_HOME": "/p/.semgrep", "TRIVY_DB_REPOSITORY": "mirror.local/trivy-db", "TRIVY_SKIP_DB_UPDATE": "true",
          "GRYPE_DB_AUTO_UPDATE": "false", "NUCLEI_TEMPLATES_DIR": "/t", "LD_LIBRARY_PATH": "/lib"}
    bad = {"TRIVY_PASSWORD": "p", "TRIVY_REGISTRY_TOKEN": "t", "GRYPE_REGISTRY_AUTH_PASSWORD": "p",
           "SEMGREP_APP_TOKEN": "t", "NUCLEI_API_KEY": "k", "TRIVY_GITHUB_TOKEN": "g", "CHECKOV_API_KEY": "k"}
    env = scrubbed_env(base={**ok, **bad, "PATH": "/bin"})
    for k, v in ok.items():
        assert env.get(k) == v, k
    for k in bad:
        assert k not in env, k


def test_tool_config_env_reaches_real_child(monkeypatch):
    monkeypatch.setenv("SEMGREP_HOME", "/p/.semgrep")
    monkeypatch.setenv("TRIVY_DB_REPOSITORY", "mirror.local/db")
    monkeypatch.setenv("TRIVY_PASSWORD", "pw-secret-xyz")
    from scanner.scanners.base import run_command
    rc, out, _ = _run(run_command([sys.executable, "-c", DUMP]))
    assert "SEMGREP_HOME" in out and "TRIVY_DB_REPOSITORY" in out and "pw-secret-xyz" not in out


def test_in_loop_llm_failure_persisted_failed_and_sanitised():
    """Lỗi LLM trong vòng lặp: run phải FAILED + error_message đã sanitise được COMMIT (không bị refresh huỷ)."""
    from api.database import Base, SessionLocal, engine
    from api.pentest_models import PentestRun, RunStatus
    from scanner.pentest import agent as agent_mod
    from scanner.pentest.agent import PentestAgent
    from tests.pentest_fakes import ScriptedDriver, make_engagement, make_run
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        eng = make_engagement(db, [{"type": "ip", "value": "10.0.0.5", "mode": "allow"}])
        rid = make_run(db, eng).id
    finally:
        db.close()

    class Boom(ScriptedDriver):
        async def create(self, *a, **k):
            raise _E401("Incorrect API key provided: sk-ant-api03-FAKEKEYFAKEKEY1234 https://evil.example/v1?token=TOK123")

    drv = Boom([])
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(asyncio.wait_for(PentestAgent(rid, driver_factory=lambda cfg: drv).run(), 30))
    finally:
        loop.close()
    db = SessionLocal()
    try:
        run = db.query(PentestRun).filter(PentestRun.id == rid).first()
        assert run.status == RunStatus.FAILED
        assert "[auth_failed]" in (run.error_message or "")
        assert "sk-ant" not in run.error_message and "evil.example" not in run.error_message and "TOK123" not in run.error_message
    finally:
        db.close()
