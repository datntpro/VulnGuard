"""[AI PR-1] LLM resolver seam: không đổi hành vi; mọi call site đi qua resolve(); không lộ secret."""
import asyncio
import copy
import importlib
import json
import pickle
import re
import sqlite3
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
KEY = "sk-ant-api03-SECRETSECRETSECRET-abcd1234"


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@pytest.fixture
def ai(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_CONFIG_FILE", str(tmp_path / "ai.json"))
    monkeypatch.setenv("RUNTIME_SETTINGS_FILE", str(tmp_path / "rt.json"))
    from api.services import ai_config, runtime_settings
    importlib.reload(ai_config)
    importlib.reload(runtime_settings)
    runtime_settings.set_ollama(url="http://10.9.8.7:11434", model="qwen2.5:7b", vision_model="llava")
    return ai_config


def _save(ai, **kw):
    base = {"provider": "anthropic", "anthropic": {"api_key": KEY}}
    base.update(kw)
    return ai.validate_and_save(base)


def _ctx(feature, **kw):
    from api.services.llm_resolver import LLMContext
    return LLMContext(feature=feature, **kw)


# ── 1. Định tuyến = hành vi cũ (mode × feature) ───────────────────────────────
@pytest.mark.parametrize("mode,feature,escalate,expected", [
    ("local_only", "triage", False, "local"),
    ("hybrid", "triage", False, "local"),
    ("hybrid", "triage", True, "cloud"),
    ("cloud_only", "triage", False, "cloud"),
    ("local_only", "reanalyze", False, "cloud"),      # hôm nay reanalyze luôn dùng cloud
    ("local_only", "pentest", False, "cloud"),
    ("cloud_only", "pentest_summarizer", False, "cloud"),
    ("local_only", "test", False, "cloud"),
    *[(m, f, False, "local") for m in ("local_only", "hybrid", "cloud_only")
      for f in ("docreview", "coworker", "file_assistant")],
])
def test_routing_matrix_matches_legacy(ai, mode, feature, escalate, expected):
    from api.services.llm_resolver import resolve
    _save(ai, mode=mode)
    assert resolve(_ctx(feature, escalate=escalate)).kind == expected


def test_coworker_is_local_in_every_mode_and_uses_runtime_ollama(ai):
    from api.services.llm_resolver import LocalOllama, resolve
    for mode in ("local_only", "hybrid", "cloud_only"):
        _save(ai, mode=mode)
        r = resolve(_ctx("coworker", user_id="u1", job_kind="coworker_conversation", needs_tools=True))
        assert isinstance(r, LocalOllama)
        assert (r.url, r.model, r.vision_model) == ("http://10.9.8.7:11434", "qwen2.5:7b", "llava")


@pytest.mark.parametrize("provider,sec,model,family", [
    ("anthropic", {"api_key": KEY, "model": "claude-x"}, "claude-x", "anthropic_first"),
    ("openai", {"api_key": "sk-proj-abcdefghijkl1234", "model": "gpt-z"}, "gpt-z", "openai"),
    ("openrouter", {"api_key": "sk-or-v1-abcdefghijkl1234", "model": "a/b"}, "a/b", "openai"),
    ("bedrock", {"auth_mode": "aws_chain", "model": "anthropic.x"}, "anthropic.x", "bedrock"),
])
def test_cloud_route_provider_model_family_parity(ai, provider, sec, model, family):
    from api.services.llm_resolver import Cloud, resolve
    _save(ai, mode="cloud_only", provider=provider, **{provider: sec})
    r = resolve(_ctx("triage"))
    assert isinstance(r, Cloud) and (r.provider, r.model, r.family) == (provider, model, family)


def test_open_client_family_and_model_match_legacy_build(ai):
    from api.services.llm_resolver import open_client, resolve
    _save(ai, mode="cloud_only", anthropic={"api_key": KEY, "model": "claude-x"})
    client, model, family = open_client(resolve(_ctx("pentest")))
    assert (model, family) == ("claude-x", "anthropic_first") and client.api_key == KEY


def test_bad_provider_refuses_and_open_client_raises(ai):
    from api.services.llm_resolver import Refuse, RouteRefused, open_client
    import api.services.llm_resolver as lr
    r = lr._cloud_route({"provider": "nope"})
    assert isinstance(r, Refuse)
    with pytest.raises(RouteRefused):
        open_client(r)


def test_missing_key_error_message_unchanged(ai):
    from api.services.llm_resolver import open_client, resolve
    _save(ai, mode="cloud_only", provider="openai", openai={"model": "gpt-4o"})
    with pytest.raises(RuntimeError, match="Chưa cấu hình API key cho openai"):
        open_client(resolve(_ctx("test")))


def test_ollama_native_route_for_agents_needs_no_key():
    from api.services.llm_resolver import LocalOllama, open_client
    client, model, family = open_client(LocalOllama(url="http://h:11434/", model="m"))
    assert family == "openai" and model == "m"
    assert str(client.base_url).rstrip("/") == "http://h:11434/v1"


# ── 2. Golden theo call site ──────────────────────────────────────────────────
class _FakeResp:
    def __init__(self, data): self._d = data
    def raise_for_status(self): pass
    def json(self): return self._d


def _fake_httpx(monkeypatch, module, payload_reply):
    seen = []

    class _C:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, json=None, **k):
            seen.append((url, json))
            return _FakeResp(payload_reply)
    monkeypatch.setattr(module.httpx, "AsyncClient", _C)
    return seen


def test_coworker_local_backend_golden_request(ai, monkeypatch):
    import api.routes.coworker_agent as ca
    seen = _fake_httpx(monkeypatch, ca, {"message": {"content": '{"action":"final","args":{"answer":"ok"}}'}})
    raw, model = _run(ca._chat_ollama([{"role": "user", "content": "hi"}], skill_body="SK"))
    url, body = seen[0]
    assert url == "http://10.9.8.7:11434/api/chat" and model == "qwen2.5:7b"
    assert body == {"model": "qwen2.5:7b",
                    "messages": [{"role": "system",
                                  "content": f"{ca.SYSTEM_PROMPT}\n\n# ── SKILL NGHIỆP VỤ ĐANG ÁP DỤNG ──\nSK"},
                                 {"role": "user", "content": "hi"}],
                    "stream": False, "options": {"temperature": 0.1, "top_p": 0.9, "num_predict": 4096}}
    assert isinstance(ca._backend(), ca.LocalJsonBackend)


def test_coworker_loop_transcript_unchanged(ai, monkeypatch):
    import api.routes.coworker_agent as ca
    replies = iter(['{"thought":"t","action":"final","args":{"answer":"xong"}}'])

    class B(ca.CoworkBackend):
        async def chat(self, messages, skill_body=None):
            return next(replies), "m"
    out = _run(ca._advance("f", [{"role": "user", "content": "q"}], backend=B()))
    assert out["status"] == "done" and out["answer"] == "xong" and out["model"] == "m"
    assert out["messages"][-1] == {"role": "assistant", "content": '{"thought":"t","action":"final","args":{"answer":"xong"}}'}


def test_coworker_suggest_and_vision_use_resolver_url(ai, monkeypatch):
    import api.routes.coworker as cw
    import api.routes.coworker_agent as ca
    seen = _fake_httpx(monkeypatch, cw, {"response": "txt"})
    _run(cw._call_ollama("p"))
    assert seen[0][0] == "http://10.9.8.7:11434/api/generate" and seen[0][1]["model"] == "qwen2.5:7b"
    seen2 = _fake_httpx(monkeypatch, ca, {"response": " mô tả "})
    assert _run(ca._describe_image(b"x")) == "mô tả"
    assert seen2[0][0] == "http://10.9.8.7:11434/api/generate" and seen2[0][1]["model"] == "llava"


def test_docreview_and_file_assistant_use_resolver_url(ai):
    from scanner.doc_reviewer import DocReviewer
    from api.services import ollama_client
    d = DocReviewer()
    assert (d.ollama_url, d.model) == ("http://10.9.8.7:11434", "qwen2.5:7b")
    ollama_client._ollama_client = None
    assert ollama_client.get_ollama_client().base_url == "http://10.9.8.7:11434"


def test_triage_local_call_golden_and_no_cloud(ai, monkeypatch):
    import scanner.cloud_ai as cai
    from scanner import ai_analyzer as aa
    _save(ai, mode="local_only")
    cloud_calls = []
    monkeypatch.setattr(cai, "CloudAnalyzer", lambda *a, **k: cloud_calls.append(a))
    seen = _fake_httpx(monkeypatch, aa, {"response": json.dumps({"false_positive_likelihood": "90%"})})
    a = aa.AIAnalyzer()
    out = _run(a.analyze_raw({"title": "t", "severity": "CRITICAL"}))
    assert out["provider"] == "ollama:qwen2.5:7b"
    assert seen[0][0] == "http://10.9.8.7:11434/api/generate" and seen[0][1]["model"] == "qwen2.5:7b"
    assert cloud_calls == []


def _cloud_spy(monkeypatch):
    import scanner.cloud_ai as cai
    got = []

    class Spy:
        def __init__(self, route=None, cfg=None):
            got.append(route)
        async def analyze_finding(self, vuln, local_opinion=None):
            return {"provider": "spy", "false_positive_likelihood": "1%"}
    monkeypatch.setattr(cai, "CloudAnalyzer", Spy)
    return got


def test_triage_cloud_only_goes_cloud_without_local(ai, monkeypatch):
    from scanner import ai_analyzer as aa
    from api.services.llm_resolver import Cloud
    _save(ai, mode="cloud_only")
    got = _cloud_spy(monkeypatch)
    seen = _fake_httpx(monkeypatch, aa, {"response": "{}"})
    out = _run(aa.AIAnalyzer().analyze_raw({"title": "t", "severity": "LOW"}))
    assert out["provider"] == "spy" and seen == [] and isinstance(got[0], Cloud)


def test_triage_hybrid_escalates_through_resolver(ai, monkeypatch):
    from scanner import ai_analyzer as aa
    from api.services.llm_resolver import Cloud
    _save(ai, mode="hybrid")
    got = _cloud_spy(monkeypatch)
    _fake_httpx(monkeypatch, aa, {"response": json.dumps({"false_positive_likelihood": "5%"})})
    out = _run(aa.AIAnalyzer().analyze_raw({"title": "t", "severity": "CRITICAL"}))
    assert out["provider"] == "spy" and len(got) == 1 and isinstance(got[0], Cloud)
    got.clear()   # severity thấp + FP rõ ràng → không leo thang
    out = _run(aa.AIAnalyzer().analyze_raw({"title": "t", "severity": "LOW"}))
    assert got == [] and out["provider"] == "ollama:qwen2.5:7b"


def test_reanalyze_and_test_endpoints_use_cloud_route(ai, monkeypatch):
    from scanner import ai_analyzer as aa
    from api.services.llm_resolver import Cloud
    _save(ai, mode="local_only")
    got = _cloud_spy(monkeypatch)
    out = _run(aa.AIAnalyzer().analyze_cloud({"title": "t"}))
    assert out["provider"] == "spy" and isinstance(got[0], Cloud)


# ── 3. Pentest: cfg không chứa secret, driver đi qua route ────────────────────
def test_pentest_cfg_has_route_without_secret_and_is_not_serialisable(ai, monkeypatch):
    from api.database import Base, SessionLocal, engine
    from scanner.pentest.agent import PentestAgent
    from tests.pentest_fakes import ScriptedDriver, make_engagement, make_run
    Base.metadata.create_all(bind=engine)
    _save(ai, mode="local_only")
    db = SessionLocal()
    try:
        eng = make_engagement(db, [{"type": "ip", "value": "10.0.0.5", "mode": "allow"}])
        run = make_run(db, eng)
        rid = run.id
    finally:
        db.close()
    seen = []

    def factory(cfg):
        seen.append(cfg)
        return ScriptedDriver([[]])
    _run(asyncio.wait_for(PentestAgent(rid, driver_factory=factory).run(), 30))
    cfg = seen[0]
    from api.services.llm_resolver import Cloud
    assert isinstance(cfg["_route"], Cloud) and cfg["_ctx"].feature == "pentest" and cfg["_ctx"].needs_tools
    blob = repr(cfg) + str(cfg)
    assert KEY not in blob and "SECRETSECRET" not in blob and "api_key_enc" not in blob
    with pytest.raises(TypeError):
        pickle.dumps(cfg)          # checkpoint không thể mang route/credential
    with pytest.raises(TypeError):
        json.dumps(cfg, default=lambda o: o.__dict__ if hasattr(o, "__dict__") else json.JSONEncoder().default(o))


def test_summarizer_role_resolves_pentest_summarizer_feature(ai):
    from api.services.llm_resolver import LLMContext, resolve
    from scanner.pentest.orchestrator.loop import role_cfg
    _save(ai)
    ctx = LLMContext(feature="pentest", job_kind="pentest_run", job_id="r1", needs_tools=True)
    cfg = {"_ctx": ctx, "_route": resolve(ctx)}
    assert role_cfg(cfg, "summarizer")["_route"].provider == "anthropic"
    assert role_cfg(cfg, "planner")["_route"] is cfg["_route"]


# ── 4. Không lộ secret trong Route ────────────────────────────────────────────
def test_route_and_credential_repr_contain_no_secret(ai):
    from api.services.llm_resolver import resolve
    _save(ai, mode="cloud_only")
    r = resolve(_ctx("pentest"))
    for text in (repr(r), str(r), repr(r.credential), str(r.credential), f"{r}", repr([r]), repr({"r": r})):
        assert KEY not in text and "SECRETSECRET" not in text and "sk-ant" not in text and "api_key_enc" not in text
    assert "…1234" in repr(r.credential) and "anthropic" in repr(r.credential)


def test_resolved_credential_not_serialisable_or_copyable(ai):
    from api.services.llm_resolver import resolve
    _save(ai, mode="cloud_only")
    r = resolve(_ctx("pentest"))
    for f in (pickle.dumps, copy.copy, copy.deepcopy, lambda o: json.dumps(o)):
        with pytest.raises(TypeError):
            f(r.credential)
    with pytest.raises(TypeError):
        pickle.dumps(r)
    with pytest.raises(AttributeError):
        r.credential._provider = "x"
    assert not hasattr(r.credential, "secret") and not hasattr(r.credential, "api_key")


def test_route_holds_only_selected_provider_section(ai):
    from api.services.llm_resolver import resolve
    _save(ai, mode="cloud_only", openai={"api_key": "sk-proj-OTHERKEYOTHERKEY1234"})
    r = resolve(_ctx("test"))
    assert r.provider == "anthropic" and set(r.credential._cfg()) == {"provider", "anthropic"}


# ── 5. Seam là đường duy nhất tới client (grep guard) ────────────────────────
_CLIENT_PAT = re.compile(r"\bbuild_client\b|\bAsyncAnthropic\w*|\bAsyncOpenAI\b|\banthropic\.(Anthropic|AnthropicBedrock)\b"
                         r"|\bopenai\.(OpenAI|AsyncOpenAI)\b|from anthropic import|from openai import")
_OLLAMA_URL_PAT = re.compile(r"runtime_settings\.ollama_(url|model|vision_model)\(|settings\.ollama_url\b"
                             r"|\bget_active_(vision_)?model\b")
# Ollama admin API (/api/ollama*) là nơi CẤU HÌNH endpoint → được đọc runtime_settings trực tiếp.
_OLLAMA_ALLOWED = {"api/services/llm_resolver.py", "api/services/runtime_settings.py", "api/routes/ollama.py",
                   "api/config.py"}
# Miễn trừ có chủ đích: eval/harness/inproc.py dựng client SDK với relay token (không phải key provider) → ngoài phạm vi.
_SCAN_DIRS = ("api", "scanner", "mcp_server", "coworker_host", "services")


def _py_files():
    for d in _SCAN_DIRS:
        for p in (ROOT / d).rglob("*.py"):
            if "node_modules" in p.parts or ".venv" in p.parts:
                continue
            yield p, p.relative_to(ROOT).as_posix()


def test_only_resolver_builds_llm_clients():
    bad = [rel for p, rel in _py_files() if rel != "api/services/llm_resolver.py"
           and _CLIENT_PAT.search(p.read_text(encoding="utf-8", errors="ignore"))]
    assert bad == [], f"chỉ llm_resolver được dựng client SDK: {bad}"


def test_only_resolver_and_ollama_admin_read_effective_ollama_endpoint():
    bad = [rel for p, rel in _py_files() if rel not in _OLLAMA_ALLOWED
           and _OLLAMA_URL_PAT.search(p.read_text(encoding="utf-8", errors="ignore"))]
    assert bad == [], f"URL/model Ollama hiệu lực phải lấy qua resolve(): {bad}"


def test_pentest_driver_has_no_direct_client_path():
    src = (ROOT / "scanner/pentest/llm.py").read_text(encoding="utf-8")
    assert "open_client" in src and "build_client" not in src


# ── 6. Hội thoại Co-work theo chủ sở hữu ─────────────────────────────────────
def test_conversations_scoped_to_owner():
    from api.auth_models import UserRole
    from tests._authutil import bearer, login, make_user, new_client
    ca, cb = new_client(), new_client()
    ea, _ = make_user(UserRole.ADMIN)
    eb, _ = make_user(UserRole.ADMIN)
    ha, hb = bearer(login(ca, ea)), bearer(login(cb, eb))
    r = ca.post("/api/coworker/agent/conversations", headers=ha,
                json={"messages": [{"role": "user", "content": "bí mật của A"}], "folder_id": "f"})
    assert r.status_code == 200, r.text
    cid = r.json()["id"]
    assert cid in [c["id"] for c in ca.get("/api/coworker/agent/conversations", headers=ha).json()["conversations"]]
    assert cid not in [c["id"] for c in cb.get("/api/coworker/agent/conversations", headers=hb).json()["conversations"]]
    assert cb.get(f"/api/coworker/agent/conversations/{cid}", headers=hb).status_code == 404
    assert cb.delete(f"/api/coworker/agent/conversations/{cid}", headers=hb).status_code == 404
    # B cũng không ghi đè được hội thoại của A bằng cách dùng lại id
    r = cb.post("/api/coworker/agent/conversations", headers=hb,
                json={"id": cid, "messages": [{"role": "user", "content": "x"}]})
    assert r.status_code == 404
    assert ca.get(f"/api/coworker/agent/conversations/{cid}", headers=ha).status_code == 200


def test_legacy_conversation_visible_to_admin_only_when_owner_null():
    from api.agent_conversation_models import AgentConversation
    from api.auth_models import UserRole
    from api.database import Base, SessionLocal, engine
    from tests._authutil import bearer, login, make_user, new_client
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        row = AgentConversation(title="legacy", messages=[])
        db.add(row); db.commit()
        cid = row.id
    finally:
        db.close()
    c = new_client()
    e, _ = make_user(UserRole.ADMIN)
    assert c.get(f"/api/coworker/agent/conversations/{cid}", headers=bearer(login(c, e))).status_code == 200
    import api.routes.coworker_agent as ca

    class _U:
        id = "u"; role = UserRole.ANALYST

    class _Req:
        class state: user = _U()
    assert ca._may_access(row, _Req()) is False


# ── 7. Migration m0013 (backfill đúng một lần) ───────────────────────────────
def _boot(db, mod):
    for ddl in mod.DDL:
        try:
            db.execute(ddl)
        except sqlite3.OperationalError as e:
            assert "duplicate column" in str(e)


def test_m0013_backfills_once_and_never_reassigns_on_email_reuse():
    mod = importlib.import_module("api.pentest_migrations.m0013_run_owner")
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE users (id TEXT, email TEXT)")
    db.execute("CREATE TABLE pentest_runs (id TEXT, started_by TEXT)")
    db.execute("INSERT INTO users VALUES ('u1','Alice@x.io'), ('u0','alice@x.io')")   # email trùng hoa/thường
    db.executemany("INSERT INTO pentest_runs VALUES (?,?)", [("r1", "alice@x.io"), ("r2", "ghost@x.io"), ("r3", None)])
    _boot(db, mod)
    rows = dict(db.execute("SELECT id, started_by_user_id FROM pentest_runs").fetchall())
    assert rows == {"r1": "u0", "r2": None, "r3": None}          # đúng 1 dòng, không lỗi subquery
    # boot lại sau khi user "ghost" mới đăng ký bằng email cũ → KHÔNG thừa hưởng run cũ
    db.execute("INSERT INTO users VALUES ('u9','ghost@x.io')")
    for _ in range(2):
        _boot(db, mod)
    rows = dict(db.execute("SELECT id, started_by_user_id FROM pentest_runs").fetchall())
    assert rows["r2"] is None and rows["r1"] == "u0"
    assert db.execute("SELECT count(*) FROM pentest_schema_migrations").fetchone()[0] == 1


def test_list_conversations_filters_owner_in_sql_before_limit():
    from api.agent_conversation_models import AgentConversation
    from api.auth_models import UserRole
    from api.database import Base, SessionLocal, engine
    from tests._authutil import bearer, login, make_user, new_client
    Base.metadata.create_all(bind=engine)
    c = new_client()
    e, uid = make_user(UserRole.ADMIN)
    _, other = make_user(UserRole.ADMIN)
    db = SessionLocal()
    try:
        mine = AgentConversation(title="mine", messages=[], owner_user_id=uid)
        db.add(mine); db.commit()
        mine_id = mine.id
        db.add_all([AgentConversation(title=f"o{i}", messages=[], owner_user_id=other) for i in range(210)])
        db.commit()   # mới hơn hội thoại của mình
    finally:
        db.close()
    r = c.get("/api/coworker/agent/conversations", headers=bearer(login(c, e)))
    ids = [x["id"] for x in r.json()["conversations"]]
    assert mine_id in ids
    assert all(x["title"] != "o0" for x in r.json()["conversations"])


def test_credential_hint_decrypted_once(ai, monkeypatch):
    import api.security as sec
    from api.services.llm_resolver import resolve
    _save(ai, mode="cloud_only")
    r = resolve(_ctx("test"))
    calls = []
    real = sec.decrypt_secret
    monkeypatch.setattr(sec, "decrypt_secret", lambda v: calls.append(1) or real(v))
    repr(r.credential); repr(r.credential); str(r)
    assert len(calls) == 1
