"""[AI PR-4] Route-level: RBAC, giá trị chưa lưu, validate khi lưu, throttle, /api/ai/models qua resolver.
(Tách file, đặt tên sau test_app: các test tạo user không được chạy trước test_app — nó cần setup_required.)"""
import pytest

from api.services import ai_probe

SECRET = "sk-ant-SECRETKEY1234567890"


@pytest.fixture(autouse=True)
def _reset():
    ai_probe.reset_throttle()
    yield
    ai_probe.reset_throttle()


# ── Route-level ────────────────────────────────────────────────────────────────
def test_routes_rbac_unsaved_values_and_validation(monkeypatch):
    from api.auth_models import UserRole
    from tests._authutil import bearer, login, make_user, new_client
    c = new_client()
    ea, _ = make_user(UserRole.ADMIN)
    eb, _ = make_user(UserRole.ANALYST)
    ha, hb = bearer(login(c, ea)), bearer(login(c, eb))
    assert c.post("/api/ai/ollama/check", json={}, headers=hb).status_code == 403
    assert c.post("/api/ai/test", json={}, headers=hb).status_code == 403
    # test giá trị CHƯA LƯU: base_url nội bộ → BAD_BASE_URL, không lộ gì, không cần lưu
    r = c.post("/api/ai/test", headers=ha, json={"provider": "openai", "api_key": SECRET,
                                                 "base_url": "https://169.254.169.254/v1"})
    assert r.status_code == 200
    j = r.json()
    assert j["ok"] is False and j["code"] == "BAD_BASE_URL" and SECRET not in r.text
    # lưu cấu hình với base_url cấm → 422
    r = c.put("/api/ai/config", headers=ha, json={"openai": {"base_url": "http://10.0.0.1/v1"}})
    assert r.status_code == 422 and "BAD_BASE_URL" in r.text
    # endpoint Ollama: metadata → 400
    r = c.put("/api/ollama/endpoint", headers=ha, json={"url": "http://169.254.169.254:11434"})
    assert r.status_code == 400
    assert c.post("/api/ai/test", headers=ha, json={"provider": "nope"}).status_code == 422
    # throttle → 429 sau 5 lần/phút
    ai_probe.reset_throttle()
    codes = [c.post("/api/ai/test", headers=ha, json={"provider": "openai", "base_url": "https://10.0.0.1/"}).status_code
             for _ in range(6)]
    assert codes[:5] == [200] * 5 and codes[5] == 429


def test_models_route_uses_resolver_not_direct_key_reads(monkeypatch):
    import api.services.ai_models as m
    import pathlib
    src = pathlib.Path(m.__file__).read_text(encoding="utf-8")
    assert "get_api_key" not in src and "get_anthropic_api_key" not in src and "api_key_enc" not in src
    from api.auth_models import UserRole
    from tests._authutil import bearer, login, make_user, new_client
    c = new_client()
    h = bearer(login(c, make_user(UserRole.ADMIN)[0]))
    seen = {}

    async def fake_list(provider, route):
        seen["route"] = route
        return {"models": ["x"], "source": "static", "note": "", "error": None}
    monkeypatch.setattr(m, "list_models", fake_list)
    r = c.get("/api/ai/models?provider=openai", headers=h)
    assert r.status_code == 200 and r.json()["models"] == ["x"]
    assert seen["route"].provider == "openai"                     # route do resolver dựng
    assert c.get("/api/ai/models?provider=zzz", headers=h).status_code == 422


# ── [fix] B2: khoá đã lưu không bao giờ đi theo base_url/region do request chọn ─────────────────
def _admin():
    from api.auth_models import UserRole
    from tests._authutil import bearer, login, make_user, new_client
    c = new_client()
    return c, bearer(login(c, make_user(UserRole.ADMIN)[0]))


def _save_key(provider="openai"):
    from api.services.ai_config import validate_and_save
    validate_and_save({"provider": provider, provider: {"api_key": "sk-SAVED-KEY-1234567890"}})


def _capture(monkeypatch):
    got = {}

    async def fake(route, **kw):
        got["route"] = route
        return ai_probe.ProbeResult(True, "VALID", route.model, 1, True, None)
    monkeypatch.setattr(ai_probe, "probe_cloud", fake)
    return got


@pytest.mark.parametrize("body", [
    {"provider": "openai", "base_url": "https://attacker.tld/v1"},
    {"provider": "openai", "base_url": "https://attacker.tld/v1", "model": "x"},
    {"provider": "openai", "endpoint": "https://attacker.tld"},
    {"provider": "openai", "deployment": "d"},
    {"provider": "bedrock", "region": "example.com/x?"},
    {"provider": "bedrock", "region": "eu-west-1"},
    {"provider": "bedrock", "auth_mode": "bedrock_api_key"},
])
def test_saved_key_never_reused_when_destination_changes(monkeypatch, body):
    c, h = _admin()
    _save_key("bedrock"); _save_key("openai")
    got = _capture(monkeypatch)
    assert c.post("/api/ai/test", headers=h, json=body).status_code == 200
    assert got["route"].credential._section.get("api_key_enc") is None


def test_saved_key_reused_for_unchanged_destination_and_new_key_accepted(monkeypatch):
    c, h = _admin()
    _save_key("openai")
    got = _capture(monkeypatch)
    c.post("/api/ai/test", headers=h, json={"model": "gpt-x"})
    assert got["route"].credential._section.get("api_key_enc")                      # cấu hình đã lưu, chỉ đổi model
    c.post("/api/ai/test", headers=h, json={"provider": "openai", "base_url": "https://llm.example.com/v1", "api_key": "sk-NEW-123456789"})
    assert got["route"].credential._section.get("api_key_enc")                      # key mới nằm trong chính request


def test_bedrock_region_injection_blocked_everywhere(monkeypatch):
    c, h = _admin()
    for region in ("example.com/x?", "us-east-1.evil.com", "US-EAST-1", "a-b", "us-east-1\n", "../x", "x" * 40):
        ai_probe.reset_throttle()
        r = c.post("/api/ai/test", headers=h, json={"provider": "bedrock", "region": region, "auth_mode": "bedrock_api_key",
                                                    "api_key": "ABSKtest123456789"})
        assert r.json()["code"] == "BAD_BASE_URL", region
        assert c.put("/api/ai/config", headers=h, json={"bedrock": {"region": region}}).status_code == 422, region
    from api.services.llm_resolver import valid_region
    assert all(valid_region(r) for r in ("us-east-1", "eu-west-2", "ap-southeast-1", "us-gov-west-1"))
