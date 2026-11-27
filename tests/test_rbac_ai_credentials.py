"""[AI PR-3] API credential theo user + admin + usage + settings: RBAC matrix, không lộ key, vòng đời user."""
import json
import logging
from datetime import datetime
from uuid import uuid4

import pytest

from api.ai_cred_models import AiCredential, AiUsageEvent
from api.auth_models import UserRole
from api.database import Base, SessionLocal, engine
from api.services import ai_credentials as creds
from tests._authutil import bearer, login, make_user, new_client

KEY_A = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAA-aaA1"
KEY_A2 = "sk-ant-api03-A2A2A2A2A2A2A2A2A2A2-aaA2"
KEY_B = "sk-ant-api03-BBBBBBBBBBBBBBBBBBBB-bbB1"
ORG_KEY = "sk-ant-api03-ORGORGORGORGORG-0rg1"


@pytest.fixture(autouse=True)
def clean(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_CONFIG_FILE", str(tmp_path / "ai.json"))
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    db.query(AiUsageEvent).delete()
    db.query(AiCredential).delete()
    db.commit()
    db.close()
    from api.services import ai_config
    ai_config.validate_and_save({"provider": "anthropic", "mode": "cloud_only", "anthropic": {"api_key": ORG_KEY}})
    yield


class Probe:
    """Thay seam `_probe`/`_throttle` của route (probe thật là của PR-4)."""
    def __init__(self):
        self.calls = []
        self.result = {"ok": True, "code": "VALID", "model": "claude-opus-5-5", "latency_ms": 7, "tools": True, "json": True}

    async def __call__(self, route):
        self.calls.append(route)
        return dict(self.result)

    def fail(self, code):
        self.result = {"ok": False, "code": code, "model": None, "latency_ms": 5, "tools": None, "json": None}


@pytest.fixture
def probe(monkeypatch):
    p = Probe()
    monkeypatch.setattr("api.routes.ai_credentials._probe", p)
    monkeypatch.setattr("api.routes.ai_credentials._throttle", lambda uid: None)
    return p


def who(role=UserRole.ANALYST):
    email, uid = make_user(role)
    c = new_client()
    return c, bearer(login(c, email)), uid, email


def add(c, h, key=KEY_A, **kw):
    body = {"provider": "anthropic", "secret": key, **kw}
    return c.post("/api/me/ai-credentials", json=body, headers=h)


def db():
    return SessionLocal()


def app_logs(caplog):
    """Log của app (bỏ echo SQL của sqlalchemy — chỉ là tên cột/ciphertext của test DB)."""
    return "\n".join(r.getMessage() for r in caplog.records if not r.name.startswith("sqlalchemy"))


def no_secret(*texts):
    for t in texts:
        for k in (KEY_A, KEY_A2, KEY_B, ORG_KEY, "AAAAAAAAAAAAAAAAAAAA", "BBBBBBBBBBBBBBBBBBBB", "secret_enc", "api_key_enc", "gAAAA"):
            assert k not in t, k


# ── self-service happy path ──────────────────────────────────────────────────
def test_create_list_never_returns_key_and_first_is_default(probe, caplog):
    caplog.set_level(logging.DEBUG)
    c, h, uid, _ = who()
    r = add(c, h, label="main", model="claude-opus-5-5")
    assert r.status_code == 201, r.text
    b = r.json()
    assert b["key_hint"] == "…aaA1" and b["is_default"] is True and b["status"] == "valid"
    assert b["provider"] == "anthropic" and b["model"] == "claude-opus-5-5"
    lst = c.get("/api/me/ai-credentials", headers=h)
    assert lst.status_code == 200 and len(lst.json()["credentials"]) == 1
    no_secret(r.text, lst.text, app_logs(caplog))
    assert len(probe.calls) == 1                                     # validate trước khi lưu


def test_second_key_not_default_until_asked_and_default_flips(probe):
    c, h, uid, _ = who()
    a = add(c, h, label="a").json()
    b = add(c, h, key=KEY_A2, label="b").json()
    assert a["is_default"] and not b["is_default"]
    r = c.patch(f"/api/me/ai-credentials/{b['id']}", json={"is_default": True}, headers=h)
    assert r.status_code == 200 and r.json()["is_default"] is True
    ids = {x["id"]: x["is_default"] for x in c.get("/api/me/ai-credentials", headers=h).json()["credentials"]}
    assert ids == {a["id"]: False, b["id"]: True}


def test_failed_probe_stores_nothing_and_returns_code_only(probe):
    c, h, uid, _ = who()
    probe.fail("INVALID_KEY")
    r = add(c, h)
    assert r.status_code == 422 and r.json()["detail"] == {"code": "INVALID_KEY"}
    assert c.get("/api/me/ai-credentials", headers=h).json()["credentials"] == []
    no_secret(r.text)


@pytest.mark.parametrize("body,status,code", [
    ({"provider": "azure_openai", "secret": KEY_A}, 422, "AI_BAD_PROVIDER"),
    ({"provider": "anthropic", "secret": KEY_A, "model": "a b; rm -rf"}, 422, "AI_BAD_MODEL"),
    ({"provider": "bedrock", "secret": "ABSK" + "x" * 30, "region": "evil.com"}, 422, "AI_BAD_REGION"),
    ({"provider": "anthropic", "secret": "short"}, 422, "AI_KEY_INVALID_FORMAT"),
    ({"provider": "anthropic", "secret": "sk-ant-api03 with spaces 12345"}, 422, "AI_KEY_INVALID_FORMAT"),
    ({"provider": "anthropic", "secret": "sk-ant-oat01-" + "z" * 30}, 422, "AI_KEY_UNSUPPORTED"),
])
def test_create_validation(probe, body, status, code):
    c, h, *_ = who()
    r = c.post("/api/me/ai-credentials", json=body, headers=h)
    assert r.status_code == status and r.json()["detail"]["code"] == code
    assert not probe.calls


def test_user_cannot_set_base_url_or_profile(probe):
    c, h, uid, _ = who()
    r = add(c, h, provider="openai", base_url="http://169.254.169.254/", aws_profile="x") if False else \
        c.post("/api/me/ai-credentials", json={"provider": "openai", "secret": "sk-proj-OPENAIOPENAIOPENAI1",
                                                "base_url": "http://169.254.169.254/v1", "aws_profile": "p"}, headers=h)
    assert r.status_code == 201
    row = db().query(AiCredential).filter_by(owner_user_id=uid).one()
    assert "base_url" not in (row.params or {}) and "aws_profile" not in (row.params or {})


def test_duplicate_label_and_per_user_limit(probe):
    c, h, *_ = who()
    assert add(c, h, label="x").status_code == 201
    assert add(c, h, key=KEY_A2, label="x").status_code == 409
    for i in range(19):
        assert add(c, h, key=f"sk-ant-api03-{i:020d}-zzzz", label=f"k{i}").status_code == 201
    assert add(c, h, key="sk-ant-api03-OVER0000000000000000-zzzz", label="over").json()["detail"]["code"] == "AI_CRED_LIMIT"


def test_policy_byok_off_and_allowed_block_creation(probe):
    from api.services import ai_config
    c, h, *_ = who()
    ai_config.validate_and_save({"policy": {"byok": "off"}})
    r = add(c, h)
    assert r.status_code == 403 and r.json()["detail"]["code"] == "AI_BYOK_OFF"
    ai_config.validate_and_save({"policy": {"byok": "allowed", "allowed": ["openai:*"]}})
    assert add(c, h).json()["detail"]["code"] == "AI_NOT_ALLOWED"


def test_patch_model_reseals_and_credential_still_resolves(probe):
    from api.services.llm_resolver import LLMContext, resolve
    c, h, uid, _ = who()
    a = add(c, h).json()
    r = c.patch(f"/api/me/ai-credentials/{a['id']}", json={"model": "claude-sonnet-5-5", "label": "renamed"}, headers=h)
    assert r.status_code == 200 and r.json()["model"] == "claude-sonnet-5-5" and r.json()["status"] == "unknown"
    route = resolve(LLMContext(feature="reanalyze", user_id=uid))
    assert route.credential.scope == "user" and route.model == "claude-sonnet-5-5"


def test_rotate_validates_first_and_keeps_same_id(probe):
    from api.services.ai_config import get_api_key
    from api.services.llm_resolver import LLMContext, resolve
    c, h, uid, _ = who()
    a = add(c, h).json()
    probe.fail("INVALID_KEY")
    r = c.put(f"/api/me/ai-credentials/{a['id']}/secret", json={"secret": KEY_A2}, headers=h)
    assert r.status_code == 422
    assert get_api_key("anthropic", resolve(LLMContext(feature="reanalyze", user_id=uid)).credential._cfg()) == KEY_A
    probe.result = Probe().result
    r = c.put(f"/api/me/ai-credentials/{a['id']}/secret", json={"secret": KEY_A2}, headers=h)
    assert r.status_code == 200 and r.json()["id"] == a["id"] and r.json()["key_hint"] == "…aaA2"
    route = resolve(LLMContext(feature="reanalyze", user_id=uid))
    assert get_api_key("anthropic", route.credential._cfg()) == KEY_A2 and route.credential.cid == a["id"]
    no_secret(r.text)


def test_delete_tombstones_and_resolver_stops_using_it(probe):
    from api.services.llm_resolver import LLMContext, resolve
    c, h, uid, _ = who()
    a = add(c, h).json()
    assert c.delete(f"/api/me/ai-credentials/{a['id']}", headers=h).status_code == 204
    assert c.get("/api/me/ai-credentials", headers=h).json()["credentials"] == []
    row = db().get(AiCredential, a["id"])
    assert row.secret_enc is None and row.status == "revoked" and row.is_default is False
    assert resolve(LLMContext(feature="reanalyze", user_id=uid)).credential.scope == "org"
    assert c.delete(f"/api/me/ai-credentials/{a['id']}", headers=h).status_code == 404


def test_test_endpoints_update_status_without_provider_text(probe):
    c, h, uid, _ = who()
    a = add(c, h).json()
    probe.fail("NO_MODEL_ACCESS")
    r = c.post(f"/api/me/ai-credentials/{a['id']}/test", headers=h)
    assert r.status_code == 200 and r.json()["code"] == "NO_MODEL_ACCESS" and r.json()["ok"] is False
    assert set(r.json()) == {"ok", "code", "model", "latency_ms", "tools", "json"}
    assert c.get("/api/me/ai-credentials", headers=h).json()["credentials"][0]["status"] == "forbidden"
    probe.fail("NETWORK")                                            # lỗi mạng không kết luận key hỏng
    c.post(f"/api/me/ai-credentials/{a['id']}/test", headers=h)
    assert c.get("/api/me/ai-credentials", headers=h).json()["credentials"][0]["status"] == "forbidden"
    probe.result = Probe().result
    c.post(f"/api/me/ai-credentials/{a['id']}/test", headers=h)
    assert c.get("/api/me/ai-credentials", headers=h).json()["credentials"][0]["status"] == "valid"
    # test key chưa lưu: không tạo hàng nào
    n = db().query(AiCredential).filter_by(owner_user_id=uid).count()
    r = c.post("/api/me/ai-credentials/test", json={"provider": "anthropic", "secret": KEY_A2}, headers=h)
    assert r.status_code == 200 and r.json()["ok"] is True
    assert db().query(AiCredential).filter_by(owner_user_id=uid).count() == n
    no_secret(r.text)


def test_test_records_cloud_tools_probe_for_coworker(probe):
    from api.services import ai_policy
    c, h, *_ = who()
    assert ai_policy.cloud_tools_ok("anthropic", "claude-opus-5-5") is False
    add(c, h)
    assert ai_policy.cloud_tools_ok("anthropic", "claude-opus-5-5") is True


# ── RBAC matrix ──────────────────────────────────────────────────────────────
def test_user_a_can_never_touch_user_b_credential(probe):
    from api.services.llm_resolver import LLMContext, Refuse, resolve, route_for_own_credential
    ca, ha, ua, _ = who()
    cb, hb, ub, _ = who()
    b = add(cb, hb, key=KEY_B, label="b").json()
    base = f"/api/me/ai-credentials/{b['id']}"
    # list: không thấy
    assert ca.get("/api/me/ai-credentials", headers=ha).json()["credentials"] == []
    # patch / rotate / delete / test: 404 (không lộ tồn tại)
    assert ca.patch(base, json={"label": "x"}, headers=ha).status_code == 404
    assert ca.put(base + "/secret", json={"secret": KEY_A}, headers=ha).status_code == 404
    assert ca.post(base + "/test", headers=ha).status_code == 404
    assert ca.delete(base, headers=ha).status_code == 404
    # resolve: ghim id của B vào job của A → FORBIDDEN, route_for_own_credential → Refuse
    r = resolve(LLMContext(feature="reanalyze", user_id=ua, pinned_credential_id=b["id"]))
    assert isinstance(r, Refuse) and r.code == "AI_CRED_FORBIDDEN"
    assert isinstance(route_for_own_credential(db(), b["id"], ua), Refuse)
    # B nguyên vẹn
    assert db().get(AiCredential, b["id"]).secret_enc and db().get(AiCredential, b["id"]).status == "valid"
    # open_for_call với ctx của A bị từ chối
    from api.services.llm_resolver import RouteRefused
    with pytest.raises(RouteRefused):
        creds.open_for_call(db(), b["id"], LLMContext(feature="x", user_id=ua))


def test_admin_cannot_read_test_use_or_modify_users_key_via_me(probe):
    from api.services.llm_resolver import LLMContext, Refuse, resolve
    cu, hu, uu, _ = who()
    u = add(cu, hu, key=KEY_B, label="u").json()
    ad, had, uadmin, _ = who(UserRole.ADMIN)
    base = f"/api/me/ai-credentials/{u['id']}"
    assert ad.get("/api/me/ai-credentials", headers=had).json()["credentials"] == []
    for m, p, kw in (("patch", base, {"json": {"label": "x"}}), ("put", base + "/secret", {"json": {"secret": KEY_A}}),
                     ("post", base + "/test", {}), ("delete", base, {})):
        assert getattr(ad, m)(p, headers=had, **kw).status_code == 404
    # không có đường test/đọc dưới /api/ai/credentials
    for m, p in (("post", f"/api/ai/credentials/{u['id']}/test"), ("get", f"/api/ai/credentials/{u['id']}"),
                 ("put", f"/api/ai/credentials/{u['id']}/secret"), ("get", f"/api/ai/credentials/{u['id']}/secret"),
                 ("patch", f"/api/ai/credentials/{u['id']}"), ("delete", f"/api/ai/credentials/{u['id']}")):
        assert getattr(ad, m)(p, headers=had).status_code in (404, 405), (m, p)
    # key admin không bao giờ phục vụ job của user khác; key của user không phục vụ admin
    add(ad, had, key=KEY_A, label="adm")
    from api.services.ai_config import get_api_key
    ru = resolve(LLMContext(feature="reanalyze", user_id=uu))
    assert get_api_key("anthropic", ru.credential._cfg()) == KEY_B
    r3 = resolve(LLMContext(feature="reanalyze", user_id="someone-else"))
    assert get_api_key("anthropic", r3.credential._cfg()) == ORG_KEY


def test_admin_lists_metadata_and_revokes_but_never_sees_secret(probe, caplog):
    caplog.set_level(logging.INFO)
    cu, hu, uu, email = who()
    u = add(cu, hu, key=KEY_B, label="u").json()
    ad, had, uadmin, _ = who(UserRole.ADMIN)
    r = ad.get("/api/ai/credentials", headers=had)
    assert r.status_code == 200
    row = next(x for x in r.json()["credentials"] if x["id"] == u["id"])
    assert row["owner"]["email"] == email and row["key_hint"] == "…bbB1" and row["status"] == "valid"
    assert {"calls_30d", "est_cost_usd_30d", "last_used_at"} <= set(row)
    no_secret(r.text)
    rv = ad.post(f"/api/ai/credentials/{u['id']}/revoke", headers=had)
    assert rv.status_code == 200 and rv.json()["status"] == "revoked"
    no_secret(rv.text)
    db_ = db()
    assert db_.get(AiCredential, u["id"]).secret_enc is None
    # chủ không còn dùng được; job pin vào key đã thu hồi → refuse (không fallback)
    from api.services.llm_resolver import LLMContext, resolve
    assert resolve(LLMContext(feature="reanalyze", user_id=uu, pinned_credential_id=u["id"])).code == "AI_CRED_REVOKED"
    assert cu.get("/api/me/ai-credentials", headers=hu).json()["credentials"] == []
    assert any("action=revoke_by_admin" in m and u["id"] in m for m in caplog.messages)
    no_secret(app_logs(caplog))
    assert ad.post("/api/ai/credentials/nope/revoke", headers=had).status_code == 404


@pytest.mark.parametrize("role", [UserRole.ANALYST, UserRole.VIEWER])
def test_non_admin_forbidden_on_admin_credential_endpoints(role, probe):
    c, h, *_ = who(role)
    assert c.get("/api/ai/credentials", headers=h).status_code == 403
    assert c.post("/api/ai/credentials/x/revoke", headers=h).status_code == 403
    assert c.get("/api/ai/usage?scope=all", headers=h).status_code == 403
    assert c.put("/api/ai/settings", json={}, headers=h).status_code == 403


def test_viewer_has_no_personal_keys_or_usage(probe):
    c, h, *_ = who(UserRole.VIEWER)
    assert c.get("/api/me/ai-credentials", headers=h).status_code == 403
    assert c.post("/api/me/ai-credentials", json={"provider": "anthropic", "secret": KEY_A}, headers=h).status_code == 403
    assert c.post("/api/me/ai-credentials/test", json={"provider": "anthropic", "secret": KEY_A}, headers=h).status_code == 403
    assert c.get("/api/ai/usage?scope=me", headers=h).status_code == 403


def test_unauthenticated_is_401():
    c = new_client()
    for m, p in (("get", "/api/me/ai-credentials"), ("post", "/api/me/ai-credentials"), ("get", "/api/ai/credentials"),
                 ("get", "/api/ai/usage"), ("get", "/api/ai/settings")):
        assert getattr(c, m)(p).status_code == 401, p


def test_admin_credentials_prefix_is_admin_only_in_middleware_and_me_is_not():
    from api.routes.auth import _is_admin_only
    assert _is_admin_only("GET", "/api/ai/credentials") and _is_admin_only("POST", "/api/ai/credentials/x/revoke")
    assert _is_admin_only("PUT", "/api/ai/settings")
    assert not _is_admin_only("GET", "/api/me/ai-credentials") and not _is_admin_only("POST", "/api/me/ai-credentials/x/test")
    assert not _is_admin_only("GET", "/api/ai/settings") and not _is_admin_only("GET", "/api/ai/usage")


# ── usage ────────────────────────────────────────────────────────────────────
def test_usage_me_vs_all(probe):
    ca, ha, ua, _ = who()
    cb, hb, ub, emb = who()
    ad, had, *_ = who(UserRole.ADMIN)
    a = add(ca, ha).json()
    d = db()
    for uid, cid, sc, cost in ((ua, a["id"], "user", 0.5), (ub, None, "org", 2.0), (None, None, "org", 1.0)):
        d.add(AiUsageEvent(user_id=uid, credential_id=cid, credential_scope=sc, provider="anthropic",
                           model="claude-opus-5-5", feature="reanalyze", est_cost_usd=cost, outcome="ok",
                           tokens_in=10, tokens_out=5))
    d.commit()
    me = ca.get("/api/ai/usage?scope=me", headers=ha).json()
    assert [r["est_cost_usd"] for r in me["rows"]] == [0.5] and me["rows"][0]["key_hint"] == "…aaA1"
    allr = ad.get("/api/ai/usage?scope=all&days=30", headers=had).json()["rows"]
    assert {(r["credential_scope"], r["est_cost_usd"]) for r in allr} == {("user", 0.5), ("org", 2.0), ("system", 1.0)}
    assert any(r.get("user_email") == emb for r in allr)
    no_secret(json.dumps(allr))
    assert ad.get("/api/ai/usage?days=9999", headers=had).status_code == 422


def test_usage_quota_pct(probe):
    from api.services import ai_config
    ai_config.validate_and_save({"policy": {"org_quota": {"usd_per_user_month": 10}}})
    ca, ha, ua, _ = who()
    d = db()
    d.add(AiUsageEvent(user_id=ua, credential_scope="org", provider="anthropic", model="m", feature="reanalyze",
                       est_cost_usd=2.5, outcome="ok"))
    d.commit()
    assert ca.get("/api/ai/usage?scope=me", headers=ha).json()["rows"][0]["quota_pct"] == 25.0


# ── settings ─────────────────────────────────────────────────────────────────
def test_settings_policy_visibility_and_put(probe):
    ca, ha, *_ = who()
    ad, had, *_ = who(UserRole.ADMIN)
    s = ca.get("/api/ai/settings", headers=ha).json()
    assert "policy" not in s and "advanced" not in s
    assert s["policy_public"]["byok"] == "allowed" and s["hybrid"]["tasks"]["coworker"] == "local"
    assert s["status"]["mine"]["source"] == "org" and s["ollama"]["url"]
    sa = ad.get("/api/ai/settings", headers=had).json()
    assert sa["policy"]["byok"] == "allowed" and "pentest_models" in sa["advanced"]
    no_secret(json.dumps(s), json.dumps(sa))
    assert "policy" not in ca.get("/api/ai/config", headers=ha).json()           # GET cũ không lộ policy cho mọi role
    r = ad.put("/api/ai/settings", headers=had, json={
        "policy": {"byok": "required", "allowed": ["anthropic:*"], "org_quota": {"usd_per_user_month": 20, "rpm_per_user": 60}},
        "hybrid": {"tasks": {"coworker": "cloud"}}})
    assert r.status_code == 200, r.text
    assert r.json()["policy"]["byok"] == "required" and r.json()["policy"]["org_quota"]["usd_per_user_month"] == 20
    assert r.json()["hybrid"]["tasks"]["coworker"] == "cloud"
    assert ca.get("/api/ai/settings", headers=ha).json()["policy_public"]["byok"] == "required"
    for bad in ({"policy": {"byok": "x"}}, {"hybrid": {"tasks": {"coworker": "x"}}}, {"policy": {"allowed": [1]}}):
        assert ad.put("/api/ai/settings", headers=had, json=bad).status_code == 422
    assert ad.put("/api/ai/settings", headers=had, json={"policy": {"byok": "allowed"}}).status_code == 200


def test_settings_put_cannot_inject_internal_keys(probe):
    from api.services.ai_config import load_config
    ad, had, *_ = who(UserRole.ADMIN)
    ad.put("/api/ai/settings", headers=had, json={"org_credential_id": "evil", "probe": {"anthropic:x": {"tools": True}},
                                                 "migrations": {"creds_v1": True}})
    cfg = load_config()
    assert cfg.get("org_credential_id") != "evil" and not cfg.get("probe")


def test_settings_mine_reflects_own_key(probe):
    c, h, *_ = who()
    assert c.get("/api/ai/settings", headers=h).json()["status"]["mine"]["source"] == "org"
    add(c, h)
    m = c.get("/api/ai/settings", headers=h).json()["status"]["mine"]
    assert m == {"source": "own", "provider": "anthropic", "hint": "…aaA1"}
    v, hv, *_ = who(UserRole.VIEWER)
    assert v.get("/api/ai/settings", headers=hv).json()["status"]["mine"]["source"] == "none"


# ── user lifecycle (D13) ─────────────────────────────────────────────────────
def test_deactivate_user_disables_credentials_and_resolver_ignores_them(probe):
    from api.services.llm_resolver import LLMContext, resolve
    cu, hu, uu, _ = who()
    a = add(cu, hu).json()
    ad, had, *_ = who(UserRole.ADMIN)
    assert ad.patch(f"/api/auth/users/{uu}", json={"is_active": False}, headers=had).status_code == 200
    row = db().get(AiCredential, a["id"])
    assert row.status == "disabled" and row.secret_enc is None and row.status_changed_at is not None
    assert resolve(LLMContext(feature="reanalyze", user_id=uu, pinned_credential_id=a["id"])).code == "AI_CRED_REVOKED"
    assert ad.patch(f"/api/auth/users/{uu}", json={"is_active": True}, headers=had).status_code == 200
    assert db().get(AiCredential, a["id"]).status == "disabled"        # bật lại không sống lại key


def test_demote_to_viewer_and_delete_user_disable_credentials(probe):
    ad, had, *_ = who(UserRole.ADMIN)
    c1, h1, u1, _ = who()
    c2, h2, u2, _ = who()
    k1 = add(c1, h1).json()
    k2 = add(c2, h2, key=KEY_B).json()
    assert ad.patch(f"/api/auth/users/{u1}", json={"role": "VIEWER"}, headers=had).status_code == 200
    assert db().get(AiCredential, k1["id"]).status == "disabled"
    assert ad.delete(f"/api/auth/users/{u2}", headers=had).status_code == 204
    assert db().get(AiCredential, k2["id"]).status == "disabled"


def test_purge_after_30_days_keeps_fresh_tombstones(probe):
    from datetime import timedelta
    c, h, *_ = who()
    a = add(c, h, label="old").json()
    b = add(c, h, key=KEY_A2, label="new").json()
    c.delete(f"/api/me/ai-credentials/{a['id']}", headers=h)
    c.delete(f"/api/me/ai-credentials/{b['id']}", headers=h)
    d = db()
    d.get(AiCredential, a["id"]).status_changed_at = datetime.utcnow() - timedelta(days=31)
    d.commit()
    assert creds.purge_expired(d) == 1
    d.commit()
    assert d.get(AiCredential, a["id"]) is None and d.get(AiCredential, b["id"]) is not None


def test_usage_retention_180_days():
    from datetime import timedelta
    from api.services import ai_usage
    d = db()
    d.add(AiUsageEvent(user_id="u", provider="p", outcome="ok", ts=datetime.utcnow() - timedelta(days=181)))
    d.add(AiUsageEvent(user_id="u", provider="p", outcome="ok"))
    d.commit()
    assert ai_usage.purge_old(d) == 1 and d.query(AiUsageEvent).count() == 1


# ── audit không có key ───────────────────────────────────────────────────────
def test_audit_lines_carry_id_and_last4_never_the_key(probe, caplog):
    caplog.set_level(logging.INFO, logger="vulnguard.audit.ai")
    c, h, uid, _ = who()
    a = add(c, h).json()
    c.post(f"/api/me/ai-credentials/{a['id']}/test", headers=h)
    c.put(f"/api/me/ai-credentials/{a['id']}/secret", json={"secret": KEY_A2}, headers=h)
    c.delete(f"/api/me/ai-credentials/{a['id']}", headers=h)
    lines = [m for m in caplog.messages if m.startswith("ai_cred ")]
    acts = {m.split("action=")[1].split()[0] for m in lines}
    assert {"create", "test", "rotate", "delete"} <= acts
    assert all(a["id"] in m or "cred=-" in m for m in lines)
    no_secret("\n".join(lines))
    assert any("hint=…aaA1" in m for m in lines)


# ── báo cáo / export / API công khai không chứa credential id ───────────────
def test_scan_report_and_run_json_have_no_credential_id(probe):
    from api.models import Project, Scan, ScanStatus
    c, h, uid, _ = who()
    a = add(c, h).json()
    d = db()
    p = Project(name="p-" + uuid4().hex)
    d.add(p)
    d.commit()
    s = Scan(project_id=p.id, scan_number=1, scan_path="/x", scan_types=["SAST"], status=ScanStatus.COMPLETED,
             triggered_by_user_id=uid, ai_credential_id=a["id"], ai_sched_policy="owner", ai_sched_owner_id=uid)
    d.add(s)
    d.commit()
    for path in (f"/api/scans/{s.id}", f"/api/{p.id}/scans", f"/api/scans/{s.id}/export?format=json",
                 f"/api/scans/{s.id}/export?format=md", f"/api/scans/{s.id}/export?format=ai",
                 f"/api/scans/{s.id}/export?format=sarif"):
        r = c.get(path, headers=h)
        assert a["id"] not in r.text and "…aaA1" not in r.text and "ai_credential" not in r.text, path


def test_pentest_run_json_has_no_credential_id():
    from api.pentest_models import PentestRun
    from api.routes.pentest import _run_out
    r = PentestRun(id="r", engagement_id="e", run_number=1, goal="g", ai_credential_id="cred-123")
    assert "cred-123" not in json.dumps(_run_out(r), default=str)


# ── lịch ─────────────────────────────────────────────────────────────────────
def test_schedule_records_creator_and_validates_policy(probe):
    from api.scm_models import ScanSchedule, ScmConnection, ScmProvider, ScmRepo
    c, h, uid, _ = who(UserRole.ADMIN)
    d = db()
    conn = ScmConnection(name="c" + uuid4().hex, provider=list(ScmProvider)[0], base_url="https://x.example", token_enc="x")
    d.add(conn)
    d.commit()
    repo = ScmRepo(connection_id=conn.id, repo_full_name="o/r")
    d.add(repo)
    d.commit()
    r = c.post("/api/scm/schedules", json={"repo_id": repo.id, "interval_minutes": 60, "ai_credential_policy": "owner"}, headers=h)
    assert r.status_code == 201, r.text
    assert r.json()["ai_credential_policy"] == "owner"
    s = db().get(ScanSchedule, r.json()["id"])
    assert s.created_by_user_id == uid and s.ai_credential_policy == "owner"
    bad = c.post("/api/scm/schedules", json={"repo_id": repo.id, "interval_minutes": 60, "ai_credential_policy": "everyone"}, headers=h)
    assert bad.status_code == 422
    up = c.put(f"/api/scm/schedules/{s.id}", json={"repo_id": repo.id, "interval_minutes": 60}, headers=h)
    assert up.json()["ai_credential_policy"] == "inherit"


# ── verify B1: lịch + ghim — RBAC matrix ─────────────────────────────────────
def _repo(d):
    from api.scm_models import ScmConnection, ScmProvider, ScmRepo
    conn = ScmConnection(name="c" + uuid4().hex, provider=list(ScmProvider)[0], base_url="https://x.example", token_enc="x")
    d.add(conn)
    d.commit()
    repo = ScmRepo(connection_id=conn.id, repo_full_name="o/r")
    d.add(repo)
    d.commit()
    return repo.id


def test_b1_poc_other_user_cannot_flip_schedule_to_owner_and_spend_victims_key(probe):
    """PoC của verify: A (ANALYST) hoặc ADMIN đặt lịch của B sang policy=owner + 5 phút → phải 403, key của B không bị ghim."""
    from api.scm_models import ScanSchedule
    from api.services.llm_resolver import LLMContext, resolve, schedule_pin
    cb, hb, ub, _ = who()
    add(cb, hb, key=KEY_B)
    repo = _repo(db())
    sid = cb.post("/api/scm/schedules", json={"repo_id": repo, "interval_minutes": 60}, headers=hb).json()["id"]
    ca, ha, ua, _ = who()
    ad, had, uadm, _ = who(UserRole.ADMIN)
    for c, h in ((ca, ha), (ad, had)):
        r = c.put(f"/api/scm/schedules/{sid}", json={"repo_id": repo, "interval_minutes": 5, "ai_credential_policy": "owner"}, headers=h)
        assert r.status_code == 403, r.text
    s = db().get(ScanSchedule, sid)
    assert s.ai_credential_policy in (None, "inherit") and s.interval_minutes == 60
    pol, owner, pin = schedule_pin(s.created_by_user_id, s.ai_credential_policy)
    assert pol == "org" and owner is None and pin is None
    r = resolve(LLMContext(feature="triage", user_id=None, job_kind="schedule", sched_policy=pol, sched_owner_id=owner,
                           pinned_credential_id=pin))
    assert r.credential.scope == "org"


def test_b1_schedule_matrix(probe):
    from api.scm_models import ScanSchedule
    co, ho, uo, _ = who()
    add(co, ho, key=KEY_B)
    repo = _repo(db())
    # chủ đặt owner: OK
    sid = co.post("/api/scm/schedules", json={"repo_id": repo, "interval_minutes": 60, "ai_credential_policy": "owner"}, headers=ho).json()["id"]
    cx, hx, ux, _ = who()
    ad, had, *_ = who(UserRole.ADMIN)
    for c, h in ((cx, hx), (ad, had)):
        body = {"repo_id": repo, "interval_minutes": 5, "ai_credential_policy": "owner"}
        assert c.put(f"/api/scm/schedules/{sid}", json=body, headers=h).status_code == 403               # giữ owner
        assert c.put(f"/api/scm/schedules/{sid}", json={**body, "ai_credential_policy": "inherit"}, headers=h).status_code == 403  # đổi tần suất
        assert db().get(ScanSchedule, sid).interval_minutes == 60
    # người khác chỉ được TẮT hoặc chuyển sang org/local_only
    assert cx.put(f"/api/scm/schedules/{sid}", json={"repo_id": repo, "interval_minutes": 60, "enabled": False,
                                                     "ai_credential_policy": "owner"}, headers=hx).status_code == 403
    assert cx.put(f"/api/scm/schedules/{sid}", json={"repo_id": repo, "interval_minutes": 60, "enabled": False,
                                                     "ai_credential_policy": "inherit"}, headers=hx).status_code == 200
    assert ad.put(f"/api/scm/schedules/{sid}", json={"repo_id": repo, "interval_minutes": 15, "ai_credential_policy": "org"},
                  headers=had).status_code == 200
    assert db().get(ScanSchedule, sid).ai_credential_policy == "org"
    # chủ vẫn đặt lại owner được; ANALYST khác tạo lịch riêng với owner (của chính mình) OK
    assert co.put(f"/api/scm/schedules/{sid}", json={"repo_id": repo, "interval_minutes": 30, "ai_credential_policy": "owner"},
                  headers=ho).status_code == 200
    assert cx.post("/api/scm/schedules", json={"repo_id": repo, "interval_minutes": 60, "ai_credential_policy": "owner"},
                   headers=hx).status_code == 201


def test_b1_global_owner_policy_protects_inherit_schedules(probe):
    from api.services import ai_config
    co, ho, *_ = who()
    repo = _repo(db())
    sid = co.post("/api/scm/schedules", json={"repo_id": repo, "interval_minutes": 60}, headers=ho).json()["id"]
    ai_config.validate_and_save({"policy": {"scheduled_jobs_credential": "owner"}})
    ad, had, *_ = who(UserRole.ADMIN)
    assert ad.put(f"/api/scm/schedules/{sid}", json={"repo_id": repo, "interval_minutes": 5}, headers=had).status_code == 403
    assert ad.put(f"/api/scm/schedules/{sid}", json={"repo_id": repo, "interval_minutes": 5, "ai_credential_policy": "org"},
                  headers=had).status_code == 200


def test_pin_endpoints_ignore_client_supplied_credentials(probe, monkeypatch):
    """scan/pentest: ghim chỉ do server suy ra từ người gọi; body không nhận credential id."""
    from api.schemas import ScanCreate
    from api.routes.pentest import RepinIn
    assert not [f for f in ScanCreate.model_fields if "cred" in f or "ai_" in f.replace("ai_analysis", "")]
    assert set(RepinIn.model_fields) == {"credential_id"}
    from api.routes.ai_credentials import CredCreate, CredPatch
    for m in (CredCreate, CredPatch):
        assert not {"owner_user_id", "scope", "status", "auth_mode", "base_url", "aws_profile"} & set(m.model_fields)


def test_scan_now_pins_requester_default_only(probe, monkeypatch):
    from api.services.llm_resolver import pin_for_user
    c1, h1, u1, _ = who()
    c2, h2, u2, _ = who()
    k = add(c1, h1).json()
    assert pin_for_user(u1) == k["id"] and pin_for_user(u2) is None


def test_coworker_step_accepts_no_client_route_or_credential():
    """S5: Co-work conversation pinning (columns + server wiring) is PR-3b. Guard: PR-3 never trusts client route/cred."""
    from api.routes.coworker_agent import AgentStepRequest
    bad = {"provider", "model", "credential", "credential_id", "ai_credential_id", "route", "route_kind", "pinned_route_kind",
           "pinned_credential_id", "transcript"}
    assert not bad & set(AgentStepRequest.model_fields)


# ── verify S3/S4 ─────────────────────────────────────────────────────────────
def test_s3_disable_failure_rolls_back_user_deactivation(probe, monkeypatch):
    from api.auth_models import User
    cu, hu, uu, _ = who()
    add(cu, hu)
    ad, had, *_ = who(UserRole.ADMIN)

    def boom(*a, **k):
        raise RuntimeError("db down")
    monkeypatch.setattr(creds, "disable_for_user", boom)
    from fastapi.testclient import TestClient
    from api.main import app
    bad = TestClient(app, raise_server_exceptions=False)
    r = bad.patch(f"/api/auth/users/{uu}", json={"is_active": False}, headers=had)
    assert r.status_code == 500
    assert db().get(User, uu).is_active is True            # không deactivate nửa vời
    assert db().query(AiCredential).filter_by(owner_user_id=uu).one().status == "valid"


def test_s4_custom_base_url_off_enforced_on_legacy_put(probe):
    ad, had, *_ = who(UserRole.ADMIN)
    assert ad.put("/api/ai/settings", json={"policy": {"custom_base_url": "off"}}, headers=had).status_code == 200
    for path in ("/api/ai/config", "/api/ai/settings"):
        r = ad.put(path, json={"openai": {"base_url": "https://llm.example.com/v1"}}, headers=had)
        assert r.status_code == 422 and "BAD_BASE_URL" in r.text, path
    assert ad.put("/api/ai/config", json={"openai": {"model": "gpt-4o"}}, headers=had).status_code == 200
