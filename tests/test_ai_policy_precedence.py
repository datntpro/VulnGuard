"""[AI PR-3] Precedence của resolver (§4.3), policy, quota/rpm, job hệ thống/lịch, Co-work (§4.11) và Meter."""
import json
from datetime import datetime, timedelta

import pytest

from api.ai_cred_models import AiCredential, AiUsageEvent
from api.database import Base, SessionLocal, engine
from api.services import ai_credentials as creds
from api.services import ai_policy, ai_usage
from api.services.llm_resolver import (AI_CLOUD_NO_TOOLS, AI_CRED_FORBIDDEN, AI_CRED_REVOKED, AI_NO_CREDENTIAL,
                                       AI_NOT_ALLOWED, AI_QUOTA, AI_ROUTE_CHANGED, Cloud, LLMContext, LocalOllama,
                                       Refuse, RouteRefused, resolve)

ORG_KEY = "sk-ant-api03-ORGORGORGORGORG-0rg1"
A_KEY = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAA-aaA1"
A2_KEY = "sk-ant-api03-A2A2A2A2A2A2A2A2A2A2-aaA2"
B_KEY = "sk-ant-api03-BBBBBBBBBBBBBBBBBBBB-bbB1"
ADMIN_KEY = "sk-ant-api03-ADMINADMINADMINADMIN-adm1"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_CONFIG_FILE", str(tmp_path / "ai.json"))
    monkeypatch.setenv("RUNTIME_SETTINGS_FILE", str(tmp_path / "rt.json"))
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    db.query(AiUsageEvent).delete()
    db.query(AiCredential).delete()
    db.commit()
    ai_usage.reset_rpm()
    from api.services import ai_config
    ai_config.validate_and_save({"provider": "anthropic", "mode": "cloud_only", "anthropic": {"api_key": ORG_KEY}})
    yield db
    db.query(AiUsageEvent).delete()
    db.query(AiCredential).delete()
    db.commit()
    db.close()


def _cfg(**kw):
    from api.services import ai_config
    return ai_config.validate_and_save(kw)


def _policy(**kw):
    return _cfg(policy=kw)


def _mk(db, uid, key=A_KEY, label="k", default=True, provider="anthropic", model="claude-opus-5-5", status="valid"):
    m = creds.create(db, scope="user", owner_user_id=uid, provider=provider, label=label, secret=key,
                     params={"model": model}, created_by=uid, status=status)
    if default:
        creds.set_default(db, uid, m["id"])
    db.commit()
    return m["id"]


def _key(route):
    from api.services.ai_config import get_api_key
    return get_api_key(route.provider, route.credential._cfg())


def _ctx(uid="u1", feature="reanalyze", **kw):
    return LLMContext(feature=feature, user_id=uid, **kw)


def _spend(db, uid, usd, scope="org", ts=None):
    db.add(AiUsageEvent(user_id=uid, credential_scope=scope, provider="anthropic", model="claude-opus-5-5",
                        feature="reanalyze", est_cost_usd=usd, outcome="ok", ts=ts or datetime.utcnow()))
    db.commit()


# ── precedence: pinned → default → org → refuse ──────────────────────────────
def test_no_user_key_uses_org(env):
    r = resolve(_ctx())
    assert isinstance(r, Cloud) and r.credential.scope == "org" and _key(r) == ORG_KEY


def test_user_default_beats_org_and_is_scoped_to_that_user(env):
    _mk(env, "u1")
    _mk(env, "u2", key=B_KEY)
    r1, r2, r3 = resolve(_ctx("u1")), resolve(_ctx("u2")), resolve(_ctx("u3"))
    assert (r1.credential.scope, _key(r1)) == ("user", A_KEY)
    assert (r2.credential.scope, _key(r2)) == ("user", B_KEY)
    assert (r3.credential.scope, _key(r3)) == ("org", ORG_KEY)       # người không có key không bao giờ mượn key người khác


def test_admin_own_key_never_serves_other_users(env):
    _mk(env, "admin1", key=ADMIN_KEY)
    r = resolve(_ctx("u1"))
    assert _key(r) == ORG_KEY
    assert _key(resolve(_ctx(None))) == ORG_KEY


def test_pinned_wins_over_default(env):
    _mk(env, "u1", key=A_KEY, label="d")
    pinned = _mk(env, "u1", key=A2_KEY, label="p", default=False)
    r = resolve(_ctx(pinned_credential_id=pinned))
    assert _key(r) == A2_KEY and r.credential.cid == pinned


def test_pinned_revoked_refuses_without_fallthrough(env):
    _mk(env, "u1", key=A_KEY, label="d")
    pinned = _mk(env, "u1", key=A2_KEY, label="p", default=False)
    creds.delete(env, pinned, actor="u1")
    env.commit()
    r = resolve(_ctx(pinned_credential_id=pinned))
    assert isinstance(r, Refuse) and r.code == AI_CRED_REVOKED       # KHÔNG rơi sang default hay org


def test_pinned_missing_or_invalid_status_refuses(env):
    assert resolve(_ctx(pinned_credential_id="nope")).code == AI_CRED_REVOKED
    bad = _mk(env, "u1", default=False, status="invalid")
    assert resolve(_ctx(pinned_credential_id=bad)).code == AI_CRED_REVOKED


def test_pinned_other_users_credential_is_forbidden(env):
    other = _mk(env, "u2", key=B_KEY)
    r = resolve(_ctx("u1", pinned_credential_id=other))
    assert isinstance(r, Refuse) and r.code == AI_CRED_FORBIDDEN


def test_pinned_org_follows_org_config_and_stops_if_provider_changes(env):
    org_id = _cfg().get("org_credential_id")
    from api.services import ai_credentials
    ai_credentials.migrate_org_config(env)
    org_id = __import__("api.services.ai_config", fromlist=["x"]).load_config().get("org_credential_id")
    assert org_id
    r = resolve(_ctx(pinned_credential_id=org_id))
    assert isinstance(r, Cloud) and r.credential.scope == "org" and r.credential_id == org_id
    _cfg(provider="openai", openai={"api_key": "sk-proj-OPENAIOPENAIOPENAI1"})       # đổi provider org giữa job
    assert resolve(_ctx(pinned_credential_id=org_id)).code == AI_CRED_REVOKED


def test_pinned_org_blocked_when_policy_requires_byok(env):
    from api.services import ai_credentials
    ai_credentials.migrate_org_config(env)
    org_id = __import__("api.services.ai_config", fromlist=["x"]).load_config().get("org_credential_id")
    _policy(byok="required")
    assert resolve(_ctx(pinned_credential_id=org_id)).code == AI_NO_CREDENTIAL


def test_byok_off_ignores_user_keys(env):
    _mk(env, "u1")
    pinned = _mk(env, "u1", key=A2_KEY, label="p", default=False)
    _policy(byok="off")
    assert _key(resolve(_ctx("u1"))) == ORG_KEY
    assert resolve(_ctx("u1", pinned_credential_id=pinned)).code == AI_CRED_REVOKED


def test_byok_required_never_uses_org_for_user_jobs(env):
    _policy(byok="required")
    r = resolve(_ctx("u1"))
    assert isinstance(r, Refuse) and r.code == AI_NO_CREDENTIAL
    _mk(env, "u1")
    assert _key(resolve(_ctx("u1"))) == A_KEY
    # job hệ thống vẫn dùng org khi scheduled_jobs_credential='org'
    assert _key(resolve(_ctx(None))) == ORG_KEY


def test_fallback_to_org_false_refuses_without_own_key(env):
    _policy(fallback_to_org=False)
    assert resolve(_ctx("u1")).code == AI_NO_CREDENTIAL
    _mk(env, "u1")
    assert _key(resolve(_ctx("u1"))) == A_KEY


def test_non_default_valid_key_is_not_used_implicitly(env):
    _mk(env, "u1", default=False)
    assert _key(resolve(_ctx("u1"))) == ORG_KEY


@pytest.mark.parametrize("status", ["invalid", "forbidden", "revoked", "disabled"])
def test_unusable_default_falls_to_org_if_policy_allows(env, status):
    cid = _mk(env, "u1")
    row = env.get(AiCredential, cid)
    row.status = status
    env.commit()
    assert _key(resolve(_ctx("u1"))) == ORG_KEY


# ── quota / rpm ──────────────────────────────────────────────────────────────
def test_org_quota_exhausted_refuses_but_own_key_unaffected(env):
    _policy(org_quota={"usd_per_user_month": 5, "rpm_per_user": None})
    _spend(env, "u1", 4.0)
    assert _key(resolve(_ctx("u1"))) == ORG_KEY                       # còn hạn mức
    _spend(env, "u1", 1.5)
    r = resolve(_ctx("u1"))
    assert isinstance(r, Refuse) and r.code == AI_QUOTA
    _mk(env, "u1")                                                    # có key riêng → không bị hạn mức org chặn
    assert _key(resolve(_ctx("u1"))) == A_KEY
    assert _key(resolve(_ctx("u2"))) == ORG_KEY                       # user khác không bị ảnh hưởng


def test_quota_ignores_previous_month_user_scope_and_blocked_events(env):
    _policy(org_quota={"usd_per_user_month": 1, "rpm_per_user": None})
    now = datetime.utcnow()
    prev = ai_usage.month_start(now) - timedelta(days=2)
    _spend(env, "u1", 50, ts=prev)
    _spend(env, "u1", 50, scope="user")
    env.add(AiUsageEvent(user_id="u1", credential_scope="org", est_cost_usd=50, outcome="quota_blocked"))
    env.commit()
    assert isinstance(resolve(_ctx("u1")), Cloud)


def test_unlimited_by_default(env):
    _spend(env, "u1", 10_000)
    assert isinstance(resolve(_ctx("u1")), Cloud)


def test_rpm_bucket(env):
    assert all(ai_usage.rpm_take("k", 3, now=100.0 + i) for i in range(3))
    assert not ai_usage.rpm_take("k", 3, now=110.0)
    assert ai_usage.rpm_take("k", 3, now=161.0)                       # cửa sổ 60 s trượt
    assert ai_usage.rpm_take("k", None) and ai_usage.rpm_take("k", 0)  # không giới hạn


# ── allowed providers/models ─────────────────────────────────────────────────
def test_allowed_globs():
    p = ai_policy.normalize({"allowed": ["anthropic:claude-*", "bedrock"]})
    assert ai_policy.is_allowed(p, "anthropic", "claude-opus-5-5")
    assert not ai_policy.is_allowed(p, "anthropic", "gpt-4o")
    assert ai_policy.is_allowed(p, "bedrock", "anthropic.claude-x")   # mẫu không có ':' = provider:*
    assert not ai_policy.is_allowed(p, "openai", "gpt-4o")
    assert ai_policy.is_allowed(ai_policy.normalize({}), "openai", "anything")


def test_allowed_filters_default_org_and_pinned(env):
    d = _mk(env, "u1", model="claude-opus-5-5")
    _policy(allowed=["openai:*"])
    assert resolve(_ctx("u1")).code == AI_NOT_ALLOWED                 # default bị chặn → org cũng bị chặn
    assert resolve(_ctx("u1", pinned_credential_id=d)).code == AI_CRED_REVOKED
    _policy(allowed=["anthropic:*"])
    assert _key(resolve(_ctx("u1"))) == A_KEY


def test_default_disallowed_falls_back_to_allowed_org(env):
    _mk(env, "u1", model="claude-opus-5-5")
    _cfg(openai={"api_key": "sk-proj-OPENAIOPENAIOPENAI1"}, provider="openai")
    _policy(allowed=["openai:*"])
    r = resolve(_ctx("u1"))
    assert isinstance(r, Cloud) and r.provider == "openai" and r.credential.scope == "org"


def test_policy_validation():
    for bad in ({"byok": "maybe"}, {"scheduled_jobs_credential": "all"}, {"org_quota": {"usd_per_user_month": -1}},
                {"allowed": "x"}, {"org_quota": {"rpm_per_user": "abc"}}, {"custom_base_url": "yes"}):
        with pytest.raises(ValueError):
            ai_policy.normalize(bad)
    assert ai_policy.get_policy({"policy": {"byok": "bogus"}})["byok"] == "allowed"   # hỏng → mặc định an toàn


# ── job hệ thống / lịch ──────────────────────────────────────────────────────
def test_system_job_uses_org_never_a_user_key(env):
    _mk(env, "u1")
    _mk(env, "u2", key=B_KEY)
    r = resolve(_ctx(None, "triage", job_kind="schedule"))
    assert _key(r) == ORG_KEY and r.credential.scope == "org"


def test_system_job_user_key_only_under_owner_policy_with_matching_creator(env):
    mine = _mk(env, "u1")
    theirs = _mk(env, "u2", key=B_KEY)
    base = dict(feature="triage", user_id=None, job_kind="schedule")
    # owner + đúng chủ lịch (tự chọn default của chủ)
    r = resolve(LLMContext(sched_policy="owner", sched_owner_id="u1", **base))
    assert _key(r) == A_KEY
    # ghim đúng key của chủ
    assert _key(resolve(LLMContext(sched_policy="owner", sched_owner_id="u1", pinned_credential_id=mine, **base))) == A_KEY
    # ghim key của NGƯỜI KHÁC → từ chối
    r = resolve(LLMContext(sched_policy="owner", sched_owner_id="u1", pinned_credential_id=theirs, **base))
    assert r.code == AI_CRED_FORBIDDEN
    # chủ không có key → KHÔNG rơi sang org
    r = resolve(LLMContext(sched_policy="owner", sched_owner_id="u3", **base))
    assert r.code == AI_NO_CREDENTIAL
    # owner nhưng không có chủ
    assert resolve(LLMContext(sched_policy="owner", sched_owner_id=None, **base)).code == AI_NO_CREDENTIAL
    # org / local_only
    assert _key(resolve(LLMContext(sched_policy="org", **base))) == ORG_KEY
    assert resolve(LLMContext(sched_policy="local_only", **base)).code == AI_NO_CREDENTIAL


def test_system_job_owner_policy_respects_byok_off_and_revocation(env):
    mine = _mk(env, "u1")
    base = dict(feature="triage", user_id=None, job_kind="schedule", sched_policy="owner", sched_owner_id="u1")
    creds.revoke(env, mine, actor="admin")
    env.commit()
    assert resolve(LLMContext(**base)).code == AI_NO_CREDENTIAL
    _mk(env, "u1", label="n")
    _policy(byok="off")
    assert resolve(LLMContext(**base)).code == AI_NO_CREDENTIAL


def test_global_scheduled_jobs_credential_policy(env):
    _policy(scheduled_jobs_credential="local_only")
    assert resolve(_ctx(None, "triage")).code == AI_NO_CREDENTIAL
    _policy(scheduled_jobs_credential="org")
    assert _key(resolve(_ctx(None, "triage"))) == ORG_KEY


def test_schedule_pin_and_pin_for_user(env):
    from api.services.llm_resolver import pin_for_user, schedule_pin
    d = _mk(env, "u1")
    assert pin_for_user("u1") == d and pin_for_user("u2") is None and pin_for_user(None) is None
    assert schedule_pin("u1", "owner") == ("owner", "u1", d)
    assert schedule_pin("u1", "org") == ("org", None, None)
    assert schedule_pin("u1", "inherit") == ("org", None, None)
    assert schedule_pin("u1", None)[0] == "org"
    _policy(byok="off")
    assert pin_for_user("u1") is None
    _policy(byok="allowed", scheduled_jobs_credential="owner")
    assert schedule_pin("u1", "inherit")[:2] == ("owner", "u1")


def test_pin_for_user_includes_org_row_only_when_policy_allows(env):
    from api.services import ai_credentials
    from api.services.llm_resolver import pin_for_user
    ai_credentials.migrate_org_config(env)
    org_id = __import__("api.services.ai_config", fromlist=["x"]).load_config().get("org_credential_id")
    assert pin_for_user("u1", include_org=True) == org_id and pin_for_user("u1") is None
    _policy(byok="required")
    assert pin_for_user("u1", include_org=True) is None
    _policy(byok="allowed", fallback_to_org=False)
    assert pin_for_user("u1", include_org=True) is None


# ── Meter: kiểm trước mỗi lần gọi + usage event ──────────────────────────────
def _meter(uid="u1", feature="reanalyze", **kw):
    r = resolve(_ctx(uid, feature, **kw))
    assert isinstance(r, Cloud), r
    return ai_usage.meter_for(r), r


def test_meter_blocks_after_revoke_mid_job_and_never_switches_key(env):
    cid = _mk(env, "u1")
    m, route = _meter("u1", pinned_credential_id=cid)
    m.pre()                                                            # còn hiệu lực
    creds.revoke(env, cid, actor="admin")
    env.commit()
    with pytest.raises(RouteRefused) as e:
        m.pre()
    assert e.value.code == AI_CRED_REVOKED
    ev = env.query(AiUsageEvent).order_by(AiUsageEvent.ts.desc()).first()
    assert ev.outcome == "refused" and ev.credential_id == cid and ev.error_code == AI_CRED_REVOKED


def test_meter_blocks_when_policy_disallows_or_byok_turns_off(env):
    cid = _mk(env, "u1")
    m, _ = _meter("u1")
    _policy(allowed=["openai:*"])
    with pytest.raises(RouteRefused):
        m.pre()
    _policy(allowed=[], byok="off")
    with pytest.raises(RouteRefused):
        m.pre()


def test_meter_quota_and_rpm_for_org_key_only(env):
    _policy(org_quota={"usd_per_user_month": 1, "rpm_per_user": 2})
    m, _ = _meter("u1")
    m.pre()
    m.pre()
    with pytest.raises(RouteRefused) as e:
        m.pre()
    assert e.value.code == "AI_RATE_LIMIT"
    ai_usage.reset_rpm()
    _spend(env, "u1", 2.0)
    with pytest.raises(RouteRefused) as e:
        m.pre()
    assert e.value.code == AI_QUOTA
    assert env.query(AiUsageEvent).filter_by(outcome="quota_blocked").count() == 1
    # key riêng: hạn mức org không áp, chỉ rpm riêng
    _mk(env, "u1")
    m2, r2 = _meter("u1")
    assert r2.credential.scope == "user"
    for _ in range(5):
        m2.pre()
    _policy(user_quota_own_keys={"rpm_per_user": 2})
    ai_usage.reset_rpm()
    m2.pre(); m2.pre()
    with pytest.raises(RouteRefused):
        m2.pre()


def test_system_job_meter_has_no_per_user_limits(env):
    _policy(org_quota={"usd_per_user_month": 1, "rpm_per_user": 1})
    m, r = _meter(None, "triage")
    for _ in range(5):
        m.pre()


def test_usage_event_has_credential_id_scope_and_no_secret_fields(env):
    cid = _mk(env, "u1")
    m, route = _meter("u1", pinned_credential_id=cid)

    class U:
        input_tokens, output_tokens, cache_read_input_tokens, cache_creation_input_tokens = 1000, 500, 0, 0

    class Raw:
        usage = U()
    m.post(Raw())
    ev = env.query(AiUsageEvent).one()
    assert (ev.user_id, ev.credential_id, ev.credential_scope, ev.provider, ev.feature, ev.outcome) == \
           ("u1", cid, "user", "anthropic", "reanalyze", "ok")
    assert ev.tokens_in == 1000 and ev.tokens_out == 500 and ev.est_cost_usd > 0
    cols = {c.name for c in AiUsageEvent.__table__.columns}
    assert not [c for c in cols if any(w in c for w in ("secret", "key", "hint", "token_"))]
    blob = json.dumps({c: str(getattr(ev, c)) for c in cols})
    assert A_KEY not in blob and "…aaA1" not in blob and "aaA1" not in blob
    assert env.get(AiCredential, cid).last_used_at is not None


def test_est_cost_unknown_model_is_conservative_not_free():
    from api.services.ai_prices import est_cost_usd
    assert est_cost_usd("totally-unknown-model", 1_000_000, 0) >= 5.0
    assert est_cost_usd("anthropic.claude-opus-5-5-v1:0", 1_000_000, 0) == pytest.approx(4.0)


# ── Co-work (A1, §4.11) ──────────────────────────────────────────────────────
def _cw(uid="u1", **kw):
    return LLMContext(feature="coworker", user_id=uid, job_kind="coworker_conversation", needs_tools=True, **kw)


def _tools_ok(provider="anthropic", model="claude-opus-5-5"):
    ai_policy.record_cloud_probe(provider, model, True)


@pytest.mark.parametrize("mode,row,expect_cloud", [
    ("local_only", "local", False), ("local_only", "cloud", False),
    ("hybrid", "local", False), ("hybrid", "cloud", True),
    ("cloud_only", "local", True), ("cloud_only", "cloud", True),
])
def test_coworker_routing_matrix(env, mode, row, expect_cloud):
    _cfg(mode=mode, hybrid={"tasks": {"coworker": row}})
    _tools_ok()
    r = resolve(_cw())
    assert isinstance(r, Cloud if expect_cloud else LocalOllama)


def test_coworker_default_row_is_local_and_validated(env):
    from api.services import ai_config
    assert ai_config.load_config()["hybrid"]["tasks"]["coworker"] == "local"
    with pytest.raises(ValueError):
        _cfg(hybrid={"tasks": {"coworker": "everywhere"}})


def test_coworker_cloud_credential_order_and_refusals(env):
    _tools_ok()
    # không key riêng → org
    assert _key(resolve(_cw())) == ORG_KEY
    _mk(env, "u1")
    assert _key(resolve(_cw())) == A_KEY                              # user default → org
    assert _key(resolve(_cw("u2"))) == ORG_KEY
    _policy(fallback_to_org=False)
    assert resolve(_cw("u2")).code == AI_NO_CREDENTIAL
    _policy(fallback_to_org=True, allowed=["openai:*"])
    assert resolve(_cw("u2")).code == AI_NOT_ALLOWED
    _policy(allowed=[], org_quota={"usd_per_user_month": 1, "rpm_per_user": None})
    _spend(env, "u2", 5)
    assert resolve(_cw("u2")).code == AI_QUOTA


def test_coworker_cloud_requires_tool_probe(env):
    r = resolve(_cw())
    assert isinstance(r, Refuse) and r.code == AI_CLOUD_NO_TOOLS      # chưa probe = chưa biết
    ai_policy.record_cloud_probe("anthropic", "claude-opus-5-5", False)
    assert resolve(_cw()).code == AI_CLOUD_NO_TOOLS
    _tools_ok()
    assert isinstance(resolve(_cw()), Cloud)


def test_coworker_pinned_local_stays_local_after_settings_go_cloud(env):
    _tools_ok()
    _cfg(mode="cloud_only")
    assert isinstance(resolve(_cw(pinned_route_kind="local")), LocalOllama)


def test_coworker_pinned_cloud_refused_not_switched_when_settings_go_local(env):
    _tools_ok()
    cid = _mk(env, "u1")
    _cfg(mode="local_only")
    r = resolve(_cw(pinned_route_kind="cloud", pinned_credential_id=cid))
    assert isinstance(r, Refuse) and r.code == AI_ROUTE_CHANGED


def test_coworker_pinned_cloud_not_replaced_by_org_on_revoke_or_quota(env):
    _tools_ok()
    cid = _mk(env, "u1")
    ctx = _cw(pinned_route_kind="cloud", pinned_credential_id=cid)
    assert _key(resolve(ctx)) == A_KEY
    creds.delete(env, cid, actor="u1")
    env.commit()
    assert resolve(ctx).code == AI_CRED_REVOKED                       # user key không bị thay bằng org key giữa hội thoại
    # pinned org + quota hết → AI_QUOTA, không đổi sang local
    from api.services import ai_credentials
    ai_credentials.migrate_org_config(env)
    org_id = __import__("api.services.ai_config", fromlist=["x"]).load_config().get("org_credential_id")
    _policy(org_quota={"usd_per_user_month": 1, "rpm_per_user": None})
    _spend(env, "u1", 9)
    assert resolve(_cw(pinned_route_kind="cloud", pinned_credential_id=org_id)).code == AI_QUOTA


def test_coworker_no_silent_cloud_when_local_or_default_hybrid(env):
    """Local / Hybrid mặc định: zero route cloud dù có key riêng + org."""
    _tools_ok()
    _mk(env, "u1")
    for mode in ("local_only", "hybrid"):
        _cfg(mode=mode)
        for _ in range(3):
            assert isinstance(resolve(_cw()), LocalOllama)


def test_coworker_backend_refuses_cloud_until_pr3b_and_never_runs_local_instead(env):
    from api.routes import coworker_agent
    _tools_ok()
    with pytest.raises(RouteRefused) as e:
        coworker_agent._backend("c1", user_id="u1")
    assert e.value.code == "AI_COWORKER_CLOUD_UNAVAILABLE"
    _cfg(mode="local_only")
    assert coworker_agent._backend("c1", user_id="u1").__class__.__name__ == "LocalJsonBackend"
    _cfg(mode="cloud_only", hybrid={"tasks": {"coworker": "local"}})
    with pytest.raises(RouteRefused) as e:
        coworker_agent._backend("c1", user_id="u1", pinned_route_kind="cloud")
    assert e.value.code == "AI_COWORKER_CLOUD_UNAVAILABLE"


# ── resolver không làm rò secret ─────────────────────────────────────────────
def test_routes_repr_and_ctx_never_contain_keys(env):
    d = _mk(env, "u1")
    r = resolve(_ctx("u1", pinned_credential_id=d))
    for blob in (repr(r), str(r), repr(r.ctx), repr(r.credential)):
        assert A_KEY not in blob and "AAAAAAAAAAAAAAAA" not in blob
    import copy
    import pickle
    for fn in (pickle.dumps, copy.deepcopy, json.dumps):
        with pytest.raises(Exception):
            fn(r.credential)
