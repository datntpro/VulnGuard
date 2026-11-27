"""[AI PR-2] Credential store + crypto: owner-bound envelope, no plaintext getters, org migration, log filter."""
import copy
import importlib
import json
import logging
import pickle

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

KEY = "sk-ant-api03-SECRETSECRETSECRET-9fA1"


@pytest.fixture
def db():
    from api.database import Base
    from api import ai_cred_models  # noqa: F401
    from sqlalchemy.pool import StaticPool
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng, tables=[ai_cred_models.AiCredential.__table__, ai_cred_models.AiUsageEvent.__table__])
    sm = sessionmaker(bind=eng)
    s = sm()
    s._factory = sm
    yield s
    s.close()


@pytest.fixture
def svc():
    from api.services import ai_credentials
    return ai_credentials


@pytest.fixture
def ai(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_CONFIG_FILE", str(tmp_path / "ai.json"))
    from api.services import ai_config
    importlib.reload(ai_config)
    return ai_config


def _ctx(uid="u1", **kw):
    from api.services.llm_resolver import LLMContext
    return LLMContext(feature="pentest", user_id=uid, **kw)


def _mk(svc, db, uid="u1", provider="anthropic", label="a", secret=KEY, **kw):
    m = svc.create(db, scope="user", owner_user_id=uid, provider=provider, label=label, secret=secret,
                   created_by=uid, **kw)
    db.commit()
    return m["id"]


# ── round-trip / no plaintext ─────────────────────────────────────────────────
def test_round_trip_and_hint(svc, db):
    cid = _mk(svc, db)
    cred = svc.open_for_call(db, cid, _ctx())
    from api.services.llm_resolver import _build_cloud_client
    # secret chỉ giải mã khi dựng client (section → get_api_key)
    from api.services.ai_config import get_api_key
    assert get_api_key("anthropic", cred._cfg()) == KEY
    assert cred.provider == "anthropic" and cred.scope == "user"
    meta = svc.list_meta(db, owner_user_id="u1")[0]
    assert meta["key_hint"] == "…9fA1" and "secret_enc" not in meta
    assert KEY not in json.dumps(meta, default=str)


def test_secret_at_rest_is_not_plaintext(svc, db):
    cid = _mk(svc, db)
    raw = db.execute(text("select secret_enc from ai_credentials where id=:i"), {"i": cid}).scalar()
    assert KEY not in raw and "SECRETSECRET" not in raw


def test_no_plaintext_getter_in_public_api(svc):
    names = [n for n in dir(svc) if not n.startswith("_")]
    assert not [n for n in names if n.startswith(("get_secret", "decrypt", "reveal", "get_key"))]


def test_resolved_credential_repr_str_json_pickle_never_contain_key(svc, db):
    cred = svc.open_for_call(db, _mk(svc, db), _ctx())
    for out in (repr(cred), str(cred), f"{cred}", repr({"c": cred}), repr([cred])):
        assert KEY not in out and "SECRETSECRET" not in out
    assert "9fA1" in repr(cred) and "anthropic" in repr(cred)
    with pytest.raises(TypeError):
        json.dumps({"c": cred})
    for fn in (pickle.dumps, copy.copy, copy.deepcopy):
        with pytest.raises(TypeError):
            fn(cred)


# ── owner-bound envelope ──────────────────────────────────────────────────────
def test_swapped_secret_enc_between_rows_is_refused(svc, db):
    a = _mk(svc, db, uid="u1", label="a")
    b = _mk(svc, db, uid="u2", label="b", secret="sk-ant-api03-OTHEROTHEROTHER-zzzz")
    ea = db.execute(text("select secret_enc from ai_credentials where id=:i"), {"i": a}).scalar()
    db.execute(text("update ai_credentials set secret_enc=:e where id=:i"), {"e": ea, "i": b})
    db.commit()
    with pytest.raises(svc.CredentialError) as e:
        svc.open_for_call(db, b, _ctx("u2"))
    assert e.value.code == "AI_CRED_ENVELOPE_MISMATCH"


def test_row_owner_or_provider_tampered_is_refused(svc, db):
    cid = _mk(svc, db, uid="u1")
    db.execute(text("update ai_credentials set owner_user_id='u2' where id=:i"), {"i": cid})
    db.commit()
    with pytest.raises(svc.CredentialError):
        svc.open_for_call(db, cid, _ctx("u2"))
    db.execute(text("update ai_credentials set owner_user_id='u1', provider='openai' where id=:i"), {"i": cid})
    db.commit()
    with pytest.raises(svc.CredentialError):
        svc.open_for_call(db, cid, _ctx("u1"))


def test_wrong_owner_ctx_refused(svc, db):
    from api.services.llm_resolver import RouteRefused
    cid = _mk(svc, db, uid="u1")
    with pytest.raises(RouteRefused) as e:
        svc.open_for_call(db, cid, _ctx("u2"))
    assert e.value.code == "AI_CRED_FORBIDDEN"
    with pytest.raises(RouteRefused):
        svc.open_for_call(db, cid, _ctx(None))           # job hệ thống không dùng key của user


def test_garbage_and_wrong_key_fail_closed(svc, db, monkeypatch):
    cid = _mk(svc, db)
    db.execute(text("update ai_credentials set secret_enc='not-a-token' where id=:i"), {"i": cid})
    db.commit()
    with pytest.raises(svc.CredentialError) as e:
        svc.open_for_call(db, cid, _ctx())
    assert e.value.code == "AI_CRED_DECRYPT_FAILED"


def test_create_rejects_bad_scope_owner(svc, db):
    with pytest.raises(svc.CredentialError):
        svc.create(db, scope="org", owner_user_id="u1", provider="anthropic", label="x", secret=KEY)
    with pytest.raises(svc.CredentialError):
        svc.create(db, scope="user", owner_user_id=None, provider="anthropic", label="x", secret=KEY)


def test_key_rotation_via_previous_secret(svc, db, monkeypatch):
    from api import security
    cid = _mk(svc, db)
    old = security.get_secret_key()
    monkeypatch.setattr(security, "_secret_cache", b"brand-new-secret-key-xxxxxxxxxxxxxxxxxxxxxxxx")
    with pytest.raises(svc.CredentialError):
        svc.open_for_call(db, cid, _ctx())
    monkeypatch.setenv("VULNGUARD_SECRET_KEY_PREVIOUS", old.decode())
    assert svc.reencrypt_all(db) == 1
    monkeypatch.delenv("VULNGUARD_SECRET_KEY_PREVIOUS")
    svc.open_for_call(db, cid, _ctx())                    # đọc được chỉ với khoá mới


# ── rotate / revoke / disable / purge ─────────────────────────────────────────
def test_rotate_keeps_cid_and_swaps_secret(svc, db):
    from api.services.ai_config import get_api_key
    cid = _mk(svc, db)
    svc.rotate(db, cid, "sk-ant-api03-NEWNEWNEWNEWNEW-abcd")
    db.commit()
    cred = svc.open_for_call(db, cid, _ctx())
    assert get_api_key("anthropic", cred._cfg()).endswith("abcd")
    assert svc.list_meta(db)[0]["key_hint"] == "…abcd" and svc.list_meta(db)[0]["rotated_at"]


def test_delete_tombstones_and_fails_closed(svc, db):
    from api.services.llm_resolver import RouteRefused
    cid = _mk(svc, db)
    svc.delete(db, cid, actor="u1")
    db.commit()
    assert db.execute(text("select secret_enc, status from ai_credentials where id=:i"), {"i": cid}).one() == (None, "revoked")
    with pytest.raises(RouteRefused) as e:
        svc.open_for_call(db, cid, _ctx())
    assert e.value.code == "AI_CRED_REVOKED"
    with pytest.raises(svc.CredentialError):
        svc.rotate(db, cid, "x" * 20)


def test_disable_for_user_and_purge_after_30_days(svc, db):
    from datetime import datetime, timedelta
    a, b = _mk(svc, db, uid="u1", label="a"), _mk(svc, db, uid="u2", label="b")
    assert svc.disable_for_user(db, "u1") == 1
    svc.revoke(db, b, actor="admin")
    db.commit()
    st = dict(db.execute(text("select id, status from ai_credentials")).all())
    assert st == {a: "disabled", b: "revoked"}
    assert svc.purge_expired(db) == 0                      # chưa đủ 30 ngày
    assert svc.purge_expired(db, now=datetime.utcnow() + timedelta(days=31)) == 2
    assert svc.list_meta(db) == []


def test_one_default_per_user(svc, db):
    from sqlalchemy.exc import IntegrityError
    _mk(svc, db, label="a", is_default=True)
    with pytest.raises(IntegrityError):
        _mk(svc, db, label="b", is_default=True)
    db.rollback()
    _mk(svc, db, uid="u2", label="a", is_default=True)     # user khác thì được


def test_audit_log_has_no_key(svc, db, caplog):
    caplog.set_level(logging.INFO, logger="vulnguard.audit.ai")
    cid = _mk(svc, db)
    svc.rotate(db, cid, "sk-ant-api03-ROTATEDROTATED-wxyz")
    assert "ai_cred action=create" in caplog.text and "ai_cred action=rotate" in caplog.text
    assert "SECRET" not in caplog.text and "ROTATED" not in caplog.text and KEY not in caplog.text


# ── migration of org config (§4.10) ───────────────────────────────────────────
def _org_cfg(ai, **extra):
    base = {"provider": "anthropic", "anthropic": {"api_key": KEY},
            "openai": {"api_key": "sk-proj-OPENAIOPENAIOPENAIOPENAI-qwer", "base_url": "https://gw.example/v1"}}
    base.update(extra)
    return ai.validate_and_save(base)


def test_migration_creates_org_rows_idempotent_and_keeps_old_fields(svc, db, ai):
    from api.services.ai_config import get_api_key
    _org_cfg(ai)
    assert svc.migrate_org_config(db) == 2
    rows = {r["provider"]: r for r in svc.list_meta(db, scope="org")}
    assert set(rows) == {"anthropic", "openai"}
    assert rows["anthropic"]["key_hint"] == "…9fA1" and rows["anthropic"]["owner_user_id"] is None
    assert rows["openai"]["params"]["base_url"] == "https://gw.example/v1"
    cfg = ai.load_config()
    assert cfg["migrations"]["creds_v1"] is True and cfg["org_credential_id"] == rows["anthropic"]["id"]
    assert get_api_key("anthropic", cfg) == KEY            # api_key_enc cũ còn nguyên (rollback)
    assert svc.migrate_org_config(db) == 0                  # idempotent
    assert len(svc.list_meta(db)) == 2
    # đường org vẫn chạy sau migrate: mở credential đã migrate + resolver cũ
    from api.services.llm_resolver import LLMContext, resolve, Cloud
    cred = svc.open_for_call(db, rows["anthropic"]["id"], LLMContext(feature="pentest", user_id="anyone"))
    assert get_api_key("anthropic", cred._cfg()) == KEY and cred.scope == "org"
    assert isinstance(resolve(LLMContext(feature="pentest")), Cloud)


def test_migration_keyless_selected_provider(svc, db, ai):
    ai.validate_and_save({"provider": "bedrock", "bedrock": {"auth_mode": "aws_chain", "region": "ap-southeast-1"}})
    assert svc.migrate_org_config(db) == 1
    r = svc.list_meta(db, scope="org")[0]
    assert r["provider"] == "bedrock" and not r["has_secret"] and r["params"]["region"] == "ap-southeast-1"
    assert ai.load_config()["org_credential_id"] == r["id"]


def test_migration_rollback_on_failure_leaves_old_config_usable(svc, db, ai, monkeypatch):
    from api.services.ai_config import get_api_key
    _org_cfg(ai)
    real, calls = svc.create, {"n": 0}

    def flaky(*a, **kw):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("disk full")
        return real(*a, **kw)
    monkeypatch.setattr(svc, "create", flaky)
    with pytest.raises(RuntimeError):
        svc.migrate_org_config(db)
    assert svc.list_meta(db) == []                          # hàng đầu đã rollback
    cfg = ai.load_config()
    assert not (cfg.get("migrations") or {}).get("creds_v1") and "org_credential_id" not in cfg
    assert get_api_key("anthropic", cfg) == KEY             # cấu hình cũ vẫn đọc được
    monkeypatch.setattr(svc, "create", real)
    assert svc.migrate_org_config(db) == 2                  # chạy lại sau khi sửa lỗi


def test_migration_empty_config_sets_flag_only(svc, db, ai):
    assert svc.migrate_org_config(db) == 0
    assert ai.load_config()["migrations"]["creds_v1"] is True and svc.list_meta(db) == []


def test_validate_and_save_preserves_migration_keys(svc, db, ai):
    _org_cfg(ai)
    svc.migrate_org_config(db)
    ai.validate_and_save({"mode": "hybrid"})
    cfg = ai.load_config()
    assert cfg["migrations"]["creds_v1"] and cfg["org_credential_id"]


# ── log filter ────────────────────────────────────────────────────────────────
SECRETS = [
    "sk-ant-api03-AAAAAAAAAAAAAAAAAAAA", "sk-" + "a" * 30, "sk-or-v1-" + "b" * 30,
    "ABSK" + "c" * 30, "ksk_" + "d" * 24, "AIza" + "e" * 35, "ghp_" + "f" * 36, "github_pat_" + "g" * 30,
    "AKIA" + "H" * 16,
]


@pytest.fixture
def masked_log():
    from api import log_redaction
    log_redaction.install()
    lg = logging.getLogger("vg.test.mask")
    lg.setLevel(logging.DEBUG)
    return lg


@pytest.mark.parametrize("secret", SECRETS)
def test_log_filter_masks_every_pattern(masked_log, caplog, secret):
    caplog.set_level(logging.DEBUG)
    masked_log.info("calling provider with %s ok", secret)
    masked_log.warning(f"fstring {secret}")
    assert secret not in caplog.text and "REDACTED" in caplog.text


def test_log_filter_masks_headers_query_and_exceptions(masked_log, caplog):
    caplog.set_level(logging.DEBUG)
    masked_log.debug("hdr Authorization: Bearer abcdefghijklmnop1234 x-api-key: zzzzzzzzzzzz9999 GET /v1?key=SEKRETQS12345&a=1")
    try:
        raise ValueError("boom sk-ant-api03-TRACEBACKSECRET12345")
    except ValueError:
        masked_log.exception("failed")
    for leak in ("abcdefghijklmnop1234", "zzzzzzzzzzzz9999", "SEKRETQS12345", "TRACEBACKSECRET12345"):
        assert leak not in caplog.text
    assert "Traceback" in caplog.text


def test_log_filter_masks_azure_key_and_gcp_sa(masked_log, caplog):
    caplog.set_level(logging.DEBUG)
    masked_log.info('api-key: 0123456789abcdef0123456789abcdef and "private_key_id": "%s" svc@proj.iam.gserviceaccount.com', "a" * 40)
    assert "0123456789abcdef0123456789abcdef" not in caplog.text and "a" * 40 not in caplog.text
    assert "gserviceaccount" not in caplog.text


def test_sdk_debug_guard_only_in_production(monkeypatch):
    from api import log_redaction
    monkeypatch.setenv("ANTHROPIC_LOG", "debug")
    log_redaction.check_sdk_debug_env("development")        # không raise
    with pytest.raises(RuntimeError):
        log_redaction.check_sdk_debug_env("production")
    monkeypatch.setenv("ANTHROPIC_LOG", "info")
    monkeypatch.setenv("OPENAI_LOG", "DEBUG")
    with pytest.raises(RuntimeError):
        log_redaction.check_sdk_debug_env("production")


def test_prompt_redaction_covers_new_patterns():
    from scanner.cloud_ai import redact
    out = redact('api-key: 0123456789abcdef0123456789abcdef  "private_key_id": "' + "b" * 40 + '"')
    assert "0123456789abcdef0123456789abcdef" not in out and "b" * 40 not in out


def test_startup_does_not_raise_on_migration_error(svc, monkeypatch):
    monkeypatch.setattr(svc, "migrate_org_config", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    svc.startup()


# ── verify round (PR114): B1 scope flip, B2 log patterns, S1 params, S2 replay, S3 sync ──────────────
def _sql(db, q, **kw):
    db.execute(text(q), kw)
    db.commit()


def test_b1_scope_flip_user_to_org_refused(svc, db):
    from api.services.llm_resolver import RouteRefused
    cid = _mk(svc, db, uid="u1")
    _sql(db, "update ai_credentials set scope='org' where id=:i", i=cid)      # owner_user_id vẫn u1
    for who in ("u1", "attacker", None):
        with pytest.raises((svc.CredentialError, RouteRefused)):
            svc.open_for_call(db, cid, _ctx(who))
    _sql(db, "update ai_credentials set owner_user_id=NULL where id=:i", i=cid)  # lật cả owner
    with pytest.raises(svc.CredentialError) as e:
        svc.open_for_call(db, cid, _ctx("attacker"))
    assert e.value.code == "AI_CRED_ENVELOPE_MISMATCH"


def test_b1_org_row_cannot_be_created_from_user_path(svc, db):
    with pytest.raises(svc.CredentialError) as e:
        svc.create(db, scope="org", provider="anthropic", label="x", secret=KEY)
    assert e.value.code == "AI_CRED_FORBIDDEN"
    svc.create(db, scope="org", provider="anthropic", label="x", secret=KEY, admin_path=True)


def test_b1_org_row_flipped_to_user_refused(svc, db):
    m = svc.create(db, scope="org", provider="anthropic", label="o", secret=KEY, admin_path=True)
    db.commit()
    _sql(db, "update ai_credentials set scope='user', owner_user_id='u9' where id=:i", i=m["id"])
    with pytest.raises(svc.CredentialError):
        svc.open_for_call(db, m["id"], _ctx("u9"))


def test_s1_base_url_edit_refused_and_update_params_reseals(svc, db):
    cid = _mk(svc, db, provider="openai", params={"base_url": "https://gw.example/v1", "model": "gpt-4o"})
    _sql(db, "update ai_credentials set params=:p where id=:i",
         p=json.dumps({"base_url": "https://evil.example/v1", "model": "gpt-4o"}), i=cid)
    with pytest.raises(svc.CredentialError) as e:
        svc.open_for_call(db, cid, _ctx())
    assert e.value.code == "AI_CRED_ENVELOPE_MISMATCH"
    # đường hợp lệ: update_params (chủ đã mở được) re-seal → dùng được, và đổi model (không bị ràng buộc) không cần seal
    cid2 = _mk(svc, db, provider="openai", label="b", params={"base_url": "https://gw.example/v1"})
    svc.update_params(db, cid2, {"base_url": "https://gw2.example/v1"})
    db.commit()
    svc.open_for_call(db, cid2, _ctx())


def test_s2_old_ciphertext_replay_after_rotate_refused(svc, db):
    cid = _mk(svc, db)
    old = db.execute(text("select secret_enc from ai_credentials where id=:i"), {"i": cid}).scalar()
    svc.rotate(db, cid, "sk-ant-api03-NEWNEWNEWNEWNEW-abcd")
    db.commit()
    _sql(db, "update ai_credentials set secret_enc=:e where id=:i", e=old, i=cid)
    with pytest.raises(svc.CredentialError) as e:
        svc.open_for_call(db, cid, _ctx())
    assert e.value.code == "AI_CRED_ENVELOPE_MISMATCH"


def test_s2_revoked_row_cannot_be_resurrected(svc, db):
    cid = _mk(svc, db)
    old = db.execute(text("select secret_enc from ai_credentials where id=:i"), {"i": cid}).scalar()
    svc.delete(db, cid)
    db.commit()
    _sql(db, "update ai_credentials set secret_enc=:e, status='valid' where id=:i", e=old, i=cid)
    with pytest.raises(svc.CredentialError):
        svc.open_for_call(db, cid, _ctx())


def test_s3_legacy_save_syncs_org_row(svc, db, ai, monkeypatch):
    from api.services.ai_config import get_api_key
    monkeypatch.setattr("api.database.SessionLocal", db._factory)
    _org_cfg(ai)
    svc.migrate_org_config(db)
    new = "sk-ant-api03-ROTATEDVIALEGACY-wxyz"
    ai.validate_and_save({"anthropic": {"api_key": new, "model": "claude-x"}})
    row = [r for r in svc.list_meta(db, scope="org") if r["provider"] == "anthropic"][0]
    assert row["key_hint"] == "…wxyz" and row["params"]["model"] == "claude-x"
    cred = svc.open_for_call(db, row["id"], _ctx("anyone"))
    assert get_api_key("anthropic", cred._cfg()) == new
    ai.validate_and_save({"anthropic": {"clear_api_key": True}})
    row = [r for r in svc.list_meta(db, scope="org") if r["provider"] == "anthropic"][0]
    assert row["has_secret"] is False


def test_s3_skipped_provider_leaves_flag_unset(svc, db, ai, monkeypatch):
    _org_cfg(ai)
    import api.security as sec
    real = sec.decrypt_secret
    monkeypatch.setattr(sec, "decrypt_secret", lambda t: None if t else real(t))
    svc.migrate_org_config(db)
    assert not (ai.load_config().get("migrations") or {}).get("creds_v1")


POCS = [
    "openai sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
    "svc sk-svcacct-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
    "cfg api_key='Zk39fJQpw0aLmNcVb'",
    "cfg api_key=\"plainSecretValue99\"",
    "headers {'x-api-key': 'abc123DEF456ghi'}",
    "headers {'Authorization': 'Bearer abcdefgh12345678'}",
    "kwargs {'api_key': 'sk-proj-ZZZZZZZZZZZZZZZZZZZZZZZZ'}",
    "blob aB3dE5gH7jK9mN1pQ3sT5vX7zA9cD1fG3hJ5kL7mN",   # token entropy cao, không có tên gợi ý
]


@pytest.mark.parametrize("line", POCS)
def test_b2_log_pocs_masked(masked_log, caplog, line):
    caplog.set_level(logging.DEBUG)
    masked_log.info(line)
    out = caplog.text
    for leak in ("AbCdEfGhIjKl", "Zk39fJQpw0aLmNcVb", "plainSecretValue99", "abc123DEF456ghi",
                 "abcdefgh12345678", "ZZZZZZZZZZZZ", "aB3dE5gH7jK9"):
        assert leak not in out


def test_b2_no_false_positive_on_hashes_and_plain_text(masked_log, caplog):
    caplog.set_level(logging.DEBUG)
    masked_log.info("sha %s scan done in 12s user=alice", "a" * 40)
    assert "a" * 40 in caplog.text and "scan done" in caplog.text
