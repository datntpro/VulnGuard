"""[AI PR-2] Kho credential AI: Fernet + sub-key riêng + envelope gắn chủ, KHÔNG có getter plaintext.

  * Sub-key: SHA-256("vulnguard-ai-cred:v1:" + secret_key) — tách khỏi hộp secret chung. `MultiFernet([mới, cũ…])`
    để xoay khoá = re-encrypt (`reencrypt_all`). Khoá cũ lấy từ env `VULNGUARD_SECRET_KEY_PREVIOUS` (tuỳ chọn).
  * Envelope: Fernet mã hoá JSON {"v":1,"cid","owner","p","s"}; khi giải mã ASSERT cid/owner/provider khớp hàng →
    ciphertext bị hoán đổi giữa hàng (DB bị sửa / bug copy) fail-closed.
  * API công khai chỉ có create/rotate/revoke/disable/purge/list_meta + `open_for_call()` (giải mã đúng lúc, trả
    ResolvedCredential che repr, không serialise được). Không hàm nào trả plaintext cho caller.
  * Migration khởi động (§4.10) org config → ai_credentials, idempotent (cờ `migrations.creds_v1`), giữ nguyên
    `api_key_enc` cũ một release để rollback; lỗi giữa chừng → rollback toàn bộ, cờ không bật.
PR-2 KHÔNG đổi precedence của resolver (vẫn org-only đọc ai_config) và KHÔNG có endpoint người dùng.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

logger = logging.getLogger(__name__)
audit = logging.getLogger("vulnguard.audit.ai")

ENVELOPE_VERSION = 1
ORG_OWNER = "org"
PURGE_AFTER_DAYS = 30
_KEYLESS_ANTHROPIC = ("wif", "environment")
_KEYLESS_BEDROCK = ("aws_chain", "profile")


class CredentialError(RuntimeError):
    """Lỗi credential store. Thông điệp không chứa secret."""
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


# ── Crypto ───────────────────────────────────────────────
def _derive(secret: bytes) -> Fernet:
    digest = hashlib.sha256(b"vulnguard-ai-cred:v1:" + secret).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def _box() -> MultiFernet:
    from api.security import get_secret_key
    keys = [_derive(get_secret_key())]
    prev = (os.environ.get("VULNGUARD_SECRET_KEY_PREVIOUS") or "").strip()
    if prev:
        keys.append(_derive(prev.encode()))
    return MultiFernet(keys)


def _owner_tag(owner_user_id: Optional[str]) -> str:
    return owner_user_id or ORG_OWNER


# Tham số ảnh hưởng NƠI key được gửi tới → ràng buộc toàn vẹn vào envelope (sửa DB không đổi được host)
_BOUND_PARAMS = ("base_url", "region", "deployment", "project", "location", "api_version", "endpoint", "aws_profile")


def params_digest(params: Optional[Dict[str, Any]]) -> str:
    sub = {k: (params or {}).get(k) for k in _BOUND_PARAMS if (params or {}).get(k) not in (None, "")}
    return hashlib.sha256(json.dumps(sub, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _seal(row_id: str, scope: str, owner_user_id: Optional[str], provider: str, gen: int,
          params: Optional[Dict[str, Any]], secret: str) -> str:
    env = {"v": ENVELOPE_VERSION, "cid": row_id, "sc": scope, "owner": _owner_tag(owner_user_id), "p": provider,
           "gen": gen, "pd": params_digest(params), "s": secret}
    return _box().encrypt(json.dumps(env).encode()).decode()


def _check_shape(row) -> None:
    """scope ⇔ owner: org không có chủ, user bắt buộc có chủ (chặn lật scope ngay cả khi envelope khớp)."""
    if row.scope not in ("user", "org") or (row.scope == "org") != (row.owner_user_id is None):
        logger.error("[ai-cred] hàng %s có scope/owner không hợp lệ — từ chối", row.id)
        raise CredentialError("AI_CRED_ENVELOPE_MISMATCH")


def _open_envelope(row) -> str:
    """Giải mã + ASSERT envelope khớp hàng (cid, scope, owner, provider, generation, params). Fail-closed."""
    if not row.secret_enc:
        raise CredentialError("AI_CRED_NO_SECRET")
    _check_shape(row)
    try:
        env = json.loads(_box().decrypt(row.secret_enc.encode()).decode())
    except (InvalidToken, ValueError, UnicodeError):
        logger.error("[ai-cred] không giải mã được credential %s (secret key đã đổi?)", row.id)
        raise CredentialError("AI_CRED_DECRYPT_FAILED") from None
    if (not isinstance(env, dict) or env.get("v") != ENVELOPE_VERSION or env.get("cid") != row.id
            or env.get("sc") != row.scope or env.get("owner") != _owner_tag(row.owner_user_id)
            or env.get("p") != row.provider or env.get("gen") != row.secret_gen
            or env.get("pd") != params_digest(row.params) or not isinstance(env.get("s"), str)):
        logger.error("[ai-cred] envelope không khớp hàng %s — từ chối (hoán đổi/replay/sửa params?)", row.id)
        raise CredentialError("AI_CRED_ENVELOPE_MISMATCH")
    return env["s"]


def _hint(secret: Optional[str]) -> str:
    if not secret:
        return ""
    return "…" + secret[-4:] if len(secret) >= 8 else "…"


def reencrypt_all(db) -> int:
    """Xoay khoá: giải mã bằng MultiFernet (mới + cũ) rồi mã hoá lại bằng khoá mới. Trả số hàng đã xử lý."""
    from api.ai_cred_models import AiCredential
    n = 0
    for row in db.query(AiCredential).filter(AiCredential.secret_enc.isnot(None)).all():
        row.secret_enc = _box().rotate(row.secret_enc.encode()).decode()
        n += 1
    db.commit()
    return n


# ── Repository ───────────────────────────────────────────
def _meta(row) -> Dict[str, Any]:
    """Metadata an toàn — KHÔNG secret_enc."""
    return {
        "id": row.id, "scope": row.scope, "owner_user_id": row.owner_user_id, "provider": row.provider,
        "label": row.label, "auth_mode": row.auth_mode, "key_hint": row.key_hint,
        "params": dict(row.params or {}), "is_default": bool(row.is_default), "status": row.status,
        "has_secret": bool(row.secret_enc), "last_validated_at": row.last_validated_at,
        "last_error_code": row.last_error_code, "last_used_at": row.last_used_at,
        "created_by": row.created_by, "created_at": row.created_at, "rotated_at": row.rotated_at,
    }


def _get(db, cred_id: str):
    from api.ai_cred_models import AiCredential
    row = db.get(AiCredential, cred_id)
    if row is None:
        raise CredentialError("AI_CRED_NOT_FOUND")
    return row


def _audit(action: str, actor: Optional[str], row, outcome: str = "ok") -> None:
    audit.info("ai_cred action=%s actor=%s owner=%s cred=%s provider=%s hint=%s outcome=%s",
               action, actor or "system", _owner_tag(row.owner_user_id), row.id, row.provider, row.key_hint, outcome)


def create(db, *, scope: str, provider: str, label: str, auth_mode: str = "api_key",
           secret: Optional[str] = None, owner_user_id: Optional[str] = None,
           params: Optional[Dict[str, Any]] = None, is_default: bool = False,
           created_by: Optional[str] = None, status: str = "unknown",
           admin_path: bool = False) -> Dict[str, Any]:
    """`admin_path=True` chỉ dành cho migration / đường ADMIN (PR-3): hàng scope='org' không tạo được từ đường user."""
    from api.ai_cred_models import AiCredential, PROVIDERS, SCOPES
    if scope not in SCOPES or provider not in PROVIDERS:
        raise CredentialError("AI_CRED_BAD_ARGUMENT")
    if (scope == "org") != (owner_user_id is None):
        raise CredentialError("AI_CRED_BAD_ARGUMENT")      # org ⇒ không chủ; user ⇒ bắt buộc có chủ
    if scope == "org" and not admin_path:
        raise CredentialError("AI_CRED_FORBIDDEN")
    cid = str(uuid.uuid4())
    params = dict(params or {})
    row = AiCredential(
        id=cid, scope=scope, owner_user_id=owner_user_id, provider=provider, label=label[:80],
        auth_mode=auth_mode, params=params, is_default=bool(is_default and owner_user_id),
        status=status, created_by=created_by, secret_gen=1,
        secret_enc=_seal(cid, scope, owner_user_id, provider, 1, params, secret) if secret else None,
        key_hint=_hint(secret))
    db.add(row)
    db.flush()
    _audit("create", created_by, row)
    return _meta(row)


def rotate(db, cred_id: str, new_secret: str, actor: Optional[str] = None) -> Dict[str, Any]:
    """Thay secret (cùng cid ⇒ job đã pin lấy secret mới ở lần gọi kế). Không cho xoay credential đã revoked."""
    if not new_secret:
        raise CredentialError("AI_CRED_BAD_ARGUMENT")
    row = _get(db, cred_id)
    if row.status in ("revoked", "disabled"):
        raise CredentialError("AI_CRED_REVOKED")
    _check_shape(row)
    row.secret_gen = (row.secret_gen or 1) + 1          # ciphertext cũ (gen cũ) không còn mở được
    row.secret_enc = _seal(row.id, row.scope, row.owner_user_id, row.provider, row.secret_gen, row.params, new_secret)
    row.key_hint = _hint(new_secret)
    row.rotated_at = datetime.utcnow()
    row.status, row.last_error_code = "unknown", None
    db.flush()
    _audit("rotate", actor, row)
    return _meta(row)


def _tombstone(db, cred_id: str, status: str, action: str, actor: Optional[str]) -> Dict[str, Any]:
    row = _get(db, cred_id)
    row.secret_enc = None            # xoá secret NGAY; hàng còn lại để audit/usage resolve id
    row.secret_gen = (row.secret_gen or 1) + 1   # đặt lại status + dán ciphertext cũ cũng không sống lại được
    row.status, row.is_default = status, False
    row.status_changed_at = datetime.utcnow()
    db.flush()
    _audit(action, actor, row)
    return _meta(row)


def delete(db, cred_id: str, actor: Optional[str] = None) -> Dict[str, Any]:
    """Chủ xoá: tombstone (status=revoked, secret_enc=NULL), hàng bị purge sau 30 ngày."""
    return _tombstone(db, cred_id, "revoked", "delete", actor)


def revoke(db, cred_id: str, actor: Optional[str] = None) -> Dict[str, Any]:
    """Admin thu hồi: giống delete nhưng ghi audit `revoke_by_admin`."""
    return _tombstone(db, cred_id, "revoked", "revoke_by_admin", actor)


def disable_for_user(db, user_id: str, actor: Optional[str] = None) -> int:
    """User bị vô hiệu hoá / hạ VIEWER → credential của họ `disabled` ngay (xoá secret), purge sau 30 ngày."""
    from api.ai_cred_models import AiCredential
    rows = db.query(AiCredential.id).filter(AiCredential.owner_user_id == user_id,
                                            AiCredential.status.notin_(("revoked", "disabled"))).all()
    for (cid,) in rows:
        _tombstone(db, cid, "disabled", "disable", actor)
    return len(rows)


def purge_expired(db, now: Optional[datetime] = None) -> int:
    """Xoá hẳn hàng revoked/disabled quá PURGE_AFTER_DAYS."""
    from api.ai_cred_models import AiCredential
    cutoff = (now or datetime.utcnow()) - timedelta(days=PURGE_AFTER_DAYS)
    q = db.query(AiCredential).filter(AiCredential.status.in_(("revoked", "disabled")),
                                      AiCredential.status_changed_at.isnot(None),
                                      AiCredential.status_changed_at < cutoff)
    n = q.delete(synchronize_session=False)
    db.flush()
    return n


def update_params(db, cred_id: str, params: Dict[str, Any], actor: Optional[str] = None) -> Dict[str, Any]:
    """Đổi params (vd base_url): mở envelope rồi RE-SEAL với digest mới. Không có secret → chỉ lưu params."""
    row = _get(db, cred_id)
    if row.status in ("revoked", "disabled"):
        raise CredentialError("AI_CRED_REVOKED")
    _check_shape(row)
    secret = _open_envelope(row) if row.secret_enc else None
    row.params = dict(params or {})
    if secret is not None:
        row.secret_gen = (row.secret_gen or 1) + 1
        row.secret_enc = _seal(row.id, row.scope, row.owner_user_id, row.provider, row.secret_gen, row.params, secret)
    db.flush()
    _audit("update_params", actor, row)
    return _meta(row)


_CODE_STATUS = {"VALID": "valid", "INVALID_KEY": "invalid", "NO_MODEL_ACCESS": "forbidden", "RATE_LIMITED": "rate_limited"}


def record_validation(db, cred_id: str, code: str, actor: Optional[str] = None) -> Dict[str, Any]:
    """Ghi kết quả test/validate (mã chuẩn hoá, KHÔNG văn bản provider). Không đụng credential đã thu hồi."""
    row = _get(db, cred_id)
    if row.status in ("revoked", "disabled"):
        return _meta(row)
    row.last_validated_at = datetime.utcnow()
    row.last_error_code = None if code == "VALID" else (code or "UNKNOWN")[:40]
    if code in _CODE_STATUS:                  # NETWORK/TIMEOUT/BAD_BASE_URL: không kết luận key hỏng → giữ status
        row.status = _CODE_STATUS[code]
    db.flush()
    _audit("test", actor, row, outcome=code or "UNKNOWN")
    return _meta(row)


def set_default(db, owner_user_id: str, cred_id: Optional[str]) -> None:
    """Đặt credential mặc định của user (hoặc bỏ mặc định nếu None). Tối đa MỘT (partial unique index)."""
    from api.ai_cred_models import AiCredential
    db.query(AiCredential).filter(AiCredential.owner_user_id == owner_user_id,
                                  AiCredential.is_default.is_(True)).update({"is_default": False})
    db.flush()
    if cred_id:
        row = _get(db, cred_id)
        if row.owner_user_id != owner_user_id or row.status in ("revoked", "disabled"):
            raise CredentialError("AI_CRED_FORBIDDEN")
        row.is_default = True
        db.flush()


def count_active(db, owner_user_id: str) -> int:
    from api.ai_cred_models import AiCredential
    return (db.query(AiCredential).filter(AiCredential.owner_user_id == owner_user_id,
                                          AiCredential.status.notin_(("revoked", "disabled"))).count())


def list_meta(db, *, owner_user_id: Optional[str] = None, scope: Optional[str] = None) -> List[Dict[str, Any]]:
    from api.ai_cred_models import AiCredential
    q = db.query(AiCredential)
    if scope:
        q = q.filter(AiCredential.scope == scope)
    if owner_user_id is not None:
        q = q.filter(AiCredential.owner_user_id == owner_user_id)
    return [_meta(r) for r in q.order_by(AiCredential.created_at, AiCredential.id).all()]


def open_for_call(db, cred_id: str, ctx):
    """DUY NHẤT đường lấy secret: giải mã đúng lúc → ResolvedCredential (không plaintext getter).
    Từ chối: revoked/disabled; credential của user khác; envelope không khớp. `ctx` là LLMContext."""
    from api.services.llm_resolver import ResolvedCredential, RouteRefused, AI_CRED_REVOKED, AI_CRED_FORBIDDEN
    row = _get(db, cred_id)
    if row.status in ("revoked", "disabled"):
        raise RouteRefused(AI_CRED_REVOKED, "ai.error.cred_revoked")
    _check_shape(row)
    if row.scope == "user" and (ctx is None or getattr(ctx, "user_id", None) != row.owner_user_id):
        raise RouteRefused(AI_CRED_FORBIDDEN, "ai.error.cred_forbidden")
    secret = _open_envelope(row) if row.secret_enc else None
    params = dict(row.params or {})
    section: Dict[str, Any] = dict(params)
    section["auth_mode"] = row.auth_mode
    if secret is not None:
        # giữ secret ở dạng mã hoá (hộp chung) trong section — ResolvedCredential chỉ giải mã khi dựng client
        from api.security import encrypt_secret
        section["api_key_enc"] = encrypt_secret(secret)
    row.last_used_at = datetime.utcnow()
    db.flush()
    return ResolvedCredential(row.provider, section, scope=row.scope, cid=row.id)


# ── Migration cấu hình org (§4.10) ───────────────────────
def _org_params(provider: str, sec: Dict[str, Any]) -> Dict[str, Any]:
    keys = {"anthropic": ("model", "wif"), "bedrock": ("model", "region", "aws_profile"),
            "openai": ("model", "base_url"), "openrouter": ("model",)}[provider]
    return {k: sec[k] for k in keys if k in sec and sec[k] not in (None, "")}


def _upsert_org(db, provider: str, sec: Dict[str, Any], selected: Optional[str]) -> Optional[str]:
    """Đồng bộ MỘT section provider của ai_config → hàng org. Trả id hàng, hoặc None nếu không có gì để lưu /
    không giải mã được key cũ (khi đó trả "SKIP" qua ngoại lệ không dùng — xem migrate: skipped đếm riêng)."""
    from api.ai_cred_models import AiCredential
    from api.security import decrypt_secret
    enc = sec.get("api_key_enc")
    auth_mode = sec.get("auth_mode") or "api_key"
    keyless = (provider == selected and
               ((provider == "anthropic" and auth_mode in _KEYLESS_ANTHROPIC) or
                (provider == "bedrock" and auth_mode in _KEYLESS_BEDROCK)))
    row = db.query(AiCredential).filter(AiCredential.scope == "org", AiCredential.provider == provider).first()
    if not enc and not keyless and row is None:
        return None
    plain = decrypt_secret(enc) if enc else None
    if enc and not plain:
        raise _Skip(provider)
    params = _org_params(provider, sec)
    if row is None:
        return create(db, scope="org", provider=provider, label=f"Org – {provider}", auth_mode=auth_mode,
                      secret=plain, params=params, created_by=None, admin_path=True)["id"]
    if row.status in ("revoked", "disabled"):
        return row.id                                   # admin đã thu hồi — không tự sống lại
    # một chiều legacy → hàng: cập nhật khi key / auth_mode / params đổi, hoặc key bị xoá
    cur = _open_envelope(row) if row.secret_enc else None
    if cur != plain or (row.params or {}) != params or row.auth_mode != auth_mode:
        row.auth_mode = auth_mode
        row.params = params
        row.secret_gen = (row.secret_gen or 1) + 1
        row.secret_enc = _seal(row.id, row.scope, None, provider, row.secret_gen, params, plain) if plain else None
        row.key_hint = _hint(plain)
        row.rotated_at = datetime.utcnow() if cur != plain else row.rotated_at
        db.flush()
        _audit("sync_from_config", None, row)
    return row.id


class _Skip(Exception):
    pass


def _sync(db, cfg: Dict[str, Any]) -> Dict[str, str]:
    from api.services import ai_config
    selected = cfg.get("provider")
    ids: Dict[str, str] = {}
    skipped = []
    for provider in ai_config.PROVIDERS:
        sec = cfg.get(provider)
        if not isinstance(sec, dict):
            continue
        try:
            rid = _upsert_org(db, provider, sec, selected)
        except _Skip:
            logger.error("[ai-cred] bỏ qua migrate %s: không giải mã được api_key_enc cũ", provider)
            skipped.append(provider)
            continue
        if rid:
            ids[provider] = rid
    ids["_skipped"] = ",".join(skipped)
    return ids


def _open_session(db):
    if db is not None:
        return db, False
    from api.database import SessionLocal
    return SessionLocal(), True


def migrate_org_config(db=None, cfg: Optional[Dict[str, Any]] = None) -> int:
    """Chuyển section provider của ai_config.json → ai_credentials(scope='org'). Idempotent: cờ
    `migrations.creds_v1` đã bật ⇒ no-op. Lỗi giữa chừng → rollback, cờ KHÔNG bật, api_key_enc cũ nguyên vẹn.
    Provider bị bỏ qua (không giải mã được key cũ) ⇒ cờ KHÔNG bật để lần boot sau thử lại. Trả số hàng tạo/đồng bộ."""
    from api.services import ai_config
    cfg = cfg if cfg is not None else ai_config.load_config()
    if (cfg.get("migrations") or {}).get("creds_v1"):
        return 0
    db, own = _open_session(db)
    try:
        ids = _sync(db, cfg)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("[ai-cred] migrate org config thất bại — rollback, cấu hình cũ giữ nguyên")
        raise
    finally:
        if own:
            db.close()
    skipped = ids.pop("_skipped", "")

    def _flag(c):
        if not skipped:
            c.setdefault("migrations", {})["creds_v1"] = True
        sel = cfg.get("provider")
        if sel in ids:
            c["org_credential_id"] = ids[sel]
    ai_config.update_raw(_flag)
    return len(ids)


def sync_after_save(cfg: Dict[str, Any]) -> None:
    """Gọi sau `ai_config.validate_and_save` (khi đã migrate): hàng org luôn theo config cũ — MỘT chiều, tránh
    key lệch khi PR-3 chuyển resolver sang hàng. Lỗi sync không làm hỏng việc lưu config."""
    if not (cfg.get("migrations") or {}).get("creds_v1"):
        return
    db = None
    try:
        db, _ = _open_session(None)
        ids = _sync(db, cfg)
        db.commit()
        ids.pop("_skipped", None)
        sel = cfg.get("provider")
        if sel in ids and cfg.get("org_credential_id") != ids[sel]:
            from api.services import ai_config
            ai_config.update_raw(lambda c: c.__setitem__("org_credential_id", ids[sel]))
    except Exception:
        if db is not None:
            db.rollback()
        logger.exception("[ai-cred] sync org credential sau khi lưu config thất bại")
    finally:
        if db is not None:
            db.close()


def startup() -> None:
    """Gọi một lần lúc import api.main: log filter, guard debug SDK, migrate. Lỗi migrate KHÔNG chặn boot."""
    from api import log_redaction
    from api.config import settings
    log_redaction.install()
    log_redaction.check_sdk_debug_env(settings.app_env)
    try:   # DB cũ (tạo trước khi có index này): thêm nếu chưa có; trùng dữ liệu → log, không chặn boot
        from sqlalchemy import text
        from api.database import engine
        with engine.connect() as conn:
            conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_ai_cred_org_provider "
                              "ON ai_credentials (provider) WHERE scope = 'org'"))
            conn.commit()
    except Exception:
        logger.error("[ai-cred] không tạo được unique index org/provider (có hàng org trùng?)")
    try:
        migrate_org_config()
    except Exception:
        logger.error("[ai-cred] startup migration lỗi (app vẫn chạy với cấu hình cũ)")
    try:   # [AI PR-3] purge tombstone quá hạn lúc boot (scheduler chỉ chạy ở production)
        from api.services import ai_usage
        db, _ = _open_session(None)
        try:
            purge_expired(db)
            ai_usage.purge_old(db)
            db.commit()
        finally:
            db.close()
    except Exception:
        logger.error("[ai-cred] purge lúc khởi động lỗi")
