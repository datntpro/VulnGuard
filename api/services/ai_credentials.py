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


def _seal(cid: str, owner_user_id: Optional[str], provider: str, secret: str) -> str:
    env = {"v": ENVELOPE_VERSION, "cid": cid, "owner": _owner_tag(owner_user_id), "p": provider, "s": secret}
    return _box().encrypt(json.dumps(env).encode()).decode()


def _open_envelope(row) -> str:
    """Giải mã + ASSERT envelope khớp hàng. Fail-closed: mọi lỗi → CredentialError (không lộ chi tiết)."""
    if not row.secret_enc:
        raise CredentialError("AI_CRED_NO_SECRET")
    try:
        env = json.loads(_box().decrypt(row.secret_enc.encode()).decode())
    except (InvalidToken, ValueError, UnicodeError):
        logger.error("[ai-cred] không giải mã được credential %s (secret key đã đổi?)", row.id)
        raise CredentialError("AI_CRED_DECRYPT_FAILED") from None
    if (not isinstance(env, dict) or env.get("v") != ENVELOPE_VERSION or env.get("cid") != row.id
            or env.get("owner") != _owner_tag(row.owner_user_id) or env.get("p") != row.provider
            or not isinstance(env.get("s"), str)):
        logger.error("[ai-cred] envelope không khớp hàng %s — từ chối (ciphertext bị hoán đổi?)", row.id)
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
           created_by: Optional[str] = None, status: str = "unknown") -> Dict[str, Any]:
    from api.ai_cred_models import AiCredential, PROVIDERS, SCOPES
    if scope not in SCOPES or provider not in PROVIDERS:
        raise CredentialError("AI_CRED_BAD_ARGUMENT")
    if (scope == "org") != (owner_user_id is None):
        raise CredentialError("AI_CRED_BAD_ARGUMENT")      # org ⇒ không chủ; user ⇒ bắt buộc có chủ
    cid = str(uuid.uuid4())
    row = AiCredential(
        id=cid, scope=scope, owner_user_id=owner_user_id, provider=provider, label=label[:80],
        auth_mode=auth_mode, params=dict(params or {}), is_default=bool(is_default and owner_user_id),
        status=status, created_by=created_by,
        secret_enc=_seal(cid, owner_user_id, provider, secret) if secret else None,
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
    row.secret_enc = _seal(row.id, row.owner_user_id, row.provider, new_secret)
    row.key_hint = _hint(new_secret)
    row.rotated_at = datetime.utcnow()
    row.status, row.last_error_code = "unknown", None
    db.flush()
    _audit("rotate", actor, row)
    return _meta(row)


def _tombstone(db, cred_id: str, status: str, action: str, actor: Optional[str]) -> Dict[str, Any]:
    row = _get(db, cred_id)
    row.secret_enc = None            # xoá secret NGAY; hàng còn lại để audit/usage resolve id
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


def migrate_org_config(db=None, cfg: Optional[Dict[str, Any]] = None) -> int:
    """Chuyển section provider của ai_config.json → ai_credentials(scope='org'). Idempotent: chạy lại khi cờ
    `migrations.creds_v1` đã bật là no-op. Lỗi giữa chừng → rollback, cờ KHÔNG bật, api_key_enc cũ nguyên vẹn.
    Trả số hàng đã tạo."""
    from api.services import ai_config
    from api.security import decrypt_secret
    cfg = cfg if cfg is not None else ai_config.load_config()
    if (cfg.get("migrations") or {}).get("creds_v1"):
        return 0
    own = db is None
    if own:
        from api.database import SessionLocal
        db = SessionLocal()
    try:
        from api.ai_cred_models import AiCredential
        selected = cfg.get("provider")
        created: Dict[str, str] = {}
        for provider in ai_config.PROVIDERS:
            sec = cfg.get(provider)
            if not isinstance(sec, dict):
                continue
            enc = sec.get("api_key_enc")
            auth_mode = sec.get("auth_mode") or "api_key"
            keyless = (provider == selected and
                       ((provider == "anthropic" and auth_mode in _KEYLESS_ANTHROPIC) or
                        (provider == "bedrock" and auth_mode in _KEYLESS_BEDROCK)))
            if not enc and not keyless:
                continue
            existing = db.query(AiCredential).filter(AiCredential.scope == "org",
                                                     AiCredential.provider == provider).first()
            if existing:                       # đã có (chạy dở lần trước mà chưa kịp bật cờ) → dùng lại
                created[provider] = existing.id
                continue
            plain = decrypt_secret(enc) if enc else None
            if enc and not plain:
                logger.error("[ai-cred] bỏ qua migrate %s: không giải mã được api_key_enc cũ", provider)
                continue
            meta = create(db, scope="org", provider=provider, label=f"Org – {provider}", auth_mode=auth_mode,
                          secret=plain, params=_org_params(provider, sec), created_by=None)
            created[provider] = meta["id"]
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("[ai-cred] migrate org config thất bại — rollback, cấu hình cũ giữ nguyên")
        raise
    finally:
        if own:
            db.close()

    def _flag(c):
        c.setdefault("migrations", {})["creds_v1"] = True
        if selected in created:
            c["org_credential_id"] = created[selected]
    ai_config.update_raw(_flag)
    return len(created)


def startup() -> None:
    """Gọi một lần lúc import api.main: log filter, guard debug SDK, migrate. Lỗi migrate KHÔNG chặn boot."""
    from api import log_redaction
    from api.config import settings
    log_redaction.install()
    log_redaction.check_sdk_debug_env(settings.app_env)
    try:
        migrate_org_config()
    except Exception:
        logger.error("[ai-cred] startup migration lỗi (app vẫn chạy với cấu hình cũ)")
