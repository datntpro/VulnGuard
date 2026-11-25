"""
Security primitives cho VulnGuard: secret key, password hashing, JWT session,
mã hoá secret khi lưu (API key cloud AI).

- Password: hashlib.scrypt (stdlib, không cần bcrypt native build).
- Session: JWT HS256, lưu trong HttpOnly cookie `vg_session` (SameSite=Strict)
  hoặc header `Authorization: Bearer <token>` (CLI / CI).
- Secret at-rest: Fernet (AES-128-CBC + HMAC) với key dẫn xuất từ secret key.
"""
import base64
import hashlib
import hmac
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from cryptography.fernet import Fernet, InvalidToken

from api.config import settings

logger = logging.getLogger(__name__)

COOKIE_NAME = "vg_session"
_JWT_ALG = "HS256"
_secret_cache: Optional[bytes] = None


def get_secret_key() -> bytes:
    """Secret key: env VULNGUARD_SECRET_KEY > <storage>/secret.key (tự sinh lần đầu)."""
    global _secret_cache
    if _secret_cache:
        return _secret_cache
    if settings.vulnguard_secret_key:
        _secret_cache = settings.vulnguard_secret_key.encode()
        return _secret_cache
    path = os.path.join(settings.storage_dir, "secret.key")
    try:
        with open(path, "rb") as f:
            key = f.read().strip()
            if key:
                _secret_cache = key
                return key
    except FileNotFoundError:
        pass
    key = secrets.token_urlsafe(48).encode()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    logger.warning(f"[Security] Đã sinh secret key mới tại {path} — backup file này cùng DB.")
    _secret_cache = key
    return key


# ── Password ──────────────────────────────────────────────
_SCRYPT = dict(n=2 ** 14, r=8, p=1, dklen=64)


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


def verify_password(password: str, stored: Optional[str]) -> bool:
    if not stored or not stored.startswith("scrypt$"):
        return False
    try:
        _, salt_b64, dk_b64 = stored.split("$")
        dk = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt_b64), **_SCRYPT)
        return hmac.compare_digest(dk, base64.b64decode(dk_b64))
    except Exception:
        return False


PASSWORD_RULES_TEXT = ("Mật khẩu 10–200 ký tự, gồm ít nhất 3 trong 4 loại (chữ thường, chữ hoa, số, ký tự đặc biệt), "
                       "không chứa phần tên của email và không lặp một ký tự.")


def validate_password_strength(pw: str, email: str = "") -> None:
    """Raise ValueError (thông báo tiếng Việt) nếu mật khẩu không đạt chính sách."""
    if not isinstance(pw, str) or not (10 <= len(pw) <= 200):
        raise ValueError(PASSWORD_RULES_TEXT)
    classes = sum(bool(x) for x in (
        any(c.islower() for c in pw), any(c.isupper() for c in pw),
        any(c.isdigit() for c in pw), any(not c.isalnum() for c in pw)))
    if classes < 3 or len(set(pw)) == 1:
        raise ValueError(PASSWORD_RULES_TEXT)
    local = (email or "").split("@")[0].strip().lower()
    if len(local) >= 3 and local in pw.lower():
        raise ValueError(PASSWORD_RULES_TEXT)


# ── JWT session ───────────────────────────────────────────
def create_token(user_id: str, role: str, token_version: int = 0, ttl_hours: Optional[int] = None) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "role": role,
        "tv": token_version,   # tăng khi đổi mật khẩu / vô hiệu hoá → token cũ mất hiệu lực
        "jti": secrets.token_hex(16),   # id phiên — logout thu hồi từng token (bảng revoked_tokens)
        "iat": now,
        "exp": now + timedelta(hours=ttl_hours or settings.session_ttl_hours),
    }
    return jwt.encode(payload, get_secret_key(), algorithm=_JWT_ALG)


def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, get_secret_key(), algorithms=[_JWT_ALG])
    except jwt.PyJWTError:
        return None


# ── Secret at rest ────────────────────────────────────────
def _fernet() -> Fernet:
    digest = hashlib.sha256(b"vulnguard-secret-box:" + get_secret_key()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secret(plain: str) -> str:
    return _fernet().encrypt(plain.encode()).decode()


def decrypt_secret(token: Optional[str]) -> Optional[str]:
    if not token:
        return None
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken:
        logger.error("[Security] Không giải mã được secret — secret key đã đổi?")
        return None


def mask_secret(plain: Optional[str]) -> str:
    if not plain:
        return ""
    # Chỉ lộ 4 ký tự cuối (không lộ tiền tố/định dạng key)
    return "…" + plain[-4:] if len(plain) > 8 else "…"
