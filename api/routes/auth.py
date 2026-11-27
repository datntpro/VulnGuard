"""
Auth API + middleware bảo vệ toàn bộ /api/*.

Luồng:
  1. Lần đầu (chưa có user): GET /api/auth/status → setup_required=true
     → POST /api/auth/setup tạo ADMIN đầu tiên.
  2. POST /api/auth/login → set cookie HttpOnly `vg_session` (+ trả token cho CLI/CI).
  3. Mọi request /api/* phải có cookie hoặc header `Authorization: Bearer <token>`.

Phân quyền (enforce ở middleware, theo prefix):
  VIEWER  — chỉ GET
  ANALYST — chạy scan, đổi trạng thái vuln, waiver…
  ADMIN   — + quản lý user, cấu hình AI / scanner / Ollama, Co-work (chạy lệnh trên host)
"""
import hashlib
import hmac
import logging
import os
import re
import secrets
import threading
import time as _time
from collections import OrderedDict
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.exc import IntegrityError, OperationalError
from starlette.requests import HTTPConnection
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy.orm import Session

from api.auth_models import RevokedToken, SetupState, User, UserRole
from api.config import settings
from api.database import get_db, SessionLocal
from api.security import (
    COOKIE_NAME, create_token, decode_token, get_secret_key, hash_password, validate_password_strength,
    verify_password,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

PUBLIC_API_PATHS = {
    "/api/auth/status", "/api/auth/login", "/api/auth/setup", "/api/auth/logout",
    "/api/health",
    # P2-3b: ingest của egress gateway — KHÔNG có phiên người dùng, route tự xác thực bằng HMAC theo engagement
    "/api/pentest/internal/traffic",
}

# (method or "*", path prefix) chỉ ADMIN được gọi
# P0.2: endpoint quét CHỦ ĐỘNG — khoá khi AUTH_ENABLED=false (method != GET)
ACTIVE_SCAN_PREFIXES = ("/api/pentest", "/api/webscans", "/api/domains")

ADMIN_ONLY = [
    ("*", "/api/auth/users"),
    ("PUT", "/api/ai/config"),
    ("PUT", "/api/settings"),
    # L-1: các endpoint con của settings (logo, sonarqube/smtp test) + SCM (SSRF/dùng token đã lưu) + AI test
    ("POST", "/api/settings"),
    ("DELETE", "/api/settings"),
    ("POST", "/api/scm/connections"),
    ("DELETE", "/api/scm/connections"),
    ("GET", "/api/scm/connections/"),   # /{id}/remote-repos dùng token đã lưu; danh sách (không "/") vẫn đọc được
    ("POST", "/api/ai/test"),
    ("POST", "/api/ollama"),
    ("PUT", "/api/ollama"),
    ("DELETE", "/api/ollama"),
    ("*", "/api/coworker"),
    ("*", "/api/connectors"),
    ("POST", "/api/intel/refresh"),
    # File Assistant đọc file theo đường dẫn tuyệt đối trên host → chỉ ADMIN (H2).
    # (WebSocket stream được chặn riêng trong route vì middleware HTTP không chạy cho WS.)
    ("*", "/api/file-assistant"),
]


# ─────────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────────
class UserOut(BaseModel):
    id: str
    email: str
    name: str
    role: UserRole
    is_active: bool
    must_change_password: bool = False
    last_login_at: Optional[datetime] = None
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


def _norm_email(v: str) -> str:
    v = (v or "").strip().lower()
    if "@" not in v or len(v) > 255:
        raise ValueError("Email không hợp lệ")
    return v


class LoginIn(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def _check_email(cls, v: str) -> str:
        return _norm_email(v)


class SetupIn(BaseModel):
    email: str
    name: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=10, max_length=200)
    # L-2: chỉ /setup dùng (UserCreate kế thừa nhưng bỏ qua trường này)
    setup_token: str = Field(default="", max_length=256)

    @field_validator("email")
    @classmethod
    def _check_email(cls, v: str) -> str:
        return _norm_email(v)

    @model_validator(mode="after")
    def _check_strength(self):
        validate_password_strength(self.password, self.email)
        return self


class UserCreate(SetupIn):
    role: UserRole = UserRole.ANALYST


class UserUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    password: Optional[str] = Field(default=None, min_length=10, max_length=200)

    @field_validator("password")
    @classmethod
    def _check_pw(cls, v):
        if v is not None:
            validate_password_strength(v)
        return v


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def _token_from_request(request: HTTPConnection) -> Optional[str]:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.cookies.get(COOKIE_NAME)


def _resolve(token: Optional[str]) -> Tuple[Optional[User], Optional[dict]]:
    """Giải mã + kiểm tra DB (user active, token_version, jti chưa bị thu hồi)."""
    if not token:
        return None, None
    payload = decode_token(token)
    if not payload:
        return None, None
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == payload.get("sub")).first()
        if not user or not user.is_active or user.token_version != payload.get("tv", 0):
            return None, None
        jti = payload.get("jti")
        if jti and db.query(RevokedToken).filter(RevokedToken.jti == jti).first():
            return None, None
        db.expunge(user)
        return user, payload
    finally:
        db.close()


def resolve_user(request: HTTPConnection) -> Optional[User]:
    """Dùng được cho cả Request và WebSocket (cùng có .headers / .cookies)."""
    return _resolve(_token_from_request(request))[0]


def _set_session(response: Response, user: User) -> str:
    token = create_token(user.id, user.role.value, user.token_version)
    response.set_cookie(
        COOKIE_NAME, token,
        max_age=settings.session_ttl_hours * 3600,
        httponly=True, samesite="strict", secure=settings.cookie_secure, path="/",
    )
    return token


def current_user(request: Request) -> User:
    user = getattr(request.state, "user", None)
    if user is None:
        if not settings.auth_enabled:
            # Chế độ dev (auth tắt) — quyền ANALYST (D-6): không còn là ADMIN giả.
            u = User(email="dev@local", name="Dev (auth disabled)", role=UserRole.ANALYST, is_active=True)
            u.id = "dev-local"
            return u
        raise HTTPException(status_code=401, detail="Chưa đăng nhập")
    return user


def require_admin(user: User = Depends(current_user)) -> User:
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Chỉ ADMIN được thực hiện thao tác này")
    return user


def _is_admin_only(method: str, path: str) -> bool:
    return any((m == "*" or m == method) and path.startswith(p) for m, p in ADMIN_ONLY)


# I-1: tài liệu API chỉ cho người đã đăng nhập (mọi role)
DOCS_PATHS = {"/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"}
# L-3: user bị ép đổi mật khẩu chỉ được gọi các path này
MUST_CHANGE_ALLOWED = {
    "/api/auth/me", "/api/auth/change-password", "/api/auth/logout", "/api/auth/logout-all",
    "/api/auth/status", "/api/features", "/api/health",
}
SELF_SERVICE_PATHS = {"/api/auth/change-password", "/api/auth/logout", "/api/auth/logout-all"}
# POST chỉ để ĐỌC/xuất (không đổi dữ liệu): VIEWER được phép — job PDF kiểm quyền y như GET export.
VIEWER_READ_POSTS = {"/api/reports/pdf-jobs"}
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "[::1]"}
_SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


def _host_only(h: str) -> str:
    """Bỏ port, giữ nguyên IPv6 dạng [::1]."""
    h = (h or "").strip().lower()
    if h.startswith("["):
        return h[: h.find("]") + 1] if "]" in h else h
    return h.rsplit(":", 1)[0] if h.count(":") == 1 else h


def _csv(v: str) -> set:
    return {x.strip().lower() for x in (v or "").split(",") if x.strip()}


def _host_ok(request: Request) -> bool:
    extra = {_host_only(h) for h in _csv(settings.allowed_hosts)}
    if settings.auth_enabled and not extra:
        return True
    return _host_only(request.headers.get("host", "")) in (_LOCAL_HOSTS | extra)


def _origin_ok(request: Request) -> bool:
    """M-2: chặn CSRF xuyên site cho request ghi (kể cả multipart không cần preflight).
    Không có Origin (CLI/CI) → cho qua."""
    origin = request.headers.get("origin")
    allowed = _csv(settings.cors_allow_origins)
    if origin is not None:
        o = origin.strip().lower().rstrip("/")
        if o in allowed:
            return True
        if o == "null" or urlparse(o).netloc != (request.headers.get("host") or "").strip().lower():
            return False
    return request.headers.get("sec-fetch-site", "").lower() != "cross-site"


async def auth_middleware(request: Request, call_next):
    """Gắn request.state.user và chặn request chưa đăng nhập / thiếu quyền."""
    path = request.url.path
    request.state.user = None

    # 1.9: chặn module đã tắt bằng feature flag (ẩn khỏi bản bán)
    _feat = (("/api/coworker", settings.feature_coworker),
             ("/api/docreview", settings.feature_docreview),
             ("/api/file-assistant", settings.feature_file_assistant))
    for prefix, on in _feat:
        if not on and path.startswith(prefix):
            return JSONResponse({"detail": "Module đã tắt trên bản triển khai này."}, status_code=404)

    # M-2: Host allow-list (DNS rebinding) + CSRF/Origin guard — luôn bật, kể cả khi auth tắt
    if not _host_ok(request):
        return JSONResponse({"detail": "Host không được phép", "code": "bad_host"}, status_code=421)
    if path.startswith("/api/") and request.method not in _SAFE_METHODS and not _origin_ok(request):
        return JSONResponse({"detail": "Origin không hợp lệ", "code": "bad_origin"}, status_code=403)

    if not settings.auth_enabled:
        # P0.2: auth TẮT → chặn các tính năng quét CHỦ ĐỘNG (có thể tấn công mục tiêu
        # ngoài). Instance mở không auth không được phép bắn web scan/crawl/pentest.
        if request.method not in ("GET", "HEAD", "OPTIONS") and any(
                path.startswith(p) for p in ACTIVE_SCAN_PREFIXES):
            return JSONResponse(
                {"detail": "Tính năng quét chủ động (web scan/crawl/pentest) bị khoá khi "
                           "AUTH_ENABLED=false. Hãy bật auth và đăng nhập để dùng."},
                status_code=403)
        # M-2/D-6: auth tắt → user giả KHÔNG còn là ADMIN thật: khoá mọi tính năng quản trị,
        # Co-work (chạy lệnh trên host) và File Assistant.
        # C4: auth tắt → không cho /api/auth/setup gieo ADMIN đầu tiên (setup chỉ có nghĩa khi auth bật)
        if (_is_admin_only(request.method, path) or path == "/api/auth/setup"
                or path.startswith(("/api/coworker", "/api/file-assistant"))):
            return JSONResponse(
                {"detail": "Tính năng quản trị / Co-work / File Assistant bị khoá khi AUTH_ENABLED=false. "
                           "Hãy bật auth và đăng nhập để dùng.", "code": "auth_required"},
                status_code=403)
        return await call_next(request)

    is_api = path.startswith("/api/")
    is_docs = path in DOCS_PATHS
    is_app_shell = path in ("/", "/index.html", "/static/index.html", "/static/agent.html") or path in ("/docs", "/redoc")
    if not (is_api or is_app_shell or is_docs) or path in PUBLIC_API_PATHS or request.method == "OPTIONS":
        return await call_next(request)

    user = resolve_user(request)
    if user is None:
        if is_app_shell:
            return RedirectResponse("/login", status_code=303)
        return JSONResponse({"detail": "Chưa đăng nhập hoặc phiên đã hết hạn"}, status_code=401)

    if is_docs:     # I-1: mọi role đã đăng nhập đều xem được
        return await call_next(request)

    # B1: self-service (đổi mật khẩu, đăng xuất mọi phiên) phải dùng được cho VIEWER, nếu không user VIEWER
    # bị ép đổi mật khẩu (D-11) sẽ bị khoá vĩnh viễn.
    if (request.method not in ("GET", "HEAD") and user.role == UserRole.VIEWER
            and path not in SELF_SERVICE_PATHS and path not in VIEWER_READ_POSTS):
        return JSONResponse({"detail": "Tài khoản VIEWER chỉ có quyền xem"}, status_code=403)
    if _is_admin_only(request.method, path) and user.role != UserRole.ADMIN:
        return JSONResponse({"detail": "Chỉ ADMIN được thực hiện thao tác này"}, status_code=403)
    # L-3: phải đổi mật khẩu trước khi dùng API (không chỉ ở UI)
    if user.must_change_password and is_api and path not in MUST_CHANGE_ALLOWED:
        return JSONResponse({"detail": "Bạn phải đổi mật khẩu trước khi tiếp tục",
                             "code": "must_change_password"}, status_code=403)

    request.state.user = user
    return await call_next(request)


# ─────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────
def _user_count(db: Session) -> int:
    return db.query(User).count()


def _storage_dir() -> str:
    return settings.storage_dir


_SETUP_LOCK = threading.Lock()          # bảo vệ việc tạo file token
_SETUP_COMMIT_LOCK = threading.Lock()   # M-2: tuần tự hoá "đếm user → INSERT → commit" (D-14: 1 tiến trình)
_setup_hint_logged = False
_MIN_ENV_TOKEN = 16
SETUP_RL_KEY = "setup|global"            # S-1/S-2: một bucket toàn cục, không phụ thuộc IP (NAT/XFF)
_log = logging.getLogger("vulnguard.auth")


def _env_setup_token() -> str:
    env = (settings.vulnguard_setup_token or "").strip()
    if env and len(env) < _MIN_ENV_TOKEN:
        _log.error("VULNGUARD_SETUP_TOKEN quá ngắn (<%d ký tự) → bỏ qua, dùng file storage/setup_token", _MIN_ENV_TOKEN)
        return ""
    return env


def _read_setup_token() -> Optional[str]:
    """Chỉ ĐỌC token (env hoặc file) — không bao giờ tạo (R-1)."""
    env = _env_setup_token()
    if env:
        return env
    try:
        with open(os.path.join(_storage_dir(), "setup_token"), encoding="utf-8") as f:
            return f.read().strip() or None
    except OSError:
        return None


def _setup_token(user_count: int) -> Optional[str]:
    """L-2: token thiết lập lần đầu. Env VULNGUARD_SETUP_TOKEN (>=16 ký tự) ưu tiên; nếu không, khi chưa có
    user thì đọc/tạo <storage>/setup_token (0600). Đã có user → None."""
    global _setup_hint_logged
    env = _env_setup_token()
    if env:
        return env
    if user_count > 0:
        return None
    path = os.path.join(_storage_dir(), "setup_token")
    with _SETUP_LOCK:
        try:
            with open(path, encoding="utf-8") as f:
                tok = f.read().strip()
            if tok:
                return tok
        except OSError:
            pass
        tok = secrets.token_urlsafe(24)
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(tok + "\n")
            os.chmod(path, 0o600)
        except OSError as e:
            _log.error("Không ghi được %s (%s). Docker: chown 10001 storage", path, e)
            raise HTTPException(status_code=500, detail="Không tạo được setup token — thư mục storage không ghi được")
        if not _setup_hint_logged:
            _setup_hint_logged = True
            _log.warning("Thiết lập lần đầu: lấy setup token tại %s (docker exec vulnguard-api cat /app/storage/setup_token)", path)
        return tok


def _clear_setup_token():
    try:
        os.remove(os.path.join(_storage_dir(), "setup_token"))
    except OSError:
        pass


def init_setup_token():
    """M-1: gọi lúc khởi động — tạo file token (đã có user thì xoá file cũ) để hướng dẫn đọc token chạy ngay lần đầu."""
    if not settings.auth_enabled:
        return
    db = SessionLocal()
    try:
        count = _user_count(db)
    finally:
        db.close()
    if count > 0:
        _clear_setup_token()
        return
    # chưa có user → guard cũ (nếu có, vd user bị xoá hết) không được chặn setup
    gdb = SessionLocal()
    try:
        gdb.query(SetupState).delete()
        gdb.commit()
    except Exception:
        gdb.rollback()
    finally:
        gdb.close()
    try:
        if _env_setup_token():
            _log.warning("Thiết lập lần đầu: dùng setup token từ VULNGUARD_SETUP_TOKEN")
        else:
            _setup_token(0)
    except HTTPException:
        pass


@router.get("/status")
def auth_status(db: Session = Depends(get_db)):
    required = settings.auth_enabled and _user_count(db) == 0
    return {
        "auth_enabled": settings.auth_enabled,
        "setup_required": required,
        "setup_token_required": required,
    }


@router.post("/setup")
def setup_first_admin(payload: SetupIn, response: Response, db: Session = Depends(get_db)):
    count = _user_count(db)
    if count > 0:
        raise HTTPException(status_code=409, detail="Hệ thống đã có tài khoản — hãy đăng nhập")
    expected = _read_setup_token()
    if expected is None:
        # R-1: file thiếu — có thể kẻ thắng vừa xoá nó. Đếm lại trong lock; chỉ tạo khi thật sự chưa có user.
        with _SETUP_COMMIT_LOCK:
            if _user_count(db) > 0:
                raise HTTPException(status_code=409, detail="Hệ thống đã có tài khoản — hãy đăng nhập")
            expected = _setup_token(0)
    # S-1: so sánh TRƯỚC; token đúng không bao giờ bị khoá (kẻ tấn công NAT/LAN không DoS được chủ máy).
    # Chỉ lần sai mới bị đếm, vào 1 bucket toàn cục → xoay IP/X-Forwarded-For không né được.
    if not expected or not hmac.compare_digest(payload.setup_token.encode(), expected.encode()):
        with _LOGIN_LOCK:
            now = _time.time()
            retry = _locked_retry(SETUP_RL_KEY, now)
            if not retry:
                _record_fail_locked(SETUP_RL_KEY, now)
        if retry:
            raise HTTPException(status_code=429, detail=f"Quá nhiều lần nhập sai setup token. Thử lại sau {retry // 60 + 1} phút.",
                                headers={"Retry-After": str(retry)})
        raise HTTPException(status_code=403, detail="Setup token không đúng")
    pw_hash = hash_password(payload.password)   # tính ngoài lock (scrypt chậm)
    with _SETUP_COMMIT_LOCK:                    # M-2: một người thắng, còn lại 409
        if _user_count(db) > 0:
            raise HTTPException(status_code=409, detail="Hệ thống đã có tài khoản — hãy đăng nhập")
        user = User(email=payload.email, name=payload.name.strip(), password_hash=pw_hash,
                    role=UserRole.ADMIN, last_login_at=datetime.utcnow())
        # R-2: guard cấp DB (PK id=1) → chỉ 1 tiến trình tạo được ADMIN đầu tiên; còn lại IntegrityError → 409
        db.add(SetupState(id=1))
        db.add(user)
        try:
            db.commit()
        except (IntegrityError, OperationalError):
            db.rollback()
            if _user_count(db) > 0 or db.query(SetupState).count() > 0:
                raise HTTPException(status_code=409, detail="Hệ thống đã có tài khoản — hãy đăng nhập")
            raise HTTPException(status_code=503, detail="Cơ sở dữ liệu đang bận — thử lại")
        db.refresh(user)
    with _LOGIN_LOCK:
        _LOGIN_FAILS.pop(SETUP_RL_KEY, None)
    _clear_setup_token()
    token = _set_session(response, user)
    return {"user": UserOut.model_validate(user), "token": token}


# M5/N-3: chống brute-force đăng nhập — khoá tạm sau nhiều lần sai.
# Khoá theo "thiết bị" (cookie ký HMAC cấp sau lần đăng nhập đúng) nếu có, ngược lại theo (IP, email).
# Kẻ tấn công không có device cookie của nạn nhân chỉ khoá được bucket "ip|email" của chính nó,
# nên ADMIN thật (trình duyệt đã đăng nhập trước đó) không bị DoS. Lockout nằm trong bộ nhớ:
# khởi động lại tiến trình sẽ xoá.
DEVICE_COOKIE = "vg_device"
_LOGIN_FAILS: "OrderedDict[str, list]" = OrderedDict()   # key → [count, first_ts]
_LOGIN_LOCK = threading.Lock()
_MAX_FAILS = 5
_LOCK_WINDOW = 15 * 60             # 15 phút
_MAX_KEYS = 10_000


def _login_key(request, email: str) -> str:
    ip = request.client.host if request.client else "?"
    return f"{ip}|{(email or '').lower()}"


_NONCE_RE = re.compile(r"[A-Za-z0-9_-]{22}")
_DUMMY_HASH = hash_password("x" * 12)   # tính 1 lần: user không tồn tại tốn cùng thời gian với user tồn tại


def _device_sig(user_id: str, nonce: str) -> str:
    # Subkey riêng + mã hoá có độ dài → không mơ hồ; ràng buộc theo user id (không phải email).
    key = hashlib.sha256(b"vg-device-cookie\x00" + get_secret_key()).digest()
    msg = b"device\x00" + str(len(user_id)).encode() + b":" + user_id.encode() + b"\x00" + nonce.encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()[:32]


def _device_nonce(request: Request, user_id: Optional[str]) -> Optional[str]:
    if not user_id:
        return None
    raw = request.cookies.get(DEVICE_COOKIE) or ""
    nonce, _, sig = raw.partition(".")
    if not _NONCE_RE.fullmatch(nonce) or not sig:
        return None
    if hmac.compare_digest(sig, _device_sig(user_id, nonce)):
        return nonce
    return None


def _set_device_cookie(response: Response, user_id: str, nonce: Optional[str] = None):
    nonce = nonce or secrets.token_urlsafe(16)
    response.set_cookie(DEVICE_COOKIE, f"{nonce}.{_device_sig(user_id, nonce)}",
                        max_age=180 * 86400, httponly=True, samesite="strict",
                        secure=settings.cookie_secure, path="/api/auth")


def _locked_retry(key: str, now: float) -> Optional[int]:
    """Giây còn lại nếu key đang bị khoá, ngược lại None (xoá bản ghi hết hạn). Gọi khi đang giữ _LOGIN_LOCK."""
    rec = _LOGIN_FAILS.get(key)
    if not rec:
        return None
    count, first = rec
    if now - first > _LOCK_WINDOW:
        _LOGIN_FAILS.pop(key, None)
        return None
    if count >= _MAX_FAILS:
        return max(1, int(_LOCK_WINDOW - (now - first)))
    return None


def _raise_locked(retry: int):
    raise HTTPException(status_code=429,
                        detail=f"Quá nhiều lần đăng nhập sai. Thử lại sau {retry // 60 + 1} phút.",
                        headers={"Retry-After": str(retry)})


def _check_lockout(key: str):
    with _LOGIN_LOCK:
        retry = _locked_retry(key, _time.time())
    if retry:
        _raise_locked(retry)


def _record_fail_locked(key: str, now: float):
    count, first = _LOGIN_FAILS.get(key, [0, now])
    if now - first > _LOCK_WINDOW:
        count, first = 0, now
    _LOGIN_FAILS[key] = [count + 1, first]
    _LOGIN_FAILS.move_to_end(key)
    # dọn bản ghi hết hạn ở đầu hàng đợi
    while _LOGIN_FAILS:
        _, (_, f0) = next(iter(_LOGIN_FAILS.items()))
        if now - f0 > _LOCK_WINDOW:
            _LOGIN_FAILS.popitem(last=False)
        else:
            break
    # cắt cho đủ giới hạn, ưu tiên bỏ key CHƯA bị khoá (không dùng spray để mở khoá bucket)
    while len(_LOGIN_FAILS) > _MAX_KEYS:
        # không bao giờ đẩy chính key vừa ghi (nếu không, khi kho đầy key đã khoá, bucket mới không thể khoá)
        victim = next((k for k, (c, _) in _LOGIN_FAILS.items() if c < _MAX_FAILS and k != key), None)
        if victim is None:
            victim = next(k for k in _LOGIN_FAILS if k != key)   # key khoá cũ nhất
        _LOGIN_FAILS.pop(victim)


def _record_fail(key: str):
    with _LOGIN_LOCK:
        _record_fail_locked(key, _time.time())


def _reserve_attempt(key: str):
    """Kiểm tra khoá VÀ tính 1 lần thử trong cùng một critical section (trước scrypt),
    nên N request đồng thời không thể vượt _MAX_FAILS lần thử."""
    with _LOGIN_LOCK:
        now = _time.time()
        retry = _locked_retry(key, now)
        if not retry:
            _record_fail_locked(key, now)
    if retry:
        _raise_locked(retry)


@router.post("/login")
def login(payload: LoginIn, response: Response, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()
    nonce = _device_nonce(request, user.id if user else None)
    # Bucket "thiết bị" nếu có cookie hợp lệ của CHÍNH user này; ngược lại một bucket chung cho mọi
    # client chưa biết của email đó (không theo IP: IP có thể bị giả qua X-Forwarded-For / xoay vòng).
    key = f"dev|{nonce}" if nonce else f"untrusted|{payload.email}"
    _reserve_attempt(key)
    # verify_password chạy cả khi user không tồn tại → không lộ timing "email có tồn tại"
    ok = verify_password(payload.password, user.password_hash if user else _DUMMY_HASH)
    if not user or not ok or not user.is_active:
        raise HTTPException(status_code=401, detail="Email hoặc mật khẩu không đúng")
    with _LOGIN_LOCK:
        _LOGIN_FAILS.pop(key, None)        # reset khi đăng nhập thành công
    user.last_login_at = datetime.utcnow()
    db.commit()
    token = _set_session(response, user)
    _set_device_cookie(response, user.id, nonce)
    return {"user": UserOut.model_validate(user), "token": token}


@router.post("/logout")
def logout(response: Response, request: Request, db: Session = Depends(get_db)):
    """N-1: thu hồi đúng token đang dùng (jti denylist). Endpoint public để xoá được cả cookie hỏng/hết hạn,
    nên tự giải mã token ở đây (middleware không gắn request.state.user cho path public)."""
    user, payload = _resolve(_token_from_request(request))
    if user is None:     # header Authorization hỏng nhưng cookie hợp lệ → vẫn thu hồi cookie
        user, payload = _resolve(request.cookies.get(COOKIE_NAME))
    if user is not None and payload is not None:
        jti = payload.get("jti")
        if jti:
            try:
                db.add(RevokedToken(jti=jti, user_id=user.id,
                                    expires_at=datetime.fromtimestamp(payload["exp"], timezone.utc).replace(tzinfo=None)))
                db.commit()
            except IntegrityError:        # logout lặp lại
                db.rollback()
        else:
            # token cũ (trước khi có jti) — cách duy nhất để thu hồi là tăng token_version
            row = db.query(User).filter(User.id == user.id).first()
            if row:
                row.token_version = (row.token_version or 0) + 1
                db.commit()
        db.query(RevokedToken).filter(RevokedToken.expires_at < datetime.utcnow()).delete()
        db.commit()
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


@router.post("/logout-all")
def logout_all(response: Response, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Đăng xuất MỌI phiên (web + token CLI/CI) của chính user: tăng token_version."""
    row = db.query(User).filter(User.id == user.id).first()
    if row:
        row.token_version = (row.token_version or 0) + 1
        db.commit()
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str = Field(min_length=10, max_length=200)
    confirm_password: str = Field(max_length=200)

    @model_validator(mode="after")
    def _check(self):
        if self.new_password != self.confirm_password:
            raise ValueError("Mật khẩu xác nhận không khớp")
        validate_password_strength(self.new_password)
        return self


@router.post("/change-password")
def change_password(payload: ChangePasswordIn, response: Response,
                    user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Người dùng tự đổi mật khẩu — xoá cờ must_change_password (P0.3)."""
    # `user` của middleware đã bị expunge khỏi session → phải nạp lại hàng DB, nếu không commit không lưu gì
    # (bug cũ: đổi mật khẩu không có hiệu lực, token cấp lại mang tv sai → 401; lộ ra khi API ép must_change_password).
    user = db.query(User).filter(User.id == user.id).first()
    if user is None:
        raise HTTPException(status_code=401, detail="Chưa đăng nhập")
    if not verify_password(payload.current_password, user.password_hash or ""):
        raise HTTPException(status_code=400, detail="Mật khẩu hiện tại không đúng")
    if payload.new_password == payload.current_password:
        raise HTTPException(status_code=400, detail="Mật khẩu mới phải khác mật khẩu cũ")
    try:
        validate_password_strength(payload.new_password, user.email)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    if verify_password(payload.new_password, user.password_hash or ""):
        raise HTTPException(status_code=400, detail="Mật khẩu mới phải khác mật khẩu cũ")
    user.password_hash = hash_password(payload.new_password)
    user.must_change_password = False
    user.token_version = (user.token_version or 0) + 1   # vô hiệu các phiên cũ (mọi thiết bị khác)
    db.commit()
    db.refresh(user)
    with _LOGIN_LOCK:   # không để lần gõ nhầm trước đó khoá người vừa đổi mật khẩu
        for k in [k for k in _LOGIN_FAILS if k == f"untrusted|{user.email}"]:
            _LOGIN_FAILS.pop(k, None)
    token = _set_session(response, user)   # phiên mới gắn token_version mới đã lưu DB
    return {"ok": True, "token": token, "user": UserOut.model_validate(user)}


# ── User management (ADMIN) ──
@router.get("/users", response_model=List[UserOut])
def list_users(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    return db.query(User).order_by(User.created_at).all()


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(payload: UserCreate, _: User = Depends(require_admin), db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email đã tồn tại")
    user = User(email=payload.email, name=payload.name.strip(),
                password_hash=hash_password(payload.password), role=payload.role,
                must_change_password=True)   # D-11: user do admin tạo phải đổi mật khẩu lần đầu
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _active_admin_count(db: Session) -> int:
    return db.query(User).filter(User.role == UserRole.ADMIN, User.is_active.is_(True)).count()


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(user_id: str, payload: UserUpdate, admin: User = Depends(require_admin),
                db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User không tồn tại")
    demoting = (payload.role is not None and payload.role != UserRole.ADMIN) or payload.is_active is False
    if demoting and user.role == UserRole.ADMIN and _active_admin_count(db) <= 1:
        raise HTTPException(status_code=400, detail="Phải còn ít nhất 1 ADMIN đang hoạt động")
    if payload.name is not None:
        user.name = payload.name.strip()
    if payload.role is not None and payload.role != user.role:
        user.role = payload.role
        user.token_version += 1
    if payload.is_active is not None and payload.is_active != user.is_active:
        user.is_active = payload.is_active
        user.token_version += 1
    if payload.password:
        user.password_hash = hash_password(payload.password)
        user.must_change_password = True    # D-11: admin đặt lại mật khẩu → người dùng phải đổi
        user.token_version += 1
    db.commit()
    db.refresh(user)
    return user


@router.delete("/users/{user_id}", status_code=204)
def delete_user(user_id: str, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User không tồn tại")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Không thể tự xoá tài khoản đang đăng nhập")
    if user.role == UserRole.ADMIN and _active_admin_count(db) <= 1:
        raise HTTPException(status_code=400, detail="Phải còn ít nhất 1 ADMIN đang hoạt động")
    db.delete(user)
    db.commit()
    return None
