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
import secrets
import threading
import time as _time
from collections import OrderedDict
from datetime import datetime
from typing import List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.exc import IntegrityError
from starlette.requests import HTTPConnection
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from api.auth_models import RevokedToken, User, UserRole
from api.config import settings
from api.database import get_db, SessionLocal
from api.security import (
    COOKIE_NAME, create_token, decode_token, get_secret_key, hash_password, verify_password,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

PUBLIC_API_PATHS = {
    "/api/auth/status", "/api/auth/login", "/api/auth/setup", "/api/auth/logout",
    "/api/health",
}

# (method or "*", path prefix) chỉ ADMIN được gọi
# P0.2: endpoint quét CHỦ ĐỘNG — khoá khi AUTH_ENABLED=false (method != GET)
ACTIVE_SCAN_PREFIXES = ("/api/pentest", "/api/webscans", "/api/domains")

ADMIN_ONLY = [
    ("*", "/api/auth/users"),
    ("PUT", "/api/ai/config"),
    ("PUT", "/api/settings"),
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

    @field_validator("email")
    @classmethod
    def _check_email(cls, v: str) -> str:
        return _norm_email(v)


class UserCreate(SetupIn):
    role: UserRole = UserRole.ANALYST


class UserUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    password: Optional[str] = Field(default=None, min_length=10, max_length=200)


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
            # Chế độ dev (auth tắt) — coi như ADMIN để không chặn các route admin.
            u = User(email="dev@local", name="Dev (auth disabled)", role=UserRole.ADMIN, is_active=True)
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

    if not settings.auth_enabled:
        # P0.2: auth TẮT → chặn các tính năng quét CHỦ ĐỘNG (có thể tấn công mục tiêu
        # ngoài). Instance mở không auth không được phép bắn web scan/crawl/pentest.
        if request.method not in ("GET", "HEAD", "OPTIONS") and any(
                path.startswith(p) for p in ACTIVE_SCAN_PREFIXES):
            return JSONResponse(
                {"detail": "Tính năng quét chủ động (web scan/crawl/pentest) bị khoá khi "
                           "AUTH_ENABLED=false. Hãy bật auth và đăng nhập để dùng."},
                status_code=403)
        return await call_next(request)

    is_api = path.startswith("/api/")
    is_app_shell = path in ("/", "/index.html", "/static/index.html", "/static/agent.html")
    if not (is_api or is_app_shell) or path in PUBLIC_API_PATHS or request.method == "OPTIONS":
        return await call_next(request)

    user = resolve_user(request)
    if user is None:
        if is_app_shell:
            return RedirectResponse("/login", status_code=303)
        return JSONResponse({"detail": "Chưa đăng nhập hoặc phiên đã hết hạn"}, status_code=401)

    if request.method not in ("GET", "HEAD") and user.role == UserRole.VIEWER:
        return JSONResponse({"detail": "Tài khoản VIEWER chỉ có quyền xem"}, status_code=403)
    if _is_admin_only(request.method, path) and user.role != UserRole.ADMIN:
        return JSONResponse({"detail": "Chỉ ADMIN được thực hiện thao tác này"}, status_code=403)

    request.state.user = user
    return await call_next(request)


# ─────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────
@router.get("/status")
def auth_status(db: Session = Depends(get_db)):
    return {
        "auth_enabled": settings.auth_enabled,
        "setup_required": settings.auth_enabled and db.query(User).count() == 0,
    }


@router.post("/setup")
def setup_first_admin(payload: SetupIn, response: Response, db: Session = Depends(get_db)):
    if db.query(User).count() > 0:
        raise HTTPException(status_code=409, detail="Hệ thống đã có tài khoản — hãy đăng nhập")
    user = User(email=payload.email, name=payload.name.strip(),
                password_hash=hash_password(payload.password), role=UserRole.ADMIN,
                last_login_at=datetime.utcnow())
    db.add(user)
    db.commit()
    db.refresh(user)
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


def _device_sig(email: str, nonce: str) -> str:
    return hmac.new(get_secret_key(), f"device|{email}|{nonce}".encode(), hashlib.sha256).hexdigest()[:32]


def _device_nonce(request: Request, email: str) -> Optional[str]:
    raw = request.cookies.get(DEVICE_COOKIE) or ""
    nonce, _, sig = raw.partition(".")
    if not nonce or not sig:
        return None
    if hmac.compare_digest(sig, _device_sig((email or "").lower(), nonce)):
        return nonce
    return None


def _set_device_cookie(response: Response, email: str, nonce: Optional[str] = None):
    nonce = nonce or secrets.token_urlsafe(16)
    response.set_cookie(DEVICE_COOKIE, f"{nonce}.{_device_sig(email.lower(), nonce)}",
                        max_age=180 * 86400, httponly=True, samesite="strict",
                        secure=settings.cookie_secure, path="/api/auth")


def _check_lockout(key: str):
    with _LOGIN_LOCK:
        rec = _LOGIN_FAILS.get(key)
        if not rec:
            return
        count, first = rec
        if _time.time() - first > _LOCK_WINDOW:
            _LOGIN_FAILS.pop(key, None)
            return
        if count >= _MAX_FAILS:
            retry = max(1, int(_LOCK_WINDOW - (_time.time() - first)))
            raise HTTPException(status_code=429,
                                detail=f"Quá nhiều lần đăng nhập sai. Thử lại sau {retry // 60 + 1} phút.",
                                headers={"Retry-After": str(retry)})


def _record_fail(key: str):
    with _LOGIN_LOCK:
        now = _time.time()
        count, first = _LOGIN_FAILS.get(key, [0, now])
        if now - first > _LOCK_WINDOW:
            count, first = 0, now
        _LOGIN_FAILS[key] = [count + 1, first]
        _LOGIN_FAILS.move_to_end(key)
        # dọn bản ghi hết hạn ở đầu hàng đợi, rồi cắt cho đủ giới hạn
        while _LOGIN_FAILS:
            k0, (_, f0) = next(iter(_LOGIN_FAILS.items()))
            if now - f0 > _LOCK_WINDOW:
                _LOGIN_FAILS.popitem(last=False)
            else:
                break
        while len(_LOGIN_FAILS) > _MAX_KEYS:
            _LOGIN_FAILS.popitem(last=False)


@router.post("/login")
def login(payload: LoginIn, response: Response, request: Request, db: Session = Depends(get_db)):
    nonce = _device_nonce(request, payload.email)
    key = f"dev|{nonce}" if nonce else f"ip|{_login_key(request, payload.email)}"
    _check_lockout(key)
    user = db.query(User).filter(User.email == payload.email).first()
    # verify_password chạy cả khi user không tồn tại → không lộ timing "email có tồn tại"
    ok = verify_password(payload.password, user.password_hash if user else hash_password("x" * 12))
    if not user or not ok or not user.is_active:
        _record_fail(key)
        raise HTTPException(status_code=401, detail="Email hoặc mật khẩu không đúng")
    with _LOGIN_LOCK:
        _LOGIN_FAILS.pop(key, None)        # reset khi đăng nhập thành công
    user.last_login_at = datetime.utcnow()
    db.commit()
    token = _set_session(response, user)
    _set_device_cookie(response, payload.email, nonce)
    return {"user": UserOut.model_validate(user), "token": token}


@router.post("/logout")
def logout(response: Response, request: Request, db: Session = Depends(get_db)):
    """N-1: thu hồi đúng token đang dùng (jti denylist). Endpoint public để xoá được cả cookie hỏng/hết hạn,
    nên tự giải mã token ở đây (middleware không gắn request.state.user cho path public)."""
    user, payload = _resolve(_token_from_request(request))
    if user is not None and payload is not None:
        jti = payload.get("jti")
        if jti:
            try:
                db.add(RevokedToken(jti=jti, user_id=user.id,
                                    expires_at=datetime.utcfromtimestamp(payload["exp"])))
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


@router.post("/change-password")
def change_password(payload: ChangePasswordIn, response: Response,
                    user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Người dùng tự đổi mật khẩu — xoá cờ must_change_password (P0.3)."""
    if not verify_password(payload.current_password, user.password_hash or ""):
        raise HTTPException(status_code=400, detail="Mật khẩu hiện tại không đúng")
    if payload.new_password == payload.current_password:
        raise HTTPException(status_code=400, detail="Mật khẩu mới phải khác mật khẩu cũ")
    user.password_hash = hash_password(payload.new_password)
    user.must_change_password = False
    user.token_version = (user.token_version or 0) + 1   # vô hiệu các phiên cũ
    db.commit()
    token = _set_session(response, user)   # cấp lại phiên cho chính người đổi
    return {"ok": True, "token": token}


# ── User management (ADMIN) ──
@router.get("/users", response_model=List[UserOut])
def list_users(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    return db.query(User).order_by(User.created_at).all()


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(payload: UserCreate, _: User = Depends(require_admin), db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email đã tồn tại")
    user = User(email=payload.email, name=payload.name.strip(),
                password_hash=hash_password(payload.password), role=payload.role)
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
