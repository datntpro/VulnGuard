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
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from api.auth_models import User, UserRole
from api.config import settings
from api.database import get_db, SessionLocal
from api.security import (
    COOKIE_NAME, create_token, decode_token, hash_password, verify_password,
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
def _token_from_request(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.cookies.get(COOKIE_NAME)


def resolve_user(request: Request) -> Optional[User]:
    token = _token_from_request(request)
    if not token:
        return None
    payload = decode_token(token)
    if not payload:
        return None
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == payload.get("sub")).first()
        if not user or not user.is_active or user.token_version != payload.get("tv", 0):
            return None
        db.expunge(user)
        return user
    finally:
        db.close()


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


# M5: chống brute-force đăng nhập — khoá tạm theo (IP, email) sau nhiều lần sai.
import threading
import time as _time

_LOGIN_FAILS: dict = {}            # key → [count, first_ts]
_LOGIN_LOCK = threading.Lock()
_MAX_FAILS = 5
_LOCK_WINDOW = 15 * 60             # 15 phút


def _login_key(request: Request, email: str) -> str:
    ip = request.client.host if request.client else "?"
    return f"{ip}|{(email or '').lower()}"


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
            retry = int(_LOCK_WINDOW - (_time.time() - first))
            raise HTTPException(status_code=429,
                                detail=f"Quá nhiều lần đăng nhập sai. Thử lại sau {retry // 60 + 1} phút.")


def _record_fail(key: str):
    with _LOGIN_LOCK:
        count, first = _LOGIN_FAILS.get(key, [0, _time.time()])
        if _time.time() - first > _LOCK_WINDOW:
            count, first = 0, _time.time()
        _LOGIN_FAILS[key] = [count + 1, first]


@router.post("/login")
def login(payload: LoginIn, response: Response, request: Request, db: Session = Depends(get_db)):
    key = _login_key(request, payload.email)
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
    return {"user": UserOut.model_validate(user), "token": token}


@router.post("/logout")
def logout(response: Response, request: Request, db: Session = Depends(get_db)):
    # M5: thu hồi JWT — tăng token_version để MỌI token đã cấp mất hiệu lực ngay
    # (current_user kiểm tra tv khớp token_version). Không chỉ xoá cookie.
    user = getattr(request.state, "user", None)
    if user is not None and getattr(user, "id", None):
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
