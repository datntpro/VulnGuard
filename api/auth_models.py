"""User model — đăng nhập Web UI / API."""
import enum
import uuid

from sqlalchemy import Column, String, DateTime, Enum, Boolean, Integer
from sqlalchemy.sql import func

from api.database import Base


class UserRole(str, enum.Enum):
    ADMIN = "ADMIN"        # quản lý user, cấu hình AI / scanner
    ANALYST = "ANALYST"    # chạy scan, đổi trạng thái vuln, waiver
    VIEWER = "VIEWER"      # chỉ xem


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), nullable=False, unique=True, index=True)
    name = Column(String(200), nullable=False)
    password_hash = Column(String(300), nullable=True)
    role = Column(Enum(UserRole), nullable=False, default=UserRole.ANALYST)
    is_active = Column(Boolean, nullable=False, default=True)
    must_change_password = Column(Boolean, nullable=False, default=False)  # P0.3
    token_version = Column(Integer, nullable=False, default=0)
    last_login_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())


class RevokedToken(Base):
    """Denylist jti của JWT đã logout (xoá khi hết hạn)."""
    __tablename__ = "revoked_tokens"

    jti = Column(String(64), primary_key=True)
    user_id = Column(String, index=True, nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)


class SetupState(Base):
    """R-2: guard cấp DB — đúng 1 dòng (id=1) cho phép tạo ADMIN đầu tiên qua /setup, an toàn đa tiến trình."""
    __tablename__ = "setup_state"

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, server_default=func.now())
