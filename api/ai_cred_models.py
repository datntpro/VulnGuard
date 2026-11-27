"""[AI PR-2] Bảng credential AI (`ai_credentials`) và nhật ký dùng (`ai_usage_events`).

`secret_enc` là Fernet(envelope gắn chủ) — xem api/services/ai_credentials.py. Không bao giờ trả ra API.
Chưa có endpoint người dùng (PR-3); bảng do create_all() tạo (bảng mới, không cần ALTER).
"""
import uuid

from sqlalchemy import (Boolean, Column, DateTime, Float, Index, Integer, JSON, String, Text,
                        UniqueConstraint, text)
from sqlalchemy.sql import func

from api.database import Base


def gen_id() -> str:
    return str(uuid.uuid4())


SCOPES = ("user", "org")
PROVIDERS = ("anthropic", "bedrock", "openai", "azure_openai", "gemini", "vertex", "openrouter", "openai_compatible")
STATUSES = ("unknown", "valid", "invalid", "forbidden", "rate_limited", "revoked", "disabled")


class AiCredential(Base):
    __tablename__ = "ai_credentials"
    __table_args__ = (
        UniqueConstraint("scope", "owner_user_id", "provider", "label", name="uq_ai_cred_owner_label"),
        # tối đa MỘT credential mặc định cho mỗi user (partial unique index, SQLite + Postgres)
        Index("uq_ai_cred_default_per_user", "owner_user_id", unique=True,
              sqlite_where=text("is_default = 1 AND owner_user_id IS NOT NULL"),
              postgresql_where=text("is_default AND owner_user_id IS NOT NULL")),
    )

    id = Column(String(36), primary_key=True, default=gen_id)
    scope = Column(String(8), nullable=False)                      # 'user' | 'org'
    owner_user_id = Column(String(64), nullable=True, index=True)  # null khi scope='org'
    provider = Column(String(30), nullable=False)
    label = Column(String(80), nullable=False)
    auth_mode = Column(String(30), nullable=False, default="api_key")
    secret_gen = Column(Integer, nullable=False, default=1)         # thế hệ secret; nằm trong envelope → chống replay ciphertext cũ
    secret_enc = Column(Text, nullable=True)                       # null: keyless / tombstone
    key_hint = Column(String(8), nullable=False, default="")       # "…9fA1" (4 ký tự cuối)
    params = Column(JSON, nullable=False, default=dict)            # KHÔNG secret: model, region, base_url…
    is_default = Column(Boolean, nullable=False, default=False)
    status = Column(String(16), nullable=False, default="unknown")
    last_validated_at = Column(DateTime, nullable=True)
    last_error_code = Column(String(40), nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    created_by = Column(String(64), nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)
    rotated_at = Column(DateTime, nullable=True)
    status_changed_at = Column(DateTime, nullable=True)            # mốc revoked/disabled → purge sau 30 ngày

    def __repr__(self) -> str:  # không in secret_enc
        return f"<AiCredential {self.id} {self.scope} {self.provider} {self.key_hint} {self.status}>"


class AiUsageEvent(Base):
    """Append-only. Schema theo kế hoạch §4.1; PR-3 mới ghi."""
    __tablename__ = "ai_usage_events"
    __table_args__ = (Index("idx_ai_usage_user_ts", "user_id", "ts"),)

    id = Column(String(36), primary_key=True, default=gen_id)
    ts = Column(DateTime, server_default=func.now(), nullable=False)
    user_id = Column(String(64), nullable=True)
    credential_id = Column(String(36), nullable=True)
    credential_scope = Column(String(8), nullable=True)
    provider = Column(String(30), nullable=True)
    model = Column(String(120), nullable=True)
    feature = Column(String(30), nullable=True)
    job_kind = Column(String(30), nullable=True)
    job_id = Column(String(64), nullable=True)
    tokens_in = Column(Integer, nullable=False, default=0)
    tokens_out = Column(Integer, nullable=False, default=0)
    tokens_cache_read = Column(Integer, nullable=False, default=0)
    tokens_cache_write = Column(Integer, nullable=False, default=0)
    est_cost_usd = Column(Float, nullable=True)
    latency_ms = Column(Integer, nullable=True)
    outcome = Column(String(16), nullable=True)                    # ok | refused | error | quota_blocked
    error_code = Column(String(40), nullable=True)
