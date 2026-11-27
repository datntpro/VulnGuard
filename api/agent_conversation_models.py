"""
Agent Conversation ORM Model — lưu lịch sử chat của Co-work Agent.

Lưu cả hội thoại (mảng messages) vào 1 dòng dạng JSON cho đơn giản. Bảng nằm
trong DB SQLite (storage/db/vulnguard.db) — được mount ra host qua volume
./storage nên SỐNG SÓT qua restart Docker.
"""
from sqlalchemy import Column, String, DateTime, JSON, Index, Integer, Text
from sqlalchemy.sql import func
import uuid

from api.database import Base


def gen_id():
    return str(uuid.uuid4())


class AgentConversation(Base):
    __tablename__ = "agent_conversations"
    __table_args__ = (
        Index("idx_agent_conv_updated", "updated_at"),
    )

    id = Column(String(36), primary_key=True, default=gen_id)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)

    title = Column(String(200), nullable=True)
    folder_id = Column(String(64), nullable=True)
    skill_id = Column(String(120), nullable=True)
    owner_user_id = Column(String(64), nullable=True, index=True)   # [AI PR-1] None = hội thoại cũ (chỉ ADMIN thấy)
    messages = Column(JSON, nullable=False, default=list)  # [{role, content}, ...]
    # [AI PR-3b] route ghim theo hội thoại (§4.11.1) + transcript phía server (client KHÔNG bao giờ gửi lịch sử)
    route_kind = Column(String(8), nullable=True)           # 'local' | 'cloud' (None = chưa có bước nào)
    provider = Column(String(32), nullable=True)
    model = Column(String(120), nullable=True)
    ai_credential_id = Column(String(36), nullable=True)
    transcript = Column(JSON, nullable=True)                # danh sách message native, append-only
    cloud_state = Column(JSON, nullable=True)               # {steps, sent_bytes, suspicious:{signals,hosts}}


class AgentPendingAction(Base):
    """[AI PR-3b] Hành động write_file/exec (hoặc đọc file nhạy cảm) chờ người dùng duyệt. Args do SERVER giữ:
    client chỉ gửi `pending_id`; id gắn với hội thoại + chủ sở hữu (args do client gửi không bao giờ được tin)."""
    __tablename__ = "agent_pending_actions"
    __table_args__ = (Index("idx_agent_pending_conv", "conversation_id"),)

    id = Column(String(36), primary_key=True, default=gen_id)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    owner_user_id = Column(String(64), nullable=True)
    conversation_id = Column(String(36), nullable=True)     # None = bước stateless của backend local cũ
    folder_id = Column(String(64), nullable=True)
    kind = Column(String(16), nullable=False, default="side_effect")   # 'side_effect' | 'sensitive_read'
    action = Column(String(32), nullable=False)
    args = Column(JSON, nullable=False, default=dict)
    tool_use_id = Column(String(120), nullable=True)
    extra_ids = Column(JSON, nullable=True)                 # tool_use id còn lại của cùng lượt model (cần tool_result)
    warning = Column(JSON, nullable=True)                   # {suspicious, signals, hosts}
    status = Column(String(12), nullable=False, default="open")   # open | done | rejected
