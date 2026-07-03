"""
Agent Conversation ORM Model — lưu lịch sử chat của Co-work Agent.

Lưu cả hội thoại (mảng messages) vào 1 dòng dạng JSON cho đơn giản. Bảng nằm
trong DB SQLite (storage/db/vulnguard.db) — được mount ra host qua volume
./storage nên SỐNG SÓT qua restart Docker.
"""
from sqlalchemy import Column, String, DateTime, JSON, Index
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
    messages = Column(JSON, nullable=False, default=list)  # [{role, content}, ...]
