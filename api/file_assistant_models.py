"""
File Assistant ORM Models
SQLAlchemy models for chat sessions, messages, and file summaries
"""

from sqlalchemy import (
    Column, String, Integer, DateTime, Text, Enum, ForeignKey, JSON, Boolean, Index
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
import enum

from api.database import Base


def gen_id():
    return str(uuid.uuid4())


class SessionStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    ARCHIVED = "ARCHIVED"
    DELETED = "DELETED"


class MessageRole(str, enum.Enum):
    USER = "USER"
    ASSISTANT = "ASSISTANT"


# ─────────────────────────────────────────────
class FileAssistantSession(Base):
    __tablename__ = "file_assistant_sessions"
    __table_args__ = (
        Index('idx_status', 'status'),
        Index('idx_created_at', 'created_at'),
    )

    id = Column(String(36), primary_key=True, default=gen_id)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)

    # Session metadata
    title = Column(String(200), nullable=True)  # Auto-generated or user-named
    status = Column(Enum(SessionStatus), default=SessionStatus.ACTIVE, nullable=False)
    model_used = Column(String(100), nullable=False)  # "llama3.2", "deepseek-coder", etc.

    # Files in session: JSON array of {path, size, hash, type, name}
    files_json = Column(JSON, nullable=False, default=list)

    # Message count for session management
    message_count = Column(Integer, default=0)

    # Relationships
    messages = relationship(
        "FileAssistantMessage",
        back_populates="session",
        cascade="all, delete-orphan",
        lazy="select"
    )
    summaries = relationship(
        "FileAssistantSummary",
        back_populates="session",
        cascade="all, delete-orphan",
        lazy="select"
    )

    def __repr__(self):
        return f"<FileAssistantSession {self.id[:8]}... title={self.title}>"


# ─────────────────────────────────────────────
class FileAssistantMessage(Base):
    __tablename__ = "file_assistant_messages"
    __table_args__ = (
        Index('idx_session_created', 'session_id', 'created_at'),
        Index('idx_session_role', 'session_id', 'role'),
    )

    id = Column(String(36), primary_key=True, default=gen_id)
    session_id = Column(String(36), ForeignKey("file_assistant_sessions.id"), nullable=False)

    # Message content
    role = Column(Enum(MessageRole), nullable=False)  # USER or ASSISTANT
    content = Column(Text, nullable=False)  # Full message text

    # Token tracking for context window management
    token_count = Column(Integer, nullable=True)  # Estimated token count

    # Metadata for debugging/analytics
    created_at = Column(DateTime, server_default=func.now(), nullable=False)

    # Relationship
    session = relationship("FileAssistantSession", back_populates="messages")

    def __repr__(self):
        role_char = "U" if self.role == MessageRole.USER else "A"
        preview = self.content[:30] + "..." if len(self.content) > 30 else self.content
        return f"<FileAssistantMessage {role_char}: {preview}>"


# ─────────────────────────────────────────────
class FileAssistantSummary(Base):
    __tablename__ = "file_assistant_summaries"
    __table_args__ = (
        Index('idx_session_file', 'session_id', 'file_path'),
    )

    id = Column(String(36), primary_key=True, default=gen_id)
    session_id = Column(String(36), ForeignKey("file_assistant_sessions.id"), nullable=False)

    # File reference
    file_path = Column(String(500), nullable=False)  # Absolute path on host machine
    file_hash = Column(String(64), nullable=True)  # SHA256 for detecting file changes

    # Summary content
    summary = Column(Text, nullable=False)  # AI-generated summary

    # Chunk index: JSON array for large files
    # Format: [
    #   {"chunk_id": "chunk_001", "start_line": 1, "end_line": 50, "size_bytes": 4096},
    #   {"chunk_id": "chunk_002", "start_line": 51, "end_line": 100, "size_bytes": 4096},
    #   ...
    # ]
    chunk_index_json = Column(JSON, nullable=True)

    # Metadata
    total_lines = Column(Integer, nullable=True)
    total_size_bytes = Column(Integer, nullable=True)
    file_type = Column(String(50), nullable=True)  # "python", "javascript", "json", etc.

    generated_at = Column(DateTime, server_default=func.now(), nullable=False)

    # Relationship
    session = relationship("FileAssistantSession", back_populates="summaries")

    def __repr__(self):
        return f"<FileAssistantSummary {self.file_path} chunks={len(self.chunk_index_json or [])}>"


# ─────────────────────────────────────────────
class FileAssistantPreference(Base):
    """User preferences for File Assistant behavior"""
    __tablename__ = "file_assistant_preferences"

    id = Column(String(36), primary_key=True, default=gen_id)

    # User ID (can be None for now, future multi-user support)
    user_id = Column(String(100), unique=True, nullable=True)

    # Thresholds & limits
    auto_summarize_threshold = Column(Integer, default=51200)  # 50KB in bytes
    context_window_tokens = Column(Integer, default=8000)  # Max context for Ollama
    max_turns_per_session = Column(Integer, default=10)  # Max chat turns before session ends
    max_sessions_stored = Column(Integer, default=50)  # Rolling: auto-delete oldest

    # Behavior settings
    auto_export_on_exit = Column(Boolean, default=False)  # Auto-export to HTML on session close
    show_token_count = Column(Boolean, default=False)  # Display token count in UI

    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)

    def __repr__(self):
        return f"<FileAssistantPreference user={self.user_id}>"
