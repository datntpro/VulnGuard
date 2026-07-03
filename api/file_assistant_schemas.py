"""
File Assistant Pydantic Schemas
Request/response validation and serialization
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum


class SessionStatus(str, Enum):
    ACTIVE = "ACTIVE"
    ARCHIVED = "ARCHIVED"
    DELETED = "DELETED"


class MessageRole(str, Enum):
    USER = "USER"
    ASSISTANT = "ASSISTANT"


# ─────────────────────────────────────────────
# File Operations
# ─────────────────────────────────────────────

class FileInfo(BaseModel):
    """File metadata sent to session"""
    path: str = Field(..., description="Absolute path on host machine")
    name: str = Field(..., description="File name only (e.g., 'app.py')")
    size_bytes: int = Field(..., description="File size in bytes")
    type: str = Field(..., description="File type (python, javascript, json, etc.)")
    hash: Optional[str] = Field(None, description="SHA256 hash for change detection")

    class Config:
        json_schema_extra = {
            "example": {
                "path": "/home/user/projects/app.py",
                "name": "app.py",
                "size_bytes": 2400,
                "type": "python"
            }
        }


# ─────────────────────────────────────────────
# Messages
# ─────────────────────────────────────────────

class MessageCreate(BaseModel):
    """User sends a message to chat"""
    content: str = Field(..., description="Message text", min_length=1, max_length=2000)

    class Config:
        json_schema_extra = {
            "example": {
                "content": "What does this function do?"
            }
        }


class MessageOut(BaseModel):
    """Message response"""
    id: str
    session_id: str
    role: MessageRole
    content: str
    token_count: Optional[int] = None
    created_at: datetime

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": "msg-uuid",
                "session_id": "session-uuid",
                "role": "USER",
                "content": "What does this function do?",
                "token_count": 15,
                "created_at": "2026-06-29T14:00:00Z"
            }
        }


# ─────────────────────────────────────────────
# Summaries
# ─────────────────────────────────────────────

class ChunkInfo(BaseModel):
    """Chunk metadata for large files"""
    chunk_id: str
    start_line: int
    end_line: int
    size_bytes: int


class SummaryOut(BaseModel):
    """File summary response"""
    id: str
    file_path: str
    summary: str
    chunk_index: Optional[List[ChunkInfo]] = None
    total_lines: Optional[int] = None
    total_size_bytes: Optional[int] = None
    file_type: Optional[str] = None
    generated_at: datetime

    class Config:
        from_attributes = True


# ─────────────────────────────────────────────
# Sessions
# ─────────────────────────────────────────────

class SessionCreate(BaseModel):
    """Create a new chat session"""
    title: Optional[str] = Field(None, description="Session title (auto-generated if not provided)")
    files: List[FileInfo] = Field(..., description="1-3 files to chat with")
    model: Optional[str] = Field("llama3.2", description="Ollama model to use")

    class Config:
        json_schema_extra = {
            "example": {
                "title": "Chat with app.py",
                "files": [
                    {
                        "path": "/home/user/projects/app.py",
                        "name": "app.py",
                        "size_bytes": 2400,
                        "type": "python"
                    }
                ],
                "model": "llama3.2"
            }
        }


class SessionOut(BaseModel):
    """Session response"""
    id: str
    created_at: datetime
    updated_at: datetime
    title: Optional[str]
    status: SessionStatus
    model_used: str
    message_count: int
    files: List[FileInfo] = Field(..., description="Files in this session")

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": "session-uuid",
                "created_at": "2026-06-29T14:00:00Z",
                "updated_at": "2026-06-29T14:15:00Z",
                "title": "Chat with app.py",
                "status": "ACTIVE",
                "model_used": "llama3.2",
                "message_count": 5,
                "files": []
            }
        }

    @classmethod
    def from_orm_with_files(cls, session):
        """Custom converter to parse files_json"""
        data = {
            "id": session.id,
            "created_at": session.created_at,
            "updated_at": session.updated_at,
            "title": session.title,
            "status": session.status,
            "model_used": session.model_used,
            "message_count": session.message_count,
            "files": session.files_json or []
        }
        return cls(**data)


class SessionDetail(SessionOut):
    """Detailed session response with messages"""
    messages: List[MessageOut] = []
    summaries: List[SummaryOut] = []


# ─────────────────────────────────────────────
# Chat Streaming
# ─────────────────────────────────────────────

class ChatRequest(BaseModel):
    """Chat message request"""
    content: str = Field(..., min_length=1, max_length=2000)


class ChatResponse(BaseModel):
    """Chat response with message ID"""
    message_id: str
    content: str
    role: MessageRole = MessageRole.ASSISTANT
    token_count: Optional[int] = None
    created_at: datetime


class StreamingChunk(BaseModel):
    """Streaming chunk from Ollama"""
    chunk_id: str
    content: str  # Partial response chunk
    is_complete: bool = False
    tokens_so_far: Optional[int] = None


# ─────────────────────────────────────────────
# Preferences
# ─────────────────────────────────────────────

class PreferenceUpdate(BaseModel):
    """Update user preferences"""
    auto_summarize_threshold: Optional[int] = None
    context_window_tokens: Optional[int] = None
    max_turns_per_session: Optional[int] = None
    auto_export_on_exit: Optional[bool] = None
    show_token_count: Optional[bool] = None


class PreferenceOut(BaseModel):
    """Preferences response"""
    auto_summarize_threshold: int
    context_window_tokens: int
    max_turns_per_session: int
    max_sessions_stored: int
    auto_export_on_exit: bool
    show_token_count: bool

    class Config:
        from_attributes = True


# ─────────────────────────────────────────────
# Error Responses
# ─────────────────────────────────────────────

class ErrorResponse(BaseModel):
    """Standard error response"""
    error: str
    detail: Optional[str] = None
    code: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "error": "File not found",
                "detail": "File /home/user/app.py does not exist or is not readable",
                "code": "FILE_NOT_FOUND"
            }
        }


class HealthCheck(BaseModel):
    """System health status"""
    status: str  # "ok", "degraded", "error"
    ollama_available: bool
    database_available: bool
    coworker_host_available: bool
    message: Optional[str] = None


# ─────────────────────────────────────────────
# Bulk Operations
# ─────────────────────────────────────────────

class SessionListOut(BaseModel):
    """List of sessions for home page"""
    total: int
    sessions: List[SessionOut]


class ChunkRequest(BaseModel):
    """Request for file chunk"""
    chunk_id: str = Field(..., description="Chunk ID like 'chunk_001'")
    with_context: bool = Field(False, description="Include surrounding lines")
