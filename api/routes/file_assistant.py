"""
File Assistant API Routes
Chat with files using local Ollama
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query, Path, WebSocket
from fastapi.responses import StreamingResponse
import logging
import json
import uuid
from typing import List, Optional
from datetime import datetime
from sqlalchemy.orm import Session

from api.database import get_db
from api.file_assistant_models import (
    FileAssistantSession, FileAssistantMessage, FileAssistantSummary,
    SessionStatus, MessageRole
)
from api.file_assistant_schemas import (
    SessionCreate, SessionOut, SessionDetail, MessageCreate, MessageOut,
    ChatRequest, ChatResponse, ErrorResponse, HealthCheck, SummaryOut,
    FileInfo, SessionListOut
)
from api.services.chat_engine import ChatEngine
from api.services.ollama_client import get_ollama_client, test_ollama_connection
from api.services.file_processor import get_file_type, is_supported_file
from api.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/file-assistant", tags=["file-assistant"])


# ─────────────────────────────────────────────
# Health Check
# ─────────────────────────────────────────────

@router.get("/health", response_model=HealthCheck)
async def health_check(db: Session = Depends(get_db)):
    """Check system health"""
    ollama_available = await test_ollama_connection()

    # Test DB connection
    db_available = True
    try:
        db.execute("SELECT 1")
    except:
        db_available = False

    status = "ok"
    if not ollama_available or not db_available:
        status = "degraded" if ollama_available or db_available else "error"

    return HealthCheck(
        status=status,
        ollama_available=ollama_available,
        database_available=db_available,
        coworker_host_available=True,  # TODO: check coworker_host
        message="System ready" if status == "ok" else "Some services unavailable"
    )


# ─────────────────────────────────────────────
# Sessions
# ─────────────────────────────────────────────

@router.post("/sessions", response_model=SessionOut, status_code=201)
async def create_session(
    request: SessionCreate,
    db: Session = Depends(get_db)
):
    """Create new chat session"""
    try:
        # Validate files
        if not request.files or len(request.files) == 0:
            raise HTTPException(status_code=400, detail="At least one file required")

        if len(request.files) > 3:
            raise HTTPException(status_code=400, detail="Maximum 3 files per session")

        for file_info in request.files:
            if not is_supported_file(file_info.path):
                raise HTTPException(
                    status_code=400,
                    detail=f"Unsupported file type: {file_info.path}"
                )

        # Create session
        session_id = str(uuid.uuid4())
        session = FileAssistantSession(
            id=session_id,
            title=request.title or f"Chat with {', '.join([f.name for f in request.files])}",
            status=SessionStatus.ACTIVE,
            model_used=request.model or "llama3.2",
            files_json=[f.dict() for f in request.files]
        )

        db.add(session)
        db.commit()
        db.refresh(session)

        # Initialize files (summarize if needed)
        engine = ChatEngine(ollama_model=session.model_used, db=db)
        try:
            await engine.initialize_session_files(session)
        except Exception as e:
            logger.error(f"File initialization failed: {e}")
            # Don't fail session creation, just log error

        return SessionOut.from_orm_with_files(session)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create session: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sessions", response_model=SessionListOut)
async def list_sessions(
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
    status: Optional[SessionStatus] = None,
    db: Session = Depends(get_db)
):
    """List chat sessions"""
    try:
        query = db.query(FileAssistantSession)

        if status:
            query = query.filter(FileAssistantSession.status == status)

        total = query.count()
        sessions = query.order_by(
            FileAssistantSession.updated_at.desc()
        ).offset(skip).limit(limit).all()

        return SessionListOut(
            total=total,
            sessions=[SessionOut.from_orm_with_files(s) for s in sessions]
        )
    except Exception as e:
        logger.error(f"Failed to list sessions: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sessions/{session_id}", response_model=SessionDetail)
async def get_session(
    session_id: str,
    db: Session = Depends(get_db)
):
    """Get session details with messages"""
    try:
        session = db.query(FileAssistantSession).filter(
            FileAssistantSession.id == session_id
        ).first()

        if not session:
            raise HTTPException(status_code=404, detail="Session not found")

        # Get messages (last 10)
        messages = db.query(FileAssistantMessage).filter(
            FileAssistantMessage.session_id == session_id
        ).order_by(
            FileAssistantMessage.created_at.desc()
        ).limit(10).all()
        messages.reverse()  # Oldest first

        # Get summaries
        summaries = db.query(FileAssistantSummary).filter(
            FileAssistantSummary.session_id == session_id
        ).all()

        result = SessionDetail.from_orm_with_files(session)
        result.messages = [MessageOut.from_orm(m) for m in messages]
        result.summaries = [SummaryOut.from_orm(s) for s in summaries]

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get session: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/sessions/{session_id}", status_code=204)
async def delete_session(
    session_id: str,
    db: Session = Depends(get_db)
):
    """Delete session"""
    try:
        session = db.query(FileAssistantSession).filter(
            FileAssistantSession.id == session_id
        ).first()

        if not session:
            raise HTTPException(status_code=404, detail="Session not found")

        db.delete(session)
        db.commit()
        return None

    except Exception as e:
        logger.error(f"Failed to delete session: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ─────────────────────────────────────────────
# Messages / Chat
# ─────────────────────────────────────────────

@router.post("/sessions/{session_id}/messages", response_model=ChatResponse)
async def send_message(
    session_id: str,
    request: MessageCreate,
    db: Session = Depends(get_db)
):
    """Send message to chat"""
    try:
        # Validate session
        session = db.query(FileAssistantSession).filter(
            FileAssistantSession.id == session_id
        ).first()

        if not session:
            raise HTTPException(status_code=404, detail="Session not found")

        # Save user message
        user_msg_id = str(uuid.uuid4())
        user_msg = FileAssistantMessage(
            id=user_msg_id,
            session_id=session_id,
            role=MessageRole.USER,
            content=request.content
        )
        db.add(user_msg)
        db.commit()

        # Generate response
        engine = ChatEngine(ollama_model=session.model_used, db=db)

        try:
            response_text = await engine.process_user_message(
                session, request.content, stream=False
            )
        except Exception as e:
            logger.error(f"Failed to generate response: {e}")
            response_text = f"Error: {str(e)}"

        # Save assistant message
        msg_id = str(uuid.uuid4())
        assist_msg = FileAssistantMessage(
            id=msg_id,
            session_id=session_id,
            role=MessageRole.ASSISTANT,
            content=response_text,
            token_count=engine.estimate_context_tokens(response_text)
        )
        db.add(assist_msg)
        session.message_count += 2  # User + Assistant
        session.updated_at = datetime.utcnow()
        db.commit()

        return ChatResponse(
            message_id=msg_id,
            content=response_text,
            token_count=assist_msg.token_count
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to send message: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sessions/{session_id}/messages", response_model=List[MessageOut])
async def get_messages(
    session_id: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """Get message history"""
    try:
        session = db.query(FileAssistantSession).filter(
            FileAssistantSession.id == session_id
        ).first()

        if not session:
            raise HTTPException(status_code=404, detail="Session not found")

        messages = db.query(FileAssistantMessage).filter(
            FileAssistantMessage.session_id == session_id
        ).order_by(
            FileAssistantMessage.created_at.asc()
        ).offset(skip).limit(limit).all()

        return [MessageOut.from_orm(m) for m in messages]

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get messages: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ─────────────────────────────────────────────
# File Operations
# ─────────────────────────────────────────────

@router.get("/file-types")
async def get_supported_file_types():
    """Get supported file types"""
    from api.services.file_processor import get_supported_types_info
    return get_supported_types_info()


@router.get("/sessions/{session_id}/summaries", response_model=List[SummaryOut])
async def get_summaries(
    session_id: str,
    db: Session = Depends(get_db)
):
    """Get file summaries for session"""
    try:
        session = db.query(FileAssistantSession).filter(
            FileAssistantSession.id == session_id
        ).first()

        if not session:
            raise HTTPException(status_code=404, detail="Session not found")

        summaries = db.query(FileAssistantSummary).filter(
            FileAssistantSummary.session_id == session_id
        ).all()

        return [SummaryOut.from_orm(s) for s in summaries]

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get summaries: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sessions/{session_id}/chunks/{file_index}")
async def get_file_chunk(
    session_id: str,
    file_index: int = Path(..., ge=0),
    chunk_id: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Get specific file chunk"""
    try:
        session = db.query(FileAssistantSession).filter(
            FileAssistantSession.id == session_id
        ).first()

        if not session:
            raise HTTPException(status_code=404, detail="Session not found")

        files_json = session.files_json or []
        if file_index >= len(files_json):
            raise HTTPException(status_code=404, detail="File not found in session")

        file_path = files_json[file_index].get("path")
        if not file_path:
            raise HTTPException(status_code=400, detail="Invalid file path")

        engine = ChatEngine(db=db)
        result = await engine.get_file_chunk(
            session_id, file_path, chunk_id or "chunk_001", with_context=True
        )

        if "error" in result:
            raise HTTPException(status_code=400, detail=result["error"])

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get chunk: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ─────────────────────────────────────────────
# WebSocket for Streaming (Optional)
# ─────────────────────────────────────────────

@router.websocket("/sessions/{session_id}/chat/stream")
async def websocket_chat(websocket: WebSocket, session_id: str, db: Session = Depends(get_db)):
    """WebSocket endpoint for streaming chat responses"""
    await websocket.accept()

    try:
        session = db.query(FileAssistantSession).filter(
            FileAssistantSession.id == session_id
        ).first()

        if not session:
            await websocket.send_json({"error": "Session not found"})
            await websocket.close(code=1008)
            return

        while True:
            data = await websocket.receive_text()
            message_data = json.loads(data)
            content = message_data.get("content", "").strip()

            if not content:
                continue

            # Save user message
            user_msg = FileAssistantMessage(
                id=str(uuid.uuid4()),
                session_id=session_id,
                role=MessageRole.USER,
                content=content
            )
            db.add(user_msg)
            db.commit()

            # Stream response
            engine = ChatEngine(ollama_model=session.model_used, db=db)

            try:
                full_response = ""
                async for chunk in await engine.process_user_message(session, content, stream=True):
                    full_response += chunk
                    await websocket.send_json({
                        "type": "chunk",
                        "content": chunk
                    })

                # Save assistant message
                assist_msg = FileAssistantMessage(
                    id=str(uuid.uuid4()),
                    session_id=session_id,
                    role=MessageRole.ASSISTANT,
                    content=full_response,
                    token_count=engine.estimate_context_tokens(full_response)
                )
                db.add(assist_msg)
                session.message_count += 2
                db.commit()

                await websocket.send_json({
                    "type": "complete",
                    "message_id": assist_msg.id
                })

            except Exception as e:
                logger.error(f"Streaming error: {e}")
                await websocket.send_json({
                    "type": "error",
                    "error": str(e)
                })

    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await websocket.close(code=1011, reason=str(e))
