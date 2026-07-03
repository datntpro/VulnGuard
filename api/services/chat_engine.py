"""
Chat Engine
Orchestrates file processing, summarization, and chat with Ollama
"""

import logging
from typing import Optional, List, Dict, AsyncGenerator
from sqlalchemy.orm import Session

from api.file_assistant_models import (
    FileAssistantSession, FileAssistantMessage, FileAssistantSummary, MessageRole
)
from api.services.ollama_client import get_ollama_client
from api.services.file_processor import extract_text_from_file, get_file_type
from api.services.summarizer import FileSummarizer
from api.services.chunker import FileChunker

logger = logging.getLogger(__name__)


class ChatEngine:
    """Main chat orchestration engine"""

    def __init__(self, ollama_model: str = "llama3.2", db: Optional[Session] = None):
        self.model = ollama_model
        self.ollama = get_ollama_client()
        self.summarizer = FileSummarizer(ollama_model=ollama_model)
        self.chunker = FileChunker()
        self.db = db

    async def initialize_session_files(
        self,
        session: FileAssistantSession,
        auto_summarize_threshold: int = 51200  # 50KB
    ) -> None:
        """
        Process and summarize files for session

        Args:
            session: Session object with files_json
            auto_summarize_threshold: File size threshold for auto-summarization
        """
        files_json = session.files_json or []

        for file_info in files_json:
            file_path = file_info.get("path")
            if not file_path:
                continue

            try:
                # Extract file content
                logger.info(f"Processing file: {file_path}")
                content, line_count = await extract_text_from_file(file_path)

                file_type = get_file_type(file_path)
                file_size = len(content.encode('utf-8'))

                # Summarize if above threshold
                if file_size > auto_summarize_threshold:
                    logger.info(f"Summarizing large file: {file_path}")
                    summary, chunk_index, file_hash = await self.summarizer.summarize_file(
                        content, file_type, file_path
                    )

                    # Store summary in DB
                    summary_record = FileAssistantSummary(
                        session_id=session.id,
                        file_path=file_path,
                        file_hash=file_hash,
                        summary=summary,
                        chunk_index_json=chunk_index,
                        total_lines=line_count,
                        total_size_bytes=file_size,
                        file_type=file_type
                    )
                    self.db.add(summary_record)
                else:
                    logger.info(f"File small enough, no summary needed: {file_path}")
                    # Still create index for future chunking
                    chunks = self.chunker.chunk_text(content, file_type)
                    chunk_index = self.chunker.create_chunk_index(chunks) if chunks else []

                    summary_record = FileAssistantSummary(
                        session_id=session.id,
                        file_path=file_path,
                        summary=f"File: {file_path}",
                        chunk_index_json=chunk_index if chunk_index else None,
                        total_lines=line_count,
                        total_size_bytes=file_size,
                        file_type=file_type
                    )
                    self.db.add(summary_record)

                self.db.commit()

            except Exception as e:
                logger.error(f"Failed to process {file_path}: {e}")
                # Don't stop session initialization, just log error
                continue

    async def process_user_message(
        self,
        session: FileAssistantSession,
        user_message: str,
        stream: bool = False
    ) -> str:
        """
        Process user message and generate response

        Args:
            session: Session object
            user_message: User's question/message
            stream: Whether to stream response

        Returns:
            AI response (or stream)
        """
        # Build context from file summaries
        context_parts = []

        summaries = self.db.query(FileAssistantSummary).filter(
            FileAssistantSummary.session_id == session.id
        ).all()

        for summary in summaries:
            context_parts.append(f"File: {summary.file_path}")
            context_parts.append(f"Summary:\n{summary.summary}\n")

        full_context = "\n---\n".join(context_parts) if context_parts else ""

        # Generate response
        logger.info(f"Processing message for session {session.id}")

        try:
            if stream:
                # Return streaming response
                return await self.ollama.generate_stream(
                    model=self.model,
                    prompt=user_message,
                    context=full_context
                )
            else:
                # Return complete response
                response = await self.ollama.generate(
                    model=self.model,
                    prompt=user_message,
                    context=full_context,
                    stream=False
                )
                return response

        except Exception as e:
            logger.error(f"Failed to generate response: {e}")
            raise

    async def get_file_chunk(
        self,
        session_id: str,
        file_path: str,
        chunk_id: str,
        with_context: bool = False
    ) -> Dict:
        """
        Retrieve specific chunk from file

        Args:
            session_id: Session ID
            file_path: File path
            chunk_id: Chunk ID (chunk_001, etc.)
            with_context: Include surrounding chunks

        Returns:
            Chunk content with metadata
        """
        # Get summary with chunk index
        summary = self.db.query(FileAssistantSummary).filter(
            FileAssistantSummary.session_id == session_id,
            FileAssistantSummary.file_path == file_path
        ).first()

        if not summary:
            return {"error": "File not found in session"}

        if not summary.chunk_index_json:
            return {"error": "No chunks available for this file"}

        # Find requested chunk
        chunk_metadata = None
        for chunk in summary.chunk_index_json:
            if chunk.get("chunk_id") == chunk_id:
                chunk_metadata = chunk
                break

        if not chunk_metadata:
            return {"error": f"Chunk {chunk_id} not found"}

        # Re-extract file and get chunk content
        try:
            content, _ = await extract_text_from_file(file_path)
            chunks = self.chunker.chunk_text(content, summary.file_type)

            # Find chunk by ID
            chunk_content = None
            for chunk in chunks:
                if chunk["chunk_id"] == chunk_id:
                    chunk_content = chunk
                    break

            if not chunk_content:
                return {"error": "Could not extract chunk content"}

            result = {
                "chunk_id": chunk_id,
                "file_path": file_path,
                "start_line": chunk_content["start_line"],
                "end_line": chunk_content["end_line"],
                "content": chunk_content["content"],
                "size_bytes": chunk_content["size_bytes"]
            }

            if with_context:
                result["context"] = self.chunker.get_chunk_with_context(
                    chunks, chunk_id, context_chunks=1
                )

            return result

        except Exception as e:
            logger.error(f"Failed to get chunk: {e}")
            return {"error": str(e)}

    async def search_files(
        self,
        session_id: str,
        query: str
    ) -> List[Dict]:
        """
        Search for keyword in session files

        Args:
            session_id: Session ID
            query: Search keyword

        Returns:
            List of matching chunks
        """
        session = self.db.query(FileAssistantSession).filter(
            FileAssistantSession.id == session_id
        ).first()

        if not session:
            return []

        results = []
        files_json = session.files_json or []

        for file_info in files_json:
            file_path = file_info.get("path")
            if not file_path:
                continue

            try:
                content, _ = await extract_text_from_file(file_path)
                file_type = get_file_type(file_path)

                chunks = self.chunker.chunk_text(content, file_type)
                matches = self.chunker.search_chunks(chunks, query)

                for match in matches:
                    results.append({
                        "file_path": file_path,
                        "chunk_id": match["chunk_id"],
                        "matching_lines": match.get("matching_lines", [])
                    })

            except Exception as e:
                logger.warning(f"Failed to search {file_path}: {e}")
                continue

        return results

    def estimate_context_tokens(self, text: str) -> int:
        """Estimate tokens in text"""
        return self.ollama.estimate_tokens(text)

    def prune_old_messages(
        self,
        session_id: str,
        keep_count: int = 10
    ) -> int:
        """
        Remove old messages to keep context manageable

        Args:
            session_id: Session ID
            keep_count: How many recent messages to keep

        Returns:
            Number of messages deleted
        """
        messages = self.db.query(FileAssistantMessage).filter(
            FileAssistantMessage.session_id == session_id
        ).order_by(FileAssistantMessage.created_at.desc()).all()

        if len(messages) <= keep_count:
            return 0

        to_delete = messages[keep_count:]
        deleted_count = len(to_delete)

        for msg in to_delete:
            self.db.delete(msg)

        self.db.commit()
        logger.info(f"Pruned {deleted_count} old messages from session {session_id}")

        return deleted_count
