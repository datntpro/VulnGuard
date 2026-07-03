"""
Chunker Service
Break large files into logical chunks (respecting code/syntax boundaries)
"""

import logging
import re
from typing import List, Dict

logger = logging.getLogger(__name__)

# Approximate chunk size in bytes (~1000 tokens)
TARGET_CHUNK_SIZE = 4096

# Language-specific patterns for intelligent chunking
CHUNK_PATTERNS = {
    "python": r'^(class |def |\S+ = )',
    "javascript": r'^(class |function |const |let |var |export |async )',
    "typescript": r'^(class |function |interface |type |const |let |var |export |async )',
    "java": r'^(public |private |protected |class |interface |enum |static )',
    "go": r'^(func |type |const |var |package )',
    "rust": r'^(fn |pub |impl |struct |enum |trait |use )',
}


class FileChunker:
    """Break files into chunks"""

    @staticmethod
    def chunk_text(
        content: str,
        file_type: str,
        chunk_size: int = TARGET_CHUNK_SIZE,
        overlap: int = 200
    ) -> List[Dict]:
        """
        Break content into logical chunks

        Args:
            content: Full file content
            file_type: Type of file (python, javascript, etc.)
            chunk_size: Target chunk size in bytes
            overlap: Overlap between chunks in bytes

        Returns:
            List of chunks with metadata
        """
        if not content:
            return []

        lines = content.split('\n')
        chunks = []
        current_chunk_lines = []
        current_chunk_size = 0
        start_line = 1

        # Get pattern for this file type
        pattern = CHUNK_PATTERNS.get(file_type)

        for i, line in enumerate(lines):
            line_with_newline = line + '\n'
            line_size = len(line_with_newline.encode('utf-8'))

            # Try to break at boundaries if we exceed chunk size
            if current_chunk_size + line_size > chunk_size and current_chunk_lines:
                # Check if this line is a boundary (function/class definition)
                is_boundary = pattern and re.match(pattern, line.strip()) if pattern else False

                if is_boundary or current_chunk_size > chunk_size:
                    # Save current chunk
                    chunk_text = '\n'.join(current_chunk_lines)
                    chunk = {
                        "chunk_id": f"chunk_{len(chunks)+1:03d}",
                        "start_line": start_line,
                        "end_line": start_line + len(current_chunk_lines) - 1,
                        "line_count": len(current_chunk_lines),
                        "size_bytes": len(chunk_text.encode('utf-8')),
                        "content": chunk_text
                    }
                    chunks.append(chunk)

                    # Start new chunk with overlap
                    overlap_lines = max(1, int(overlap / 50))  # Rough estimate
                    current_chunk_lines = current_chunk_lines[-overlap_lines:] if overlap_lines else []
                    current_chunk_size = sum(len(l.encode('utf-8')) + 1 for l in current_chunk_lines)
                    start_line = i + 1 - len(current_chunk_lines)

            current_chunk_lines.append(line)
            current_chunk_size += line_size

        # Add final chunk
        if current_chunk_lines:
            chunk_text = '\n'.join(current_chunk_lines)
            chunk = {
                "chunk_id": f"chunk_{len(chunks)+1:03d}",
                "start_line": start_line,
                "end_line": start_line + len(current_chunk_lines) - 1,
                "line_count": len(current_chunk_lines),
                "size_bytes": len(chunk_text.encode('utf-8')),
                "content": chunk_text
            }
            chunks.append(chunk)

        logger.info(f"Created {len(chunks)} chunks from {len(lines)} lines")
        return chunks

    @staticmethod
    def get_chunk_by_line(
        chunks: List[Dict],
        line_number: int
    ) -> Dict:
        """
        Find chunk containing given line number

        Args:
            chunks: List of chunks
            line_number: Line number to find

        Returns:
            Chunk dict or empty dict if not found
        """
        for chunk in chunks:
            if chunk["start_line"] <= line_number <= chunk["end_line"]:
                return chunk
        return {}

    @staticmethod
    def get_chunk_with_context(
        chunks: List[Dict],
        chunk_id: str,
        context_chunks: int = 1
    ) -> str:
        """
        Get chunk with surrounding context

        Args:
            chunks: List of chunks
            chunk_id: Chunk ID (chunk_001, etc.)
            context_chunks: How many surrounding chunks to include

        Returns:
            Combined chunk text with context
        """
        chunk_idx = None
        for i, chunk in enumerate(chunks):
            if chunk["chunk_id"] == chunk_id:
                chunk_idx = i
                break

        if chunk_idx is None:
            return ""

        # Get context chunks
        start_idx = max(0, chunk_idx - context_chunks)
        end_idx = min(len(chunks), chunk_idx + context_chunks + 1)

        combined = []
        for i in range(start_idx, end_idx):
            chunk = chunks[i]
            marker = ">>>" if i == chunk_idx else "..."
            combined.append(f"{marker} {chunk['chunk_id']} (lines {chunk['start_line']}-{chunk['end_line']})")
            combined.append(chunk["content"])
            combined.append("")

        return '\n'.join(combined)

    @staticmethod
    def search_chunks(
        chunks: List[Dict],
        query: str,
        case_sensitive: bool = False
    ) -> List[Dict]:
        """
        Search for keyword in chunks

        Args:
            chunks: List of chunks
            query: Search keyword
            case_sensitive: Whether search is case-sensitive

        Returns:
            List of matching chunks with context
        """
        results = []
        search_query = query if case_sensitive else query.lower()

        for chunk in chunks:
            chunk_content = chunk["content"] if case_sensitive else chunk["content"].lower()

            if search_query in chunk_content:
                # Extract lines containing the query
                lines = chunk["content"].split('\n')
                matching_lines = [
                    (i + chunk["start_line"], line) for i, line in enumerate(lines)
                    if (line if case_sensitive else line.lower()).find(search_query) != -1
                ]

                results.append({
                    **chunk,
                    "matching_lines": matching_lines
                })

        return results

    @staticmethod
    def create_chunk_index(chunks: List[Dict]) -> List[Dict]:
        """
        Create index metadata for all chunks (without content)

        Args:
            chunks: List of chunks

        Returns:
            List of chunk metadata
        """
        return [
            {
                "chunk_id": c["chunk_id"],
                "start_line": c["start_line"],
                "end_line": c["end_line"],
                "line_count": c["line_count"],
                "size_bytes": c["size_bytes"]
            }
            for c in chunks
        ]
