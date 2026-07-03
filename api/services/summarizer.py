"""
Summarizer Service
Generate summaries and chunk indexes for files using Ollama
"""

import logging
import hashlib
from typing import Tuple, List, Dict, Optional
from api.services.ollama_client import get_ollama_client
from api.services.chunker import FileChunker

logger = logging.getLogger(__name__)

# Summarization prompt template
SUMMARIZE_PROMPT = """Please summarize the following {file_type} file in 200-300 words. Focus on:
- Main purpose and what the code/document does
- Key functions, classes, or sections
- Important dependencies or inputs
- Any critical warnings or important notes
- High-level architecture or structure

File content:
{content}

Summary:"""


class FileSummarizer:
    """Generate file summaries and chunk indexes"""

    def __init__(self, ollama_model: str = "llama3.2"):
        self.model = ollama_model
        self.ollama = get_ollama_client()

    async def summarize_file(
        self,
        file_content: str,
        file_type: str,
        file_path: str
    ) -> Tuple[str, List[Dict], str]:
        """
        Summarize file and create chunk index

        Args:
            file_content: Full file content
            file_type: File type (python, javascript, etc.)
            file_path: Original file path (for hashing)

        Returns:
            Tuple of (summary, chunk_index, file_hash)
        """
        # Calculate file hash
        file_hash = hashlib.sha256(file_content.encode()).hexdigest()

        # Generate summary
        logger.info(f"Generating summary for {file_path}")
        prompt = SUMMARIZE_PROMPT.format(
            file_type=file_type or "code",
            content=file_content[:3000]  # Limit to first 3000 chars for summarization
        )

        try:
            summary = await self.ollama.generate(
                model=self.model,
                prompt=prompt,
                stream=False
            )
        except Exception as e:
            logger.error(f"Summarization failed: {e}")
            # Fallback: create basic summary
            lines = file_content.split('\n')
            summary = f"File with {len(lines)} lines. First 100 chars: {file_content[:100]}"

        # Create chunk index if file is large
        lines = file_content.split('\n')
        content_size = len(file_content.encode('utf-8'))

        chunk_index = []
        if content_size > 51200:  # 50KB threshold
            logger.info(f"File large ({content_size} bytes), creating chunk index")
            chunks = FileChunker.chunk_text(file_content, file_type)
            chunk_index = FileChunker.create_chunk_index(chunks)
            logger.info(f"Created {len(chunk_index)} chunks")

        return summary, chunk_index, file_hash

    async def answer_question(
        self,
        question: str,
        file_content: str,
        file_summary: Optional[str] = None,
        file_type: Optional[str] = None
    ) -> str:
        """
        Answer question about file using Ollama

        Args:
            question: User's question
            file_content: File content or relevant chunk
            file_summary: Optional summary of file
            file_type: File type hint

        Returns:
            Answer from AI
        """
        # Build context
        context = ""
        if file_summary:
            context += f"File Summary:\n{file_summary}\n\n"

        context += f"File Content ({file_type or 'text'}):\n{file_content}\n\n"

        prompt = f"""{context}---

Question: {question}

Please answer the question based on the file content above. Be specific and reference line numbers or function names where relevant."""

        try:
            answer = await self.ollama.generate(
                model=self.model,
                prompt=prompt,
                stream=False
            )
            return answer
        except Exception as e:
            logger.error(f"Failed to answer question: {e}")
            return f"Error: {str(e)}"

    async def compare_files(
        self,
        file1_content: str,
        file1_name: str,
        file2_content: str,
        file2_name: str,
        question: Optional[str] = None
    ) -> str:
        """
        Compare two files and answer question about their relationship

        Args:
            file1_content: First file content
            file1_name: First file name
            file2_content: Second file content
            file2_name: Second file name
            question: Specific question about the files

        Returns:
            Comparison result
        """
        comparison_prompt = f"""Compare the following two files and explain their relationship and differences:

File 1: {file1_name}
```
{file1_content[:2000]}
...
```

File 2: {file2_name}
```
{file2_content[:2000]}
...
```

{f'Focus on: {question}' if question else ''}

Provide a detailed analysis of:
- How these files interact
- Key differences in implementation or structure
- Dependencies or integration points
- Any potential issues or improvements
"""

        try:
            result = await self.ollama.generate(
                model=self.model,
                prompt=comparison_prompt,
                stream=False
            )
            return result
        except Exception as e:
            logger.error(f"Comparison failed: {e}")
            return f"Error: {str(e)}"

    @staticmethod
    def create_summary_context(
        summary: str,
        chunks: Optional[List[Dict]] = None,
        limit_tokens: int = 2000
    ) -> str:
        """
        Create context string for chat (summary + chunk info)

        Args:
            summary: File summary
            chunks: Optional chunk index
            limit_tokens: Token limit for context

        Returns:
            Formatted context string
        """
        context_parts = [f"Summary:\n{summary}"]

        if chunks:
            chunk_list = "\n".join([
                f"- chunk_{i:03d}: lines {c['start_line']}-{c['end_line']}"
                for i, c in enumerate(chunks[:20])  # Show first 20 chunks
            ])
            context_parts.append(f"\nAvailable chunks:\n{chunk_list}")

            if len(chunks) > 20:
                context_parts.append(f"\n... and {len(chunks) - 20} more chunks")

        return "\n".join(context_parts)

    @staticmethod
    def estimate_summary_quality(
        original_content: str,
        summary: str
    ) -> Dict:
        """
        Estimate quality of summary

        Args:
            original_content: Original file content
            summary: Generated summary

        Returns:
            Quality metrics dict
        """
        orig_words = len(original_content.split())
        summary_words = len(summary.split())
        compression_ratio = summary_words / orig_words if orig_words > 0 else 0

        # Quality heuristics
        quality_score = 1.0
        issues = []

        if compression_ratio > 0.5:
            quality_score -= 0.2
            issues.append("Summary is too long (>50% of original)")

        if compression_ratio < 0.05:
            quality_score -= 0.1
            issues.append("Summary is very short (<5% of original)")

        if len(summary) < 50:
            quality_score -= 0.3
            issues.append("Summary is too brief")

        return {
            "quality_score": max(0, quality_score),
            "compression_ratio": compression_ratio,
            "original_words": orig_words,
            "summary_words": summary_words,
            "issues": issues
        }
