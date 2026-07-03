"""
Ollama Local AI Client
Handles communication with local Ollama instance
"""

import httpx
import asyncio
import json
import logging
from typing import AsyncGenerator, Optional, List, Dict, Callable
from datetime import datetime

logger = logging.getLogger(__name__)


class OllamaClient:
    """Client for Ollama local AI"""

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        timeout: int = 120,
        max_retries: int = 2
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries

    async def health_check(self) -> bool:
        """Check if Ollama is running and responsive"""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(f"{self.base_url}/api/tags")
                return response.status_code == 200
        except Exception as e:
            logger.error(f"Ollama health check failed: {e}")
            return False

    async def get_available_models(self) -> List[str]:
        """Get list of available models"""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(f"{self.base_url}/api/tags")
                if response.status_code == 200:
                    data = response.json()
                    models = data.get("models", [])
                    return [m.get("name", "") for m in models]
        except Exception as e:
            logger.error(f"Failed to get models: {e}")
        return []

    async def generate(
        self,
        model: str,
        prompt: str,
        context: Optional[str] = None,
        on_chunk: Optional[Callable[[str], None]] = None,
        stream: bool = True
    ) -> str:
        """
        Generate response from Ollama model

        Args:
            model: Model name (e.g., "llama3.2")
            prompt: User's question/prompt
            context: Optional file content or summary
            on_chunk: Optional callback for streaming chunks
            stream: Whether to stream response

        Returns:
            Full generated response text
        """
        # Build the full prompt with context
        full_prompt = prompt
        if context:
            full_prompt = f"{context}\n\n---\n\nQuestion: {prompt}"

        payload = {
            "model": model,
            "prompt": full_prompt,
            "stream": stream,
            "temperature": 0.7,
            "top_p": 0.9,
        }

        full_response = ""
        retry_count = 0

        while retry_count <= self.max_retries:
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    async with client.stream(
                        "POST",
                        f"{self.base_url}/api/generate",
                        json=payload
                    ) as response:
                        if response.status_code != 200:
                            raise Exception(f"Ollama error: {response.status_code}")

                        async for line in response.aiter_lines():
                            if not line:
                                continue

                            try:
                                chunk_data = json.loads(line)
                                chunk_text = chunk_data.get("response", "")
                                full_response += chunk_text

                                if on_chunk:
                                    on_chunk(chunk_text)

                                # Check if done
                                if chunk_data.get("done", False):
                                    break

                            except json.JSONDecodeError:
                                logger.warning(f"Failed to parse chunk: {line}")
                                continue

                return full_response.strip()

            except asyncio.TimeoutError:
                retry_count += 1
                if retry_count > self.max_retries:
                    raise Exception(f"Ollama timeout after {self.max_retries} retries")
                await asyncio.sleep(1)

            except Exception as e:
                retry_count += 1
                if retry_count > self.max_retries:
                    raise
                logger.warning(f"Ollama error (retry {retry_count}): {e}")
                await asyncio.sleep(1)

        return full_response.strip()

    async def generate_stream(
        self,
        model: str,
        prompt: str,
        context: Optional[str] = None,
    ) -> AsyncGenerator[str, None]:
        """
        Stream response chunks from Ollama

        Yields:
            Partial response text chunks
        """
        full_prompt = prompt
        if context:
            full_prompt = f"{context}\n\n---\n\nQuestion: {prompt}"

        payload = {
            "model": model,
            "prompt": full_prompt,
            "stream": True,
            "temperature": 0.7,
            "top_p": 0.9,
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                async with client.stream(
                    "POST",
                    f"{self.base_url}/api/generate",
                    json=payload
                ) as response:
                    if response.status_code != 200:
                        raise Exception(f"Ollama error: {response.status_code}")

                    async for line in response.aiter_lines():
                        if not line:
                            continue

                        try:
                            chunk_data = json.loads(line)
                            chunk_text = chunk_data.get("response", "")

                            if chunk_text:
                                yield chunk_text

                            if chunk_data.get("done", False):
                                break

                        except json.JSONDecodeError:
                            logger.warning(f"Failed to parse chunk: {line}")
                            continue

        except Exception as e:
            logger.error(f"Streaming error: {e}")
            yield f"\n\n[Error: {str(e)}]"

    def estimate_tokens(self, text: str) -> int:
        """
        Rough estimate of token count
        Ollama/LLaMA typically ~1 token per 4 chars
        """
        return max(1, len(text) // 4)

    async def embed_text(self, model: str, text: str) -> Optional[List[float]]:
        """
        Get embeddings for text (optional feature)
        Useful for semantic search
        """
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    f"{self.base_url}/api/embed",
                    json={"model": model, "input": text}
                )
                if response.status_code == 200:
                    data = response.json()
                    return data.get("embedding")
        except Exception as e:
            logger.warning(f"Failed to get embeddings: {e}")
        return None


# Global Ollama client instance
_ollama_client = None


def get_ollama_client(base_url: str = "http://localhost:11434") -> OllamaClient:
    """Get or create Ollama client"""
    global _ollama_client
    if _ollama_client is None:
        _ollama_client = OllamaClient(base_url=base_url)
    return _ollama_client


async def test_ollama_connection():
    """Test Ollama connection"""
    client = get_ollama_client()
    is_healthy = await client.health_check()
    if not is_healthy:
        logger.error("Ollama is not responding. Ensure it's running with: ollama serve")
    return is_healthy
