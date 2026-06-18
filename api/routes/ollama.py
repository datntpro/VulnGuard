"""
Ollama Model Management API
- List installed models
- Pull new model (streaming progress)
- Delete model
- Get/Set active model
- Health check
"""
import httpx
import json
import asyncio
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional

from api.config import settings

router = APIRouter(prefix="/api/ollama", tags=["ollama"])

OLLAMA_URL = settings.ollama_url

# In-memory active model (persists per session, overrides env default)
_active_model: Optional[str] = None


def get_active_model() -> str:
    return _active_model or settings.ollama_model


class PullRequest(BaseModel):
    model: str


class SetModelRequest(BaseModel):
    model: str


@router.get("/health")
async def ollama_health():
    """Kiểm tra Ollama service có đang chạy không."""
    try:
        async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
            r = await client.get(f"{OLLAMA_URL}/api/tags")
            r.raise_for_status()
            return {"status": "ok", "ollama_url": OLLAMA_URL, "active_model": get_active_model()}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Ollama không khả dụng: {e}")


@router.get("/models")
async def list_models():
    """Danh sách models đã cài trong Ollama."""
    try:
        async with httpx.AsyncClient(timeout=10, trust_env=False) as client:
            r = await client.get(f"{OLLAMA_URL}/api/tags")
            r.raise_for_status()
            data = r.json()
            models = data.get("models", [])
            return {
                "active_model": get_active_model(),
                "models": [
                    {
                        "name": m["name"],
                        "size_gb": round(m.get("size", 0) / 1e9, 1),
                        "modified_at": m.get("modified_at", ""),
                        "is_active": m["name"] == get_active_model(),
                    }
                    for m in models
                ],
            }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.post("/pull")
async def pull_model(payload: PullRequest):
    """Pull một model từ Ollama registry — streaming progress."""
    model = payload.model.strip()
    if not model:
        raise HTTPException(status_code=400, detail="Model name không được để trống")

    async def stream_pull():
        try:
            async with httpx.AsyncClient(timeout=None, trust_env=False) as client:  # No timeout khi pull
                async with client.stream(
                    "POST",
                    f"{OLLAMA_URL}/api/pull",
                    json={"name": model, "stream": True},
                ) as response:
                    async for line in response.aiter_lines():
                        if line.strip():
                            yield line + "\n"
        except Exception as e:
            yield json.dumps({"error": str(e)}) + "\n"

    return StreamingResponse(stream_pull(), media_type="application/x-ndjson")


@router.delete("/models/{model_name:path}")
async def delete_model(model_name: str):
    """Xóa một model khỏi Ollama."""
    if model_name == get_active_model():
        raise HTTPException(status_code=400, detail="Không thể xóa model đang active. Đổi model khác trước.")
    try:
        async with httpx.AsyncClient(timeout=30, trust_env=False) as client:
            r = await client.request(
                "DELETE",
                f"{OLLAMA_URL}/api/delete",
                json={"name": model_name},
            )
            if r.status_code == 404:
                raise HTTPException(status_code=404, detail=f"Model '{model_name}' không tồn tại")
            r.raise_for_status()
            return {"message": f"Đã xóa model '{model_name}'"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/active-model")
async def set_active_model(payload: SetModelRequest):
    """Đổi model đang dùng để phân tích vulnerability."""
    global _active_model
    model = payload.model.strip()

    # Kiểm tra model có tồn tại không
    try:
        async with httpx.AsyncClient(timeout=10, trust_env=False) as client:
            r = await client.get(f"{OLLAMA_URL}/api/tags")
            data = r.json()
            installed = [m["name"] for m in data.get("models", [])]
            if model not in installed:
                raise HTTPException(status_code=400, detail=f"Model '{model}' chưa được pull. Hãy pull trước.")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Không kết nối được Ollama: {e}")

    _active_model = model

    # Cập nhật env var để scanner dùng model mới
    import os
    os.environ["OLLAMA_MODEL"] = model

    return {"message": f"Đã đổi active model thành '{model}'", "active_model": model}


# Expose active model cho scanner dùng
def get_current_model() -> str:
    return get_active_model()
