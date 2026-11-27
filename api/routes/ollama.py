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
from api.services import runtime_settings

router = APIRouter(prefix="/api/ollama", tags=["ollama"])


def _url() -> str:
    """Endpoint Ollama hiệu lực (override người dùng > env > mặc định)."""
    return runtime_settings.ollama_url()


def get_active_model() -> str:
    return runtime_settings.ollama_model()


def get_active_vision_model() -> str:
    return runtime_settings.ollama_vision_model()


class PullRequest(BaseModel):
    model: str


class EndpointRequest(BaseModel):
    url: str = ""


@router.get("/endpoint")
def get_endpoint():
    """Endpoint Ollama hiện tại (local hoặc IP máy khác — không bắt buộc Docker)."""
    return {"url": runtime_settings.ollama_url(),
            "custom": runtime_settings.ollama_url_is_custom(),
            "default": settings.ollama_url}


@router.put("/endpoint")
async def set_endpoint(payload: EndpointRequest):
    """Đặt endpoint Ollama. Rỗng = về mặc định. Kiểm tra kết nối trước khi lưu."""
    url = (payload.url or "").strip().rstrip("/")
    if url and not (url.startswith("http://") or url.startswith("https://")):
        raise HTTPException(status_code=400, detail="URL phải bắt đầu bằng http:// hoặc https:// (ví dụ http://192.168.1.50:11434)")
    test_url = url or settings.ollama_url
    try:
        async with httpx.AsyncClient(timeout=6, trust_env=False) as client:
            r = await client.get(f"{test_url}/api/tags")
            r.raise_for_status()
            models = [m["name"] for m in r.json().get("models", [])]
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Không kết nối được Ollama tại {test_url}: {e}")
    runtime_settings.set_ollama(url=url or None)
    return {"ok": True, "url": runtime_settings.ollama_url(), "models": models}


class SetModelRequest(BaseModel):
    model: str


@router.get("/health")
async def ollama_health():
    """Kiểm tra Ollama service có đang chạy không."""
    try:
        async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
            r = await client.get(f"{_url()}/api/tags")
            r.raise_for_status()
            active = get_active_model()
            names = {m.get("name", "") for m in (r.json().get("models") or [])}
            installed = active in names or (":" not in active and f"{active}:latest" in names)
            return {"status": "ok", "ollama_url": _url(), "active_model": active,
                    "model_installed": installed,
                    "custom_endpoint": runtime_settings.ollama_url_is_custom()}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Ollama không khả dụng: {e}")


@router.get("/models")
async def list_models():
    """Danh sách models đã cài trong Ollama."""
    try:
        async with httpx.AsyncClient(timeout=10, trust_env=False) as client:
            r = await client.get(f"{_url()}/api/tags")
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
                    f"{_url()}/api/pull",
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
                f"{_url()}/api/delete",
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
    model = payload.model.strip()

    # Kiểm tra model có tồn tại không
    try:
        async with httpx.AsyncClient(timeout=10, trust_env=False) as client:
            r = await client.get(f"{_url()}/api/tags")
            data = r.json()
            installed = [m["name"] for m in data.get("models", [])]
            if model not in installed:
                raise HTTPException(status_code=400, detail=f"Model '{model}' chưa được pull. Hãy pull trước.")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Không kết nối được Ollama: {e}")

    runtime_settings.set_ollama(model=model)
    return {"message": f"Đã đổi active model thành '{model}'", "active_model": model}


@router.get("/vision-model")
async def get_vision_model():
    """Vision model hiện tại + danh sách model đã cài (để UI chọn)."""
    installed = []
    try:
        async with httpx.AsyncClient(timeout=10, trust_env=False) as client:
            r = await client.get(f"{_url()}/api/tags")
            installed = [m["name"] for m in r.json().get("models", [])]
    except Exception:
        pass
    return {"vision_model": get_active_vision_model(), "installed": installed}


@router.put("/vision-model")
async def set_vision_model(payload: SetModelRequest):
    """Đổi vision model dùng để đọc ảnh/sơ đồ trong tài liệu."""
    model = payload.model.strip()
    try:
        async with httpx.AsyncClient(timeout=10, trust_env=False) as client:
            r = await client.get(f"{_url()}/api/tags")
            installed = [m["name"] for m in r.json().get("models", [])]
            if model not in installed:
                raise HTTPException(status_code=400, detail=f"Vision model '{model}' chưa được pull. Hãy pull trước.")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Không kết nối được Ollama: {e}")
    runtime_settings.set_ollama(vision_model=model)
    return {"message": f"Đã đổi vision model thành '{model}'", "vision_model": model}


# Expose active model cho scanner dùng
def get_current_model() -> str:
    return get_active_model()
