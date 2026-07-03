"""
Co-work API — AI coding assistant đọc/sửa file qua Ollama.

Container này KHÔNG tự đụng filesystem của host — mọi việc đọc/ghi file
và chạy command đều proxy sang coworker_host (service chạy native trên
máy host, xem coworker_host/app.py), giống cách OLLAMA_URL trỏ về
host.docker.internal. Container chỉ chịu trách nhiệm:
  1. Proxy folder/file/exec request sang coworker_host
  2. Gọi Ollama để sinh nội dung file mới theo yêu cầu, rồi tính diff

An toàn: endpoint /fs/apply và /fs/exec đều yêu cầu người dùng xác nhận
ở UI trước khi gọi (xem web/index.html) — AI suggest KHÔNG tự ghi file.
"""
import difflib
import json
import logging
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from api.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/coworker", tags=["coworker"])

COWORKER_URL = settings.coworker_url
COWORKER_TIMEOUT = settings.coworker_timeout


async def _host_request(method: str, path: str, **kwargs):
    """Gọi sang coworker_host, map lỗi kết nối thành 503 dễ hiểu cho UI."""
    try:
        async with httpx.AsyncClient(timeout=COWORKER_TIMEOUT, trust_env=False) as client:
            r = await client.request(method, f"{COWORKER_URL}{path}", **kwargs)
            if r.status_code >= 400:
                try:
                    detail = r.json().get("detail", r.text)
                except Exception:
                    detail = r.text
                raise HTTPException(status_code=r.status_code, detail=detail)
            return r.json()
    except HTTPException:
        raise
    except httpx.ConnectError:
        raise HTTPException(
            status_code=503,
            detail=(
                "Không kết nối được Coworker Host Service "
                f"({COWORKER_URL}). Hãy chạy: bash coworker_host/run.sh trên máy host."
            ),
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Lỗi gọi Coworker Host: {e}")


# ─────────────────────────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────────────────────────
class AddFolderRequest(BaseModel):
    path: str
    label: Optional[str] = None


class SuggestRequest(BaseModel):
    folder_id: str
    path: str
    instruction: str


class ApplyRequest(BaseModel):
    folder_id: str
    path: str
    content: str
    create: bool = False


class ExecRequest(BaseModel):
    folder_id: str
    command: str
    cwd: str = ""
    confirm: bool = False


# ─────────────────────────────────────────────────────────────
# Health / Folders / Filesystem — proxy thuần
# ─────────────────────────────────────────────────────────────
@router.get("/health")
async def coworker_health():
    data = await _host_request("GET", "/health")
    return {**data, "coworker_url": COWORKER_URL}


@router.get("/folders")
async def list_folders():
    return await _host_request("GET", "/folders")


@router.post("/folders")
async def add_folder(req: AddFolderRequest):
    return await _host_request("POST", "/folders", json=req.model_dump())


@router.delete("/folders/{folder_id}")
async def remove_folder(folder_id: str):
    return await _host_request("DELETE", f"/folders/{folder_id}")


@router.get("/fs/tree")
async def fs_tree(folder_id: str, path: str = ""):
    return await _host_request("GET", "/fs/tree", params={"folder_id": folder_id, "path": path})


@router.get("/fs/file")
async def fs_file(folder_id: str, path: str):
    return await _host_request("GET", "/fs/file", params={"folder_id": folder_id, "path": path})


@router.get("/whitelist")
async def get_whitelist():
    return await _host_request("GET", "/whitelist")


# ─────────────────────────────────────────────────────────────
# AI Suggest — đọc file, gọi Ollama, trả về diff (KHÔNG tự ghi)
# ─────────────────────────────────────────────────────────────
SUGGEST_PROMPT_TEMPLATE = """Bạn là một AI coding assistant đang hỗ trợ sửa code trực tiếp trong project của developer.

## File: {file_path}
## Nội dung hiện tại:
```
{content}
```

## Yêu cầu của developer:
{instruction}

## Hướng dẫn trả lời (BẮT BUỘC):
- Trả về TOÀN BỘ nội dung file SAU KHI sửa — không phải diff, không phải chỉ phần thay đổi.
- Đặt toàn bộ code trong DUY NHẤT 1 code block (```...```), không thêm giải thích, không thêm text nào ngoài code block.
- Giữ nguyên style code, comment, indentation hiện có ở những phần không liên quan đến yêu cầu.
- Nếu yêu cầu không rõ ràng hoặc không thể thực hiện được, trả về nguyên file gốc không đổi.
"""


def _extract_code_block(text: str) -> str:
    text = text.strip()
    start = text.find("```")
    if start == -1:
        return text
    # Bỏ qua language tag ngay sau ``` đầu tiên (vd ```python\n)
    first_newline = text.find("\n", start)
    if first_newline == -1:
        return text
    end = text.rfind("```")
    if end <= first_newline:
        return text[first_newline + 1:].strip()
    return text[first_newline + 1:end].strip()


async def _call_ollama(prompt: str) -> str:
    from api.routes.ollama import get_active_model
    model = get_active_model()
    timeout = httpx.Timeout(connect=10.0, read=float(settings.ollama_timeout), write=10.0, pool=5.0)
    async with httpx.AsyncClient(timeout=timeout, trust_env=False) as client:
        r = await client.post(
            f"{settings.ollama_url}/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1, "top_p": 0.9, "num_predict": 4096},
            },
        )
        r.raise_for_status()
        return r.json().get("response", ""), model


@router.post("/fs/suggest")
async def fs_suggest(req: SuggestRequest):
    file_data = await _host_request("GET", "/fs/file", params={"folder_id": req.folder_id, "path": req.path})
    if file_data.get("binary"):
        raise HTTPException(status_code=400, detail="File binary — không hỗ trợ AI suggest cho file này")

    old_content = file_data.get("content") or ""
    prompt = SUGGEST_PROMPT_TEMPLATE.format(
        file_path=req.path,
        content=old_content[:8000],  # giới hạn context cho model local
        instruction=req.instruction,
    )
    try:
        raw_response, model = await _call_ollama(prompt)
    except Exception as e:
        logger.error(f"Coworker AI suggest failed: {e}")
        raise HTTPException(status_code=503, detail=f"Không gọi được Ollama: {e}")

    new_content = _extract_code_block(raw_response)
    diff = "".join(
        difflib.unified_diff(
            old_content.splitlines(keepends=True),
            new_content.splitlines(keepends=True),
            fromfile=req.path,
            tofile=f"{req.path} (AI suggestion)",
        )
    )

    return {
        "path": req.path,
        "model": model,
        "old_content": old_content,
        "new_content": new_content,
        "diff": diff,
        "unchanged": old_content.strip() == new_content.strip(),
    }


# ─────────────────────────────────────────────────────────────
# Apply (ghi file) / Exec — proxy, nhưng đây là điểm "ghi/chạy lệnh thật"
# Frontend PHẢI hỏi xác nhận người dùng trước khi gọi 2 API này.
# ─────────────────────────────────────────────────────────────
@router.post("/fs/apply")
async def fs_apply(req: ApplyRequest):
    return await _host_request("POST", "/fs/file", json=req.model_dump())


@router.post("/fs/exec")
async def fs_exec(req: ExecRequest):
    return await _host_request("POST", "/fs/exec", json=req.model_dump())
