"""
Co-work Agent — agent hỏi-đáp & giao việc chạy trên LOCAL LLM (Ollama).

Khác với /api/coworker/fs/suggest (one-shot sửa 1 file), module này là một
VÒNG LẶP AGENT kiểu ReAct: local LLM tự quyết định từng bước (đọc file nào,
sửa gì, chạy lệnh gì) qua nhiều vòng cho tới khi hoàn thành yêu cầu.

Giao thức (model trả về DUY NHẤT 1 JSON mỗi lượt):
    {"thought": "...", "action": "<tên tool>", "args": {...}}

Tools:
  - list_dir   {path}                 → liệt kê cây thư mục (READ-ONLY, tự chạy)
  - read_file  {path}                 → đọc nội dung file (READ-ONLY, tự chạy)
  - write_file {path, content, create}→ GHI file  (DỪNG, chờ user confirm)
  - exec       {command, cwd}         → CHẠY lệnh (DỪNG, chờ user confirm)
  - final      {answer}               → kết thúc, trả lời người dùng

An toàn:
  - list_dir / read_file chạy tự động phía server (không đụng gì tới hệ thống).
  - write_file / exec KHÔNG bao giờ tự chạy. Server dừng lại và trả về
    pending action; chỉ khi client gửi lại `approved` thì side-effect mới
    thực thi (proxy qua coworker_host với confirm=true).

Tất cả filesystem/exec đều đi qua coworker_host (native trên máy host),
giống như các endpoint trong coworker.py.
"""
import base64
import json
import logging
import os
import re
import tempfile
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.database import get_db

from api.config import settings
from api.routes.coworker import _host_request  # tái dùng proxy sang coworker_host

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/coworker/agent", tags=["coworker-agent"])

MAX_PARSE_RETRY = 3         # số lần thử lại khi model trả JSON sai định dạng
MAX_FILE_CHARS = 12000      # cắt nội dung file đưa vào context model local
MAX_OBS_CHARS = 6000        # cắt observation (vd output lệnh) cho gọn context
READ_ONLY_ACTIONS = {"list_dir", "read_file", "find_files"}
WRITE_ACTIONS = {"write_file", "exec"}
DOC_EXTS = {".docx", ".pdf"}  # file tài liệu cần trích xuất text (không đọc thô được)


# ─────────────────────────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────────────────────────
class ChatMessage(BaseModel):
    role: str            # "user" | "assistant" | "system"
    content: str


class ApprovedAction(BaseModel):
    action: str          # "write_file" | "exec"
    args: Dict[str, Any]


class AgentStepRequest(BaseModel):
    folder_id: str
    messages: List[ChatMessage]
    approved: Optional[ApprovedAction] = None  # nếu có: thực thi side-effect rồi loop tiếp
    skill_id: Optional[str] = None             # skill nghiệp vụ đang áp dụng (None = không)


class RouteRequest(BaseModel):
    messages: List[ChatMessage]                # dùng tin nhắn để chọn skill phù hợp


class SaveConversationRequest(BaseModel):
    id: Optional[str] = None                   # None = tạo mới; có = cập nhật
    title: Optional[str] = None
    folder_id: Optional[str] = None
    skill_id: Optional[str] = None
    messages: List[ChatMessage]


# ─────────────────────────────────────────────────────────────
# System prompt
# ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """Bạn là VulnGuard Co-work Agent — một AI coding assistant chạy CỤC BỘ, hỗ trợ developer làm việc trực tiếp trên project của họ.

Bạn làm việc theo VÒNG LẶP: mỗi lượt bạn chọn DUY NHẤT MỘT hành động. Hệ thống sẽ thực thi và trả lại kết quả (OBSERVATION) để bạn tiếp tục, cho tới khi xong việc.

## ĐỊNH DẠNG TRẢ LỜI — BẮT BUỘC
Mỗi lượt CHỈ trả về DUY NHẤT một object JSON, KHÔNG kèm bất kỳ chữ nào ngoài JSON, KHÔNG dùng markdown fence:
{"thought": "suy nghĩ ngắn gọn bằng tiếng Việt", "action": "<tên tool>", "args": { ... }}

## CÁC TOOL
- find_files  — TÌM file đệ quy ở MỌI cấp thư mục con. args: {"query": "từ khóa tên file, vd: .docx hoặc SAD"} (query="" = liệt kê toàn bộ file). DÙNG TOOL NÀY ĐẦU TIÊN khi cần tìm tài liệu/file mà chưa biết đường dẫn.
- list_dir   — liệt kê thư mục (CHỈ 1 cấp). args: {"path": "đường/dẫn/tương/đối"}  (path="" = gốc folder)
- read_file  — đọc 1 file.       args: {"path": "đường/dẫn/file"}  (đọc được cả tài liệu .docx và .pdf — hệ thống tự trích xuất text VÀ mô tả ảnh/sơ đồ nhúng bằng vision model; BẠN KHÔNG cần yêu cầu người dùng copy nội dung. Khi đánh giá, hãy xét cả phần "ẢNH/SƠ ĐỒ NHÚNG" nếu có)
- write_file — ghi/sửa 1 file.    args: {"path": "...", "content": "TOÀN BỘ nội dung file sau khi sửa", "create": false}
- exec       — chạy lệnh shell.   args: {"command": "lệnh", "cwd": ""}
- final      — kết thúc, trả lời.  args: {"answer": "câu trả lời cuối cùng cho người dùng"}

## QUY TẮC
1. Trước khi sửa file, hãy read_file để xem nội dung hiện tại. Đừng đoán.
2. write_file phải chứa TOÀN BỘ nội dung file sau khi sửa (không phải diff).
3. write_file và exec CẦN người dùng xác nhận — cứ đề xuất, hệ thống sẽ hỏi họ.
4. Khi đã đủ thông tin để trả lời hoặc đã hoàn thành yêu cầu, dùng action "final".
5. Suy nghĩ từng bước nhỏ. Mỗi lượt một hành động.
6. Tuyệt đối không bịa nội dung file — luôn dựa trên OBSERVATION thực tế.
7. KHÔNG bao giờ yêu cầu người dùng tự copy/paste nội dung file. Bạn có read_file để tự đọc, kể cả .docx/.pdf.
8. list_dir chỉ thấy 1 cấp. TUYỆT ĐỐI KHÔNG kết luận "không có tài liệu/file" nếu chưa chạy find_files (đệ quy toàn bộ thư mục con). Tài liệu thường nằm trong thư mục con như docs/, tài liệu/, specs/."""


# ─────────────────────────────────────────────────────────────
# Gọi Ollama (chat API, non-stream) — model lấy từ Settings
# ─────────────────────────────────────────────────────────────
async def _chat_ollama(messages: List[Dict[str, str]], skill_body: Optional[str] = None) -> tuple[str, str]:
    from api.routes.ollama import get_active_model
    model = get_active_model()
    system = SYSTEM_PROMPT
    if skill_body:
        system = f"{SYSTEM_PROMPT}\n\n# ── SKILL NGHIỆP VỤ ĐANG ÁP DỤNG ──\n{skill_body}"
    payload_messages = [{"role": "system", "content": system}] + messages
    timeout = httpx.Timeout(connect=10.0, read=float(settings.ollama_timeout), write=10.0, pool=5.0)
    async with httpx.AsyncClient(timeout=timeout, trust_env=False) as client:
        r = await client.post(
            f"{settings.ollama_url}/api/chat",
            json={
                "model": model,
                "messages": payload_messages,
                "stream": False,
                "options": {"temperature": 0.1, "top_p": 0.9, "num_predict": 4096},
            },
        )
        r.raise_for_status()
        data = r.json()
        return data.get("message", {}).get("content", ""), model


# ─────────────────────────────────────────────────────────────
# Parse JSON action từ output model (chịu lỗi: fence, prose thừa…)
# ─────────────────────────────────────────────────────────────
def parse_action(raw: str) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    text = raw.strip()

    # Bỏ markdown fence nếu có
    fence = re.search(r"```(?:json)?\s*(.+?)```", text, re.DOTALL)
    if fence:
        text = fence.group(1).strip()

    # Thử parse trực tiếp
    candidate = _try_json(text)
    if candidate is None:
        # Lấy object {...} cân bằng đầu tiên
        snippet = _extract_balanced_object(text)
        candidate = _try_json(snippet) if snippet else None

    if not isinstance(candidate, dict):
        return None
    if "action" not in candidate:
        return None
    candidate.setdefault("args", {})
    if not isinstance(candidate["args"], dict):
        candidate["args"] = {}
    return candidate


def _try_json(text: Optional[str]) -> Any:
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def _extract_balanced_object(text: str) -> Optional[str]:
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        else:
            if c == '"':
                in_str = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return text[start:i + 1]
    return None


# ─────────────────────────────────────────────────────────────
# Thực thi tool READ-ONLY (tự chạy)
# ─────────────────────────────────────────────────────────────
async def _run_readonly(folder_id: str, action: str, args: Dict[str, Any]) -> str:
    path = str(args.get("path", "") or "")
    if action == "list_dir":
        data = await _host_request("GET", "/fs/tree", params={"folder_id": folder_id, "path": path})
        entries = data.get("entries", data) if isinstance(data, dict) else data
        return json.dumps(entries, ensure_ascii=False)[:MAX_OBS_CHARS]
    if action == "find_files":
        query = str(args.get("query", "") or "")
        data = await _host_request("GET", "/fs/find",
                                   params={"folder_id": folder_id, "path": path, "query": query})
        files = data.get("files", []) if isinstance(data, dict) else []
        if not files:
            return (f"Không tìm thấy file nào khớp{f' với “{query}”' if query else ''} "
                    f"(đã quét đệ quy mọi thư mục con). Hãy thử find_files với query khác hoặc list_dir để xem cấu trúc.")
        head = "\n".join(files[:200])
        more = "" if not data.get("truncated") else "\n…[còn nữa, hãy lọc bằng query]"
        return f"Tìm thấy {len(files)} file (đường dẫn tương đối):\n{head}{more}"
    if action == "read_file":
        if not path:
            return "LỖI: thiếu 'path' cho read_file."
        ext = os.path.splitext(path)[1].lower()
        if ext in DOC_EXTS:
            return await _read_document(folder_id, path, ext)
        data = await _host_request("GET", "/fs/file", params={"folder_id": folder_id, "path": path})
        if data.get("binary"):
            return (f"LỖI: '{path}' là file binary, không đọc được dạng text. "
                    f"(Chỉ hỗ trợ trích xuất các định dạng tài liệu: {', '.join(sorted(DOC_EXTS))})")
        content = data.get("content") or ""
        truncated = content[:MAX_FILE_CHARS]
        suffix = "" if len(content) <= MAX_FILE_CHARS else "\n…[đã cắt bớt do file dài]…"
        return f"Nội dung '{path}':\n{truncated}{suffix}"
    return f"LỖI: tool read-only không hỗ trợ: {action}"


async def _read_document(folder_id: str, path: str, ext: str) -> str:
    """Lấy bytes tài liệu từ host (base64), trích text + mô tả ảnh nhúng (vision)."""
    from api.services.file_processor import extract_text_from_file, extract_images_from_file
    try:
        data = await _host_request("GET", "/fs/file_b64", params={"folder_id": folder_id, "path": path})
    except HTTPException as e:
        if e.status_code == 404:
            return (f"LỖI: coworker_host chưa hỗ trợ đọc tài liệu (endpoint /fs/file_b64). "
                    f"Hãy khởi động lại Coworker Host: bash coworker_host/run.sh")
        raise
    raw = base64.b64decode(data.get("b64", ""))
    tmp_path = None
    images: List[bytes] = []
    try:
        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
            tmp.write(raw)
            tmp_path = tmp.name
        text, lines = await extract_text_from_file(tmp_path)
        try:
            images = extract_images_from_file(tmp_path, max_images=settings.doc_max_images)
        except Exception:
            images = []
    except Exception as e:
        return f"LỖI: không trích xuất được text từ '{path}': {e}"
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)

    if not text.strip() and not images:
        return f"Tài liệu '{path}' trích xuất ra rỗng (có thể là file scan/ảnh, không có text layer)."

    truncated = text[:MAX_FILE_CHARS]
    suffix = "" if len(text) <= MAX_FILE_CHARS else "\n…[đã cắt bớt do tài liệu dài]…"
    out = f"Nội dung '{path}' (trích xuất {ext}, {lines} dòng):\n{truncated}{suffix}"

    if images:
        vision_part = await _analyze_images(images)
        out += f"\n\n===== ẢNH/SƠ ĐỒ NHÚNG TRONG TÀI LIỆU ({len(images)} ảnh) =====\n{vision_part}"
    return out


VISION_PROMPT = (
    "Đây là một ảnh/sơ đồ trích từ tài liệu kỹ thuật phần mềm. Hãy mô tả CHI TIẾT bằng tiếng Việt: "
    "nếu là sơ đồ kiến trúc/luồng/ERD thì liệt kê các thành phần, quan hệ, hướng luồng dữ liệu, "
    "công nghệ ghi trên hình; nếu là ảnh chụp màn hình/bảng thì tóm tắt nội dung chính. "
    "Chỉ mô tả những gì THỰC SỰ thấy, không suy diễn."
)


async def _describe_image(image_bytes: bytes) -> str:
    """Gọi vision model trên Ollama để mô tả 1 ảnh."""
    from api.routes.ollama import get_active_vision_model
    model = get_active_vision_model()
    b64 = base64.b64encode(image_bytes).decode("ascii")
    timeout = httpx.Timeout(connect=10.0, read=float(settings.ollama_timeout), write=15.0, pool=5.0)
    async with httpx.AsyncClient(timeout=timeout, trust_env=False) as client:
        r = await client.post(
            f"{settings.ollama_url}/api/generate",
            json={"model": model, "prompt": VISION_PROMPT, "images": [b64],
                  "stream": False, "options": {"temperature": 0.1}},
        )
        r.raise_for_status()
        return (r.json().get("response", "") or "").strip()


async def _analyze_images(images: List[bytes]) -> str:
    """Mô tả từng ảnh. Nếu vision model lỗi/chưa cài → báo rõ thay vì im lặng."""
    from api.routes.ollama import get_active_vision_model
    parts = []
    for i, img in enumerate(images, 1):
        try:
            desc = await _describe_image(img)
            parts.append(f"[Hình {i}] {desc or '(không mô tả được)'}")
        except Exception as e:
            note = (f"[Hình {i}] KHÔNG phân tích được ảnh bằng vision model "
                    f"'{get_active_vision_model()}': {e}. "
                    f"Hãy cài model hỗ trợ ảnh (vd: ollama pull llama3.2-vision) và chọn trong Settings.")
            parts.append(note)
            # Lỗi model thường lặp cho mọi ảnh → dừng sớm, chỉ báo 1 lần
            break
    return "\n\n".join(parts)


# ─────────────────────────────────────────────────────────────
# Thực thi tool WRITE/EXEC (chỉ khi đã approved)
# ─────────────────────────────────────────────────────────────
async def _run_sideeffect(folder_id: str, action: str, args: Dict[str, Any]) -> str:
    if action == "write_file":
        path = str(args.get("path", "") or "")
        content = args.get("content", "")
        create = bool(args.get("create", False))
        if not path:
            return "LỖI: thiếu 'path' cho write_file."
        await _host_request("POST", "/fs/file", json={
            "folder_id": folder_id, "path": path, "content": content, "create": create,
        })
        return f"Đã ghi file '{path}' ({len(content)} ký tự)."
    if action == "exec":
        command = str(args.get("command", "") or "")
        cwd = str(args.get("cwd", "") or "")
        if not command:
            return "LỖI: thiếu 'command' cho exec."
        data = await _host_request("POST", "/fs/exec", json={
            "folder_id": folder_id, "command": command, "cwd": cwd, "confirm": True,
        })
        out = (data.get("stdout") or "") + (("\n[stderr]\n" + data.get("stderr")) if data.get("stderr") else "")
        code = data.get("exit_code", data.get("returncode", "?"))
        return f"Lệnh '{command}' (exit={code}):\n{out[:MAX_OBS_CHARS]}"
    return f"LỖI: tool side-effect không hỗ trợ: {action}"


async def _build_preview(folder_id: str, action: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Tạo preview để UI hiển thị trước khi user xác nhận."""
    if action == "write_file":
        import difflib
        path = str(args.get("path", "") or "")
        new_content = args.get("content", "") or ""
        old_content = ""
        try:
            cur = await _host_request("GET", "/fs/file", params={"folder_id": folder_id, "path": path})
            if not cur.get("binary"):
                old_content = cur.get("content") or ""
        except Exception:
            old_content = ""  # file chưa tồn tại → tạo mới
        diff = "".join(difflib.unified_diff(
            old_content.splitlines(keepends=True),
            new_content.splitlines(keepends=True),
            fromfile=path, tofile=f"{path} (đề xuất)",
        ))
        return {"kind": "write_file", "path": path, "diff": diff,
                "is_new": old_content == "", "new_content": new_content}
    if action == "exec":
        return {"kind": "exec", "command": args.get("command", ""), "cwd": args.get("cwd", "")}
    return {"kind": action}


# ─────────────────────────────────────────────────────────────
# Vòng lặp agent
# ─────────────────────────────────────────────────────────────
def _to_llm_messages(messages: List[ChatMessage]) -> List[Dict[str, str]]:
    return [{"role": m.role, "content": m.content} for m in messages]


async def _advance(folder_id: str, llm_messages: List[Dict[str, str]], skill_body: Optional[str] = None) -> Dict[str, Any]:
    """Chạy ĐÚNG MỘT bước agent rồi trả về (client tự gọi tiếp để có progress trực tiếp).

    - read_only  → thực thi, trả status "step" (kèm thought + observation) để render ngay.
    - write/exec → trả status "awaiting_confirmation" (chưa thực thi).
    - final      → trả status "done".
    Chỉ tự retry NỘI BỘ khi model trả JSON sai định dạng (tối đa MAX_PARSE_RETRY lần).
    """
    model = None
    for _ in range(MAX_PARSE_RETRY):
        raw, model = await _chat_ollama(llm_messages, skill_body=skill_body)
        llm_messages.append({"role": "assistant", "content": raw})

        action = parse_action(raw)
        if action is None:
            llm_messages.append({
                "role": "user",
                "content": "LỖI ĐỊNH DẠNG: Hãy trả về DUY NHẤT một JSON {\"thought\":..,\"action\":..,\"args\":..}, không kèm chữ nào khác.",
            })
            continue

        name = action.get("action")
        args = action.get("args", {})
        thought = action.get("thought", "")

        if name == "final":
            return {"status": "done", "answer": args.get("answer") or args.get("message") or raw,
                    "thought": thought, "messages": llm_messages, "model": model}

        if name in READ_ONLY_ACTIONS:
            obs = await _run_readonly(folder_id, name, args)
            llm_messages.append({"role": "user", "content": f"OBSERVATION:\n{obs}"})
            return {"status": "step",
                    "step": {"action": name, "args": args, "thought": thought, "observation": obs},
                    "messages": llm_messages, "model": model}

        if name in WRITE_ACTIONS:
            preview = await _build_preview(folder_id, name, args)
            return {"status": "awaiting_confirmation",
                    "pending": {"action": name, "args": args, "preview": preview},
                    "thought": thought, "messages": llm_messages, "model": model}

        # Tool lạ → báo lỗi cho model rồi thử lại
        llm_messages.append({
            "role": "user",
            "content": f"LỖI: tool '{name}' không tồn tại. Chỉ dùng: list_dir, read_file, write_file, exec, final.",
        })

    return {"status": "done",
            "answer": "Model local không trả về hành động hợp lệ sau nhiều lần thử. Hãy nhắn lại rõ hơn, hoặc đổi sang model hỗ trợ tốt hơn trong Settings.",
            "messages": llm_messages, "model": model}


# ─────────────────────────────────────────────────────────────
# Endpoint chính
# ─────────────────────────────────────────────────────────────
def _resolve_skill_body(skill_id: Optional[str]) -> Optional[str]:
    if not skill_id:
        return None
    from api.services.agent_skills import get_skill
    s = get_skill(skill_id)
    return s["body"] if s else None


@router.post("/step")
async def agent_step(req: AgentStepRequest):
    llm_messages = _to_llm_messages(req.messages)
    skill_body = _resolve_skill_body(req.skill_id)

    # Nếu user vừa duyệt một hành động ghi/exec → thực thi, ghi observation, rồi loop tiếp
    if req.approved is not None:
        if req.approved.action not in WRITE_ACTIONS:
            raise HTTPException(status_code=400, detail=f"Hành động không duyệt được: {req.approved.action}")
        try:
            obs = await _run_sideeffect(req.folder_id, req.approved.action, req.approved.args)
        except HTTPException:
            raise
        except Exception as e:
            obs = f"LỖI khi thực thi: {e}"
        llm_messages.append({"role": "user", "content": f"OBSERVATION:\n{obs}"})

    try:
        return await _advance(req.folder_id, llm_messages, skill_body=skill_body)
    except HTTPException:
        raise
    except httpx.HTTPError as e:
        raise HTTPException(status_code=503, detail=f"Không gọi được Ollama: {e}")
    except Exception as e:
        logger.exception("Agent loop lỗi")
        raise HTTPException(status_code=500, detail=f"Lỗi agent: {e}")


@router.get("/health")
async def agent_health():
    """Kiểm tra coworker_host + model đang active."""
    from api.routes.ollama import get_active_model
    host = await _host_request("GET", "/health")
    return {"ok": True, "coworker_host": host, "model": get_active_model()}


# ─────────────────────────────────────────────────────────────
# Skills — thư viện playbook nghiệp vụ; agent tự chọn theo ngữ cảnh
# ─────────────────────────────────────────────────────────────
@router.get("/skills")
async def get_skills():
    from api.services.agent_skills import list_skills
    return {"skills": list_skills(include_body=False)}


ROUTER_PROMPT = """Bạn là bộ định tuyến skill. Dựa vào yêu cầu của người dùng, chọn skill NGHIỆP VỤ phù hợp nhất trong danh sách, hoặc "none" nếu không skill nào hợp.

Danh sách skill:
{skill_list}

Yêu cầu của người dùng:
{user_msg}

Chỉ trả về DUY NHẤT một JSON: {{"skill_id": "<id hoặc none>"}}"""


@router.post("/route")
async def route_skill(req: RouteRequest):
    """Chọn skill phù hợp theo ngữ cảnh (LLM phân loại + fallback từ khóa)."""
    from api.services.agent_skills import list_skills, keyword_match, get_skill

    skills = list_skills(include_body=False)
    if not skills:
        return {"skill_id": None, "skill_name": None, "reason": "Chưa có skill nào."}

    user_msg = ""
    for m in reversed(req.messages):
        if m.role == "user":
            user_msg = m.content
            break

    chosen = None
    # 1) Thử LLM phân loại
    try:
        skill_list = "\n".join(f'- id="{s["id"]}": {s["name"]} — {s["description"]}' for s in skills)
        raw, _ = await _chat_ollama([{
            "role": "user",
            "content": ROUTER_PROMPT.format(skill_list=skill_list, user_msg=user_msg[:1500]),
        }])
        parsed = parse_action(raw) or {}
        cand = parsed.get("skill_id") or parsed.get("args", {}).get("skill_id")
        if cand and cand != "none" and get_skill(cand):
            chosen = cand
    except Exception as e:
        logger.warning(f"LLM route lỗi, dùng fallback từ khóa: {e}")

    # 2) Fallback: khớp từ khóa trigger
    if not chosen:
        chosen = keyword_match(user_msg)

    if not chosen:
        return {"skill_id": None, "skill_name": None, "reason": "Không có skill phù hợp với yêu cầu."}
    s = get_skill(chosen)
    return {"skill_id": chosen, "skill_name": s["name"] if s else chosen,
            "reason": "Phù hợp với ngữ cảnh yêu cầu."}


# ─────────────────────────────────────────────────────────────
# Lịch sử hội thoại — lưu DB (sống sót qua restart Docker)
# ─────────────────────────────────────────────────────────────
def _derive_title(messages: List[ChatMessage]) -> str:
    for m in messages:
        if m.role == "user" and not m.content.startswith(("OBSERVATION:", "LỖI", "[Người dùng từ chối")):
            return m.content.strip()[:80] or "Hội thoại mới"
    return "Hội thoại mới"


@router.post("/conversations")
async def save_conversation(req: SaveConversationRequest, db: Session = Depends(get_db)):
    from api.agent_conversation_models import AgentConversation
    msgs = [m.model_dump() for m in req.messages]
    title = req.title or _derive_title(req.messages)

    conv = None
    if req.id:
        conv = db.query(AgentConversation).filter(AgentConversation.id == req.id).first()
    if conv is None:
        conv = AgentConversation(id=req.id) if req.id else AgentConversation()
        db.add(conv)
    conv.title = title
    conv.folder_id = req.folder_id
    conv.skill_id = req.skill_id
    conv.messages = msgs
    db.commit()
    db.refresh(conv)
    return {"id": conv.id, "title": conv.title, "updated_at": conv.updated_at.isoformat()}


@router.get("/conversations")
async def list_conversations(db: Session = Depends(get_db)):
    from api.agent_conversation_models import AgentConversation
    rows = db.query(AgentConversation).order_by(AgentConversation.updated_at.desc()).limit(200).all()
    return {"conversations": [
        {"id": r.id, "title": r.title, "skill_id": r.skill_id, "folder_id": r.folder_id,
         "updated_at": r.updated_at.isoformat() if r.updated_at else None}
        for r in rows
    ]}


@router.get("/conversations/{conv_id}")
async def get_conversation(conv_id: str, db: Session = Depends(get_db)):
    from api.agent_conversation_models import AgentConversation
    r = db.query(AgentConversation).filter(AgentConversation.id == conv_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Không tìm thấy hội thoại")
    return {"id": r.id, "title": r.title, "skill_id": r.skill_id, "folder_id": r.folder_id,
            "messages": r.messages or []}


@router.delete("/conversations/{conv_id}")
async def delete_conversation(conv_id: str, db: Session = Depends(get_db)):
    from api.agent_conversation_models import AgentConversation
    r = db.query(AgentConversation).filter(AgentConversation.id == conv_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Không tìm thấy hội thoại")
    db.delete(r)
    db.commit()
    return {"ok": True}
