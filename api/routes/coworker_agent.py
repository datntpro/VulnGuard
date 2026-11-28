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
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.database import get_db

from api.config import settings
from api.services.llm_resolver import RouteRefused
from api.routes.coworker import _host_request  # tái dùng proxy sang coworker_host

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/coworker/agent", tags=["coworker-agent"])

MAX_PARSE_RETRY = 3         # số lần thử lại khi model trả JSON sai định dạng
MAX_FILE_CHARS = 12000      # cắt nội dung file đưa vào context model local
MAX_RAW_CHARS = 200_000     # trần "thô" cho route cloud: che secret TRƯỚC, cắt SAU (wrap_observation)
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
    """[AI PR-3b] Chỉ `pending_id` có hiệu lực: action/args do SERVER giữ (client không bao giờ được tin)."""
    pending_id: Optional[str] = None
    action: Optional[str] = None             # tương thích cũ — bị bỏ qua
    args: Optional[Dict[str, Any]] = None    # tương thích cũ — bị bỏ qua


class ConversationStepRequest(BaseModel):
    """[AI PR-3b] Bước trên hội thoại do server giữ transcript. Đúng một trong: message | approve | reject | (rỗng = tiếp tục).
    Mọi trường khác (messages, assistant/tool turn, approved.args, provider, route…) bị BỎ QUA."""
    message: Optional[str] = None
    approve: Optional[str] = None            # pending_id
    ack: Optional[str] = None                # confirm_token của đúng pending đó (cloud: bắt buộc khi approve)
    explicit: bool = False                   # người dùng đã xác nhận RÕ (bắt buộc với pending rủi ro)
    auto: bool = False                       # client khai báo đây là tự-duyệt: bị từ chối với pending rủi ro
    reject: Optional[str] = None             # pending_id
    folder_id: Optional[str] = None          # chỉ có hiệu lực ở bước đầu tiên
    skill_id: Optional[str] = None           # chỉ có hiệu lực ở bước đầu tiên


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
class CoworkBackend:
    """[AI PR-1] Giao diện backend của vòng lặp Co-work (A1). `chat()` trả (raw_text, model).
    PR-3b sẽ thêm CloudToolBackend (native tools); hiện chỉ có LocalJsonBackend."""
    async def chat(self, messages: List[Dict[str, str]], skill_body: Optional[str] = None) -> tuple[str, str]:
        raise NotImplementedError


class LocalJsonBackend(CoworkBackend):
    """Giao thức hiện tại: JSON-in-text ReAct trên Ollama /api/chat — không đổi."""
    def __init__(self, route):
        self.route = route

    async def chat(self, messages: List[Dict[str, str]], skill_body: Optional[str] = None) -> tuple[str, str]:
        route = self.route
        model = route.model
        system = SYSTEM_PROMPT
        if skill_body:
            system = f"{SYSTEM_PROMPT}\n\n# ── SKILL NGHIỆP VỤ ĐANG ÁP DỤNG ──\n{skill_body}"
        payload_messages = [{"role": "system", "content": system}] + messages
        timeout = httpx.Timeout(connect=10.0, read=float(settings.ollama_timeout), write=10.0, pool=5.0)
        async with httpx.AsyncClient(timeout=timeout, trust_env=False) as client:
            r = await client.post(
                f"{route.url}/api/chat",
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


class CloudToolBackend(CoworkBackend):
    """[AI PR-3b] Co-work trên model cloud: native tool-calling qua LLMDriver (Anthropic/Bedrock/OpenAI-compatible).
    Mọi lần gửi đi qua coworker_cloud_send() (che secret/PII bắt buộc). Meter của driver ghi usage/quota."""
    native = True

    def __init__(self, route, conversation_id: Optional[str] = None, user_id: Optional[str] = None):
        self.route = route
        self.conv = conversation_id
        self.user = user_id
        self._drv = None

    @property
    def driver(self):
        if self._drv is None:
            from scanner.pentest.llm import make_driver
            self._drv = make_driver(self.route)
        return self._drv

    async def chat(self, messages, skill_body=None):   # giao thức JSON-in-text không dùng cho cloud
        raise NotImplementedError("CloudToolBackend dùng turn()")

    async def turn(self, transcript: List[dict], skill_body: Optional[str] = None):
        from api.services.coworker_cloud import CLOUD_SYSTEM_PROMPT, coworker_cloud_send
        system = CLOUD_SYSTEM_PROMPT
        if skill_body:
            system += f"\n\n# ── SKILL NGHIỆP VỤ ĐANG ÁP DỤNG ──\n{skill_body}"
        r = self.route
        return await coworker_cloud_send(self.driver, system, transcript,
                                         ctx={"conv": self.conv, "user": self.user, "cred": r.credential_id,
                                              "provider": r.provider, "model": r.model})


def _backend(conversation_id: Optional[str] = None, user_id: Optional[str] = None,
             pinned_route_kind: Optional[str] = None, pinned_credential_id: Optional[str] = None,
             *, allow_cloud: bool = True) -> CoworkBackend:
    """Chọn backend qua resolver (§4.11: Co-work đi theo Settings › AI). Local → LocalJsonBackend; cloud →
    CloudToolBackend (chỉ cho hội thoại có transcript phía server: allow_cloud=False cho /step stateless).
    Không bao giờ lặng lẽ chạy local thay cho cloud."""
    from api.services.llm_resolver import LLMContext, LocalOllama, RouteRefused, resolve
    route = resolve(LLMContext(feature="coworker", user_id=user_id, job_kind="coworker_conversation",
                               job_id=conversation_id, needs_tools=True, pinned_route_kind=pinned_route_kind,
                               pinned_credential_id=pinned_credential_id))
    if isinstance(route, LocalOllama):
        return LocalJsonBackend(route)
    if getattr(route, "kind", None) == "cloud":
        if not allow_cloud:
            raise RouteRefused("AI_COWORKER_USE_CONVERSATION_STEP", "ai.error.coworker_use_conversation_step")
        return CloudToolBackend(route, conversation_id, user_id)
    raise RouteRefused(getattr(route, "code", "AI_ROUTE"), getattr(route, "message_key", ""))


async def _chat_ollama(messages: List[Dict[str, str]], skill_body: Optional[str] = None) -> tuple[str, str]:
    """Phân loại skill: LUÔN local (không bao giờ cloud) — resolver trả Ollama cho job_kind khác 'coworker_conversation'."""
    from api.services.llm_resolver import LLMContext, resolve
    route = resolve(LLMContext(feature="coworker", job_kind="coworker_route"))
    return await LocalJsonBackend(route).chat(messages, skill_body=skill_body)


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
class SensitiveRead(Exception):
    """[AI PR-3b] Route cloud: file đọc được thực ra nhạy cảm (đường dẫn THẬT, symlink, hard link) → cần xác nhận."""
    def __init__(self, reason: str, resolved: str = ""):
        super().__init__(reason)
        self.reason, self.resolved = reason, resolved


def _gate_read(gate: bool, path: str, data: dict) -> None:
    if not gate:
        return
    from api.services.coworker_cloud import read_needs_confirmation
    why = read_needs_confirmation(path, data)
    if why:
        raise SensitiveRead(why, str((data or {}).get("resolved") or ""))


async def _run_readonly(folder_id: str, action: str, args: Dict[str, Any], *, gate: bool = False, raw: bool = False) -> str:
    path = str(args.get("path", "") or "")
    if action == "list_dir":
        data = await _host_request("GET", "/fs/tree", params={"folder_id": folder_id, "path": path})
        entries = data.get("entries", data) if isinstance(data, dict) else data
        return json.dumps(entries, ensure_ascii=False)[:MAX_RAW_CHARS if raw else MAX_OBS_CHARS]
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
            return await _read_document(folder_id, path, ext, gate=gate, raw=raw)
        data = await _host_request("GET", "/fs/file", params={"folder_id": folder_id, "path": path})
        _gate_read(gate, path, data)
        if data.get("binary"):
            return (f"LỖI: '{path}' là file binary, không đọc được dạng text. "
                    f"(Chỉ hỗ trợ trích xuất các định dạng tài liệu: {', '.join(sorted(DOC_EXTS))})")
        content = data.get("content") or ""
        lim = MAX_RAW_CHARS if raw else MAX_FILE_CHARS
        truncated = content[:lim]
        suffix = "" if len(content) <= lim else "\n…[đã cắt bớt do file dài]…"
        return f"Nội dung '{path}':\n{truncated}{suffix}"
    return f"LỖI: tool read-only không hỗ trợ: {action}"


async def _read_document(folder_id: str, path: str, ext: str, gate: bool = False, raw: bool = False) -> str:
    """Lấy bytes tài liệu từ host (base64), trích text + mô tả ảnh nhúng (vision)."""
    from api.services.file_processor import extract_text_from_file, extract_images_from_file
    try:
        data = await _host_request("GET", "/fs/file_b64", params={"folder_id": folder_id, "path": path})
    except HTTPException as e:
        if e.status_code == 404:
            return (f"LỖI: coworker_host chưa hỗ trợ đọc tài liệu (endpoint /fs/file_b64). "
                    f"Hãy khởi động lại Coworker Host: bash coworker_host/run.sh")
        raise
    _gate_read(gate, path, data)
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

    lim = MAX_RAW_CHARS if raw else MAX_FILE_CHARS
    truncated = text[:lim]
    suffix = "" if len(text) <= lim else "\n…[đã cắt bớt do tài liệu dài]…"
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
    from api.services.llm_resolver import LLMContext, resolve
    route = resolve(LLMContext(feature="coworker", job_kind="coworker_vision"))
    model = route.vision_model
    b64 = base64.b64encode(image_bytes).decode("ascii")
    timeout = httpx.Timeout(connect=10.0, read=float(settings.ollama_timeout), write=15.0, pool=5.0)
    async with httpx.AsyncClient(timeout=timeout, trust_env=False) as client:
        r = await client.post(
            f"{route.url}/api/generate",
            json={"model": model, "prompt": VISION_PROMPT, "images": [b64],
                  "stream": False, "options": {"temperature": 0.1}},
        )
        r.raise_for_status()
        return (r.json().get("response", "") or "").strip()


async def _analyze_images(images: List[bytes]) -> str:
    """Mô tả từng ảnh. Nếu vision model lỗi/chưa cài → báo rõ thay vì im lặng."""
    from api.services.llm_resolver import LLMContext, resolve
    parts = []
    for i, img in enumerate(images, 1):
        try:
            desc = await _describe_image(img)
            parts.append(f"[Hình {i}] {desc or '(không mô tả được)'}")
        except Exception as e:
            note = (f"[Hình {i}] KHÔNG phân tích được ảnh bằng vision model "
                    f"'{resolve(LLMContext(feature='coworker')).vision_model}': {e}. "
                    f"Hãy cài model hỗ trợ ảnh (vd: ollama pull llama3.2-vision) và chọn trong Settings.")
            parts.append(note)
            # Lỗi model thường lặp cho mọi ảnh → dừng sớm, chỉ báo 1 lần
            break
    return "\n\n".join(parts)


# ─────────────────────────────────────────────────────────────
# Thực thi tool WRITE/EXEC (chỉ khi đã approved)
# ─────────────────────────────────────────────────────────────
async def _run_sideeffect(folder_id: str, action: str, args: Dict[str, Any], *, raw: bool = False) -> str:
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
        # Người dùng đã duyệt ở UI agent → gọi host KHÔNG kèm confirm; nếu host (chế độ trusted)
        # trả needs_confirm + confirm_id thì gọi lại đúng 1 lần với confirm_id đó.
        payload = {"folder_id": folder_id, "command": command, "cwd": cwd}
        try:
            data = await _host_request("POST", "/fs/exec", json=payload)
            if data.get("needs_confirm") and data.get("confirm_id"):
                data = await _host_request("POST", "/fs/exec", json={**payload, "confirm_id": data["confirm_id"]})
        except HTTPException as e:
            code = (e.headers or {}).get("X-Coworker-Code")
            if e.status_code == 403 and code in ("exec_mode_safe", "exec_disabled"):
                return ("LỖI: exec bị tắt/hạn chế trên Coworker Host (chế độ safe/off) — lệnh này không chạy được. "
                        f"Chi tiết: {e.detail}. Hãy dùng các tool đọc/ghi file thay thế hoặc báo người dùng.")
            raise
        if data.get("needs_confirm"):
            return "LỖI: host yêu cầu xác nhận nhưng không cấp confirm_id — lệnh không được chạy."
        out = (data.get("stdout") or "") + (("\n[stderr]\n" + data.get("stderr")) if data.get("stderr") else "")
        code = data.get("exit_code", data.get("returncode", "?"))
        return f"Lệnh '{command}' (exit={code}):\n{out[:MAX_RAW_CHARS if raw else MAX_OBS_CHARS]}"
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


async def _advance(folder_id: str, llm_messages: List[Dict[str, str]], skill_body: Optional[str] = None,
                   backend: Optional[CoworkBackend] = None, user_id: Optional[str] = None) -> Dict[str, Any]:
    """Chạy ĐÚNG MỘT bước agent rồi trả về (client tự gọi tiếp để có progress trực tiếp).

    - read_only  → thực thi, trả status "step" (kèm thought + observation) để render ngay.
    - write/exec → trả status "awaiting_confirmation" (chưa thực thi).
    - final      → trả status "done".
    Chỉ tự retry NỘI BỘ khi model trả JSON sai định dạng (tối đa MAX_PARSE_RETRY lần).
    """
    model = None
    backend = backend or _backend(user_id=user_id, allow_cloud=False)
    for _ in range(MAX_PARSE_RETRY):
        raw, model = await backend.chat(llm_messages, skill_body=skill_body)
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


def _new_pending(db, *, owner, conv_id, folder_id, kind, action, args, tool_use_id=None, extra_ids=None, warning=None):
    from api.agent_conversation_models import AgentPendingAction
    row = AgentPendingAction(owner_user_id=owner, conversation_id=conv_id, folder_id=folder_id, kind=kind,
                             action=action, args=dict(args or {}), tool_use_id=tool_use_id,
                             extra_ids=list(extra_ids or []), warning=warning, status="open")
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _take_pending(db, pending_id: Optional[str], *, owner, conv_id, to_status: str, ignore_ttl: bool = False):
    """Lấy + KHOÁ (open → done|rejected, nguyên tử) một pending action. id lạ / của người khác / của hội thoại khác /
    đã dùng → 409 (không lộ sự tồn tại). Args luôn là args do SERVER lưu."""
    from api.agent_conversation_models import AgentPendingAction as P
    bad = HTTPException(status_code=409, detail={"code": "AI_PENDING_INVALID", "message_key": "ai.error.pending_invalid"})
    if not pending_id or not isinstance(pending_id, str):
        raise bad
    row = db.query(P).filter(P.id == pending_id).first()
    if row is None or row.owner_user_id != owner or row.conversation_id != conv_id or row.status != "open":
        raise bad
    if not ignore_ttl and _pending_expired(row):
        db.query(P).filter(P.id == pending_id, P.status == "open").update({"status": "expired"}, synchronize_session=False)
        db.commit()
        raise HTTPException(status_code=409, detail={"code": "AI_PENDING_EXPIRED", "message_key": "ai.error.pending_expired"})
    n = db.query(P).filter(P.id == pending_id, P.status == "open").update({"status": to_status}, synchronize_session=False)
    db.commit()
    if n != 1:
        raise bad
    db.refresh(row)
    return row


PENDING_TTL_SECONDS = 15 * 60       # pending quá hạn → 409 AI_PENDING_EXPIRED (không duyệt được "vài ngày sau")


def _pending_expired(row) -> bool:
    from datetime import datetime, timedelta
    c = row.created_at
    return bool(c) and datetime.utcnow() - c > timedelta(seconds=PENDING_TTL_SECONDS)


def _confirm_token(row) -> str:
    """Gắn với ĐÚNG hành động: id + loại + action + args (đổi bất kỳ thứ nào → token khác). Không phải bí mật:
    tác dụng là buộc client phải trả lời đúng pending mà người dùng đã thấy, kèm `explicit` cho pending rủi ro."""
    import hashlib
    blob = json.dumps([row.id, row.kind, row.action, row.args], sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:20]


def _risky(row) -> bool:
    w = row.warning or {}
    return row.kind == "sensitive_read" or bool(w.get("suspicious"))


def _pending_view(row, preview: Dict[str, Any]) -> Dict[str, Any]:
    v = {"id": row.id, "action": row.action, "args": row.args, "preview": preview, "kind": row.kind,
         "warning": row.warning}
    if row.conversation_id is not None:
        v.update({"confirm_token": _confirm_token(row), "requires_explicit": _risky(row),
                  "expires_in": PENDING_TTL_SECONDS})
    return v


@router.post("/step")
async def agent_step(req: AgentStepRequest, request: Request, db: Session = Depends(get_db)):
    """Bước STATELESS cũ — CHỈ cho backend local (giữ một bản phát hành). Hội thoại cloud phải dùng
    POST /conversations/{id}/step (transcript phía server). `approved` chỉ hợp lệ khi kèm `pending_id` do server cấp."""
    uid = _uid(request)
    llm_messages = _to_llm_messages(req.messages)
    skill_body = _resolve_skill_body(req.skill_id)

    if req.approved is not None:
        row = _take_pending(db, req.approved.pending_id, owner=uid, conv_id=None, to_status="done")
        try:
            obs = await _run_sideeffect(row.folder_id or req.folder_id, row.action, row.args)
        except HTTPException:
            raise
        except Exception as e:
            obs = f"LỖI khi thực thi: {e}"
        llm_messages.append({"role": "user", "content": f"OBSERVATION:\n{obs}"})

    try:
        out = await _advance(req.folder_id, llm_messages, skill_body=skill_body, user_id=uid)
        if out.get("status") == "awaiting_confirmation":
            p = out["pending"]
            row = _new_pending(db, owner=uid, conv_id=None, folder_id=req.folder_id, kind="side_effect",
                               action=p["action"], args=p["args"])
            p["id"] = row.id
        return out
    except HTTPException:
        raise
    except RouteRefused:      # [AI PR-3] → 409 {code} qua exception handler (không biến thành 500)
        raise
    except httpx.HTTPError as e:
        raise HTTPException(status_code=503, detail=f"Không gọi được Ollama: {e}")
    except Exception as e:
        logger.exception("Agent loop lỗi")
        raise HTTPException(status_code=500, detail=f"Lỗi agent: {e}")


@router.get("/health")
async def agent_health():
    """Kiểm tra coworker_host + model đang active."""
    from api.services.llm_resolver import LLMContext, resolve
    host = await _host_request("GET", "/health")
    return {"ok": True, "coworker_host": host, "model": resolve(LLMContext(feature="coworker", job_kind="coworker_health")).model}


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


def _uid(request: Request) -> Optional[str]:
    return getattr(getattr(request.state, "user", None), "id", None)


def _is_admin(user) -> bool:
    return str(getattr(getattr(user, "role", ""), "value", getattr(user, "role", ""))) == "ADMIN"


def _may_access(row, request: Request) -> bool:
    """[AI PR-1] Hội thoại thuộc chủ sở hữu. Hàng cũ (owner NULL) chỉ ADMIN thấy.
    AUTH tắt (không có user) → một người dùng duy nhất, thấy hết."""
    user = getattr(request.state, "user", None)
    if user is None:
        return True
    owner = getattr(row, "owner_user_id", None)
    if owner is None:
        return _is_admin(user)
    return owner == user.id


def _scoped(db, request: Request, conv_id: str):
    from api.agent_conversation_models import AgentConversation
    r = db.query(AgentConversation).filter(AgentConversation.id == conv_id).first()
    if r is None or not _may_access(r, request):
        raise HTTPException(status_code=404, detail="Không tìm thấy hội thoại")   # không lộ sự tồn tại
    return r


@router.post("/conversations")
async def save_conversation(req: SaveConversationRequest, request: Request, db: Session = Depends(get_db)):
    from api.agent_conversation_models import AgentConversation
    msgs = [m.model_dump() for m in req.messages]
    title = req.title or _derive_title(req.messages)

    conv = None
    if req.id:
        existing = db.query(AgentConversation).filter(AgentConversation.id == req.id).first()
        if existing is not None:
            if not _may_access(existing, request):
                raise HTTPException(status_code=404, detail="Không tìm thấy hội thoại")
            conv = existing
    if conv is None:
        conv = AgentConversation(id=req.id) if req.id else AgentConversation()
        conv.owner_user_id = _uid(request)
        db.add(conv)
    conv.title = title
    if conv.transcript is None:      # [AI PR-3b] hội thoại có transcript phía server: client KHÔNG ghi đè lịch sử/folder
        conv.folder_id = req.folder_id
        conv.skill_id = req.skill_id
        conv.messages = msgs
    db.commit()
    db.refresh(conv)
    return {"id": conv.id, "title": conv.title, "updated_at": conv.updated_at.isoformat()}


@router.get("/conversations")
async def list_conversations(request: Request, db: Session = Depends(get_db)):
    from api.agent_conversation_models import AgentConversation
    q = db.query(AgentConversation)
    user = getattr(request.state, "user", None)
    if user is not None:   # lọc theo chủ sở hữu TRONG SQL, rồi mới limit (không để hội thoại người khác chiếm 200 dòng)
        from sqlalchemy import or_
        cond = AgentConversation.owner_user_id == user.id
        if _is_admin(user):
            cond = or_(cond, AgentConversation.owner_user_id.is_(None))
        q = q.filter(cond)
    rows = q.order_by(AgentConversation.updated_at.desc()).limit(200).all()
    return {"conversations": [
        {"id": r.id, "title": r.title, "skill_id": r.skill_id, "folder_id": r.folder_id,
         "updated_at": r.updated_at.isoformat() if r.updated_at else None}
        for r in rows
    ]}


@router.get("/conversations/{conv_id}")
async def get_conversation(conv_id: str, request: Request, db: Session = Depends(get_db)):
    r = _scoped(db, request, conv_id)
    return {"id": r.id, "title": r.title, "skill_id": r.skill_id, "folder_id": r.folder_id,
            "messages": _display_messages(r) if r.transcript is not None else (r.messages or []),
            "route_kind": r.route_kind}


@router.delete("/conversations/{conv_id}")
async def delete_conversation(conv_id: str, request: Request, db: Session = Depends(get_db)):
    r = _scoped(db, request, conv_id)
    from api.agent_conversation_models import AgentPendingAction
    db.query(AgentPendingAction).filter(AgentPendingAction.conversation_id == r.id).delete(synchronize_session=False)
    db.delete(r)
    db.commit()
    return {"ok": True}


# ─────────────────────────────────────────────────────────────
# [AI PR-3b] Hội thoại có transcript phía server (local + cloud) — §4.11.3
# ─────────────────────────────────────────────────────────────
# LƯU Ý (S4): khoá này chỉ có hiệu lực TRONG MỘT process. Với nhiều worker, hai step song song trên cùng hội thoại có thể
# ghi đè transcript/cloud_state của nhau (mất bước, đếm thiếu ngân sách). Pending-take là nguyên tử (UPDATE có điều kiện)
# nên không bao giờ chạy một hành động hai lần. Launcher ghim `--workers 1`; trước khi chạy đa worker cần cột `version`
# (optimistic lock) hoặc advisory lock DB. Dict không dọn: mỗi hội thoại ~100 byte.
_CONV_LOCKS: Dict[str, Any] = {}


def _conv_lock(conv_id: str):
    import asyncio
    return _CONV_LOCKS.setdefault(conv_id, asyncio.Lock())


def _block_text(content) -> str:
    if isinstance(content, str):
        return content
    out = []
    for b in content or []:
        if isinstance(b, dict) and b.get("type") == "text":
            out.append(b.get("text", ""))
    return "\n".join(out)


def _display_messages(conv) -> List[Dict[str, str]]:
    """Dạng xem ĐỌC-CHỈ của transcript (đã che) cho UI."""
    out: List[Dict[str, str]] = []
    for m in conv.transcript or []:
        role, c = m.get("role"), m.get("content")
        if role == "tool":
            out.append({"role": "user", "content": "OBSERVATION:\n" + str(c)})
        elif role == "assistant" and isinstance(c, list):
            txt = _block_text(c)
            uses = [f"{b['name']}({json.dumps(b.get('input', {}), ensure_ascii=False)[:200]})"
                    for b in c if isinstance(b, dict) and b.get("type") == "tool_use"]
            out.append({"role": "assistant", "content": "\n".join(x for x in [txt] + uses if x)})
        elif role == "user" and isinstance(c, list):
            for b in c:
                if isinstance(b, dict) and b.get("type") == "tool_result":
                    out.append({"role": "user", "content": "OBSERVATION:\n" + str(b.get("content", ""))})
                elif isinstance(b, dict) and b.get("type") == "text":
                    out.append({"role": "user", "content": b.get("text", "")})
        elif role in ("user", "assistant"):
            out.append({"role": role, "content": c if isinstance(c, str) else _block_text(c)})
    return out


def _conv_resolve(conv, uid):
    """Route HIỆN TẠI của hội thoại theo Settings, so với route đã ghim. Raise RouteRefused khi bị từ chối / đổi route.
    Không bao giờ leo local→cloud, không bao giờ rơi cloud→local hay sang key khác."""
    from api.services.llm_resolver import (AI_CRED_REVOKED, AI_ROUTE_CHANGED, LLMContext, LocalOllama, Refuse,
                                           RouteRefused, resolve)
    pinned = conv.route_kind
    route = resolve(LLMContext(feature="coworker", user_id=uid, job_kind="coworker_conversation", job_id=conv.id,
                               needs_tools=True, pinned_route_kind=pinned,
                               pinned_credential_id=conv.ai_credential_id if pinned == "cloud" else None))
    if isinstance(route, Refuse):
        raise RouteRefused(route.code, route.message_key)
    is_local = isinstance(route, LocalOllama)
    if pinned == "local" and not is_local or pinned == "cloud" and is_local:
        raise RouteRefused(AI_ROUTE_CHANGED, "ai.error.route_changed")
    if pinned == "cloud":
        if route.provider != conv.provider or route.model != conv.model:
            raise RouteRefused(AI_ROUTE_CHANGED, "ai.error.route_changed")
        if route.credential_id != conv.ai_credential_id:
            raise RouteRefused(AI_CRED_REVOKED, "ai.error.cred_revoked")
    return route


def _route_info(conv, uid) -> Dict[str, Any]:
    from api.services import ai_policy
    from api.services.ai_config import load_config
    from api.services.llm_resolver import LocalOllama, RouteRefused
    cfg = load_config()
    desired = ai_policy.coworker_route(cfg)
    info: Dict[str, Any] = {"pinned": conv.route_kind is not None, "settings_route": desired,
                            "mode": cfg.get("mode", "local_only"),
                            "coworker_row": ((cfg.get("hybrid") or {}).get("tasks") or {}).get("coworker", "local"),
                            "settings_changed": bool(conv.route_kind == "local" and desired == "cloud")}
    try:
        r = _conv_resolve(conv, uid)
    except RouteRefused as e:
        info.update({"state": "refused", "code": e.code, "message_key": e.message_key,
                     "route_kind": conv.route_kind, "provider": conv.provider, "model": conv.model,
                     "data_leaves_machine": conv.route_kind == "cloud"})
        return info
    if isinstance(r, LocalOllama):
        info.update({"state": "ok", "route_kind": "local", "provider": "ollama", "model": r.model,
                     "key_scope": None, "key_hint": None, "data_leaves_machine": False})
    else:
        cred = r.credential
        info.update({"state": "ok", "route_kind": "cloud", "provider": r.provider, "model": r.model,
                     "key_scope": cred.scope, "key_hint": cred.hint if cred.scope == "user" else None,
                     "data_leaves_machine": True})
    return info


@router.get("/route-preview")
async def route_preview(request: Request):
    """Route mà một hội thoại MỚI sẽ nhận (không gọi LLM)."""
    from api.agent_conversation_models import AgentConversation
    return _route_info(AgentConversation(id=None), _uid(request))


@router.get("/conversations/{conv_id}/route")
async def conversation_route(conv_id: str, request: Request, db: Session = Depends(get_db)):
    """ĐỌC-CHỈ: hội thoại đang chạy ở đâu và vì sao (không gọi LLM, không đổi trạng thái)."""
    conv = _scoped(db, request, conv_id)
    return _route_info(conv, _uid(request))


def _audit_action(conv, uid, action: str, outcome: str) -> None:
    from api.services.coworker_cloud import audit
    audit.info("coworker_action conv=%s user=%s route=%s cred=%s action=%s outcome=%s",
               conv.id, uid, conv.route_kind, conv.ai_credential_id, action, outcome)


def _pin_route(db, conv, route) -> None:
    from api.services.llm_resolver import LocalOllama
    if conv.route_kind is not None:
        return
    if isinstance(route, LocalOllama):
        conv.route_kind, conv.provider, conv.model, conv.ai_credential_id = "local", "ollama", route.model, None
    else:
        conv.route_kind, conv.provider, conv.model = "cloud", route.provider, route.model
        conv.ai_credential_id = route.credential_id
    db.commit()


def _suspicion(state: dict, kinds: List[str], hosts: List[str]) -> None:
    if not kinds:
        return
    sus = state.setdefault("suspicious", {"signals": [], "hosts": []})
    sus["signals"] = sorted(set(sus["signals"]) | set(kinds))[:20]
    sus["hosts"] = sorted(set(sus["hosts"]) | set(hosts))[:20]


def _warning_for(state: dict) -> Optional[Dict[str, Any]]:
    sus = state.get("suspicious")
    if not sus or not sus.get("signals"):
        return None
    return {"suspicious": True, "banner": "Đề xuất sau khi đọc nội dung đáng ngờ / Proposed after suspicious content",
            "signals": sus["signals"], "hosts": sus["hosts"]}


def _tool_results_entries(driver, first_id: str, text: str, is_err: bool, extra_ids: List[str]) -> List[dict]:
    res = [(first_id, text, is_err)] + [(i, "Bỏ qua: mỗi lượt chỉ thực hiện MỘT hành động. Hãy gọi lại nếu cần.", True)
                                       for i in extra_ids or []]
    return driver.tool_result_entries(res)


def _attach_user_text(driver, entries: List[dict], text: str) -> None:
    if entries and driver.family == "anthropic":
        entries[-1]["content"].append({"type": "text", "text": text})
    else:
        entries.append({"role": "user", "content": text})


async def _exec_pending(row, cap_read: int, *, raw: bool = False) -> str:
    """Thực thi (sau khi người dùng duyệt) bằng args do SERVER lưu. Mọi lỗi → text (tool_use luôn có tool_result)."""
    try:
        if row.kind == "sensitive_read":
            return await _run_readonly(row.folder_id, "read_file", row.args, raw=raw)
        return await _run_sideeffect(row.folder_id, row.action, row.args, raw=raw)
    except HTTPException as e:
        return f"LỖI khi thực thi: {e.detail}"
    except Exception as e:
        return f"LỖI khi thực thi: {e}"


@router.post("/conversations/{conv_id}/step")
async def conversation_step(conv_id: str, req: ConversationStepRequest, request: Request, db: Session = Depends(get_db)):
    from api.services import coworker_cloud as cc
    uid = _uid(request)
    conv = _scoped(db, request, conv_id)
    if uid is not None and conv.owner_user_id != uid:
        raise HTTPException(status_code=404, detail="Không tìm thấy hội thoại")   # hàng cũ (owner NULL) không step được
    given = [x for x in (req.message, req.approve, req.reject) if x]
    if len(given) > 1 or (req.message is not None and not req.message.strip()):
        raise HTTPException(status_code=400, detail="Gửi đúng một trong: message | approve | reject (hoặc rỗng để tiếp tục)")
    if req.message and len(req.message) > cc.MAX_USER_MESSAGE_CHARS:
        raise HTTPException(status_code=413, detail="Tin nhắn quá dài")

    async with _conv_lock(conv.id):
        db.refresh(conv)
        route = _conv_resolve(conv, uid)        # từ chối TRƯỚC khi đụng bất cứ thứ gì (kể cả approve)
        _pin_route(db, conv, route)
        if conv.folder_id is None:
            if not req.folder_id:
                raise HTTPException(status_code=400, detail="Thiếu folder_id")
            conv.folder_id = req.folder_id
        if conv.skill_id is None and req.skill_id and not conv.transcript:
            conv.skill_id = req.skill_id
        skill_body = _resolve_skill_body(conv.skill_id)
        try:
            if conv.route_kind == "cloud":
                backend = CloudToolBackend(route, conv.id, uid)
                return await _cloud_step(db, conv, uid, req, backend, skill_body)
            return await _local_conv_step(db, conv, uid, req, LocalJsonBackend(route), skill_body)
        except (HTTPException, RouteRefused):
            raise
        except httpx.HTTPError as e:
            raise HTTPException(status_code=503, detail=f"Không gọi được Ollama: {e}")
        except Exception:
            logger.exception("Co-work conversation step lỗi")
            raise HTTPException(status_code=500, detail="Lỗi agent")


def _open_pending(db, conv):
    from api.agent_conversation_models import AgentPendingAction as P
    return db.query(P).filter(P.conversation_id == conv.id, P.status == "open").first()


async def _local_conv_step(db, conv, uid, req, backend, skill_body):
    tx = list(conv.transcript or [])
    open_p = _open_pending(db, conv)
    if req.approve:
        row = _take_pending(db, req.approve, owner=uid, conv_id=conv.id, to_status="done")
        obs = await _exec_pending(row, MAX_OBS_CHARS)
        _audit_action(conv, uid, row.action, "approved")
        tx.append({"role": "user", "content": f"OBSERVATION:\n{obs}"})
    elif req.reject:
        _take_pending(db, req.reject, owner=uid, conv_id=conv.id, to_status="rejected")
        tx.append({"role": "user", "content": "[Người dùng từ chối hành động vừa rồi] Hãy thử cách khác hoặc giải thích thay vì thực hiện."})
    elif req.message:
        if open_p is not None:
            _take_pending(db, open_p.id, owner=uid, conv_id=conv.id, to_status="rejected", ignore_ttl=True)
        tx.append({"role": "user", "content": req.message})
    else:
        if open_p is not None:
            raise HTTPException(status_code=409, detail={"code": "AI_PENDING_OPEN", "message_key": "ai.error.pending_open"})
        if not tx or tx[-1].get("role") != "user":
            raise HTTPException(status_code=409, detail={"code": "AI_NOTHING_TO_CONTINUE", "message_key": "ai.error.nothing_to_continue"})
    conv.transcript = tx
    if not conv.title:
        conv.title = next((m["content"].strip()[:80] for m in tx if m["role"] == "user"
                           and not m["content"].startswith(("OBSERVATION:", "[Người dùng"))), None)
    db.commit()
    out = await _advance(conv.folder_id, tx, skill_body=skill_body, backend=backend, user_id=uid)
    conv.transcript = list(out["messages"])
    db.commit()
    res = {k: v for k, v in out.items() if k != "messages"}
    if out.get("status") == "awaiting_confirmation":
        p = out["pending"]
        row = _new_pending(db, owner=uid, conv_id=conv.id, folder_id=conv.folder_id, kind="side_effect",
                           action=p["action"], args=p["args"])
        res["pending"] = _pending_view(row, p.get("preview", {}))
    res["route_kind"] = "local"
    return res


def _check_confirm(db, req, *, owner, conv_id) -> None:
    """Cloud: approve cần `ack` = confirm_token của ĐÚNG pending; pending rủi ro (đọc file nhạy cảm / sau nội dung
    đáng ngờ) còn cần `explicit=true` và KHÔNG được tự-duyệt. Kiểm TRƯỚC khi khoá pending (từ chối không đốt pending)."""
    from api.agent_conversation_models import AgentPendingAction as P
    row = db.query(P).filter(P.id == req.approve).first()
    if row is None or row.owner_user_id != owner or row.conversation_id != conv_id or row.status != "open":
        return                                      # _take_pending sẽ trả 409 AI_PENDING_INVALID/EXPIRED
    if not req.ack or req.ack != _confirm_token(row):
        raise HTTPException(status_code=409, detail={"code": "AI_CONFIRM_REQUIRED", "message_key": "ai.error.confirm_required"})
    if _risky(row) and (req.auto or not req.explicit):
        raise HTTPException(status_code=409, detail={"code": "AI_EXPLICIT_CONFIRM_REQUIRED",
                                                     "message_key": "ai.error.explicit_confirm_required"})


async def _cloud_step(db, conv, uid, req, backend, skill_body):
    from api.services import coworker_cloud as cc
    driver = backend.driver
    tx = list(conv.transcript or [])
    state = dict(conv.cloud_state or {})
    state.setdefault("steps", 0)
    state.setdefault("sent_bytes", 0)
    stale = _open_pending(db, conv)
    expired_id = None
    if stale is not None and _pending_expired(stale):
        from api.agent_conversation_models import AgentPendingAction as P
        db.query(P).filter(P.id == stale.id, P.status == "open").update({"status": "expired"}, synchronize_session=False)
        entries = _tool_results_entries(driver, stale.tool_use_id, "Hành động đề xuất đã hết hạn (không được duyệt kịp thời).",
                                        True, stale.extra_ids or [])
        tx += entries
        conv.transcript = tx
        db.commit()
        expired_id = stale.id
        if req.approve == expired_id:
            raise HTTPException(status_code=409, detail={"code": "AI_PENDING_EXPIRED", "message_key": "ai.error.pending_expired"})
    open_p = _open_pending(db, conv)
    sent = 0

    def _count(entries):
        return len(json.dumps(entries, ensure_ascii=False).encode("utf-8"))

    if req.approve or req.reject:
        if req.approve:
            _check_confirm(db, req, owner=uid, conv_id=conv.id)
        row = _take_pending(db, req.approve or req.reject, owner=uid, conv_id=conv.id,
                            to_status="done" if req.approve else "rejected")
        if req.approve:
            obs = await _exec_pending(row, MAX_OBS_CHARS, raw=True)
            _audit_action(conv, uid, row.action, "approved")
            cap = MAX_FILE_CHARS + 500 if row.kind == "sensitive_read" else MAX_OBS_CHARS
            text, kinds, hosts = cc.wrap_observation(obs, cap=cap)
            _suspicion(state, kinds, hosts)
            entries = _tool_results_entries(driver, row.tool_use_id, text, obs.startswith("LỖI"), row.extra_ids or [])
        else:
            _audit_action(conv, uid, row.action, "rejected")
            entries = _tool_results_entries(driver, row.tool_use_id, "Người dùng từ chối hành động này. Hãy thử cách khác hoặc giải thích.",
                                            True, row.extra_ids or [])
        tx += entries
        sent += _count(entries)
    elif req.message:
        entries: List[dict] = []
        if open_p is not None:      # gõ tin nhắn mới khi còn hành động chờ duyệt = từ chối nó
            row = _take_pending(db, open_p.id, owner=uid, conv_id=conv.id, to_status="rejected")
            entries = _tool_results_entries(driver, row.tool_use_id, "Người dùng không duyệt hành động này.", True,
                                            row.extra_ids or [])
        text = _redact_user_text(req.message)
        _attach_user_text(driver, entries, text) if entries else entries.append({"role": "user", "content": text})
        tx += entries
        sent += _count(entries)
        if not conv.title:
            conv.title = req.message.strip()[:80]
    else:
        if open_p is not None:
            raise HTTPException(status_code=409, detail={"code": "AI_PENDING_OPEN", "message_key": "ai.error.pending_open"})
        if not tx or tx[-1].get("role") == "assistant":
            raise HTTPException(status_code=409, detail={"code": "AI_NOTHING_TO_CONTINUE", "message_key": "ai.error.nothing_to_continue"})

    state["sent_bytes"] += sent
    conv.transcript, conv.cloud_state = tx, state
    db.commit()
    if state["sent_bytes"] > cc.UPLOAD_BUDGET_BYTES:
        raise RouteRefused("AI_UPLOAD_BUDGET", "ai.error.upload_budget")
    if state["steps"] >= cc.MAX_STEPS:
        raise RouteRefused("AI_STEP_CAP", "ai.error.step_cap")

    raw = await backend.turn(tx, skill_body)        # Meter: quota/usage; lỗi → raise (transcript giữ nguyên, thử lại được)
    state["steps"] += 1
    res = driver.parse(raw)
    meta = {"model": conv.model, "route_kind": "cloud"}
    if res.refused:
        conv.cloud_state = state
        db.commit()
        return {"status": "done", "answer": "Model từ chối yêu cầu này (safety).", "refused": True, **meta}
    tx.append(cc.serialize_assistant(driver, raw))
    conv.transcript, conv.cloud_state = tx, state
    db.commit()
    if not res.tool_calls:
        return {"status": "done", "answer": res.text, **meta}

    first, extras = res.tool_calls[0], [c.id for c in res.tool_calls[1:]]
    name, args = first.name, (first.input if isinstance(first.input, dict) else {})
    thought = res.text

    async def _finish_step(text_for_model: str, is_err: bool, observation: str, extra: Dict[str, Any] = None):
        entries = _tool_results_entries(driver, first.id, text_for_model, is_err, extras)
        conv.transcript = tx + entries
        state["sent_bytes"] += _count(entries)
        conv.cloud_state = state
        db.commit()
        return {"status": "step", "step": {"action": name, "args": args, "thought": thought,
                                           "observation": observation, **(extra or {})}, **meta}

    if name not in cc.TOOL_NAMES:
        return await _finish_step(f"LỖI: tool '{name}' không tồn tại. Chỉ dùng: find_files, list_dir, read_file, write_file, exec.",
                                  True, f"LỖI: tool '{name}' không tồn tại")

    if name in READ_ONLY_ACTIONS:
        def _sens(reason: str, resolved: str = ""):
            row = _new_pending(db, owner=uid, conv_id=conv.id, folder_id=conv.folder_id, kind="sensitive_read",
                               action="read_file", args={"path": str(args.get("path", ""))},
                               tool_use_id=first.id, extra_ids=extras,
                               warning={"reason": reason, "resolved": resolved,
                                        "suspicious": bool((_warning_for(state) or {}).get("suspicious"))})
            return {"status": "awaiting_confirmation", "thought": thought, **meta,
                    "pending": _pending_view(row, {"kind": "sensitive_read", "path": row.args["path"], "reason": reason,
                                                   "resolved": resolved,
                                                   "prompt": "Gửi nội dung file nhạy cảm này lên cloud? / Send this sensitive file to the cloud?"})}
        if name == "read_file" and cc.is_sensitive_path(str(args.get("path", ""))):
            return _sens("sensitive_path")
        try:
            obs = await _run_readonly(conv.folder_id, name, args, gate=(name == "read_file"), raw=True)
        except SensitiveRead as e:                 # đường dẫn THẬT / symlink / hard link / host cũ không báo meta
            return _sens(e.reason, e.resolved)
        except HTTPException as e:
            obs = f"LỖI: {e.detail}"
        except Exception as e:
            obs = f"LỖI: {e}"
        cap = MAX_FILE_CHARS + 500 if name == "read_file" else MAX_OBS_CHARS
        text, kinds, hosts = cc.wrap_observation(obs, cap=cap)
        _suspicion(state, kinds, hosts)
        return await _finish_step(text, obs.startswith("LỖI"), obs[:cap],
                                  {"suspicious": bool(kinds)})

    # write_file / exec — KHÔNG tự chạy
    if (name == "write_file" and (cc.has_redaction_markers(args.get("content")) or cc.has_redaction_markers(args.get("path")))) \
            or (name == "exec" and (cc.has_redaction_markers(args.get("command")) or cc.has_redaction_markers(args.get("cwd")))):
        msg = (f"{name} bị TỪ CHỐI: nội dung chứa marker che dữ liệu ([REDACTED…], [EMAIL], [CCCD]…). Ghi nội dung này sẽ "
               "đè giá trị thật bằng giá trị đã che. Hãy nhờ người dùng tự sửa các giá trị đó hoặc bỏ phần che khỏi đề xuất.")
        _audit_action(conv, uid, name, "refused_markers")
        return await _finish_step(msg, True, msg, {"refused": True})
    preview = await _build_preview(conv.folder_id, name, args)
    row = _new_pending(db, owner=uid, conv_id=conv.id, folder_id=conv.folder_id, kind="side_effect", action=name,
                       args=args, tool_use_id=first.id, extra_ids=extras, warning=_warning_for(state))
    return {"status": "awaiting_confirmation", "thought": thought, **meta, "pending": _pending_view(row, preview)}


def _redact_user_text(text: str) -> str:
    from api.services.coworker_cloud import redact_egress
    return redact_egress(text)
