"""
VulnGuard Coworker Host Service
─────────────────────────────────────────────────────────────
Service nhỏ chạy TRỰC TIẾP trên máy host (giống Ollama — KHÔNG chạy trong
Docker). Mục đích: cho phép tính năng "Co-work" (AI sửa code) đọc/ghi file
và chạy lệnh trên BẤT KỲ folder nào người dùng cấp quyền trên máy host,
việc mà container VulnGuard không làm được vì Docker chỉ thấy được các
volume đã mount sẵn (SCAN_WORKSPACE).

Container API (api/routes/coworker.py) gọi sang service này qua HTTP
(http://host.docker.internal:8765 khi chạy Docker, http://localhost:8765
khi chạy native) — đúng pattern đang dùng cho Ollama trong project này.

An toàn:
- Chỉ đọc/ghi/exec trong các folder đã được cấp quyền rõ ràng (qua UI,
  người dùng tự nhập path trên máy của họ — KHÔNG nhận folder từ nội dung
  bên ngoài/AI).
- Mọi path đều được resolve realpath và validate nằm trong folder đã cấp,
  chặn path traversal (../, symlink ra ngoài root...).
- Lệnh exec: whitelist theo executable đầu dòng; lệnh ngoài whitelist cần
  confirm=true từ người dùng. Một số pattern phá hoại rõ rệt (rm -rf /,
  mkfs, fork bomb...) bị chặn tuyệt đối dù có confirm.

Chạy: uvicorn coworker_host.app:app --host 127.0.0.1 --port 8765
(--host 127.0.0.1 mặc định — chỉ container/local mới gọi được, không
expose ra mạng ngoài. Xem coworker_host/run.sh)
"""
import json
import logging
import os
import re
import shlex
import subprocess
import time
import uuid
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

logger = logging.getLogger("coworker_host")
logging.basicConfig(level=logging.INFO)

# ─────────────────────────────────────────────────────────────
# Cấu hình / persistence
# ─────────────────────────────────────────────────────────────
DATA_DIR = Path(os.environ.get("COWORKER_DATA_DIR", str(Path.home() / ".vulnguard_coworker")))
DATA_DIR.mkdir(parents=True, exist_ok=True)
FOLDERS_FILE = DATA_DIR / "folders.json"
WHITELIST_FILE = DATA_DIR / "whitelist.json"

MAX_FILE_BYTES = 2 * 1024 * 1024  # 2MB — đủ cho file code, tránh đọc file lớn/binary lỡ tay
EXEC_TIMEOUT_SEC = 60
MAX_OUTPUT_CHARS = 20000

DEFAULT_WHITELIST = sorted([
    "ls", "pwd", "cat", "head", "tail", "wc", "find", "grep", "diff", "echo", "tree",
    "git",
    "python", "python3", "pip", "pip3", "pytest",
    "node", "npm", "npx", "yarn", "pnpm", "jest",
    "go", "cargo", "rustc",
    "make", "mvn", "gradle",
])

# Pattern bị chặn TUYỆT ĐỐI — kể cả khi confirm=true (lưới an toàn cuối)
DANGEROUS_PATTERNS = [
    r"rm\s+-[a-z]*r[a-z]*f|rm\s+-[a-z]*f[a-z]*r",   # rm -rf / -fr...
    r"\brm\b.*(/\*|\s/\s*$|\s/\s)",                  # rm trỏ vào root
    r"\bmkfs\b", r"\bdd\b\s+if=", r"\bshutdown\b", r"\breboot\b",
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",     # fork bomb
    r">\s*/dev/sd", r"\bchmod\b\s+-R\s+000\s+/",
]
_DANGEROUS_RE = re.compile("|".join(DANGEROUS_PATTERNS))

app = FastAPI(title="VulnGuard Coworker Host", version="1.0.0")


# ─────────────────────────────────────────────────────────────
# Storage helpers
# ─────────────────────────────────────────────────────────────
def _load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        logger.warning(f"Không đọc được {path}, dùng default")
        return default


def _save_json(path: Path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _load_folders() -> List[dict]:
    return _load_json(FOLDERS_FILE, [])


def _save_folders(folders: List[dict]):
    _save_json(FOLDERS_FILE, folders)


def _load_whitelist() -> List[str]:
    return _load_json(WHITELIST_FILE, DEFAULT_WHITELIST)


def _get_folder(folder_id: str) -> dict:
    for f in _load_folders():
        if f["id"] == folder_id:
            return f
    raise HTTPException(status_code=404, detail="Folder chưa được cấp quyền (folder_id không tồn tại)")


def _resolve_safe(folder: dict, rel_path: str) -> Path:
    """Resolve rel_path bên trong folder root, chặn path traversal ra ngoài root."""
    root = Path(folder["path"]).resolve()
    rel_path = (rel_path or "").strip().lstrip("/")
    target = (root / rel_path).resolve() if rel_path else root
    try:
        target.relative_to(root)
    except ValueError:
        raise HTTPException(status_code=400, detail="Path nằm ngoài folder được cấp quyền — không cho phép")
    return target


# ─────────────────────────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────────────────────────
class AddFolderRequest(BaseModel):
    path: str
    label: Optional[str] = None


class WriteFileRequest(BaseModel):
    folder_id: str
    path: str
    content: str
    create: bool = False


class ExecRequest(BaseModel):
    folder_id: str
    command: str
    cwd: str = ""
    confirm: bool = False
    timeout: Optional[int] = None


class WhitelistRequest(BaseModel):
    commands: List[str]


# ─────────────────────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "service": "vulnguard-coworker-host", "data_dir": str(DATA_DIR)}


# ─────────────────────────────────────────────────────────────
# Folders (granted access)
# ─────────────────────────────────────────────────────────────
@app.get("/folders")
def list_folders():
    return {"folders": _load_folders()}


@app.post("/folders")
def add_folder(req: AddFolderRequest):
    path = Path(req.path).expanduser()
    if not path.is_absolute():
        raise HTTPException(status_code=400, detail="Path phải là absolute path trên máy host")
    if not path.exists() or not path.is_dir():
        raise HTTPException(status_code=400, detail=f"Folder không tồn tại hoặc không phải directory: {path}")

    resolved = str(path.resolve())
    if resolved in ("/", str(Path.home())):
        raise HTTPException(
            status_code=400,
            detail="Không cho phép cấp quyền toàn bộ root hoặc toàn bộ home directory — hãy chọn folder cụ thể hơn",
        )

    folders = _load_folders()
    for f in folders:
        if f["path"] == resolved:
            return f  # đã cấp quyền rồi, trả lại luôn

    entry = {
        "id": uuid.uuid4().hex[:12],
        "path": resolved,
        "label": req.label or path.name,
        "created_at": time.time(),
    }
    folders.append(entry)
    _save_folders(folders)
    logger.info(f"[coworker] Cấp quyền folder mới: {resolved}")
    return entry


@app.delete("/folders/{folder_id}")
def remove_folder(folder_id: str):
    folders = _load_folders()
    new_folders = [f for f in folders if f["id"] != folder_id]
    if len(new_folders) == len(folders):
        raise HTTPException(status_code=404, detail="folder_id không tồn tại")
    _save_folders(new_folders)
    return {"message": "Đã thu hồi quyền truy cập folder"}


# ─────────────────────────────────────────────────────────────
# Filesystem
# ─────────────────────────────────────────────────────────────
SKIP_DIR_NAMES = {".git", "node_modules", "__pycache__", ".venv", "venv", ".idea", ".vscode", "dist", "build"}


@app.get("/fs/tree")
def fs_tree(folder_id: str, path: str = ""):
    folder = _get_folder(folder_id)
    target = _resolve_safe(folder, path)
    if not target.exists():
        raise HTTPException(status_code=404, detail="Path không tồn tại")
    if not target.is_dir():
        raise HTTPException(status_code=400, detail="Path không phải directory")

    entries = []
    try:
        for child in sorted(target.iterdir(), key=lambda p: (p.is_file(), p.name.lower())):
            if child.name in SKIP_DIR_NAMES:
                continue
            try:
                stat = child.stat()
            except OSError:
                continue
            entries.append({
                "name": child.name,
                "is_dir": child.is_dir(),
                "size": stat.st_size if child.is_file() else None,
                "mtime": stat.st_mtime,
            })
    except PermissionError:
        raise HTTPException(status_code=403, detail="Không có quyền đọc directory này")

    return {"path": path, "entries": entries}


@app.get("/fs/find")
def fs_find(folder_id: str, path: str = "", query: str = "", max_results: int = 300, max_depth: int = 8):
    """Tìm file ĐỆ QUY trong folder (mọi cấp). Trả về list đường dẫn tương đối.

    - query: lọc theo tên file (chứa chuỗi, không phân biệt hoa thường); rỗng = tất cả file.
    - Bỏ qua các thư mục trong SKIP_DIR_NAMES; giới hạn max_results & max_depth để an toàn.
    """
    folder = _get_folder(folder_id)
    root = _resolve_safe(folder, path)
    if not root.exists() or not root.is_dir():
        raise HTTPException(status_code=400, detail="Path không phải directory hợp lệ")

    q = (query or "").lower()
    results = []
    truncated = False

    def _walk(d: Path, depth: int):
        nonlocal truncated
        if truncated or depth > max_depth:
            return
        try:
            children = sorted(d.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
        except (PermissionError, OSError):
            return
        for child in children:
            if child.name in SKIP_DIR_NAMES or child.name.startswith("."):
                continue
            if child.is_dir():
                _walk(child, depth + 1)
            elif child.is_file():
                if not q or q in child.name.lower():
                    try:
                        rel = str(child.relative_to(_resolve_safe(folder, "")))
                    except Exception:
                        rel = child.name
                    results.append(rel)
                    if len(results) >= max_results:
                        truncated = True
                        return

    _walk(root, 0)
    return {"path": path, "query": query, "files": results, "truncated": truncated}


def _looks_binary(raw: bytes) -> bool:
    if b"\x00" in raw:
        return True
    try:
        raw.decode("utf-8")
        return False
    except UnicodeDecodeError:
        return True


@app.get("/fs/file")
def fs_read_file(folder_id: str, path: str):
    folder = _get_folder(folder_id)
    target = _resolve_safe(folder, path)
    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="File không tồn tại")

    size = target.stat().st_size
    if size > MAX_FILE_BYTES:
        raise HTTPException(status_code=413, detail=f"File quá lớn ({size} bytes, giới hạn {MAX_FILE_BYTES})")

    raw = target.read_bytes()
    if _looks_binary(raw):
        return {"path": path, "binary": True, "content": None, "size": size}

    return {"path": path, "binary": False, "content": raw.decode("utf-8"), "size": size}


@app.get("/fs/file_b64")
def fs_read_file_b64(folder_id: str, path: str):
    """Trả nội dung file dạng base64 — dùng cho file tài liệu (.docx/.pdf) mà
    container sẽ tự trích xuất text. Không dùng cho file code thường (đã có /fs/file)."""
    import base64
    folder = _get_folder(folder_id)
    target = _resolve_safe(folder, path)
    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="File không tồn tại")
    size = target.stat().st_size
    if size > MAX_FILE_BYTES:
        raise HTTPException(status_code=413, detail=f"File quá lớn ({size} bytes, giới hạn {MAX_FILE_BYTES})")
    raw = target.read_bytes()
    return {"path": path, "size": size, "b64": base64.b64encode(raw).decode("ascii")}


@app.post("/fs/file")
def fs_write_file(req: WriteFileRequest):
    folder = _get_folder(req.folder_id)
    target = _resolve_safe(folder, req.path)

    if not target.exists() and not req.create:
        raise HTTPException(status_code=404, detail="File không tồn tại — set create=true nếu muốn tạo mới")

    target.parent.mkdir(parents=True, exist_ok=True)

    # Backup nhẹ trước khi overwrite — phòng AI suggest sai, người dùng tự khôi phục bằng tay
    if target.exists():
        try:
            backup = target.with_suffix(target.suffix + ".vulnguard.bak")
            backup.write_bytes(target.read_bytes())
        except Exception as e:
            logger.warning(f"Không backup được {target}: {e}")

    target.write_text(req.content, encoding="utf-8")
    return {"path": req.path, "bytes_written": len(req.content.encode("utf-8"))}


# ─────────────────────────────────────────────────────────────
# Exec — sandboxed theo folder root, whitelist + confirm
# ─────────────────────────────────────────────────────────────
@app.get("/whitelist")
def get_whitelist():
    return {"commands": sorted(_load_whitelist())}


@app.put("/whitelist")
def set_whitelist(req: WhitelistRequest):
    cleaned = sorted({c.strip() for c in req.commands if c.strip()})
    _save_json(WHITELIST_FILE, cleaned)
    return {"commands": cleaned}


@app.post("/fs/exec")
def fs_exec(req: ExecRequest):
    folder = _get_folder(req.folder_id)
    cwd_path = _resolve_safe(folder, req.cwd)
    if not cwd_path.exists() or not cwd_path.is_dir():
        raise HTTPException(status_code=400, detail="cwd không tồn tại hoặc không phải directory")

    command = req.command.strip()
    if not command:
        raise HTTPException(status_code=400, detail="Command trống")

    if _DANGEROUS_RE.search(command):
        raise HTTPException(status_code=403, detail="Command bị chặn — phát hiện pattern nguy hiểm (rm -rf /, mkfs, fork bomb...)")

    try:
        tokens = shlex.split(command)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Không parse được command: {e}")
    if not tokens:
        raise HTTPException(status_code=400, detail="Command trống")

    executable = os.path.basename(tokens[0])
    whitelist = _load_whitelist()
    if executable not in whitelist and not req.confirm:
        return {
            "needs_confirm": True,
            "executable": executable,
            "message": f"'{executable}' không nằm trong whitelist. Gửi lại request với confirm=true để xác nhận chạy.",
        }

    timeout = min(req.timeout or EXEC_TIMEOUT_SEC, 300)
    start = time.time()
    try:
        proc = subprocess.run(
            tokens,
            cwd=str(cwd_path),
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        stdout = (proc.stdout or "")[:MAX_OUTPUT_CHARS]
        stderr = (proc.stderr or "")[:MAX_OUTPUT_CHARS]
        return {
            "needs_confirm": False,
            "exit_code": proc.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "duration_sec": round(time.time() - start, 2),
        }
    except FileNotFoundError:
        raise HTTPException(status_code=400, detail=f"Không tìm thấy executable: {executable}")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail=f"Command timeout sau {timeout}s")
