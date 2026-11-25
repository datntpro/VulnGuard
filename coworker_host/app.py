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
- Lệnh exec: chế độ COWORKER_EXEC_MODE (mặc định `safe` = chỉ lệnh đọc).
  `trusted` cho lệnh ngoài whitelist chạy sau khi xác nhận bằng confirm_id do
  SERVER cấp (một lần, 120s). Đối số luôn bị giới hạn trong folder root. Một số
  pattern phá hoại rõ rệt (rm -rf /, mkfs, fork bomb...) bị chặn tuyệt đối.

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
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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

# D-2: chế độ exec. off = tắt; safe (mặc định) = chỉ lệnh đọc, không có đường confirm;
# trusted = lệnh ngoài whitelist chạy được sau khi xác nhận bằng confirm_id do server cấp.
EXEC_MODE = (os.environ.get("COWORKER_EXEC_MODE") or "safe").strip().lower()
if EXEC_MODE not in ("off", "safe", "trusted"):
    logger.warning("COWORKER_EXEC_MODE=%r không hợp lệ — dùng 'safe'", EXEC_MODE)
    EXEC_MODE = "safe"

# Whitelist KHÔNG cần confirm luôn là giao của whitelist đã lưu với tập này
# (interpreter như python3/node/npm/make... không bao giờ nằm trong đây).
SAFE_COMMANDS = {"ls", "pwd", "cat", "head", "tail", "wc", "grep", "diff", "echo", "tree", "find", "git"}
DEFAULT_WHITELIST = sorted(SAFE_COMMANDS)

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


class CodedError(Exception):
    """Lỗi có mã máy đọc được: JSON {"detail": msg, "code": code}."""
    def __init__(self, status: int, code: str, detail: str):
        self.status, self.code, self.detail = status, code, detail


@app.exception_handler(CodedError)
async def _coded_error_handler(request, exc: CodedError):
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=exc.status, content={"detail": exc.detail, "code": exc.code})


# ─────────────────────────────────────────────────────────────
# Bảo mật: token bắt buộc + kiểm tra Host (chống DNS rebinding)
# Dịch vụ này chạy LỆNH trên máy host → bắt buộc xác thực, kể cả khi bind 127.0.0.1
# (tiến trình local khác / trang web qua DNS rebinding vẫn có thể gọi tới).
# ─────────────────────────────────────────────────────────────
import hmac
import secrets as _secrets

_TOKEN_FILE = DATA_DIR / "token"


def _effective_token() -> str:
    tok = (os.environ.get("VULNGUARD_COWORKER_TOKEN") or "").strip()
    if tok:
        return tok
    # Chưa đặt env → tự sinh + lưu, in hướng dẫn. Luôn ép auth (không bao giờ mở toang).
    try:
        if _TOKEN_FILE.exists():
            tok = _TOKEN_FILE.read_text().strip()
    except Exception:
        tok = ""
    if not tok:
        tok = _secrets.token_urlsafe(32)
        try:
            _TOKEN_FILE.write_text(tok)
            os.chmod(_TOKEN_FILE, 0o600)
        except Exception:
            pass
        # N-7: KHÔNG ghi token vào log — chỉ chỉ đường dẫn file (0600).
        logger.warning("⚠ VULNGUARD_COWORKER_TOKEN chưa đặt — đã tự sinh token tại %s (0600). "
                       "Copy giá trị trong file đó vào .env: VULNGUARD_COWORKER_TOKEN=…", _TOKEN_FILE)
    return tok


COWORKER_TOKEN = _effective_token()

# Host được phép (chống DNS rebinding): chỉ localhost/loopback + host.docker.internal.
_ALLOWED_HOSTS = {"127.0.0.1", "localhost", "[::1]", "::1", "host.docker.internal"}
for _h in (os.environ.get("COWORKER_ALLOWED_HOSTS") or "").split(","):
    if _h.strip():
        _ALLOWED_HOSTS.add(_h.strip().lower())

# Endpoint không cần token (chỉ để probe sống/chết, không lộ gì nhạy cảm).
_PUBLIC_PATHS = {"/health"}


def _host_only(h: str) -> str:
    """Tách cổng khỏi Host header, hiểu cả IPv6 dạng [::1]:8765 (N-6)."""
    h = h.strip().lower()
    if h.startswith("["):
        return h[: h.find("]") + 1] if "]" in h else h
    return h.rsplit(":", 1)[0] if h.count(":") == 1 else h


@app.middleware("http")
async def _guard(request, call_next):
    from fastapi.responses import JSONResponse
    # 1) Host check — tách cổng, so với allowlist (chống DNS rebinding)
    host = _host_only(request.headers.get("host") or "")
    if not host or host not in _ALLOWED_HOSTS:
        return JSONResponse(status_code=421, content={"detail": f"Host không được phép: {host}"})
    # 2) Token check (trừ _PUBLIC_PATHS)
    if request.url.path not in _PUBLIC_PATHS:
        auth = request.headers.get("authorization") or ""
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        if not token or not hmac.compare_digest(token, COWORKER_TOKEN):
            return JSONResponse(status_code=401, content={"detail": "Thiếu/sai token (Authorization: Bearer <VULNGUARD_COWORKER_TOKEN>)"})
    return await call_next(request)


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


_WARNED_WHITELIST = False


def _load_whitelist() -> List[str]:
    """Whitelist không-cần-confirm = whitelist đã lưu ∩ SAFE_COMMANDS."""
    global _WARNED_WHITELIST
    raw = _load_json(WHITELIST_FILE, DEFAULT_WHITELIST)
    if not isinstance(raw, list):
        raw = DEFAULT_WHITELIST
    kept = [c for c in raw if c in SAFE_COMMANDS]
    dropped = [c for c in raw if c not in SAFE_COMMANDS]
    if dropped and not _WARNED_WHITELIST:
        _WARNED_WHITELIST = True
        logger.warning("whitelist.json chứa lệnh không an toàn, đã bỏ qua: %s", ", ".join(map(str, dropped)))
    return kept


# D-3: folder nhạy cảm — không bao giờ được cấp quyền.
_SYSTEM_DIRS = ["/etc", "/usr", "/bin", "/sbin", "/var", "/private", "/System", "/Library",
                "/proc", "/sys", "/dev", "/boot", "/root", "/opt"]
_HOME_SENSITIVE = [".ssh", ".gnupg", ".aws", ".azure", ".config", ".docker", ".kube",
                   ".local", "Library", ".vulnguard_coworker"]


def _resolved(p) -> Path:
    try:
        return Path(p).resolve()
    except Exception:
        return Path(p)


def _folder_allowed(path) -> Optional[str]:
    """Trả về lý do từ chối (str) hoặc None nếu folder được phép cấp quyền."""
    p = _resolved(path)
    home = _resolved(Path.home())
    data = _resolved(DATA_DIR)
    if p == Path(p.anchor):
        return "Không cho phép cấp quyền toàn bộ root filesystem"
    if p == home or p in home.parents:
        return "Không cho phép cấp quyền home directory hoặc thư mục cha của nó — hãy chọn folder dự án cụ thể"
    if p == data or p in data.parents or data in p.parents:
        return "Folder trùng/chứa/nằm trong thư mục dữ liệu của Coworker Host"
    # Vùng hệ thống chỉ áp dụng cho path NGOÀI home (home có thể nằm dưới /root, /var/...).
    sensitive = [_resolved(home / d) for d in _HOME_SENSITIVE]
    if home not in p.parents:
        sensitive += [_resolved(d) for d in _SYSTEM_DIRS]
    for s_ in sensitive:
        if p == s_ or s_ in p.parents:
            return f"Folder nằm trong vùng nhạy cảm ({s_}) — không cho phép"
        if p in s_.parents:
            return f"Folder chứa vùng nhạy cảm ({s_}) — hãy chọn folder cụ thể hơn"
    roots = [r.strip() for r in (os.environ.get("COWORKER_ALLOWED_ROOTS") or "").split(",") if r.strip()]
    if roots:
        rr = [_resolved(Path(r).expanduser()) for r in roots]
        if not any(p == r or r in p.parents for r in rr):
            return "Folder nằm ngoài COWORKER_ALLOWED_ROOTS"
    return None


def _get_folder(folder_id: str) -> dict:
    for f in _load_folders():
        if f["id"] == folder_id:
            reason = _folder_allowed(f["path"])
            if reason:
                raise HTTPException(status_code=403, detail=f"Grant folder bị từ chối theo chính sách: {reason}")
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
    confirm: bool = False            # LEGACY: bị bỏ qua, không bao giờ tự cấp quyền chạy
    confirm_id: Optional[str] = None  # nonce do server cấp (chế độ trusted)
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
    reason = _folder_allowed(resolved)
    if reason:
        raise HTTPException(status_code=400, detail=reason)

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


_WRITE_DENY_DIRS = {".git", ".husky", ".vscode", ".idea", ".direnv"}


def _check_write_allowed(folder: dict, target: Path):
    root = Path(folder["path"]).resolve()
    rel_parts = target.relative_to(root).parts
    if any(part in _WRITE_DENY_DIRS for part in rel_parts) or target.name == ".envrc":
        raise CodedError(403, "write_denied", "Không cho ghi vào .git/.husky/.vscode/.idea/.direnv/.envrc (có thể tự chạy mã)")
    data = _resolved(DATA_DIR)
    if target == data or data in target.parents:
        raise CodedError(403, "write_denied", "Không cho ghi vào thư mục dữ liệu của Coworker Host")


@app.post("/fs/file")
def fs_write_file(req: WriteFileRequest):
    folder = _get_folder(req.folder_id)
    target = _resolve_safe(folder, req.path)
    _check_write_allowed(folder, target)

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
    bad = [c for c in cleaned if c not in SAFE_COMMANDS]
    if bad:
        raise HTTPException(status_code=400, detail=f"Lệnh không được phép trong whitelist: {', '.join(bad)} "
                                                    f"(chỉ cho phép: {', '.join(sorted(SAFE_COMMANDS))})")
    _save_json(WHITELIST_FILE, cleaned)
    return {"commands": cleaned}


# ── Confirm nonce (chế độ trusted) ───────────────────────────
CONFIRM_TTL_SEC = 120
CONFIRM_MAX_PENDING = 100
_PENDING: Dict[str, Tuple[str, float]] = {}


def _confirm_hash(folder_id: str, cwd: str, command: str) -> str:
    return hashlib.sha256(f"{folder_id}|{cwd}|{command}".encode("utf-8")).hexdigest()


def _issue_confirm(h: str) -> str:
    now = time.time()
    for k in [k for k, (_, exp) in _PENDING.items() if exp <= now]:
        _PENDING.pop(k, None)
    while len(_PENDING) >= CONFIRM_MAX_PENDING:
        _PENDING.pop(min(_PENDING, key=lambda k: _PENDING[k][1]), None)
    cid = _secrets.token_urlsafe(24)
    _PENDING[cid] = (h, now + CONFIRM_TTL_SEC)
    return cid


def _consume_confirm(cid: str, h: str) -> bool:
    entry = _PENDING.pop(cid, None)  # single-use dù đúng hay sai
    if not entry:
        return False
    exp_hash, exp = entry
    return exp > time.time() and hmac.compare_digest(exp_hash, h)


# ── Giới hạn đối số trong folder root ─────────────────────────
_FIND_DENIED = {"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf",
                "-fls", "-L", "-follow"}
_GREP_DENIED = {"-R", "--dereference-recursive"}
_TREE_DENIED = {"-o", "-l"}
_TAIL_DENIED = {"-f", "-F", "--follow"}
_GIT_SUBCOMMANDS = {"status", "diff", "log", "show", "branch", "rev-parse", "ls-files", "blame"}
_GIT_DENIED = {"--output", "-o", "--ext-diff", "--textconv", "--upload-pack", "--exec", "-O",
               "--open-files-in-pager"}
_PATH_CMDS = {"cat", "head", "tail", "wc", "diff", "ls", "tree"}


def _arg_err(code: str, msg: str):
    return CodedError(400, code, msg)


def _confine(value: str, root: Path, cwd: Path):
    if value.startswith("~"):
        raise _arg_err("arg_outside_root", f"Đối số '{value}' bắt đầu bằng '~' — không cho phép")
    p = Path(value)
    p = (p if p.is_absolute() else cwd / p).resolve()
    if p != root and root not in p.parents:
        raise _arg_err("arg_outside_root", f"Đối số '{value}' nằm ngoài folder được cấp quyền")


def _opt_name(t: str) -> str:
    return t.split("=", 1)[0] if t.startswith("--") else t


def _check_args(executable: str, tokens: List[str], root: Path, cwd: Path):
    """Kiểm tra đối số (tokens KHÔNG gồm executable). Ném CodedError 400 nếu vi phạm."""
    if executable == "echo":
        return
    if executable == "find":
        for t in tokens:
            if t in _FIND_DENIED:
                raise _arg_err("option_denied", f"find: tùy chọn '{t}' bị cấm")
        for t in tokens:
            if t.startswith("-") or t in ("(", "!"):
                break
            _confine(t, root, cwd)
        return
    if executable == "grep":
        for t in tokens:
            if _opt_name(t) in _GREP_DENIED:
                raise _arg_err("option_denied", f"grep: tùy chọn '{t}' bị cấm")
        pattern_given = any(t in ("-e", "-f") or t.startswith(("--regexp", "--file")) for t in tokens)
        skip_pattern = not pattern_given
        i = 0
        while i < len(tokens):
            t = tokens[i]
            if t in ("-f", "--file") and i + 1 < len(tokens):
                _confine(tokens[i + 1], root, cwd)
                i += 2
                continue
            if t.startswith("--file="):
                _confine(t.split("=", 1)[1], root, cwd)
            elif t in ("-e", "--regexp"):
                i += 2
                continue
            elif t.startswith("-"):
                pass
            elif skip_pattern:
                skip_pattern = False
            else:
                _confine(t, root, cwd)
            i += 1
        return
    if executable == "git":
        _check_git(tokens)
        # positional paths (sau subcommand) — chỉ confine thứ trông giống path tuyệt đối/~/..
        for t in tokens[1:]:
            if not t.startswith("-") and (t.startswith(("/", "~")) or ".." in Path(t).parts):
                _confine(t, root, cwd)
        return
    # Lệnh path-style (và best-effort cho lệnh ngoài whitelist ở chế độ trusted)
    denied = {"tree": _TREE_DENIED, "tail": _TAIL_DENIED}.get(executable, set())
    for t in tokens:
        if _opt_name(t) in denied:
            raise _arg_err("option_denied", f"{executable}: tùy chọn '{t}' bị cấm")
    for t in tokens:
        if t.startswith("--") and "=" in t:
            _confine(t.split("=", 1)[1], root, cwd)
        elif t.startswith("-") and t != "-":
            continue
        else:
            _confine(t, root, cwd)


def _check_git(tokens: List[str]):
    if not tokens or tokens[0] not in _GIT_SUBCOMMANDS:
        raise _arg_err("option_denied", f"git: chỉ cho phép subcommand {', '.join(sorted(_GIT_SUBCOMMANDS))} "
                                         "(không có tùy chọn trước subcommand)")
    for t in tokens:
        if _opt_name(t) in _GIT_DENIED:
            raise _arg_err("option_denied", f"git: tùy chọn '{t}' bị cấm")


def _build_argv(tokens: List[str]) -> List[str]:
    """argv thật sự chạy. Với git: vô hiệu hóa fsmonitor/hooks/pager/ext-diff."""
    if os.path.basename(tokens[0]) != "git":
        return tokens
    sub, rest = tokens[1], tokens[2:]
    extra = ["--no-ext-diff", "--no-textconv"] if sub in ("diff", "log", "show") else []
    return ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat",
            "-c", "diff.external=", "-c", "protocol.allow=never", "--no-pager", sub, *extra, *rest]


def _child_env() -> Dict[str, str]:
    """Môi trường tối thiểu cho tiến trình con — KHÔNG kế thừa VULNGUARD_COWORKER_TOKEN."""
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", str(Path.home())),
           "TERM": "dumb", "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "PAGER": "cat"}
    for k in ("LANG", "LC_ALL"):
        if os.environ.get(k):
            env[k] = os.environ[k]
    return env


@app.post("/fs/exec")
def fs_exec(req: ExecRequest):
    if EXEC_MODE == "off":
        raise CodedError(403, "exec_disabled", "Exec bị tắt trên host (COWORKER_EXEC_MODE=off)")
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
    # Lệnh phải là tên trần (không cho ./script hay /abs/path/bin) để whitelist có nghĩa.
    if tokens[0] != executable:
        raise _arg_err("arg_outside_root", "Chỉ cho phép tên lệnh trần (không có đường dẫn)")
    whitelisted = executable in _load_whitelist()

    if not whitelisted and EXEC_MODE == "safe":
        raise CodedError(403, "exec_mode_safe",
                         f"Host đang ở chế độ safe — chỉ cho phép lệnh đọc ({', '.join(sorted(SAFE_COMMANDS))}). "
                         f"'{executable}' không được phép.")

    root = Path(folder["path"]).resolve()
    _check_args(executable, tokens[1:], root, cwd_path)

    if not whitelisted:  # chỉ tới được ở chế độ trusted
        h = _confirm_hash(req.folder_id, req.cwd, command)
        if not req.confirm_id:
            return {
                "needs_confirm": True,
                "confirm_id": _issue_confirm(h),
                "executable": executable,
                "command": command,
                "expires_in": CONFIRM_TTL_SEC,
                "message": f"'{executable}' không nằm trong whitelist. Xác nhận để chạy đúng lệnh này (hiệu lực {CONFIRM_TTL_SEC}s).",
            }
        if not _consume_confirm(req.confirm_id, h):
            raise CodedError(409, "confirm_invalid", "confirm_id sai, hết hạn, đã dùng, hoặc không khớp lệnh")

    timeout = min(req.timeout or EXEC_TIMEOUT_SEC, 300)
    start = time.time()
    try:
        proc = subprocess.run(  # nosec B603 - shell=False, argv đã kiểm tra, env tối thiểu
            _build_argv(tokens),
            cwd=str(cwd_path),
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            env=_child_env(),
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
