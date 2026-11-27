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


_BRACKET_HOST_RE = re.compile(r"^(\[[0-9a-f:.]+\])(:\d+)?$")


def _host_only(h: str) -> str:
    """Tách cổng khỏi Host header, hiểu cả IPv6 dạng [::1]:8765 (N-6). Host dạng [..] sai cú pháp → ''."""
    h = h.strip().lower()
    if h.startswith("["):
        m = _BRACKET_HOST_RE.match(h)
        return m.group(1) if m else ""
    if h.count(":") == 1:
        host, port = h.split(":")
        return host if (port.isascii() and port.isdigit()) else ""
    return h


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


def _cf_parts(p) -> tuple:
    """Các thành phần path đã casefold — so sánh KHÔNG phân biệt hoa/thường (APFS/NTFS mặc định
    case-insensitive: ~/.SSH, /USERS/x, .GIT/config là cùng một nơi)."""
    return tuple(x.casefold() for x in Path(p).parts)


def _under(p, base) -> bool:
    """p nằm trong (hoặc bằng) base, so sánh casefold."""
    pp, bp = _cf_parts(p), _cf_parts(base)
    return len(pp) >= len(bp) and pp[: len(bp)] == bp


def _forms(p) -> list:
    """Dạng tuyệt đối chưa resolve + dạng đã resolve (vd /etc và /private/etc đều được kiểm)."""
    raw = Path(os.path.abspath(str(p)))
    res = _resolved(p)
    return [raw] if raw == res else [raw, res]


def _folder_allowed(path) -> Optional[str]:
    """Trả về lý do từ chối (str) hoặc None nếu folder được phép cấp quyền."""
    pforms = _forms(path)
    homes = _forms(Path.home())
    datas = _forms(DATA_DIR)
    for p in pforms:
        if len(p.parts) <= 1:
            return "Không cho phép cấp quyền toàn bộ root filesystem"
        for h in homes:
            if _under(h, p):  # p == home hoặc tổ tiên của home
                return "Không cho phép cấp quyền home directory hoặc thư mục cha của nó — hãy chọn folder dự án cụ thể"
        for d in datas:
            if _under(p, d) or _under(d, p):
                return "Folder trùng/chứa/nằm trong thư mục dữ liệu của Coworker Host"
    # Vùng hệ thống chỉ áp dụng cho path NGOÀI home (home có thể nằm dưới /root, /var/...).
    inside_home = any(_under(p, h) for p in pforms for h in homes)
    sensitive = [f for h in homes for d in _HOME_SENSITIVE for f in _forms(h / d)]
    if not inside_home:
        sensitive += [f for d in _SYSTEM_DIRS for f in _forms(d)]
    for p in pforms:
        for s_ in sensitive:
            if _under(p, s_):
                return f"Folder nằm trong vùng nhạy cảm ({s_}) — không cho phép"
            if _under(s_, p):
                return f"Folder chứa vùng nhạy cảm ({s_}) — hãy chọn folder cụ thể hơn"
    roots = [r.strip() for r in (os.environ.get("COWORKER_ALLOWED_ROOTS") or "").split(",") if r.strip()]
    if roots:
        rr = [f for r in roots for f in _forms(Path(r).expanduser())]
        if not any(_under(p, r) for p in pforms for r in rr):
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


def _path_meta(folder: dict, rel_path: str, target: Path) -> dict:
    """[AI PR-3b] Thông tin đường dẫn THẬT của file sắp đọc (cho cổng đường dẫn nhạy cảm của Co-work cloud):
    đường dẫn đã resolve (tương đối root), có symlink ở BẤT KỲ thành phần nào không, có hard link (nlink>1) không."""
    root = Path(folder["path"]).resolve()
    try:
        resolved = target.relative_to(root).as_posix()
    except ValueError:
        resolved = ""
    link = False
    cur = root
    for part in [x for x in (rel_path or "").replace("\\", "/").split("/") if x not in ("", ".")]:
        cur = cur / part
        try:
            if cur.is_symlink():
                link = True
                break
        except OSError:
            link = True
            break
    try:
        hard = target.stat().st_nlink > 1
    except OSError:
        hard = False
    return {"resolved": resolved, "symlink": link, "hardlink": hard}


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
        return {"path": path, "binary": True, "content": None, "size": size, **_path_meta(folder, path, target)}

    return {"path": path, "binary": False, "content": raw.decode("utf-8"), "size": size,
            **_path_meta(folder, path, target)}


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
    return {"path": path, "size": size, "b64": base64.b64encode(raw).decode("ascii"),
            **_path_meta(folder, path, target)}


_WRITE_DENY_DIRS = {".git", ".husky", ".vscode", ".idea", ".direnv"}
_WRITE_DENY_NAMES = {".envrc", ".gitattributes", ".gitmodules"}


def _check_write_allowed(folder: dict, target: Path):
    root = Path(folder["path"]).resolve()
    rel_parts = [x.casefold() for x in target.relative_to(root).parts]
    if any(part in _WRITE_DENY_DIRS for part in rel_parts) or (rel_parts and rel_parts[-1] in _WRITE_DENY_NAMES):
        raise CodedError(403, "write_denied",
                         "Không cho ghi vào .git/.husky/.vscode/.idea/.direnv/.envrc/.gitattributes/.gitmodules (có thể tự chạy mã)")
    for d in _forms(DATA_DIR):
        if _under(target, d):
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
                "-fls", "-L", "-H", "-f", "-D", "-follow", "-files0-from"}
_FIND_PATH_OPERANDS = {"-newer", "-anewer", "-cnewer", "-samefile", "-mnewer"}
_GREP_DENIED_CHARS = set("RSO")
_GREP_VALUE_CHARS = set("efmABCdD")
_GREP_LONG_PATHS = {"--file", "--exclude-from"}
_GREP_LONG_DENIED = {"--dereference-recursive"}
_TREE_DENIED_CHARS = set("ol")
_TAIL_DENIED_CHARS = set("fF")
_TAIL_DENIED_LONG = {"--follow", "--retry", "--pid"}
_LS_DENIED_CHARS = set("LH")
_GIT_SUBCOMMANDS = {"status", "diff", "log", "show", "branch", "rev-parse", "ls-files", "blame"}
_GIT_DENIED = {"--output", "--ext-diff", "--textconv", "--upload-pack", "--exec", "-O",
               "--open-files-in-pager", "--contents", "--no-index", "--show-signature", "--paginate",
               "--ignore-revs-file", "--git-dir", "--work-tree", "--exec-path", "--config-env"}
_GIT_BRANCH_FLAGS = set("arvl")
_GIT_BRANCH_LONG = {"--all", "--remotes", "--verbose", "--list", "--show-current", "--no-color", "--color",
                    "--contains", "--no-contains", "--merged", "--no-merged", "--points-at", "--sort",
                    "--format", "--column", "--no-column", "--abbrev", "--no-abbrev", "--ignore-case"}
_GIT_BRANCH_VALUE_LONG = {"--contains", "--no-contains", "--merged", "--no-merged", "--points-at", "--sort", "--format"}


def _arg_err(code: str, msg: str):
    return CodedError(400, code, msg)


def _confine(value: str, root: Path, cwd: Path):
    if value.startswith("~"):
        raise _arg_err("arg_outside_root", f"Đối số '{value}' bắt đầu bằng '~' — không cho phép")
    p = Path(value)
    p = (p if p.is_absolute() else cwd / p).resolve()
    if not _under(p, root):
        raise _arg_err("arg_outside_root", f"Đối số '{value}' nằm ngoài folder được cấp quyền")


def _confine_if_pathlike(value: str, root: Path, cwd: Path):
    """Dùng cho slot có thể là pattern/revision: chỉ ép khi trông như path (~, có ..) hoặc đang
    tồn tại trên đĩa (kể cả symlink trỏ ra ngoài). Path tuyệt đối không tồn tại thì vô hại."""
    if not value or value == "-":
        return
    try:
        exists = os.path.lexists(value if value.startswith("/") else cwd / value)
    except (OSError, ValueError):
        exists = False
    if value.startswith("~") or ".." in Path(value).parts or exists:
        _confine(value, root, cwd)


def _long_in(name: str, fulls) -> bool:
    """Tên option dài (có thể viết tắt theo kiểu getopt_long: --deref) khớp một option trong `fulls`."""
    return any(f == name or (len(name) >= 5 and f.startswith(name)) for f in fulls)


def _opt_name(t: str) -> str:
    return t.split("=", 1)[0] if t.startswith("--") else t


def _is_short_cluster(t: str) -> bool:
    return len(t) > 1 and t[0] == "-" and t[1] != "-" and not t[1:].isdigit()


def _deny(cmd: str, t: str):
    return _arg_err("option_denied", f"{cmd}: tùy chọn '{t}' bị cấm")


def _check_generic(executable: str, tokens: List[str], root: Path, cwd: Path,
                   denied_chars=frozenset(), denied_long=frozenset(), path_value_chars=frozenset(),
                   no_dirs=False):
    """cat/head/tail/wc/diff/ls/tree (và best-effort cho lệnh trusted): mọi positional và mọi --opt=value là path."""
    end_opts = False
    for t in tokens:
        if end_opts:
            _confine(t, root, cwd)
            if no_dirs and (cwd / t).is_dir():
                raise _arg_err("option_denied", f"{executable}: toán hạng '{t}' là thư mục — chỉ so sánh file")
        elif t == "--":
            end_opts = True
        elif t.startswith("--"):
            if _long_in(_opt_name(t), denied_long):
                raise _deny(executable, t)
            if "=" in t:
                _confine(t.split("=", 1)[1], root, cwd)
        elif _is_short_cluster(t):
            bad = denied_chars & set(t[1:])
            if bad:
                raise _deny(executable, t)
            for k, ch in enumerate(t[1:], start=2):
                if ch in path_value_chars:  # giá trị gắn liền, vd diff -X/path
                    if t[k:]:
                        _confine(t[k:], root, cwd)
                    break
        elif t.startswith("-") and t != "-":
            continue
        else:
            _confine(t, root, cwd)
            if no_dirs and (cwd / t).is_dir():
                raise _arg_err("option_denied", f"{executable}: toán hạng '{t}' là thư mục — chỉ so sánh file")


_FIND_FLAG_CLUSTER = re.compile(r"^-[EHLPXdfsx]+$")


def _check_find(tokens: List[str], root: Path, cwd: Path):
    for t in tokens:
        if t in _FIND_DENIED:
            raise _deny("find", t)
    i = 0
    # Cờ BSD đứng trước path: có thể là CỤM (-xL, -Ef, -sx) hoặc '--' kết thúc cờ.
    while i < len(tokens):
        t = tokens[i]
        if t == "--":
            i += 1
            break
        if re.match(r"^-[EHLPXdsx]*f", t):  # -f<path> (giá trị gắn liền) hoặc cụm có f
            raise _deny("find", t)
        if _FIND_FLAG_CLUSTER.match(t):
            if set(t[1:]) & set("HLf"):
                raise _deny("find", t)
            i += 1
        elif re.fullmatch(r"-O\d", t):
            i += 1
        else:
            break
    while i < len(tokens) and not (tokens[i].startswith("-") or tokens[i] in ("(", "!")):
        _confine(tokens[i], root, cwd)
        i += 1
    while i < len(tokens):
        t = tokens[i]
        if (t in _FIND_PATH_OPERANDS or t.startswith("-newer")) and i + 1 < len(tokens):
            _confine(tokens[i + 1], root, cwd)
            i += 1
        i += 1


def _check_grep(tokens: List[str], root: Path, cwd: Path):
    have_pattern_opt = False
    have_pattern_slot = False  # đã gặp positional đầu (pattern)
    i = 0
    n = len(tokens)
    end_opts = False
    # Quét lần 1: có -e/-f/--regexp/--file không (khi đó positional đầu là file, không phải pattern)
    for t in tokens:
        if t == "--":
            break
        if t.startswith("--"):
            if _opt_name(t) in ("--regexp", "--file"):
                have_pattern_opt = True
        elif _is_short_cluster(t):
            body = t[1:]
            for ch in body:
                if ch in "ef":
                    have_pattern_opt = True
                    break
                if ch in _GREP_VALUE_CHARS:
                    break
    while i < n:
        t = tokens[i]
        if end_opts:
            if not have_pattern_opt and not have_pattern_slot:
                have_pattern_slot = True
                _confine_if_pathlike(t, root, cwd)
            else:
                _confine(t, root, cwd)
        elif t == "--":
            end_opts = True
        elif t.startswith("--"):
            name = _opt_name(t)
            if _long_in(name, _GREP_LONG_DENIED):
                raise _deny("grep", t)
            val = t.split("=", 1)[1] if "=" in t else None
            if _long_in(name, _GREP_LONG_PATHS):
                if val is None:
                    i += 1
                    val = tokens[i] if i < n else ""
                _confine(val, root, cwd)
            elif _long_in(name, ("--regexp",)):
                if val is None:
                    i += 1
                    val = tokens[i] if i < n else ""
                _confine_if_pathlike(val, root, cwd)
            elif val is not None:
                _confine_if_pathlike(val, root, cwd)
        elif _is_short_cluster(t):
            body = t[1:]
            if _GREP_DENIED_CHARS & set(body):
                raise _deny("grep", t)
            for k, ch in enumerate(body):
                if ch in _GREP_VALUE_CHARS:
                    val = body[k + 1:]
                    if not val:
                        i += 1
                        val = tokens[i] if i < n else ""
                    if ch == "f":
                        _confine(val, root, cwd)
                    else:
                        _confine_if_pathlike(val, root, cwd)
                    break
        elif t.startswith("-") and t != "-":
            pass
        else:
            if not have_pattern_opt and not have_pattern_slot:
                have_pattern_slot = True
                _confine_if_pathlike(t, root, cwd)
            else:
                _confine(t, root, cwd)
        i += 1


def _check_git(tokens: List[str], root: Path, cwd: Path):
    if not tokens or tokens[0] not in _GIT_SUBCOMMANDS:
        raise _arg_err("option_denied", f"git: chỉ cho phép subcommand {', '.join(sorted(_GIT_SUBCOMMANDS))} "
                                         "(không có tùy chọn trước subcommand)")
    sub, rest = tokens[0], tokens[1:]
    end_opts = False
    for t in rest:
        if end_opts:
            _confine(t, root, cwd)
            continue
        if t == "--":
            end_opts = True
            continue
        if t.startswith(("--submodule", "--ignore-sub", "--sub")) or _opt_name(t) in _GIT_DENIED or t.startswith("-O") or t.startswith("--out") or t.startswith("--cont") \
                or t.startswith("--no-ind") or t.startswith("--ignore-revs"):
            raise _deny("git", t)
        if t.startswith("--"):
            if "=" in t:
                _confine_if_pathlike(t.split("=", 1)[1], root, cwd)
        elif _is_short_cluster(t):
            if "O" in t[1:]:
                raise _deny("git", t)
            if len(t) > 2:
                _confine_if_pathlike(t[2:], root, cwd)
        else:
            _confine_if_pathlike(t, root, cwd)
    if sub == "branch":
        _check_git_branch(rest)


def _check_git_branch(rest: List[str]):
    """`git branch` chỉ ở chế độ liệt kê (safe mode là read-only)."""
    listing = False
    positionals = []
    expect_value = False
    for t in rest:
        if expect_value:
            expect_value = False
            continue
        if t == "--":
            continue
        if t.startswith("--"):
            name = _opt_name(t)
            if name not in _GIT_BRANCH_LONG:
                raise _deny("git branch", t)
            if name in ("--list", "--show-current", "--contains", "--no-contains", "--merged", "--no-merged", "--points-at"):
                listing = True
            if name in _GIT_BRANCH_VALUE_LONG and "=" not in t:
                expect_value = True
        elif _is_short_cluster(t):
            if not set(t[1:]) <= _GIT_BRANCH_FLAGS:
                raise _deny("git branch", t)
            if "l" in t[1:]:
                listing = True
        elif t.startswith("-"):
            raise _deny("git branch", t)
        else:
            positionals.append(t)
    if positionals and not listing:
        raise _deny("git branch", positionals[0] + " (tạo branch)")


def _check_args(executable: str, tokens: List[str], root: Path, cwd: Path):
    """Kiểm tra đối số (tokens KHÔNG gồm executable). Ném CodedError 400 nếu vi phạm."""
    if executable == "echo":
        return
    if executable == "find":
        return _check_find(tokens, root, cwd)
    if executable == "grep":
        return _check_grep(tokens, root, cwd)
    if executable == "git":
        return _check_git(tokens, root, cwd)
    if executable == "tree":
        return _check_generic(executable, tokens, root, cwd, denied_chars=_TREE_DENIED_CHARS)
    if executable == "tail":
        return _check_generic(executable, tokens, root, cwd, denied_chars=_TAIL_DENIED_CHARS,
                              denied_long=_TAIL_DENIED_LONG)
    if executable == "ls":
        return _check_generic(executable, tokens, root, cwd, denied_chars=_LS_DENIED_CHARS)
    if executable == "diff":
        # Apple diff -r đi theo symlink gặp trong lúc đệ quy → cấm đệ quy
        return _check_generic(executable, tokens, root, cwd, denied_chars=set("r"),
                              denied_long={"--recursive"}, path_value_chars=set("XS"), no_dirs=True)
    return _check_generic(executable, tokens, root, cwd)


_EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
_GIT_ATTR_SUPPORT: Optional[bool] = None


def _git_attr_source_supported() -> bool:
    """git >= 2.40 có --attr-source. Dùng để vô hiệu hóa .gitattributes (filter/diff/textconv driver)."""
    global _GIT_ATTR_SUPPORT
    if _GIT_ATTR_SUPPORT is None:
        try:
            r = subprocess.run(["git", f"--attr-source={_EMPTY_TREE}", "--version"], capture_output=True,  # nosec B603 B607
                               stdin=subprocess.DEVNULL, env=_child_env(), timeout=10)
            _GIT_ATTR_SUPPORT = r.returncode == 0
        except Exception:
            _GIT_ATTR_SUPPORT = False
    return _GIT_ATTR_SUPPORT


def _build_argv(tokens: List[str]) -> List[str]:
    """argv thật sự chạy. Với git: vô hiệu hóa fsmonitor/hooks/pager/ext-diff VÀ attribute driver
    (filter/textconv/diff) bằng cách đọc attributes từ empty tree thay vì worktree/.git/info."""
    if os.path.basename(tokens[0]) != "git":
        return tokens
    sub, rest = tokens[1], tokens[2:]
    extra = ["--no-ext-diff", "--no-textconv"] if sub in ("diff", "log", "show") else []
    if sub in ("diff", "status"):
        # Không cho git vào submodule (nó chạy git con dùng info/attributes/filter của submodule); dòng lệnh
        # thắng cả submodule.<n>.ignore trong .git/config. Đổi lại: submodule bẩn không hiện ở safe mode.
        extra.append("--ignore-submodules=all")
    return ["git", f"--attr-source={_EMPTY_TREE}",
            "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat",
            "-c", "core.attributesFile=/dev/null", "-c", "core.sshCommand=false", "-c", "gpg.program=false",
            "-c", "log.showSignature=false", "-c", "diff.submodule=short", "-c", "status.submoduleSummary=false",
            "-c", "submodule.recurse=false", "-c", "diff.external=", "-c", "protocol.allow=never",
            "--no-pager", sub, *extra, *rest]


def _child_env(ceiling: Optional[Path] = None) -> Dict[str, str]:
    """Môi trường tối thiểu cho tiến trình con — KHÔNG kế thừa VULNGUARD_COWORKER_TOKEN.
    ceiling: thư mục cha của root → git không được tìm repo vượt lên trên root."""
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", str(Path.home())),
           "TERM": "dumb", "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_ATTR_NOSYSTEM": "1",
           "PAGER": "cat"}
    for k in ("LANG", "LC_ALL"):
        if os.environ.get(k):
            env[k] = os.environ[k]
    if ceiling is not None:
        env["GIT_CEILING_DIRECTORIES"] = str(ceiling)
        env["GIT_DISCOVERY_ACROSS_FILESYSTEM"] = "0"
    return env


def _git_preflight(root: Path, cwd: Path):
    """Trước khi chạy git: repo (toplevel, git-dir, common-dir) phải nằm TRONG root (chặn repo dotfiles ở
    $HOME, `.git` file/`gitdir:` trỏ ra ngoài, core.worktree ra ngoài) và .git/info/attributes không được
    định nghĩa attribute (nó vẫn bật filter/textconv dù đã đặt --attr-source)."""
    env = _child_env(root.parent)
    base = ["git", f"--attr-source={_EMPTY_TREE}", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
            "-c", "core.attributesFile=/dev/null", "--no-pager"]

    def _run(*a):
        return subprocess.run([*base, *a], cwd=str(cwd), capture_output=True, text=True,  # nosec B603 B607
                              stdin=subprocess.DEVNULL, env=env, timeout=15)

    r = _run("rev-parse", "--path-format=absolute", "--absolute-git-dir", "--git-common-dir")
    if r.returncode != 0:
        return  # không phải repo (hoặc không đọc được) — git sẽ tự báo lỗi, không có gì để rò rỉ
    dirs = [Path(x.strip()) for x in r.stdout.splitlines() if x.strip()]
    tl = _run("rev-parse", "--show-toplevel")
    if tl.returncode == 0 and tl.stdout.strip():
        dirs.append(Path(tl.stdout.strip()))
    for d in dirs:
        if not _under(_resolved(d), root):
            raise CodedError(403, "git_repo_outside_root",
                             "Repo git nằm (một phần) ngoài folder được cấp quyền (repo ở thư mục cha, `.git` trỏ ra "
                             "ngoài hoặc core.worktree ngoài root) — từ chối chạy git")
    for d in dirs[:2]:
        for alt in (d / "objects" / "info" / "alternates", d / "objects" / "info" / "http-alternates"):
            try:
                if not alt.is_file():
                    continue
                for ln in alt.read_text(errors="replace").splitlines():
                    ln = ln.strip()
                    if not ln or ln.startswith("#"):
                        continue
                    target = Path(ln) if ln.startswith("/") else (d / "objects" / ln)
                    if ln.startswith(("http:", "https:")) or not _under(_resolved(target), root):
                        raise CodedError(403, "git_repo_outside_root",
                                         "Repo git dùng object store (alternates) ngoài folder được cấp quyền — từ chối chạy git")
            except OSError:
                continue
        attrs = d / "info" / "attributes"
        try:
            if attrs.is_file() and any(ln.strip() and not ln.lstrip().startswith("#")
                                       for ln in attrs.read_text(errors="replace").splitlines()):
                raise CodedError(403, "git_hostile_repo",
                                 ".git/info/attributes có định nghĩa attribute (có thể bật filter/textconv chạy lệnh) — từ chối chạy git")
        except OSError:
            continue


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
    if executable == "git":
        if not _git_attr_source_supported():
            raise CodedError(403, "git_too_old", "git quá cũ (cần >= 2.40 để vô hiệu hóa attribute driver) — không chạy git ở safe mode")
        _git_preflight(root, cwd_path)

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
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            env=_child_env(root.parent if executable == "git" else None),
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
