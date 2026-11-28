import asyncio
import re
import subprocess
import json
import hashlib
from abc import ABC, abstractmethod
from typing import List, Dict, Any


def make_fingerprint(tool: str, rule_id: str, file_path: str, line: int, title: str) -> str:
    """Tạo fingerprint duy nhất cho vulnerability để tracking across scans."""
    raw = f"{tool}:{rule_id}:{file_path}:{line}:{title}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


# Env của tiến trình con = ALLOWLIST (không phải denylist): chỉ các biến vận hành vô hại đi qua.
# GITHUB_TOKEN / DATABASE_URL / *_TOKEN / *_SECRET / *_KEY / AWS_* / ANTHROPIC_* … KHÔNG BAO GIỜ được kế thừa.
# Tool cần biến riêng → truyền tham số `env` tường minh (vd trivy_env()).
_ENV_ALLOW = frozenset({
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "LANGUAGE", "TZ", "TMPDIR", "TEMP", "TMP", "TERM",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "no_proxy", "all_proxy",
    "PYTHONPATH", "PYTHONHOME", "PYTHONUTF8", "VIRTUAL_ENV", "JAVA_HOME",
    "GOPATH", "GOCACHE", "GOFLAGS", "GOMODCACHE", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
    "DOCKER_HOST", "VULNGUARD_WORDLIST_DIRS",
    # cấu hình tool được tài liệu hoá (không phải secret):
    "SEMGREP_HOME",                                  # install/run.sh đặt $PROJECT_DIR/.semgrep (cache rule pre-seeded)
    "LD_LIBRARY_PATH", "JAVA_TOOL_OPTIONS",          # native libs / JVM của sonar-scanner
})
# Tiền tố cấu hình theo tool (DB mirror/air-gap, skip-update, cache…). Tên chứa TOKEN/SECRET/PASSWORD/KEY/
# CREDENTIAL (vd TRIVY_PASSWORD, GRYPE_REGISTRY_AUTH_TOKEN, SEMGREP_APP_TOKEN) VẪN bị _SECRET_NAME loại.
_ENV_ALLOW_PREFIXES = ("LC_", "TRIVY_", "GRYPE_", "SEMGREP_", "NUCLEI_", "CHECKOV_", "GITLEAKS_", "KATANA_")
# Phòng thủ chiều sâu: biến trong allowlist mà tên có dạng secret vẫn bị loại.
_SECRET_NAME = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH_?KEY|API_?KEY|PRIVATE_?KEY|_KEY$|DATABASE_URL)", re.I)


def scrubbed_env(base=None, extra=None) -> dict:
    """Env tối thiểu cho tiến trình con (allowlist). `extra` do caller truyền tường minh, merge SAU cùng."""
    import os as _os
    src = _os.environ if base is None else base
    out = {k: v for k, v in src.items()
           if (k in _ENV_ALLOW or k.startswith(_ENV_ALLOW_PREFIXES)) and not _SECRET_NAME.search(k)}
    if extra:
        out.update(extra)
    return out


_KILL_GRACE_SECONDS = 3.0


async def _kill_process_group(proc, grace: float = None) -> None:
    """SIGTERM cả process group (tool + con cháu), chờ `grace` giây rồi SIGKILL. Không để tool chạy mồ côi."""
    import os as _os
    import signal as _signal
    grace = _KILL_GRACE_SECONDS if grace is None else grace

    def _send(sig):
        try:
            if hasattr(_os, "killpg"):
                _os.killpg(proc.pid, sig)      # proc là leader của session mới (start_new_session)
            elif sig == _signal.SIGTERM:
                proc.terminate()
            else:
                proc.kill()
        except (ProcessLookupError, PermissionError):
            pass

    _send(_signal.SIGTERM)
    try:
        await asyncio.wait_for(proc.wait(), timeout=grace)
    except asyncio.TimeoutError:
        pass
    # Leader có thể đã thoát nhưng con cháu còn sống → luôn SIGKILL cả group (không lỗi nếu đã chết hết).
    _send(getattr(_signal, "SIGKILL", _signal.SIGTERM))
    try:
        await asyncio.wait_for(proc.wait(), timeout=grace)
    except asyncio.TimeoutError:
        pass


_READ_CHUNK = 64 * 1024
_LIMIT_PREFIX = "Command output limit exceeded"


def _setting(name: str, default):
    """Giới hạn vận hành đọc từ api.config nếu có; scanner chạy độc lập vẫn dùng default."""
    try:
        from api.config import settings
        return getattr(settings, name, default)
    except Exception:
        return default


async def _drain(stream, limit: int, keep_tail: bool, overflow: asyncio.Event) -> bytes:
    """Đọc stream theo chunk 64 KiB vào buffer có chặn trên.
    keep_tail=True: giữ `limit` byte cuối (stderr). Ngược lại vượt `limit` → báo overflow và dừng."""
    buf = bytearray()
    while True:
        chunk = await stream.read(_READ_CHUNK)
        if not chunk:
            return bytes(buf)
        buf += chunk
        if len(buf) > limit:
            if keep_tail:
                del buf[:len(buf) - limit]
            else:
                overflow.set()
                return bytes(buf)


async def _cancel_all(*tasks) -> None:
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


async def run_command(cmd: List[str], cwd: str = None, timeout: int = 300,
                      env: dict = None, max_stdout: int = None,
                      max_stderr: int = 1 << 20) -> tuple[int, str, str]:
    """Chạy command async và trả về (returncode, stdout, stderr).

    env: biến môi trường bổ sung (merge vào môi trường hiện tại, không thay thế).
    Hết `timeout`: giết CẢ process group (SIGTERM → SIGKILL sau grace) rồi trả (-1, "", "Command timeout …"),
    để caller báo lỗi timeout (không phải 'sạch') và tool không tiếp tục đốt CPU sau khi bị bỏ.
    Output bị chặn: stdout tối đa `max_stdout` byte (mặc định settings.scanner_max_output_mb), stderr giữ
    `max_stderr` byte cuối. Vượt stdout → giết group và trả (-1, "", "Command output limit exceeded …")."""
    if max_stdout is None:
        max_stdout = int(_setting("scanner_max_output_mb", 128)) * 1024 * 1024
    run_env = scrubbed_env(extra=env)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=run_env,
            start_new_session=True,
        )
    except FileNotFoundError:
        return -1, "", f"Tool not found: {cmd[0]}"
    overflow = asyncio.Event()
    out_t = asyncio.ensure_future(_drain(proc.stdout, max_stdout, False, overflow))
    err_t = asyncio.ensure_future(_drain(proc.stderr, max_stderr, True, overflow))

    async def _finish():
        await asyncio.gather(out_t, err_t)
        await proc.wait()

    fin_t = asyncio.ensure_future(_finish())
    ovf_t = asyncio.ensure_future(overflow.wait())
    try:
        done, _ = await asyncio.wait({fin_t, ovf_t}, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
        if ovf_t in done:
            await _cancel_all(fin_t, out_t, err_t)
            await _kill_process_group(proc)
            return -1, "", f"{_LIMIT_PREFIX}: stdout over {max_stdout} bytes ({cmd[0]})"
        if fin_t not in done:
            await _cancel_all(fin_t, out_t, err_t)
            await _kill_process_group(proc)
            return -1, "", f"Command timeout after {timeout}s: {' '.join(cmd)}"
        return (proc.returncode,
                out_t.result().decode("utf-8", errors="replace"),
                err_t.result().decode("utf-8", errors="replace"))
    except asyncio.CancelledError:
        await _cancel_all(fin_t, out_t, err_t)
        await _kill_process_group(proc)
        raise
    finally:
        ovf_t.cancel()


# Thư mục rác KHÔNG phải mã nguồn của người dùng — loại khỏi mọi scan để báo cáo
# tập trung vào code của họ, không ngập phát hiện trong thư viện bên thứ ba.
# (site-packages bắt mọi virtualenv dù tên lạ như .coworker_venv/.venv-demo)
EXCLUDE_DIR_NAMES = [
    "node_modules", ".git", "__pycache__", ".tox", "venv", ".venv", "env",
    "site-packages", "dist", "build", ".next", ".nuxt", "vendor", ".gradle",
    ".mvn", "target", ".idea", ".vscode", ".pytest_cache", ".mypy_cache",
    "bower_components", ".terraform",
]
# Glob cho các tool nhận --exclude dạng path glob (bandit, semgrep)
EXCLUDE_GLOBS = [f"*/{d}/*" for d in EXCLUDE_DIR_NAMES] + ["*venv*/*"]


def find_files(root: str, patterns, max_files: int = 200, max_entries: int = 200_000,
               skipped_links: list = None) -> tuple:
    """Bounded, symlink-free file discovery. Returns (files, truncated).

    Never follows directory symlinks, skips symlinked files (collected in `skipped_links` if given),
    prunes EXCLUDE_DIR_NAMES, and stops after `max_files` matches or `max_entries` visited entries.
    Blocking: call via asyncio.to_thread from async code."""
    import fnmatch
    import os as _os
    if isinstance(patterns, str):
        patterns = (patterns,)
    excluded = set(EXCLUDE_DIR_NAMES)
    files: list = []
    visited = 0
    for dirpath, dirnames, filenames in _os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in excluded and "venv" not in d)
        for name in sorted(filenames):
            visited += 1
            if visited > max_entries:
                return files, True
            if not any(fnmatch.fnmatchcase(name, p) for p in patterns):
                continue
            full = _os.path.join(dirpath, name)
            if _os.path.islink(full):
                if skipped_links is not None:
                    skipped_links.append(full)
                continue
            if len(files) >= max_files:
                return files, True
            files.append(full)
        visited += len(dirnames)
    return files, False


def normalize_severity(raw: str) -> str:
    """Chuẩn hóa severity về CRITICAL/HIGH/MEDIUM/LOW/INFO."""
    mapping = {
        "critical": "CRITICAL",
        "high": "HIGH",
        "error": "HIGH",
        "warning": "MEDIUM",
        "medium": "MEDIUM",
        "low": "LOW",
        "note": "LOW",
        "info": "INFO",
        "informational": "INFO",
        "negligible": "INFO",
        "unknown": "INFO",
    }
    return mapping.get(str(raw).lower(), "INFO")


class BaseScanner(ABC):
    scan_type: str = "UNKNOWN"

    def __init__(self, scan_path: str):
        self.scan_path = scan_path
        # Partial failures (some inputs failed, findings from the rest kept). The
        # orchestrator turns a non-empty list into status "partial".
        self.warnings: List[str] = []

    @abstractmethod
    async def scan(self) -> List[Dict[str, Any]]:
        """Chạy scanner và trả về list findings đã normalize."""
        pass

    def is_available(self) -> bool:
        """Kiểm tra tool có được cài không."""
        result = subprocess.run(
            ["which", self.tool_name],
            capture_output=True, text=True, env=scrubbed_env()
        )
        return result.returncode == 0

    @property
    def tool_name(self) -> str:
        return self.scan_type.lower()


class ScannerRunError(RuntimeError):
    """Tool đã chạy nhưng thất bại: KHÔNG được báo cáo như "0 findings"."""


def classify_failed_run(rc: int, stderr: str) -> str:
    """"missing" = tool absent (not applicable → caller returns []); "timeout"; else ""."""
    if rc == -1 and (stderr or "").startswith("Tool not found"):
        return "missing"
    if rc == -1 and (stderr or "").startswith(_LIMIT_PREFIX):
        return "limit"
    if rc == -1 and "timeout" in (stderr or ""):
        return "timeout"
    return ""
