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


async def run_command(cmd: List[str], cwd: str = None, timeout: int = 300,
                      env: dict = None) -> tuple[int, str, str]:
    """Chạy command async và trả về (returncode, stdout, stderr).

    env: biến môi trường bổ sung (merge vào môi trường hiện tại, không thay thế)."""
    run_env = scrubbed_env(extra=env)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=run_env,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode, stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace")
    except asyncio.TimeoutError:
        return -1, "", f"Command timeout after {timeout}s: {' '.join(cmd)}"
    except FileNotFoundError:
        return -1, "", f"Tool not found: {cmd[0]}"


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
    if rc == -1 and "timeout" in (stderr or ""):
        return "timeout"
    return ""
