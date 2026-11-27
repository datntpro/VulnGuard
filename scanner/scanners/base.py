import asyncio
import subprocess
import json
import hashlib
from abc import ABC, abstractmethod
from typing import List, Dict, Any


def make_fingerprint(tool: str, rule_id: str, file_path: str, line: int, title: str) -> str:
    """Tạo fingerprint duy nhất cho vulnerability để tracking across scans."""
    raw = f"{tool}:{rule_id}:{file_path}:{line}:{title}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


# Biến môi trường nhạy cảm KHÔNG được kế thừa bởi subprocess của scanner (N-7/N-8: giảm
# nguy cơ lộ token qua tool bên thứ ba). Muốn truyền thì dùng tham số `env` tường minh.
_SCRUB_ENV = {
    "VULNGUARD_COWORKER_TOKEN", "VULNGUARD_SECRET_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
    "OPENROUTER_API_KEY", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "SONARQUBE_TOKEN",
}
# Tiền tố provider AI — luôn bị loại khỏi env tiến trình con (kể cả AWS_BEARER_TOKEN_BEDROCK, AWS_PROFILE…)
_SCRUB_ENV_PREFIXES = ("AWS_", "ANTHROPIC_", "OPENAI_", "OPENROUTER_", "KIRO_", "AZURE_OPENAI_", "GOOGLE_")


def scrubbed_env(base=None, extra=None) -> dict:
    """Bản sao env đã bỏ secret provider AI + secret app. `extra` (tường minh) được merge SAU cùng."""
    import os as _os
    src = _os.environ if base is None else base
    out = {k: v for k, v in src.items()
           if k not in _SCRUB_ENV and not k.upper().startswith(_SCRUB_ENV_PREFIXES)}
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
            capture_output=True, text=True
        )
        return result.returncode == 0

    @property
    def tool_name(self) -> str:
        return self.scan_type.lower()


class ScannerRunError(RuntimeError):
    """Tool đã chạy nhưng thất bại: KHÔNG được báo cáo như "0 findings"."""
