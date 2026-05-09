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


async def run_command(cmd: List[str], cwd: str = None, timeout: int = 300) -> tuple[int, str, str]:
    """Chạy command async và trả về (returncode, stdout, stderr)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode, stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace")
    except asyncio.TimeoutError:
        return -1, "", f"Command timeout after {timeout}s: {' '.join(cmd)}"
    except FileNotFoundError:
        return -1, "", f"Tool not found: {cmd[0]}"


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
