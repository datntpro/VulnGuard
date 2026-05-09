"""
Orchestrator — Điều phối tất cả scanners, update live progress sau mỗi tool.
"""
import asyncio
import json
import logging
import os
import time
from typing import List, Dict, Any, Optional, Callable, Awaitable

SCANNER_CONFIG_FILE = os.environ.get("SCANNER_CONFIG_FILE", "/app/storage/scanner_config.json")


def _load_enabled_tools() -> Dict[str, bool]:
    """Đọc config enable/disable. Default: tất cả enabled."""
    try:
        if os.path.exists(SCANNER_CONFIG_FILE):
            with open(SCANNER_CONFIG_FILE) as f:
                data = json.load(f)
            return data.get("enabled_tools", {})
    except Exception:
        pass
    return {}

from scanner.scanners.sast import SemgrepScanner, BanditScanner
from scanner.scanners.sca import TrivySCAScanner, PipAuditScanner
from scanner.scanners.container import TrivyContainerScanner, GrypeScanner
from scanner.scanners.iac import CheckovScanner, TrivyIaCScanner, HadolintScanner
from scanner.scanners.secrets import GitleaksScanner, DetectSecretsScanner

logger = logging.getLogger(__name__)

# Mapping scan_type → danh sách scanners (theo thứ tự ưu tiên)
SCANNER_MAP = {
    "SAST":      [BanditScanner, SemgrepScanner],
    "SCA":       [TrivySCAScanner, PipAuditScanner],
    "CONTAINER": [TrivyContainerScanner, GrypeScanner],
    "IAC":       [CheckovScanner, TrivyIaCScanner, HadolintScanner],
    "SECRETS":   [GitleaksScanner, DetectSecretsScanner],
}

# Tên hiển thị thân thiện cho từng tool
TOOL_LABELS = {
    "bandit":           "Bandit (Python SAST)",
    "semgrep":          "Semgrep (Multi-lang SAST)",
    "trivy":            "Trivy (SCA/Dependencies)",
    "pip-audit":        "pip-audit (Python Deps)",
    "trivy-container":  "Trivy (Container Images)",
    "grype":            "Grype (Container)",
    "checkov":          "Checkov (IaC)",
    "trivy-iac":        "Trivy (IaC)",
    "hadolint":         "Hadolint (Dockerfile)",
    "gitleaks":         "Gitleaks (Secrets)",
    "detect-secrets":   "detect-secrets (Secrets)",
}


def deduplicate(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen_fps = set()
    unique = []
    for f in findings:
        fp = f.get("fingerprint")
        if fp and fp in seen_fps:
            continue
        if fp:
            seen_fps.add(fp)
        unique.append(f)
    return unique


class Orchestrator:
    def __init__(self, scan_path: str, scan_types: List[str] = None):
        self.scan_path = scan_path
        self.scan_types = scan_types or list(SCANNER_MAP.keys())

    def get_scanner_list(self) -> List[Dict[str, str]]:
        """Trả về danh sách tools sẽ chạy (dùng cho initial progress state)."""
        enabled_config = _load_enabled_tools()
        tools = []
        for scan_type in self.scan_types:
            for cls in SCANNER_MAP.get(scan_type.upper(), []):
                tool_name = getattr(cls, "tool_name", cls.__name__.lower())
                if enabled_config.get(tool_name, True) is False:
                    continue
                tools.append({
                    "tool": tool_name,
                    "label": TOOL_LABELS.get(tool_name, tool_name),
                    "scan_type": scan_type,
                })
        return tools

    async def run(
        self,
        on_tool_done: Optional[Callable[[str, int, str, float], Awaitable[None]]] = None
    ) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Chạy tất cả scanners song song.

        Args:
            on_tool_done: async callback(tool_name, count, error, duration_s)
                          gọi ngay sau mỗi scanner hoàn thành

        Returns:
            (findings, scanner_logs)
        """
        # Đọc config enable/disable
        enabled_config = _load_enabled_tools()

        # Build danh sách (scanner_instance, task) — skip disabled tools
        scanners_and_tasks = []
        for scan_type in self.scan_types:
            for cls in SCANNER_MAP.get(scan_type.upper(), []):
                scanner = cls(self.scan_path)
                tool = getattr(scanner, "tool_name", cls.__name__.lower())
                # Nếu tool bị disable (config tồn tại và = False) thì skip
                if enabled_config.get(tool, True) is False:
                    logger.info(f"⊘ Skipping disabled tool: {tool}")
                    continue
                scanners_and_tasks.append(scanner)

        logger.info(f"▶ Running {len(scanners_and_tasks)} scanners on {self.scan_path}")

        # Wrap mỗi scanner để biết scanner nào trả về result
        async def _run_one(scanner):
            return scanner, *(await self._run_scanner_timed(scanner))

        tasks = [asyncio.create_task(_run_one(s)) for s in scanners_and_tasks]

        all_findings = []
        scanner_logs = {}
        seen_fps = set()

        # as_completed: xử lý ngay khi từng tool xong
        for coro in asyncio.as_completed(tasks):
            scanner, findings, duration, error = await coro
            tool = getattr(scanner, "tool_name", scanner.__class__.__name__)
            count = len(findings) if findings else 0

            if error:
                logger.warning(f"⚠ {tool}: {error} ({duration:.1f}s)")
                scanner_logs[tool] = {
                    "status": "error",
                    "error": error,
                    "count": 0,
                    "duration_s": round(duration, 1),
                    "label": TOOL_LABELS.get(tool, tool),
                }
            else:
                logger.info(f"✓ {tool}: {count} findings ({duration:.1f}s)")
                scanner_logs[tool] = {
                    "status": "ok",
                    "count": count,
                    "duration_s": round(duration, 1),
                    "label": TOOL_LABELS.get(tool, tool),
                }

            # Gộp findings (dedup inline)
            if isinstance(findings, list):
                for f in findings:
                    fp = f.get("fingerprint")
                    if fp and fp in seen_fps:
                        continue
                    if fp:
                        seen_fps.add(fp)
                    all_findings.append(f)

            # Gọi callback để update DB live
            if on_tool_done:
                try:
                    await on_tool_done(tool, count, error, duration)
                except Exception as cb_err:
                    logger.error(f"Progress callback error: {cb_err}")

        logger.info(f"✔ Total findings after dedup: {len(all_findings)}")
        return all_findings, scanner_logs

    async def _run_scanner_timed(self, scanner) -> tuple[List[Dict[str, Any]], float, str]:
        start = time.monotonic()
        error = ""
        findings = []
        try:
            findings = await scanner.scan()
        except Exception as e:
            error = str(e)
            logger.error(f"Exception in {scanner.__class__.__name__}: {e}", exc_info=True)
        duration = time.monotonic() - start
        return findings, duration, error
