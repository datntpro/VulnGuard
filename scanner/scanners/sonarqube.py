"""
SonarQube (Community) scanner — SAST sâu theo data-flow, giảm false positive.

Khác các scanner CLI khác: SonarQube là SERVER. Luồng:
  1. sonar-scanner đẩy phân tích lên server (SONARQUBE_URL + token).
  2. Chờ Compute Engine task hoàn tất (report-task.txt → ceTaskUrl).
  3. Lấy issue qua Web API /api/issues/search + hotspot /api/hotspots/search.
  4. Chuẩn hoá về finding của VulnGuard (gộp dedup + AI triage như mọi tool).

Cấu hình: SONARQUBE_URL, SONARQUBE_TOKEN (Settings → Scanner Tools, hoặc .env).
Chỉ chạy khi có server + token + binary sonar-scanner. Nếu đã có server Sonar riêng
thì trỏ vào; hoặc dùng service bundled (docker compose --profile sonar).
"""
import asyncio
import hashlib
import logging
import os
import re
import shutil
import tempfile
from typing import Any, Dict, List, Optional

import httpx

from scanner.scanners.base import (BaseScanner, ScannerRunError, classify_failed_run, make_fingerprint,
                                   normalize_severity, run_command)

logger = logging.getLogger(__name__)

_CE_TASK_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

# Sonar severity (chuẩn cũ) + MQR impact severity (chuẩn mới) → VulnGuard
_SEV = {
    "BLOCKER": "CRITICAL", "CRITICAL": "HIGH", "MAJOR": "MEDIUM", "MINOR": "LOW", "INFO": "INFO",
    "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW",
}


def _cfg(name: str, default=None):
    # Ưu tiên cấu hình người dùng lưu qua UI (Settings → Scanner Tools → SonarQube)
    try:
        from api.services import runtime_settings as rt
        if name.upper() == "SONARQUBE_URL" and rt.sonarqube_url():
            return rt.sonarqube_url()
        if name.upper() == "SONARQUBE_TOKEN" and rt.sonarqube_token():
            return rt.sonarqube_token()
    except Exception:
        pass
    try:
        from api.config import settings
        v = getattr(settings, name.lower(), None)
        if v:
            return v
    except Exception:
        pass
    return os.environ.get(name.upper(), default)


def _severity_of(issue: Dict[str, Any]) -> str:
    impacts = issue.get("impacts") or []
    if impacts:
        order = ["HIGH", "MEDIUM", "LOW"]
        worst = min((i.get("severity", "LOW") for i in impacts),
                    key=lambda s: order.index(s) if s in order else 9)
        return normalize_severity(_SEV.get(worst, "INFO"))
    return normalize_severity(_SEV.get(str(issue.get("severity", "INFO")).upper(), "INFO"))


def _cwe_from_tags(tags: List[str]) -> str:
    for t in tags or []:
        if str(t).lower().startswith("cwe-"):
            return str(t).split("-", 1)[1]
    return ""


def parse_issues(payload: Dict[str, Any], project_key: str, is_hotspot: bool = False) -> List[Dict[str, Any]]:
    """Pure — chuẩn hoá /api/issues/search hoặc /api/hotspots/search về finding."""
    findings = []
    items = payload.get("issues") if not is_hotspot else payload.get("hotspots")
    for it in items or []:
        comp = it.get("component", "") or ""
        file_path = comp.split(":", 1)[1] if ":" in comp else comp
        line = it.get("line") or (it.get("textRange") or {}).get("startLine") or 0
        rule = it.get("rule") or it.get("ruleKey") or ""
        msg = it.get("message") or it.get("securityCategory") or rule
        if is_hotspot:
            sev = normalize_severity(_SEV.get(str(it.get("vulnerabilityProbability", "LOW")).upper(), "INFO"))
            kind = "Security Hotspot"
        else:
            sev = _severity_of(it)
            kind = (it.get("type") or "ISSUE").replace("_", " ").title()
        findings.append({
            "tool": "sonarqube",
            "scan_type": "SAST",
            "rule_id": rule,
            "title": f"[Sonar:{kind}] {msg}"[:500],
            "description": msg,
            "severity": sev,
            "file_path": file_path,
            "line_start": line,
            "line_end": line,
            "code_snippet": "",
            "cwe": _cwe_from_tags(it.get("tags", [])),
            "fingerprint": make_fingerprint("sonarqube", rule, file_path, line, msg),
            "raw": {"key": it.get("key"), "project": project_key, "hotspot": is_hotspot},
        })
    return findings


class SonarQubeScanner(BaseScanner):
    scan_type = "SAST"
    tool_name = "sonar-scanner"

    def __init__(self, scan_path: str):
        super().__init__(scan_path)
        self.url = (_cfg("SONARQUBE_URL") or "").rstrip("/")
        self.token = _cfg("SONARQUBE_TOKEN") or ""
        # sha1 chỉ để tạo project key ổn định (không dùng cho mục đích bảo mật)
        self.project_key = "vulnguard-" + hashlib.sha1(
            os.path.abspath(scan_path).encode(), usedforsecurity=False).hexdigest()[:12]

    def is_available(self) -> bool:
        return bool(self.url and self.token and shutil.which(self.tool_name))

    def _headers(self):
        return {"Authorization": f"Bearer {self.token}"}

    async def scan(self) -> List[Dict[str, Any]]:
        if not self.is_available():
            logger.info("[sonarqube] bỏ qua — chưa cấu hình URL/token hoặc thiếu sonar-scanner")
            return []
        # Invariant: the scanner's settings, working directory and credentials are owned by
        # VulnGuard. Files inside the scanned tree never configure the tool or supply state.
        base_dir = os.path.abspath(self.scan_path)
        with tempfile.TemporaryDirectory(prefix="vg-sonar-") as td:
            work = os.path.join(td, "work")
            settings = os.path.join(td, "project.properties")
            open(settings, "w").close()  # empty settings file replaces any in-tree one
            rc, out, err = await run_command([
                self.tool_name,
                f"-Dproject.settings={settings}",
                f"-Dsonar.projectBaseDir={base_dir}",
                f"-Dsonar.working.directory={work}",
                f"-Dsonar.host.url={self.url}",
                f"-Dsonar.projectKey={self.project_key}",
                "-Dsonar.sources=.",
                "-Dsonar.scm.disabled=true",
            ], cwd=td, timeout=int(_cfg("SONARQUBE_TIMEOUT", 900)),
                env={"SONAR_TOKEN": self.token})
            kind = classify_failed_run(rc, err)
            if kind == "timeout":
                raise ScannerRunError(f"sonar-scanner timeout: {err[-300:]}")
            if rc != 0:
                raise ScannerRunError(f"sonar-scanner thất bại (exit {rc}): {(err or out)[-500:]}")
            task_id = self._read_task_id(os.path.join(work, "report-task.txt"))
        await self._wait_ready(task_id)
        return await self._fetch_all()

    @staticmethod
    def _read_task_id(path: str) -> str:
        """Only the task id is taken from the report file; URLs in it are ignored."""
        task_id = ""
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("ceTaskId="):
                        task_id = line.split("=", 1)[1].strip()
        except OSError:
            pass
        if not _CE_TASK_ID.match(task_id):
            raise ScannerRunError("sonar-scanner did not produce a task id")
        return task_id

    async def _wait_ready(self, task_id: str):
        """Chờ CE task hoàn tất; chỉ gọi server đã cấu hình."""
        async with httpx.AsyncClient(timeout=20, trust_env=False, follow_redirects=False) as c:
            for _ in range(60):
                r = await c.get(f"{self.url}/api/ce/task", headers=self._headers(), params={"id": task_id})
                r.raise_for_status()
                status = (r.json().get("task") or {}).get("status")
                if status == "SUCCESS":
                    return
                if status in ("FAILED", "CANCELED"):
                    raise ScannerRunError(f"SonarQube CE task {status}")
                await asyncio.sleep(2)
        raise ScannerRunError("SonarQube CE task not finished in 120s")

    async def _fetch_all(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=30, trust_env=False, follow_redirects=False) as c:
            # Issues (VULNERABILITY + BUG)
            page = 1
            while page <= 20:
                r = await c.get(f"{self.url}/api/issues/search", headers=self._headers(),
                                params={"componentKeys": self.project_key, "types": "VULNERABILITY,BUG",
                                        "statuses": "OPEN,CONFIRMED,REOPENED", "ps": 500, "p": page})
                r.raise_for_status()
                data = r.json()
                findings += parse_issues(data, self.project_key)
                if page * 500 >= data.get("total", 0):
                    break
                page += 1
                if page > 20 and data.get("total", 0) > 10000:
                    self.warnings.append("SonarQube issues truncated at 10000")
            # Security hotspots
            try:
                r = await c.get(f"{self.url}/api/hotspots/search", headers=self._headers(),
                                params={"projectKey": self.project_key, "status": "TO_REVIEW", "ps": 500})
                if r.status_code == 200:
                    findings += parse_issues(r.json(), self.project_key, is_hotspot=True)
            except Exception as e:
                self.warnings.append(f"SonarQube hotspots not fetched: {type(e).__name__}")
        return findings
