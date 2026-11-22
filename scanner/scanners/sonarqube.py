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
import shutil
from typing import Any, Dict, List, Optional

import httpx

from scanner.scanners.base import BaseScanner, make_fingerprint, normalize_severity, run_command

logger = logging.getLogger(__name__)

# Sonar severity (chuẩn cũ) + MQR impact severity (chuẩn mới) → VulnGuard
_SEV = {
    "BLOCKER": "CRITICAL", "CRITICAL": "HIGH", "MAJOR": "MEDIUM", "MINOR": "LOW", "INFO": "INFO",
    "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW",
}


def _cfg(name: str, default=None):
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
        rc, out, err = await run_command([
            self.tool_name,
            f"-Dsonar.host.url={self.url}",
            f"-Dsonar.token={self.token}",
            f"-Dsonar.projectKey={self.project_key}",
            "-Dsonar.sources=.",
            "-Dsonar.scm.disabled=true",
        ], cwd=self.scan_path, timeout=int(_cfg("SONARQUBE_TIMEOUT", 900)))
        if rc != 0:
            logger.warning(f"[sonarqube] sonar-scanner lỗi: {(err or out)[-500:]}")
            # vẫn thử lấy issue từ lần phân tích trước (nếu có)
        await self._wait_ready()
        try:
            return await self._fetch_all()
        except Exception as e:
            logger.error(f"[sonarqube] lấy issue lỗi: {e}")
            return []

    async def _wait_ready(self):
        """Chờ CE task từ report-task.txt (nếu có)."""
        rt = os.path.join(self.scan_path, ".scannerwork", "report-task.txt")
        ce_url = None
        try:
            with open(rt) as f:
                for line in f:
                    if line.startswith("ceTaskUrl="):
                        ce_url = line.split("=", 1)[1].strip()
        except FileNotFoundError:
            return
        if not ce_url:
            return
        async with httpx.AsyncClient(timeout=20, trust_env=False) as c:
            for _ in range(60):
                try:
                    r = await c.get(ce_url, headers=self._headers())
                    status = (r.json().get("task") or {}).get("status")
                    if status in ("SUCCESS", "FAILED", "CANCELED"):
                        return
                except Exception:
                    pass
                await asyncio.sleep(2)

    async def _fetch_all(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=30, trust_env=False) as c:
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
            # Security hotspots
            try:
                r = await c.get(f"{self.url}/api/hotspots/search", headers=self._headers(),
                                params={"projectKey": self.project_key, "status": "TO_REVIEW", "ps": 500})
                if r.status_code == 200:
                    findings += parse_issues(r.json(), self.project_key, is_hotspot=True)
            except Exception:
                pass
        return findings
