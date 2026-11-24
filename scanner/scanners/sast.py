"""
SAST Scanners:
- Semgrep: Multi-language — dùng bundled rules (offline) + online registry (nếu cache)
- Bandit: Python-specific
"""
import json
import logging
import os
import socket
from typing import List, Dict, Any

from scanner.scanners.base import ScannerRunError, BaseScanner, run_command, normalize_severity, make_fingerprint

logger = logging.getLogger(__name__)

# Thư mục chứa bundled semgrep rules (luôn hoạt động, không cần internet)
BUNDLED_RULES_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "rules")
)


def _has_internet(host: str = "semgrep.dev", port: int = 443, timeout: float = 3.0) -> bool:
    """Kiểm tra nhanh có kết nối internet không (tránh timeout 120s của semgrep)."""
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except Exception:
        return False



class SemgrepScanner(BaseScanner):
    """Semgrep SAST scanner.

    Strategy:
    1. Luôn chạy bundled rules (scanner/rules/*.yaml) — hoạt động offline
    2. Thử thêm online registry rules (p/python, p/security-audit, p/owasp-top-ten)
       — chỉ có kết quả nếu đã cache từ Docker build hoặc có internet
    3. Gộp findings, dedup theo fingerprint
    """
    scan_type = "SAST"
    tool_name = "semgrep"

    # Ruleset đa ngôn ngữ luôn chạy
    BASE_RULESETS = ["p/security-audit", "p/owasp-top-ten"]
    # Ánh xạ ngôn ngữ → registry ruleset (1.4: SAST hiểu JS/TS, không chỉ Python)
    LANG_RULESETS = {
        "python": ["p/python"],
        "javascript": ["p/javascript", "p/nodejs"],
        "typescript": ["p/typescript"],
        "react": ["p/react"],
        "java": ["p/java"],
        "go": ["p/golang"],
        "php": ["p/php"],
        "ruby": ["p/ruby"],
    }
    _LANG_EXT = {
        ".py": "python", ".js": "javascript", ".jsx": "react", ".mjs": "javascript",
        ".cjs": "javascript", ".ts": "typescript", ".tsx": "react", ".java": "java",
        ".go": "go", ".php": "php", ".rb": "ruby",
    }

    def _detect_languages(self) -> set:
        """Quét nhanh phần mở rộng file để chọn ruleset đúng ngôn ngữ."""
        langs = set()
        skip = {"node_modules", ".git", "venv", ".venv", "dist", "build", "__pycache__"}
        try:
            for root, dirs, files in os.walk(self.scan_path):
                dirs[:] = [d for d in dirs if d not in skip]
                for fn in files:
                    lang = self._LANG_EXT.get(os.path.splitext(fn)[1].lower())
                    if lang:
                        langs.add(lang)
                        if lang in ("javascript", "typescript", "react"):
                            langs.add("react")  # bật p/react khi có JS/TS front-end
                if len(langs) >= 6:
                    break
        except Exception:
            pass
        return langs

    def _online_rulesets(self) -> List[str]:
        langs = self._detect_languages()
        rulesets = list(self.BASE_RULESETS)
        for lang in langs:
            for rs in self.LANG_RULESETS.get(lang, []):
                if rs not in rulesets:
                    rulesets.append(rs)
        # Không nhận ra ngôn ngữ nào → mặc định Python (giữ hành vi cũ)
        if not langs:
            rulesets.append("p/python")
        return rulesets

    async def scan(self) -> List[Dict[str, Any]]:
        all_findings: List[Dict[str, Any]] = []
        seen_fps: set = set()

        def add_findings(new_findings):
            for f in new_findings:
                fp = f.get("fingerprint")
                if fp and fp in seen_fps:
                    continue
                if fp:
                    seen_fps.add(fp)
                all_findings.append(f)

        # ── Bước 1: Bundled rules (luôn hoạt động, không cần internet) ──────
        bundled_rules = os.path.join(BUNDLED_RULES_DIR, "python-security.yaml")
        if os.path.exists(bundled_rules):
            logger.info("Semgrep: chạy bundled rules...")
            add_findings(await self._run_semgrep(["--config", bundled_rules]))
        else:
            logger.warning(f"Semgrep: bundled rules không tìm thấy tại {bundled_rules}")

        # ── Bước 2: Online/cached registry rules (chỉ khi có internet) ──────
        # Kiểm tra internet trước để tránh treo 120s khi offline
        if _has_internet():
            rulesets = self._online_rulesets()
            logger.info(f"Semgrep: có internet — chạy ruleset theo ngôn ngữ: {', '.join(rulesets)}")
            config_args = []
            for ruleset in rulesets:
                config_args += ["--config", ruleset]
            try:
                online = await self._run_semgrep(config_args, timeout=120)
                add_findings(online)
            except ScannerRunError as e:
                # Timeout của lượt online (registry chậm) không làm hỏng kết quả bundled.
                if "timeout" not in str(e).lower():
                    raise
                logger.warning(f"Semgrep online pass bỏ qua: {e}")
        else:
            logger.info("Semgrep: không có internet — bỏ qua online registry rules (offline mode)")

        return all_findings

    async def _run_semgrep(self, config_args: List[str], timeout: int = 90) -> List[Dict[str, Any]]:
        """Chạy semgrep với config args đã cho."""
        from scanner.scanners.base import EXCLUDE_DIR_NAMES
        exclude_args = []
        for d in EXCLUDE_DIR_NAMES:
            exclude_args += ["--exclude", d]
        cmd = [
            "semgrep",
            *config_args,
            "--json",
            "--dataflow-traces",   # xuất đường đi source→sink (đồ thị data-flow GĐ3)
            "--metrics=off",
            "--timeout", "30",
            "--max-memory", "1500",
            "--no-git-ignore",
            *exclude_args,         # loại thư viện bên thứ ba / venv
            "--quiet",
            self.scan_path,
        ]

        rc, stdout, stderr = await run_command(cmd, timeout=timeout)
        if rc == -1 and "timeout" in stderr.lower():
            raise ScannerRunError(f"semgrep timeout sau {timeout}s")

        if not stdout.strip():
            # Với --json, semgrep chạy đúng luôn in JSON (kể cả khi sạch / rc 1).
            # stdout rỗng + exit khác 0 = tool hỏng (vd ImportError) → KHÔNG phải "0 findings".
            if rc != 0:
                raise ScannerRunError(f"semgrep thất bại (exit {rc}): {stderr[-500:]}")
            return []

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            raise ScannerRunError(
                f"semgrep output không phải JSON (exit {rc}): {stderr[-500:]}"
            ) from None

        if rc >= 2 or rc < 0:
            errors = data.get("errors") or []
            if not data.get("results"):
                first = errors[0].get("message", "") if errors else stderr[-500:]
                raise ScannerRunError(f"semgrep thất bại (exit {rc}): {first}")
            logger.warning(f"Semgrep exit {rc} nhưng có kết quả — giữ findings ({len(errors)} lỗi)")

        findings = []
        for result in data.get("results", []):
            extra = result.get("extra", {})
            metadata = extra.get("metadata", {})
            severity_raw = extra.get("severity", "WARNING")

            file_path = result.get("path", "")
            line = result.get("start", {}).get("line", 0)
            rule_id = result.get("check_id", "")
            title = rule_id.split(".")[-1].replace("-", " ").title()

            findings.append({
                "tool": "semgrep",
                "scan_type": "SAST",
                "rule_id": rule_id,
                "title": title,
                "description": extra.get("message", ""),
                "severity": normalize_severity(severity_raw),
                "file_path": file_path.replace(self.scan_path, "").lstrip("/"),
                "line_start": line,
                "line_end": result.get("end", {}).get("line", line),
                "code_snippet": extra.get("lines", ""),
                "cwe": str(metadata.get("cwe", "")),
                "cve": str(metadata.get("cve", "")) if metadata.get("cve") else "",
                "fingerprint": make_fingerprint("semgrep", rule_id, file_path, line, title),
                "raw": result,
            })

        return findings


class BanditScanner(BaseScanner):
    """Python-specific security linter."""
    scan_type = "SAST"
    tool_name = "bandit"

    async def scan(self) -> List[Dict[str, Any]]:
        findings = []
        from scanner.scanners.base import EXCLUDE_GLOBS
        cmd = [
            "bandit",
            "-r", self.scan_path,
            "-f", "json",
            "-ll",    # Minimum level: LOW
            "--quiet",
            # Loại thư viện bên thứ ba / venv khỏi scan (tránh ngập site-packages)
            "--exclude", ",".join(EXCLUDE_GLOBS),
        ]

        rc, stdout, stderr = await run_command(cmd, timeout=120)

        # Bandit trả về exit code 1 khi có findings — bình thường
        if not stdout.strip():
            if rc not in (0, 1):
                raise ScannerRunError(f"bandit thất bại (exit {rc}): {stderr[-500:]}")
            return []

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            if rc not in (0, 1):
                raise ScannerRunError(
                    f"bandit output không phải JSON (exit {rc}): {stderr[-500:]}"
                ) from None
            return []

        for result in data.get("results", []):
            file_path = result.get("filename", "")
            line = result.get("line_number", 0)
            rule_id = result.get("test_id", "")
            title = result.get("test_name", "").replace("_", " ").title()

            findings.append({
                "tool": "bandit",
                "scan_type": "SAST",
                "rule_id": rule_id,
                "title": f"[Python] {title}",
                "description": result.get("issue_text", ""),
                "severity": normalize_severity(result.get("issue_severity", "LOW")),
                "file_path": file_path.replace(self.scan_path, "").lstrip("/"),
                "line_start": line,
                "line_end": line,
                "code_snippet": result.get("code", ""),
                "cwe": str(result.get("issue_cwe", {}).get("id", "")) if result.get("issue_cwe") else "",
                "fingerprint": make_fingerprint("bandit", rule_id, file_path, line, title),
                "raw": result,
            })

        return findings
