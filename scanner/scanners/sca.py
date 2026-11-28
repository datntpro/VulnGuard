"""
SCA Scanners — Software Composition Analysis:
- Trivy: Multi-ecosystem (Maven, npm, pip, Go modules, ...)
- PipAuditScanner: Python pip packages (thay thế Safety v3 đã bị deprecated)
"""
import json
import logging
import asyncio
import os
import re
import tempfile
from typing import List, Dict, Any

from scanner.scanners.base import (find_files, ScannerRunError, BaseScanner, run_command, normalize_severity,
                                   make_fingerprint, classify_failed_run)

logger = logging.getLogger(__name__)


def _trivy_err(stderr: str, rc: int) -> str:
    """Dịch lỗi trivy thường gặp thành thông báo dễ hiểu."""
    s = (stderr or "").strip()
    low = s.lower()
    if any(k in low for k in ("failed to download", "db update", "unable to", "dial tcp",
                              "no such host", "timeout", "tls", "ghcr.io", "connection refused")):
        return ("Trivy không tải được vuln DB (cần mạng ra ghcr.io ở lần chạy đầu). "
                "Nếu máy offline: tải DB sẵn hoặc dùng Knowledge Base nội bộ. Chi tiết: "
                + s[-400:])
    if "permission denied" in low or "mkdir" in low:
        return ("Trivy không ghi được cache dir (TRIVY_CACHE_DIR). Kiểm tra quyền ghi của "
                "thư mục storage. Chi tiết: " + s[-400:])
    return f"Trivy lỗi (rc={rc}): {s[-500:] or 'không có stderr'}"


def trivy_env() -> dict:
    """Env cho trivy: cache dir GHI ĐƯỢC (service có thể chạy dưới user không có HOME
    → trivy không tạo được ~/.cache/trivy và báo lỗi khó hiểu). Trỏ về storage."""
    try:
        from api.config import settings
        cache = os.path.join(settings.storage_dir, ".trivy-cache")
    except Exception:
        cache = os.path.join(tempfile.gettempdir(), "vulnguard-trivy-cache")
    os.makedirs(cache, exist_ok=True)
    return {"TRIVY_CACHE_DIR": cache}


class TrivySCAScanner(BaseScanner):
    """Trivy filesystem scan — tìm vulnerable dependencies."""
    scan_type = "SCA"
    tool_name = "trivy"

    async def scan(self) -> List[Dict[str, Any]]:
        findings = []
        if not os.path.exists(self.scan_path):
            raise ScannerRunError(f"Đường dẫn quét không tồn tại: {self.scan_path}")
        skip_args = []
        for d in ("node_modules", ".git", "venv", ".venv", "site-packages", "dist", "build", "vendor"):
            skip_args += ["--skip-dirs", f"**/{d}/**"]
        cmd = [
            "trivy", "fs",
            "--format", "json",
            "--scanners", "vuln",
            "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
            *skip_args,
            "--quiet",
            self.scan_path,
        ]

        rc, stdout, stderr = await run_command(cmd, timeout=300, env=trivy_env())

        kind = classify_failed_run(rc, stderr)
        if kind == "missing":
            logger.info("trivy chưa cài — bỏ qua SCA")
            return []
        if kind in ("timeout", "limit"):
            raise ScannerRunError(f"trivy {kind}: {stderr[-300:]}")
        # rc != 0 (không dùng --exit-code) = lỗi thật (tải DB, cache, path…): nêu rõ để
        # orchestrator ghi status "error", KHÔNG báo "0 findings".
        if rc != 0:
            raise ScannerRunError(_trivy_err(stderr, rc))
        if not stdout.strip():
            return []
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            raise ScannerRunError(f"trivy output không phải JSON: {stderr[-500:]}") from None
        if not isinstance(data, dict):
            raise ScannerRunError("trivy output không phải object JSON")

        for result in data.get("Results", []):
            target = result.get("Target", "")
            for vuln in result.get("Vulnerabilities", []) or []:
                cve_id = vuln.get("VulnerabilityID", "")
                pkg_name = vuln.get("PkgName", "")
                installed_ver = vuln.get("InstalledVersion", "")
                fixed_ver = vuln.get("FixedVersion", "")
                severity = normalize_severity(vuln.get("Severity", "UNKNOWN"))

                title = f"{pkg_name}@{installed_ver} — {cve_id}"
                desc = vuln.get("Description", vuln.get("Title", ""))

                # CVSS Score
                cvss = vuln.get("CVSS", {})
                cvss_score = ""
                for source in ["nvd", "redhat", "ghsa"]:
                    if source in cvss:
                        cvss_score = str(cvss[source].get("V3Score", cvss[source].get("V2Score", "")))
                        break

                findings.append({
                    "tool": "trivy",
                    "scan_type": "SCA",
                    "rule_id": cve_id,
                    "title": title,
                    "description": desc,
                    "severity": severity,
                    "file_path": target.replace(self.scan_path, "").lstrip("/"),
                    "package_name": pkg_name,
                    "package_version": installed_ver,
                    "fixed_version": fixed_ver,
                    "cve": cve_id,
                    "cvss_score": cvss_score,
                    "cwe": "; ".join(vuln.get("CweIDs", [])),
                    "fingerprint": make_fingerprint("trivy-sca", cve_id, target, 0, pkg_name),
                    "raw": vuln,
                })

        return findings


# Invariant: files from the scanned tree are never handed to pip-audit directly.
# Only exactly-pinned "name==version" lines are copied into a private temp dir and
# audited with pip disabled, so no option, URL, path, include or build step in the
# target can influence the tool.
_PINNED_REQ = re.compile(
    r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[A-Za-z0-9._,\s-]*\])?\s*===?\s*"
    r"([A-Za-z0-9](?:[A-Za-z0-9.+!_-]*[A-Za-z0-9])?)\s*(?:;.*)?$")
_MAX_REQ_BYTES = 1 << 20  # 1 MiB per requirements file


def pinned_requirements(path: str) -> tuple:
    """(['name==ver', ...], dropped_count). Reads at most 1 MiB; never follows includes/options."""
    if os.path.islink(path):
        return [], 1
    with open(path, "rb") as f:
        raw = f.read(_MAX_REQ_BYTES + 1)
    if len(raw) > _MAX_REQ_BYTES:
        raise ValueError("requirements file too large")
    text = re.sub(r"\\\r?\n", " ", raw.decode("utf-8", "replace"))
    kept, dropped = [], 0
    for line in text.splitlines():
        line = re.split(r"(^|\s)#", line, maxsplit=1)[0].strip()
        if not line:
            continue
        line = re.split(r"\s+-", line, maxsplit=1)[0]   # drop per-line options
        m = _PINNED_REQ.match(line)
        if m:
            kept.append(f"{m.group(1)}=={m.group(2)}")
        else:
            dropped += 1
    return kept, dropped


class PipAuditScanner(BaseScanner):
    """pip-audit — Python package vulnerability scanner.

    Thay thế Safety vì:
    - Safety v3 yêu cầu authentication và subscription
    - pip-audit miễn phí, dùng PyPI Advisory Database + OSV
    - Output JSON chuẩn, không thay đổi format giữa các phiên bản
    """
    scan_type = "SCA"
    tool_name = "pip-audit"

    async def scan(self) -> List[Dict[str, Any]]:
        findings = []

        # Only requirements*.txt (pip-audit cannot parse the other manifests offline; Trivy covers them)
        links: list = []
        found, truncated = await asyncio.to_thread(
            find_files, self.scan_path, "requirements*.txt", 50, 200_000, links)
        if truncated:
            self.warnings.append("pip-audit: more than 50 requirements files; only the first 50 were audited")
        root_real = os.path.realpath(self.scan_path)
        req_files = []
        for f in found:
            if os.path.realpath(f).startswith(root_real + os.sep):
                req_files.append(f)
            else:
                self.warnings.append(f"{os.path.relpath(f, self.scan_path)}: resolves outside the scan path; not audited")
        for f in links:
            if not os.path.realpath(f).startswith(root_real + os.sep):
                self.warnings.append(f"{os.path.relpath(f, self.scan_path)}: symlink resolves outside the scan path; not audited")

        errors: list = []
        attempted = 0
        for req_file in req_files:
            rel = req_file.replace(self.scan_path, "").lstrip("/")
            attempted += 1
            try:
                kept, dropped = pinned_requirements(req_file)
            except (ValueError, OSError) as e:
                errors.append(f"{rel}: {e}")
                continue
            if kept and dropped:
                self.warnings.append(f"{rel}: {dropped} non-pinned line(s) not audited by pip-audit")
            if not kept:
                attempted -= 1
                self.warnings.append(f"{rel}: no exactly-pinned requirements; not audited by pip-audit")
                continue
            with tempfile.TemporaryDirectory(prefix="vg-pip-audit-") as td:
                clean = os.path.join(td, os.path.basename(req_file))
                with open(clean, "w", encoding="utf-8") as fh:
                    fh.write("\n".join(kept))
                cmd = ["pip-audit", "-r", clean, "--disable-pip", "--no-deps",
                       "--format", "json", "--progress-spinner", "off"]
                rc, stdout, stderr = await run_command(cmd, cwd=td, timeout=120)

            kind = classify_failed_run(rc, stderr)
            if kind == "missing":
                logger.info("pip-audit chưa cài — bỏ qua")
                return []
            if kind in ("timeout", "limit"):
                errors.append(f"{rel}: {kind}")
                continue
            # pip-audit: exit 0 = sạch, 1 = có vulnerabilities (bình thường); khác = hỏng.
            if rc not in (0, 1):
                errors.append(f"{rel}: exit {rc}: {stderr[-200:]}")
                continue
            try:
                data = json.loads(stdout.strip())
            except json.JSONDecodeError:
                errors.append(f"{rel}: output không phải JSON (exit {rc})")
                continue
            if not isinstance(data, dict):
                errors.append(f"{rel}: output không phải object JSON")
                continue

            for dep in data.get("dependencies", []):
                pkg_name = dep.get("name", "")
                pkg_version = dep.get("version", "")
                vulns = dep.get("vulns", [])

                for vuln in vulns:
                    vuln_id = vuln.get("id", "")
                    description = vuln.get("description", "")
                    fix_versions = vuln.get("fix_versions", [])
                    aliases = vuln.get("aliases", [])

                    # Lấy CVE từ aliases
                    cve_id = next((a for a in aliases if a.startswith("CVE-")), "")

                    # Ước tính severity từ CVSS nếu có, mặc định HIGH
                    severity = "HIGH"

                    # Determine severity from description heuristics
                    desc_lower = description.lower()
                    if any(w in desc_lower for w in ["remote code execution", "arbitrary code", "critical"]):
                        severity = "CRITICAL"
                    elif any(w in desc_lower for w in ["denial of service", "sql injection", "xss"]):
                        severity = "HIGH"
                    elif any(w in desc_lower for w in ["information disclosure", "path traversal"]):
                        severity = "MEDIUM"

                    findings.append({
                        "tool": "pip-audit",
                        "scan_type": "SCA",
                        "rule_id": vuln_id,
                        "title": f"[Python] {pkg_name}@{pkg_version} — {vuln_id}",
                        "description": description,
                        "severity": severity,
                        "file_path": req_file.replace(self.scan_path, "").lstrip("/"),
                        "package_name": pkg_name,
                        "package_version": pkg_version,
                        "fixed_version": ", ".join(fix_versions) if fix_versions else "",
                        "cve": cve_id,
                        "cwe": "",
                        "fingerprint": make_fingerprint("pip-audit", vuln_id, req_file, 0, pkg_name),
                        "raw": vuln,
                    })

        # Hỏng một vài file vẫn giữ findings của file còn lại; hỏng TẤT CẢ → báo lỗi.
        if errors and len(errors) == attempted:
            raise ScannerRunError("pip-audit thất bại: " + "; ".join(errors[:3]))
        if errors:
            logger.warning("pip-audit lỗi một phần: %s", "; ".join(errors[:3]))
            self.warnings.append(f"pip-audit lỗi {len(errors)}/{attempted} file: " + "; ".join(errors[:3]))
        return findings
