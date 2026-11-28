"""
IaC Scanners:
- Checkov: Terraform, K8s, Dockerfile, Ansible, CloudFormation, ARM
- TFSec: Terraform deep-dive
- Trivy IaC: Terraform, K8s manifests
"""
import asyncio
import json
import logging
import os
import shutil
import tempfile
from typing import List, Dict, Any

from scanner.scanners.sca import _trivy_err, trivy_env
from scanner.scanners.base import (find_files, ScannerRunError, BaseScanner, run_command, normalize_severity,
                                   make_fingerprint, classify_failed_run)

logger = logging.getLogger(__name__)

_CFG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config")


class CheckovScanner(BaseScanner):
    """Checkov — comprehensive IaC scanner."""
    scan_type = "IAC"
    tool_name = "checkov"

    async def scan(self) -> List[Dict[str, Any]]:
        findings = []
        # Invariant: target files never configure the tool. The tool reads default config files
        # relative to the scanned directory (matched on the exact `--directory=` token) and cwd, so
        # pass the directory as ONE token and run from an empty private cwd.
        # keep: see test_checkov_ignores_target_config
        if any(os.path.lexists(os.path.join(self.scan_path, n)) for n in (".checkov.yaml", ".checkov.yml")):
            logger.info("checkov: target config file present and ignored")
        with tempfile.TemporaryDirectory(prefix="vg-checkov-") as td:
            cmd = [
                "checkov",
                f"--directory={os.path.abspath(self.scan_path)}",
                "--output", "json",
                "--quiet",
                "--compact",
                "--skip-check", "CKV_DOCKER_2,CKV_DOCKER_3",  # Skip quá nhiều false positive
            ]
            rc, stdout, stderr = await run_command(cmd, cwd=td, timeout=300, env={
                "CKV_EXTERNAL_CHECKS_PUBLIC_KEY": os.path.abspath(
                    os.path.join(_CFG_DIR, "checkov-external-checks.pub")),
            })

        kind = classify_failed_run(rc, stderr)
        if kind == "missing":
            logger.info("checkov chưa cài — bỏ qua")
            return []
        if kind in ("timeout", "limit"):
            raise ScannerRunError(f"checkov {kind}: {stderr[-300:]}")
        # checkov: exit 0 = sạch, 1 = có failed checks; mọi mã khác = tool hỏng.
        if rc not in (0, 1):
            raise ScannerRunError(f"checkov thất bại (exit {rc}): {stderr[-500:]}")

        if not stdout.strip():
            if rc != 0:
                raise ScannerRunError(f"checkov không in output (exit {rc}): {stderr[-500:]}")
            return []

        # Checkov có thể in tiền tố/nhiều JSON objects
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            start = stdout.find("{")
            try:
                data = json.loads(stdout[start:]) if start >= 0 else None
            except json.JSONDecodeError:
                data = None
            if data is None:
                raise ScannerRunError(
                    f"checkov output không phải JSON (exit {rc}): {stderr[-500:]}") from None

        # Checkov có thể trả về dict hoặc list
        results_list = data if isinstance(data, list) else [data]

        for results in results_list:
            if not isinstance(results, dict):
                continue

            failed_checks = results.get("results", {}).get("failed_checks", [])

            for check in failed_checks:
                check_id = check.get("check_id", "")
                check_type = check.get("check_type", "terraform")
                file_path = check.get("repo_file_path", check.get("file_path", ""))
                line_range = check.get("file_line_range", [0, 0])
                resource = check.get("resource", "")

                severity = "MEDIUM"  # Checkov default
                # Một số checks được classify là HIGH/CRITICAL
                if any(kw in check_id for kw in ["SECRET", "CRED", "PRIV", "ENCRYPT"]):
                    severity = "HIGH"
                if any(kw in check_id for kw in ["CKV_AWS_57", "CKV_AWS_18", "CKV_K8S_8"]):
                    severity = "CRITICAL"

                title = check.get("check_id", "") + ": " + check.get("check_type", "")
                check_result_detail = check.get("check_result", {})

                findings.append({
                    "tool": "checkov",
                    "scan_type": "IAC",
                    "rule_id": check_id,
                    "title": f"[{check_type.upper()}] {check_id}",
                    "description": check.get("check_result", {}).get("result", ""),
                    "severity": severity,
                    "file_path": file_path.replace(self.scan_path, "").lstrip("/"),
                    "line_start": line_range[0] if line_range else 0,
                    "line_end": line_range[1] if len(line_range) > 1 else line_range[0] if line_range else 0,
                    "fingerprint": make_fingerprint("checkov", check_id, file_path, line_range[0] if line_range else 0, resource),
                    "raw": check,
                })

        return findings


class TrivyIaCScanner(BaseScanner):
    """Trivy IaC scan — Terraform, K8s manifests."""
    scan_type = "IAC"
    tool_name = "trivy-iac"

    def is_available(self) -> bool:
        # No binary named "trivy-iac": it is `trivy fs --scanners misconfig`.
        return shutil.which("trivy") is not None

    async def scan(self) -> List[Dict[str, Any]]:
        findings = []
        cmd = [
            "trivy", "fs",
            "--format", "json",
            "--scanners", "misconfig",
            "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
            "--quiet",
            self.scan_path,
        ]

        rc, stdout, stderr = await run_command(cmd, timeout=300, env=trivy_env())

        kind = classify_failed_run(rc, stderr)
        if kind == "missing":
            logger.info("trivy chưa cài — bỏ qua IaC")
            return []
        if kind in ("timeout", "limit"):
            raise ScannerRunError(f"trivy-iac {kind}: {stderr[-300:]}")
        if rc != 0:
            raise ScannerRunError(_trivy_err(stderr, rc))
        if not stdout.strip():
            return []
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            raise ScannerRunError(f"trivy-iac output không phải JSON: {stderr[-500:]}") from None
        if not isinstance(data, dict):
            raise ScannerRunError("trivy-iac output không phải object JSON")

        for result in data.get("Results", []):
            target = result.get("Target", "")
            result_type = result.get("Type", "")

            for misconfig in result.get("Misconfigurations", []) or []:
                check_id = misconfig.get("ID", "")
                title = misconfig.get("Title", "")
                description = misconfig.get("Description", "")
                severity = normalize_severity(misconfig.get("Severity", "LOW"))
                resolution = misconfig.get("Resolution", "")

                findings.append({
                    "tool": "trivy-iac",
                    "scan_type": "IAC",
                    "rule_id": check_id,
                    "title": f"[{result_type}] {title}",
                    "description": f"{description}\n\nResolution: {resolution}",
                    "severity": severity,
                    "file_path": target.replace(self.scan_path, "").lstrip("/"),
                    "line_start": misconfig.get("CauseMetadata", {}).get("StartLine", 0),
                    "line_end": misconfig.get("CauseMetadata", {}).get("EndLine", 0),
                    "fingerprint": make_fingerprint("trivy-iac", check_id, target, 0, title),
                    "raw": misconfig,
                })

        return findings


class HadolintScanner(BaseScanner):
    """Hadolint — Dockerfile linter."""
    scan_type = "IAC"
    tool_name = "hadolint"

    async def scan(self) -> List[Dict[str, Any]]:
        findings = []
        dockerfiles, truncated = await asyncio.to_thread(
            find_files, self.scan_path, ("Dockerfile*", "dockerfile*"), 200)
        if truncated:
            self.warnings.append("hadolint: more than 200 Dockerfiles; only the first 200 were checked")

        errors: list = []
        for dockerfile in dockerfiles:
            cmd = ["hadolint", "--format", "json", dockerfile]
            rc, stdout, stderr = await run_command(cmd, timeout=30)

            kind = classify_failed_run(rc, stderr)
            if kind == "missing":
                logger.info("hadolint chưa cài — bỏ qua")
                return []
            if kind in ("timeout", "limit"):
                errors.append(f"{dockerfile}: {kind}")
                continue
            # hadolint: exit 0 = sạch, 1 = có findings; khác = hỏng.
            if rc not in (0, 1):
                errors.append(f"{dockerfile}: exit {rc}: {stderr[-200:]}")
                continue
            if not stdout.strip():
                if rc != 0:
                    errors.append(f"{dockerfile}: không có output (exit {rc})")
                continue

            try:
                issues = json.loads(stdout)
            except json.JSONDecodeError:
                errors.append(f"{dockerfile}: output không phải JSON")
                continue
            if not isinstance(issues, list):
                errors.append(f"{dockerfile}: output không phải list")
                continue

            for issue in issues:
                code = issue.get("code", "")
                level = issue.get("level", "warning")
                line = issue.get("line", 0)
                message = issue.get("message", "")

                findings.append({
                    "tool": "hadolint",
                    "scan_type": "IAC",
                    "rule_id": code,
                    "title": f"[Dockerfile] {code}: {message[:80]}",
                    "description": message,
                    "severity": "HIGH" if level == "error" else "MEDIUM" if level == "warning" else "LOW",
                    "file_path": dockerfile.replace(self.scan_path, "").lstrip("/"),
                    "line_start": line,
                    "fingerprint": make_fingerprint("hadolint", code, dockerfile, line, message[:50]),
                    "raw": issue,
                })

        # Một vài file hỏng vẫn giữ findings của file còn lại; hỏng TẤT CẢ → báo lỗi.
        if errors and len(errors) == len(dockerfiles):
            raise ScannerRunError("hadolint thất bại: " + "; ".join(errors[:3]))
        if errors:
            logger.warning("hadolint lỗi một phần: %s", "; ".join(errors[:3]))
            self.warnings.append(f"hadolint lỗi {len(errors)}/{len(dockerfiles)} file: " + "; ".join(errors[:3]))
        return findings
