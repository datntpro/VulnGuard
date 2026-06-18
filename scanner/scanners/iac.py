"""
IaC Scanners:
- Checkov: Terraform, K8s, Dockerfile, Ansible, CloudFormation, ARM
- TFSec: Terraform deep-dive
- Trivy IaC: Terraform, K8s manifests
"""
import json
from typing import List, Dict, Any

from scanner.scanners.base import BaseScanner, run_command, normalize_severity, make_fingerprint


class CheckovScanner(BaseScanner):
    """Checkov — comprehensive IaC scanner."""
    scan_type = "IAC"
    tool_name = "checkov"

    async def scan(self) -> List[Dict[str, Any]]:
        findings = []
        cmd = [
            "checkov",
            "-d", self.scan_path,
            "--output", "json",
            "--quiet",
            "--compact",
            "--skip-check", "CKV_DOCKER_2,CKV_DOCKER_3",  # Skip quá nhiều false positive
        ]

        rc, stdout, stderr = await run_command(cmd, timeout=300)

        if not stdout.strip():
            return []

        # Checkov có thể trả về nhiều JSON objects
        try:
            # Thử parse toàn bộ stdout
            data = json.loads(stdout)
        except json.JSONDecodeError:
            # Thử tìm JSON object đầu tiên
            try:
                start = stdout.find("{")
                if start >= 0:
                    data = json.loads(stdout[start:])
                else:
                    return []
            except:
                return []

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

        rc, stdout, stderr = await run_command(cmd, timeout=300)

        if not stdout.strip():
            return []

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return []

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
        import glob
        dockerfiles = glob.glob(f"{self.scan_path}/**/Dockerfile*", recursive=True)
        dockerfiles += glob.glob(f"{self.scan_path}/**/dockerfile*", recursive=True)

        for dockerfile in dockerfiles:
            cmd = ["hadolint", "--format", "json", dockerfile]
            rc, stdout, stderr = await run_command(cmd, timeout=30)

            if not stdout.strip():
                continue

            try:
                issues = json.loads(stdout)
            except json.JSONDecodeError:
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

        return findings
