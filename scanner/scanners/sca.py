"""
SCA Scanners — Software Composition Analysis:
- Trivy: Multi-ecosystem (Maven, npm, pip, Go modules, ...)
- PipAuditScanner: Python pip packages (thay thế Safety v3 đã bị deprecated)
"""
import json
import glob
from typing import List, Dict, Any

from scanner.scanners.base import BaseScanner, run_command, normalize_severity, make_fingerprint


class TrivySCAScanner(BaseScanner):
    """Trivy filesystem scan — tìm vulnerable dependencies."""
    scan_type = "SCA"
    tool_name = "trivy"

    async def scan(self) -> List[Dict[str, Any]]:
        findings = []
        cmd = [
            "trivy", "fs",
            "--format", "json",
            "--scanners", "vuln",
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

        # Tìm requirements files
        req_files = glob.glob(f"{self.scan_path}/**/requirements*.txt", recursive=True)
        req_files += glob.glob(f"{self.scan_path}/**/Pipfile.lock", recursive=True)
        req_files += glob.glob(f"{self.scan_path}/**/pyproject.toml", recursive=True)

        # Dedup
        req_files = list(set(req_files))

        for req_file in req_files:
            cmd = [
                "pip-audit",
                "-r", req_file,
                "--format", "json",
                "--progress-spinner", "off",
                "--no-deps",          # Không resolve transitive deps (chỉ direct)
            ]

            rc, stdout, stderr = await run_command(cmd, timeout=120)

            # pip-audit trả về exit code 1 nếu có vulnerabilities — bình thường
            raw_output = stdout.strip() or stderr.strip()
            if not raw_output:
                continue

            try:
                data = json.loads(raw_output)
            except json.JSONDecodeError:
                # Thử parse từ stdout nếu stderr có non-JSON warnings
                try:
                    data = json.loads(stdout.strip())
                except json.JSONDecodeError:
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

        return findings
