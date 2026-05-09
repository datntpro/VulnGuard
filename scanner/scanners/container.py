"""
Container Scanners:
- Trivy: Container image vulnerability scan
- Grype: Anchore vulnerability scanner
"""
import json
import os
from typing import List, Dict, Any

from scanner.scanners.base import BaseScanner, run_command, normalize_severity, make_fingerprint


class TrivyContainerScanner(BaseScanner):
    """Scan container images referenced trong docker-compose hoặc K8s manifests."""
    scan_type = "CONTAINER"
    tool_name = "trivy"

    def __init__(self, scan_path: str, image: str = None):
        super().__init__(scan_path)
        self.image = image  # Có thể scan image cụ thể

    async def scan(self) -> List[Dict[str, Any]]:
        findings = []

        if self.image:
            # Scan một image cụ thể
            findings.extend(await self._scan_image(self.image))
        else:
            # Tìm images trong docker-compose files
            images = await self._extract_images_from_compose()
            for image in images:
                findings.extend(await self._scan_image(image))

        return findings

    async def _extract_images_from_compose(self) -> List[str]:
        """Extract image names từ docker-compose.yml files."""
        import glob
        import re

        images = []
        compose_files = glob.glob(f"{self.scan_path}/**/docker-compose*.yml", recursive=True)
        compose_files += glob.glob(f"{self.scan_path}/**/docker-compose*.yaml", recursive=True)

        image_pattern = re.compile(r'^\s+image:\s+(.+)$', re.MULTILINE)

        for cf in compose_files:
            try:
                with open(cf, 'r') as f:
                    content = f.read()
                matches = image_pattern.findall(content)
                for m in matches:
                    image = m.strip().strip('"').strip("'")
                    if image and not image.startswith("$"):
                        images.append(image)
            except Exception:
                pass

        return list(set(images))  # deduplicate

    async def _scan_image(self, image: str) -> List[Dict[str, Any]]:
        findings = []
        cmd = [
            "trivy", "image",
            "--format", "json",
            "--severity", "CRITICAL,HIGH,MEDIUM",
            "--quiet",
            image,
        ]

        rc, stdout, stderr = await run_command(cmd, timeout=300)

        if not stdout.strip():
            return []

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return []

        for result in data.get("Results", []):
            target = result.get("Target", image)
            for vuln in result.get("Vulnerabilities", []) or []:
                cve_id = vuln.get("VulnerabilityID", "")
                pkg = vuln.get("PkgName", "")
                installed = vuln.get("InstalledVersion", "")
                fixed = vuln.get("FixedVersion", "")
                severity = normalize_severity(vuln.get("Severity", "UNKNOWN"))

                findings.append({
                    "tool": "trivy-container",
                    "scan_type": "CONTAINER",
                    "rule_id": cve_id,
                    "title": f"[Image:{image}] {pkg}@{installed} — {cve_id}",
                    "description": vuln.get("Description", vuln.get("Title", "")),
                    "severity": severity,
                    "file_path": f"image:{image}/{target}",
                    "package_name": pkg,
                    "package_version": installed,
                    "fixed_version": fixed,
                    "cve": cve_id,
                    "fingerprint": make_fingerprint("trivy-container", cve_id, image, 0, pkg),
                    "raw": vuln,
                })

        return findings


class GrypeScanner(BaseScanner):
    """Grype — Anchore container/filesystem vulnerability scanner."""
    scan_type = "CONTAINER"
    tool_name = "grype"

    async def scan(self) -> List[Dict[str, Any]]:
        findings = []
        cmd = [
            "grype",
            f"dir:{self.scan_path}",
            "-o", "json",
            "--quiet",
        ]

        rc, stdout, stderr = await run_command(cmd, timeout=300)

        if not stdout.strip():
            return []

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return []

        for match in data.get("matches", []):
            artifact = match.get("artifact", {})
            vuln = match.get("vulnerability", {})

            pkg_name = artifact.get("name", "")
            pkg_version = artifact.get("version", "")
            vuln_id = vuln.get("id", "")
            severity = normalize_severity(vuln.get("severity", "unknown"))
            fixed_versions = vuln.get("fix", {}).get("versions", [])
            fixed = ", ".join(fixed_versions) if fixed_versions else ""

            findings.append({
                "tool": "grype",
                "scan_type": "CONTAINER",
                "rule_id": vuln_id,
                "title": f"{pkg_name}@{pkg_version} — {vuln_id}",
                "description": vuln.get("description", ""),
                "severity": severity,
                "package_name": pkg_name,
                "package_version": pkg_version,
                "fixed_version": fixed,
                "cve": vuln_id if vuln_id.startswith("CVE-") else "",
                "cvss_score": str(vuln.get("cvss", [{}])[0].get("metrics", {}).get("baseScore", "")) if vuln.get("cvss") else "",
                "fingerprint": make_fingerprint("grype", vuln_id, pkg_name, 0, pkg_version),
                "raw": match,
            })

        return findings
