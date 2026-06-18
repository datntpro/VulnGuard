"""
Settings API:
- GET  /api/settings/scanners        — health check từng tool + config hiện tại
- PUT  /api/settings/scanners        — lưu enable/disable config
- GET  /api/settings/scanner-health  — chỉ health check (no config)
"""
import asyncio
import json
import os
import subprocess
from typing import Dict, Any

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/api/settings", tags=["settings"])


class ScannerSettingsUpdate(BaseModel):
    """Body cho PUT /api/settings/scanners.

    Trước đây endpoint nhận raw `dict` không validate — payload sai field/kiểu
    dữ liệu sẽ âm thầm bị bỏ qua (degrade về {}) thay vì trả lỗi 422 rõ ràng.
    """
    enabled_tools: Dict[str, bool] = {}

# File lưu config enable/disable
SCANNER_CONFIG_FILE = os.environ.get("SCANNER_CONFIG_FILE", "/app/storage/scanner_config.json")

# Danh sách tất cả tools với metadata
TOOL_REGISTRY = [
    # SAST
    {
        "tool": "bandit",
        "label": "Bandit",
        "description": "Python security linter — phát hiện SQL injection, hardcoded secrets, subprocess shell=True...",
        "scan_type": "SAST",
        "check_cmd": ["bandit", "--version"],
        "install_hint": "pip install bandit",
        "icon": "🐍",
    },
    {
        "tool": "semgrep",
        "label": "Semgrep",
        "description": "Multi-language SAST scanner — Python, JS, Java, Go, C... dùng bundled rules + online registry.",
        "scan_type": "SAST",
        "check_cmd": ["semgrep", "--version"],
        "install_hint": "pip install semgrep",
        "icon": "🔍",
    },
    # SCA
    {
        "tool": "trivy",
        "label": "Trivy",
        "description": "Multi-ecosystem SCA + IaC + Container scanner — npm, Maven, pip, Go modules, Terraform, K8s...",
        "scan_type": "SCA / IAC / CONTAINER",
        "check_cmd": ["trivy", "--version"],
        "install_hint": "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh",
        "icon": "🔒",
    },
    {
        "tool": "pip-audit",
        "label": "pip-audit",
        "description": "Python dependency vulnerability scanner — dùng PyPI Advisory Database + OSV, không cần auth.",
        "scan_type": "SCA",
        "check_cmd": ["pip-audit", "--version"],
        "install_hint": "pip install pip-audit",
        "icon": "📦",
    },
    # Secrets
    {
        "tool": "gitleaks",
        "label": "Gitleaks",
        "description": "Secret detection trong codebase và Git history — API keys, passwords, tokens, credentials...",
        "scan_type": "SECRETS",
        "check_cmd": ["gitleaks", "version"],
        "install_hint": "Download binary từ github.com/gitleaks/gitleaks/releases",
        "icon": "🔑",
    },
    {
        "tool": "detect-secrets",
        "label": "detect-secrets",
        "description": "Yelp's secret scanner — keyword detection, entropy analysis, AWS keys, GitHub tokens...",
        "scan_type": "SECRETS",
        "check_cmd": ["detect-secrets", "--version"],
        "install_hint": "pip install detect-secrets",
        "icon": "🕵️",
    },
    # IAC
    {
        "tool": "checkov",
        "label": "Checkov",
        "description": "IaC security scanner — Terraform, CloudFormation, K8s, Dockerfile, Ansible, ARM templates.",
        "scan_type": "IAC",
        "check_cmd": ["checkov", "--version"],
        "install_hint": "pip install checkov",
        "icon": "🏗️",
    },
    {
        "tool": "hadolint",
        "label": "Hadolint",
        "description": "Dockerfile linter — phát hiện bad practices, security issues trong Dockerfile.",
        "scan_type": "IAC",
        "check_cmd": ["hadolint", "--version"],
        "install_hint": "Download binary từ github.com/hadolint/hadolint/releases",
        "icon": "🐳",
    },
    # Container
    {
        "tool": "grype",
        "label": "Grype",
        "description": "Container + filesystem vulnerability scanner (Anchore) — quét CVEs trong images và dependencies.",
        "scan_type": "CONTAINER",
        "check_cmd": ["grype", "version"],
        "install_hint": "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh",
        "icon": "🐋",
    },
]


def _load_config() -> Dict[str, bool]:
    """Đọc config enable/disable từ file."""
    try:
        if os.path.exists(SCANNER_CONFIG_FILE):
            with open(SCANNER_CONFIG_FILE) as f:
                data = json.load(f)
            return data.get("enabled_tools", {})
    except Exception:
        pass
    # Default: tất cả enabled
    return {t["tool"]: True for t in TOOL_REGISTRY}


def _save_config(enabled_tools: Dict[str, bool]):
    """Lưu config enable/disable ra file."""
    os.makedirs(os.path.dirname(SCANNER_CONFIG_FILE), exist_ok=True)
    with open(SCANNER_CONFIG_FILE, "w") as f:
        json.dump({"enabled_tools": enabled_tools}, f, indent=2)


def _check_tool_sync(tool_info: dict, enabled_map: Dict[str, bool]) -> dict:
    """Kiểm tra một tool có installed chưa (synchronous)."""
    tool = tool_info["tool"]
    enabled = enabled_map.get(tool, True)

    try:
        result = subprocess.run(
            tool_info["check_cmd"],
            capture_output=True, text=True, timeout=5
        )
        output = (result.stdout + result.stderr).strip()
        # Lấy version từ output
        version = ""
        for line in output.split("\n"):
            line = line.strip()
            if line:
                # Lấy dòng đầu tiên có content
                version = line[:80]
                break

        return {
            **tool_info,
            "installed": True,
            "version": version,
            "enabled": enabled,
            "status": "ok" if enabled else "disabled",
        }
    except FileNotFoundError:
        return {
            **tool_info,
            "installed": False,
            "version": None,
            "enabled": enabled,
            "status": "not_installed",
        }
    except Exception as e:
        return {
            **tool_info,
            "installed": False,
            "version": None,
            "enabled": enabled,
            "status": "error",
            "error": str(e),
        }


@router.get("/scanners")
def get_scanner_settings():
    """Trả về health status + enable/disable config cho tất cả tools."""
    enabled_map = _load_config()
    results = []
    for tool_info in TOOL_REGISTRY:
        results.append(_check_tool_sync(tool_info, enabled_map))

    installed_count = sum(1 for r in results if r["installed"])
    enabled_count = sum(1 for r in results if r["installed"] and r["enabled"])

    return {
        "tools": results,
        "summary": {
            "total": len(results),
            "installed": installed_count,
            "enabled": enabled_count,
            "not_installed": len(results) - installed_count,
        }
    }


@router.put("/scanners")
def update_scanner_settings(body: ScannerSettingsUpdate):
    """Lưu enable/disable config.

    Body: { "enabled_tools": { "bandit": true, "semgrep": false, ... } }
    """
    # Chỉ lưu các tools có trong registry
    valid_tools = {t["tool"] for t in TOOL_REGISTRY}
    filtered = {k: v for k, v in body.enabled_tools.items() if k in valid_tools}
    _save_config(filtered)
    return {"ok": True, "saved": filtered}


@router.get("/scanner-config")
def get_scanner_config():
    """Chỉ trả về enabled/disabled config (nhanh, không check binary)."""
    return {"enabled_tools": _load_config()}
