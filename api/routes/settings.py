"""
Settings API:
- GET  /api/settings/scanners        — health check từng tool + config hiện tại
- PUT  /api/settings/scanners        — lưu enable/disable config
- GET  /api/settings/scanner-health  — chỉ health check (no config)
"""
import asyncio
import json
import os
import shutil
import subprocess
from typing import Dict, Any

from fastapi import APIRouter, File, UploadFile, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from scanner import report_builder as rb

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
        "tool": "sonar-scanner",
        "label": "SonarQube",
        "description": "SAST sâu theo data-flow (Community) — giảm false positive; cần SONARQUBE_URL + token (server sẵn có hoặc docker compose --profile sonar).",
        "scan_type": "SAST",
        "check_cmd": ["sonar-scanner", "--version"],
        "install_hint": "docker compose --profile sonar up -d  (hoặc trỏ SONARQUBE_URL tới server sẵn có)",
        "icon": "📡",
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
    # DAST / Web
    {
        "tool": "nuclei",
        "label": "Nuclei",
        "description": "Web vulnerability scanner (ProjectDiscovery) — 10k+ template CVE, misconfig, exposure; quét các URL Katana đã crawl.",
        "scan_type": "DAST",
        "check_cmd": ["nuclei", "-version"],
        "install_hint": "Download binary từ github.com/projectdiscovery/nuclei/releases",
        "icon": "☢️",
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


# ─────────────────────────────────────────────
# Branding báo cáo PDF — logo + header/footer (Settings → Báo cáo)
# ─────────────────────────────────────────────
class ReportBranding(BaseModel):
    org_name: str | None = None
    org_tagline: str | None = None
    report_title: str | None = None
    footer_text: str | None = None
    confidential_label: str | None = None


@router.get("/report-branding")
def get_report_branding():
    """Branding hiện tại + cờ có logo tùy chỉnh hay không."""
    b = rb.load_branding()
    b["has_custom_logo"] = bool(b.get("logo_path") and os.path.exists(b["logo_path"]))
    return b


@router.put("/report-branding")
def update_report_branding(body: ReportBranding):
    """Lưu text branding (bỏ qua field None)."""
    data = {k: v for k, v in body.model_dump().items() if isinstance(v, str)}
    return rb.save_branding(data)


@router.post("/report-branding/logo")
async def upload_report_logo(file: UploadFile = File(...)):
    """Upload logo PNG/JPG cho báo cáo (≤ 2MB)."""
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in (".png", ".jpg", ".jpeg"):
        raise HTTPException(400, "Chỉ chấp nhận PNG/JPG")
    raw = await file.read()
    if len(raw) > 2 * 1024 * 1024:
        raise HTTPException(400, "Logo quá lớn (tối đa 2MB)")
    dest = os.path.join(rb.branding_dir(), "report_logo" + (".jpg" if ext in (".jpg", ".jpeg") else ".png"))
    with open(dest, "wb") as f:
        f.write(raw)
    rb.save_branding({"logo_path": dest})
    return {"ok": True, "logo_path": dest}


@router.delete("/report-branding/logo")
def reset_report_logo():
    """Về logo mặc định VulnGuard."""
    rb.save_branding({"logo_path": ""})
    return {"ok": True}


@router.get("/sonarqube")
def get_sonarqube_settings():
    """Cấu hình SonarQube hiện tại (token ẩn, chỉ hint)."""
    from api.services import runtime_settings as rt
    from api.security import mask_secret
    tok = rt.sonarqube_token()
    return {
        "url": rt.sonarqube_url(),
        "token_set": bool(tok),
        "token_hint": mask_secret(tok) if tok else "",
        "custom": rt.sonarqube_is_custom(),
    }


class SonarQubeUpdate(BaseModel):
    url: str | None = None
    token: str | None = None          # write-only
    clear_token: bool = False


@router.put("/sonarqube")
def update_sonarqube_settings(body: SonarQubeUpdate):
    from api.services import runtime_settings as rt
    rt.set_sonarqube(url=body.url, token=body.token, clear_token=body.clear_token)
    return get_sonarqube_settings()


@router.post("/sonarqube/test")
async def test_sonarqube():
    """Kiểm tra kết nối + token tới SonarQube (gọi /api/system/status + /api/authentication/validate)."""
    import httpx
    from api.services import runtime_settings as rt
    url, token = rt.sonarqube_url(), rt.sonarqube_token()
    if not url:
        raise HTTPException(400, "Chưa nhập SonarQube URL")
    try:
        async with httpx.AsyncClient(timeout=10, trust_env=False) as c:
            st = await c.get(f"{url}/api/system/status")
            status = st.json().get("status") if st.status_code == 200 else None
            auth_ok = None
            if token:
                r = await c.get(f"{url}/api/authentication/validate",
                                headers={"Authorization": f"Bearer {token}"})
                auth_ok = bool(r.status_code == 200 and r.json().get("valid"))
        return {"ok": status == "UP", "status": status, "token_valid": auth_ok,
                "has_scanner": bool(shutil.which("sonar-scanner"))}
    except Exception as e:
        raise HTTPException(503, f"Không kết nối được SonarQube tại {url}: {e}")


@router.get("/smtp")
def get_smtp_settings():
    from api.services import runtime_settings as rt
    from api.security import mask_secret
    c = rt.smtp_config()
    return {"host": c["host"], "port": c["port"], "username": c["username"],
            "from_addr": c["from_addr"], "use_tls": c["use_tls"],
            "password_set": bool(c["password"]),
            "password_hint": mask_secret(c["password"]) if c["password"] else "",
            "configured": rt.smtp_is_configured()}


class SmtpUpdate(BaseModel):
    host: str | None = None
    port: int | None = None
    username: str | None = None
    password: str | None = None
    from_addr: str | None = None
    use_tls: bool | None = None
    clear_password: bool = False


@router.put("/smtp")
def update_smtp_settings(body: SmtpUpdate):
    from api.services import runtime_settings as rt
    rt.set_smtp(host=body.host, port=body.port, username=body.username, password=body.password,
               from_addr=body.from_addr, use_tls=body.use_tls, clear_password=body.clear_password)
    return get_smtp_settings()


class SmtpTest(BaseModel):
    to: str


@router.post("/smtp/test")
def test_smtp(body: SmtpTest):
    from api.services.mailer import send_email
    try:
        send_email(body.to, "[VulnGuard] Email kiểm tra",
                   "Đây là email kiểm tra cấu hình SMTP của VulnGuard. Nếu bạn nhận được, cấu hình đã đúng.")
        return {"ok": True, "message": f"Đã gửi email kiểm tra tới {body.to}"}
    except Exception as e:
        raise HTTPException(502, f"Gửi thất bại: {str(e)[:200]}")


@router.get("/report-branding/logo-image")
def get_report_logo_image():
    """Trả về logo hiện dùng (tùy chỉnh hoặc mặc định) để preview."""
    path = rb._logo_path(rb.load_branding())
    if not path or not os.path.exists(path):
        raise HTTPException(404, "Không có logo")
    mt = "image/jpeg" if path.lower().endswith((".jpg", ".jpeg")) else "image/png"
    return FileResponse(path, media_type=mt)
