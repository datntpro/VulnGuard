"""[AI PR-6] Tham số + xác thực cho provider mở rộng: Azure OpenAI, Gemini, Vertex AI, OpenAI-compatible.

Mọi tham số quyết định NƠI khoá được gửi tới (endpoint / deployment / project / location / tenant / base_url) được
kiểm chặt Ở ĐÂY (khi lưu / test) và kiểm LẠI trong `llm_resolver._build_cloud_client` (lúc gọi), vì hàng DB hoặc
body test có thể bị sửa. Host cuối cùng luôn được dựng từ nhãn đã kiểm (resource, region, location) — không bao giờ
nối chuỗi thô vào URL. Ngoài ra mọi request còn đi qua `url_guard` (resolve + ghim IP + không redirect).

Thông điệp lỗi do VulnGuard tự viết (không chứa giá trị người dùng nhập / văn bản provider).
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

from api.services.url_guard import UrlRejected

DEFAULT_AZURE_API_VERSION = "2024-10-21"
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"
DEFAULT_VERTEX_MODEL = "google/gemini-2.5-flash"
GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai/"

# Hậu tố host Azure OpenAI được chấp nhận (cloud công cộng + Azure Government). Nhãn resource đứng ngay trước hậu tố.
_AZURE_SUFFIXES = ("openai.azure.com", "cognitiveservices.azure.com", "openai.azure.us")
_AZURE_RESOURCE_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")   # tối đa 63 ký tự (nhãn DNS)
_DEPLOYMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,63}$")
_API_VERSION_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(?:-preview)?$")
_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
_GCP_PROJECT_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_GCP_LOCATION_RE = re.compile(r"^(?:global|[a-z]+-[a-z]+\d{1,2})$")
_MAX_SA_JSON = 16 * 1024


def valid_azure_resource(resource: Any) -> bool:
    return isinstance(resource, str) and bool(_AZURE_RESOURCE_RE.fullmatch(resource))


def azure_endpoint_from_resource(resource: str) -> str:
    """User chỉ đưa TÊN resource; host do server dựng (D4: user không đặt URL tuỳ ý)."""
    if not valid_azure_resource(resource):
        raise UrlRejected("tên resource Azure OpenAI không hợp lệ")
    return f"https://{resource}.openai.azure.com"


def check_azure_endpoint(endpoint: Any) -> str:
    """Endpoint phải là `https://<resource>.<hậu tố Azure>` — không path, port, userinfo, query. Trả URL chuẩn hoá."""
    if not isinstance(endpoint, str) or not endpoint.strip():
        raise UrlRejected("thiếu endpoint Azure OpenAI")
    ep = endpoint.strip()
    if len(ep) > 200 or any(ord(c) < 33 or ord(c) == 127 for c in ep) or "\\" in ep:
        raise UrlRejected("endpoint chứa ký tự không hợp lệ")
    try:
        sp = urlsplit(ep)
        port = sp.port
    except ValueError:
        raise UrlRejected("endpoint không hợp lệ")
    if sp.scheme.lower() != "https":
        raise UrlRejected("chỉ chấp nhận https")
    if "@" in sp.netloc or port not in (None, 443) or sp.query or sp.fragment or "?" in ep or "#" in ep:
        raise UrlRejected("endpoint Azure OpenAI không được có userinfo/cổng/query/fragment")
    if sp.path not in ("", "/"):
        raise UrlRejected("endpoint Azure OpenAI không được có path")
    host = (sp.hostname or "").lower()
    for suf in _AZURE_SUFFIXES:
        if host.endswith("." + suf):
            label = host[: -(len(suf) + 1)]
            if valid_azure_resource(label):
                return f"https://{host}"
    raise UrlRejected("host phải dạng <resource>.openai.azure.com (hoặc .cognitiveservices.azure.com)")


def check_deployment(deployment: Any) -> str:
    if not isinstance(deployment, str) or not _DEPLOYMENT_RE.fullmatch(deployment.strip()):
        raise UrlRejected("tên deployment không hợp lệ")
    return deployment.strip()


def check_api_version(version: Any) -> str:
    v = (version or DEFAULT_AZURE_API_VERSION)
    if not isinstance(v, str) or not _API_VERSION_RE.fullmatch(v.strip()):
        raise UrlRejected("api_version không hợp lệ (dạng YYYY-MM-DD hoặc YYYY-MM-DD-preview)")
    return v.strip()


def check_guid(value: Any, what: str) -> str:
    if not isinstance(value, str) or not _GUID_RE.fullmatch(value.strip()):
        raise UrlRejected(f"{what} phải là GUID")
    return value.strip().lower()


def check_gcp_project(project: Any) -> str:
    if not isinstance(project, str) or not _GCP_PROJECT_RE.fullmatch(project.strip()):
        raise UrlRejected("project GCP không hợp lệ")
    return project.strip()


def check_gcp_location(location: Any) -> str:
    loc = (location or "us-central1")
    if not isinstance(loc, str) or not _GCP_LOCATION_RE.fullmatch(loc.strip()):
        raise UrlRejected("location GCP không hợp lệ")
    return loc.strip()


def vertex_base_url(project: str, location: str) -> str:
    """Endpoint OpenAI-compatible của Vertex AI. Host dựng từ `location` đã kiểm (không nối thô)."""
    project, location = check_gcp_project(project), check_gcp_location(location)
    host = "aiplatform.googleapis.com" if location == "global" else f"{location}-aiplatform.googleapis.com"
    return f"https://{host}/v1/projects/{project}/locations/{location}/endpoints/openapi"


def parse_service_account(raw: Any) -> Dict[str, str]:
    """Parse + kiểm SA JSON của Google. Chỉ trả các trường cần để ký JWT. `token_uri` trong file BỊ BỎ QUA
    (luôn dùng oauth2.googleapis.com) nên file độc hại không điều hướng được nơi gửi JWT."""
    if not isinstance(raw, str) or not raw.strip() or len(raw) > _MAX_SA_JSON:
        raise UrlRejected("service account JSON không hợp lệ")
    try:
        d = json.loads(raw)
    except ValueError:
        raise UrlRejected("service account JSON không hợp lệ") from None
    if not isinstance(d, dict) or d.get("type") != "service_account":
        raise UrlRejected("service account JSON không hợp lệ")
    email, pk = d.get("client_email"), d.get("private_key")
    if (not isinstance(email, str) or not re.fullmatch(r"[A-Za-z0-9._\-]{1,100}@[A-Za-z0-9.\-]{1,100}", email)
            or not isinstance(pk, str) or "PRIVATE KEY" not in pk):
        raise UrlRejected("service account JSON không hợp lệ")
    return {"client_email": email, "private_key": pk, "private_key_id": str(d.get("private_key_id") or "")}


def validate_section(provider: str, sec: Dict[str, Any], *, secret: Optional[str] = None) -> None:
    """Kiểm tham số một section (khi LƯU cấu hình org). Raise UrlRejected (là ValueError). Không mạng/DNS."""
    if provider == "azure_openai":
        if sec.get("endpoint"):
            check_azure_endpoint(sec["endpoint"])
        if sec.get("deployment"):
            check_deployment(sec["deployment"])
        check_api_version(sec.get("api_version"))
        if sec.get("auth_mode", "api_key") not in ("api_key", "entra"):
            raise ValueError("azure_openai.auth_mode phải là api_key | entra")
        if sec.get("auth_mode") == "entra":
            if sec.get("tenant_id"):
                check_guid(sec["tenant_id"], "tenant_id")
            if sec.get("client_id"):
                check_guid(sec["client_id"], "client_id")
    elif provider == "vertex":
        if sec.get("auth_mode", "service_account") != "service_account":
            raise ValueError("vertex.auth_mode hiện chỉ hỗ trợ service_account")
        if sec.get("project"):
            check_gcp_project(sec["project"])
        check_gcp_location(sec.get("location"))
        if secret:
            parse_service_account(secret)
    elif provider == "openai_compatible":
        if (sec.get("base_url") or "").strip():
            from api.services import url_guard
            url_guard.parse_url(sec["base_url"], url_guard.policy_for("cloud"))   # chỉ cú pháp, không DNS
