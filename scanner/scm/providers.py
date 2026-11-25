"""
Client GitHub & GitLab (cloud + self-managed/onprem).

Phần dựng URL là pure-function (test được không cần mạng); phần gọi API dùng httpx.
Token chỉ nhúng vào URL clone lúc chạy, luôn redact khi log/lỗi.
"""
import ipaddress
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, quote

import httpx

from api.config import settings

GITHUB_CLOUD = "https://github.com"
GITLAB_CLOUD = "https://gitlab.com"


def _host(url: str) -> str:
    p = urlparse(url)
    return p.netloc or url.replace("https://", "").replace("http://", "").strip("/")


def _scheme(url: str) -> str:
    return urlparse(url).scheme or "https"


# ── API base ──
def api_base(provider: str, base_url: Optional[str]) -> str:
    provider = provider.upper()
    base = (base_url or "").strip().rstrip("/")
    if provider == "GITHUB":
        if not base or _host(base) in ("github.com", "www.github.com"):
            return "https://api.github.com"
        return f"{base}/api/v3"                      # GitHub Enterprise
    # GITLAB
    return f"{base or GITLAB_CLOUD}/api/v4"


def web_base(provider: str, base_url: Optional[str]) -> str:
    base = (base_url or "").strip().rstrip("/")
    if base:
        return base
    return GITHUB_CLOUD if provider.upper() == "GITHUB" else GITLAB_CLOUD


def clone_url(provider: str, base_url: Optional[str], token: str, repo_full_name: str) -> str:
    """URL clone HTTPS có token (redact trước khi log)."""
    wb = web_base(provider, base_url)
    scheme, host = _scheme(wb), _host(wb)
    repo = repo_full_name.strip("/")
    if not repo.endswith(".git"):
        repo += ".git"
    if provider.upper() == "GITHUB":
        return f"{scheme}://x-access-token:{token}@{host}/{repo}"
    return f"{scheme}://oauth2:{token}@{host}/{repo}"   # GitLab


def redact(text: str, token: str) -> str:
    return text.replace(token, "***") if token else text


def check_base_url(url: Optional[str]) -> None:
    """L-1: chống SSRF qua base_url do người dùng nhập. Rỗng = cloud mặc định (hợp lệ).
    Chặn scheme không phải https (trừ khi SCM_ALLOW_HTTP), loopback, link-local (169.254/16, fe80::/10),
    unspecified, multicast, reserved, metadata AWS IPv6; RFC1918/ULA chỉ khi SCM_ALLOW_PRIVATE_HOSTS.
    Kiểm tra lại lúc dùng (validate/list_repos/clone) để thu hẹp DNS rebinding (chưa pin IP)."""
    url = (url or "").strip()
    if not url:
        return
    p = urlparse(url)
    allowed = {"https"} | ({"http"} if settings.scm_allow_http else set())
    if p.scheme not in allowed:
        raise ValueError(f"base_url phải dùng {'/'.join(sorted(allowed))}://")
    host = p.hostname
    if not host:
        raise ValueError("base_url thiếu hostname")
    try:
        infos = socket.getaddrinfo(host, p.port or (443 if p.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ValueError(f"Không phân giải được host: {host}") from e
    for info in infos:
        _check_ip(ipaddress.ip_address(info[4][0].split("%")[0]))


_ALWAYS_BLOCKED = [ipaddress.ip_address(a) for a in ("fd00:ec2::254", "100.100.100.200", "192.0.0.192")]
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _embedded_v4(ip):
    """IPv4 nhúng trong IPv6 (mapped, NAT64 64:ff9b::/96, 6to4 2002::/16, Teredo)."""
    if ip.version != 6:
        return None
    if ip.ipv4_mapped:
        return ip.ipv4_mapped
    if ip.sixtofour:
        return ip.sixtofour
    if ip.teredo:
        return ip.teredo[1]
    if ip in ipaddress.ip_network("64:ff9b::/96"):
        return ipaddress.ip_address(int(ip) & 0xFFFFFFFF)
    return None


def _check_ip(ip) -> None:
    inner = _embedded_v4(ip)
    if inner is not None:
        _check_ip(inner)
    if (ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast
            or ip.is_reserved or ip in _ALWAYS_BLOCKED):
        raise ValueError(f"base_url trỏ tới địa chỉ không được phép ({ip})")
    if not settings.scm_allow_private_hosts:
        # is_global loại cả CGNAT 100.64/10 (metadata Alibaba), 192.0.0.0/24 và các dải đặc biệt khác
        if ip.is_private or not ip.is_global or (ip.version == 4 and ip in _CGNAT):
            raise ValueError(f"base_url trỏ tới dải private ({ip}) — bật SCM_ALLOW_PRIVATE_HOSTS nếu là on-prem")


def _headers(provider: str, token: str) -> Dict[str, str]:
    if provider.upper() == "GITHUB":
        return {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28"}
    return {"PRIVATE-TOKEN": token}


async def validate(provider: str, base_url: Optional[str], token: str) -> Dict[str, Any]:
    """Kiểm tra token hợp lệ → trả thông tin user."""
    check_base_url(base_url)
    base = api_base(provider, base_url)
    path = "/user"
    async with httpx.AsyncClient(timeout=15, trust_env=False) as c:
        r = await c.get(f"{base}{path}", headers=_headers(provider, token))
        r.raise_for_status()
        u = r.json()
    if provider.upper() == "GITHUB":
        return {"ok": True, "user": u.get("login"), "name": u.get("name")}
    return {"ok": True, "user": u.get("username"), "name": u.get("name")}


async def list_repos(provider: str, base_url: Optional[str], token: str,
                     limit: int = 100) -> List[Dict[str, Any]]:
    """Danh sách repo user có quyền (chuẩn hoá: full_name, default_branch, web_url)."""
    check_base_url(base_url)
    base = api_base(provider, base_url)
    out: List[Dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=20, trust_env=False) as c:
        if provider.upper() == "GITHUB":
            r = await c.get(f"{base}/user/repos",
                            headers=_headers(provider, token),
                            params={"per_page": min(limit, 100), "sort": "updated",
                                    "affiliation": "owner,collaborator,organization_member"})
            r.raise_for_status()
            for repo in r.json():
                out.append({"full_name": repo.get("full_name"),
                            "default_branch": repo.get("default_branch") or "main",
                            "web_url": repo.get("html_url"),
                            "private": repo.get("private")})
        else:
            r = await c.get(f"{base}/projects",
                            headers=_headers(provider, token),
                            params={"membership": "true", "per_page": min(limit, 100),
                                    "order_by": "last_activity_at", "simple": "true"})
            r.raise_for_status()
            for repo in r.json():
                out.append({"full_name": repo.get("path_with_namespace"),
                            "default_branch": repo.get("default_branch") or "main",
                            "web_url": repo.get("web_url"),
                            "private": repo.get("visibility") != "public"})
    return out[:limit]
