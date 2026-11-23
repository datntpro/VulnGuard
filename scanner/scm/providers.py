"""
Client GitHub & GitLab (cloud + self-managed/onprem).

Phần dựng URL là pure-function (test được không cần mạng); phần gọi API dùng httpx.
Token chỉ nhúng vào URL clone lúc chạy, luôn redact khi log/lỗi.
"""
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, quote

import httpx

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


def _headers(provider: str, token: str) -> Dict[str, str]:
    if provider.upper() == "GITHUB":
        return {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28"}
    return {"PRIVATE-TOKEN": token}


async def validate(provider: str, base_url: Optional[str], token: str) -> Dict[str, Any]:
    """Kiểm tra token hợp lệ → trả thông tin user."""
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
