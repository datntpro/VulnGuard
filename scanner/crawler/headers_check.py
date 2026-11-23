"""
Kiểm tra security header thiếu (1.2) — native, không phụ thuộc nuclei template.

Fetch các URL mục tiêu (dedup theo host), kiểm các header bảo mật phổ biến và
sinh finding theo đúng shape WebFinding để gộp chung kết quả web scan.
"""
from typing import Any, Awaitable, Callable, Dict, List
from urllib.parse import urlparse

# header → (severity, mô tả, khuyến nghị)
_CHECKS = {
    "strict-transport-security": ("medium", "Thiếu HSTS (Strict-Transport-Security)",
        "Thêm header: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    "content-security-policy": ("medium", "Thiếu Content-Security-Policy (CSP)",
        "Cấu hình CSP phù hợp để giảm rủi ro XSS/injection."),
    "x-frame-options": ("low", "Thiếu X-Frame-Options",
        "Thêm X-Frame-Options: DENY (hoặc SAMEORIGIN) để chống clickjacking."),
    "x-content-type-options": ("low", "Thiếu X-Content-Type-Options",
        "Thêm X-Content-Type-Options: nosniff."),
    "referrer-policy": ("info", "Thiếu Referrer-Policy",
        "Thêm Referrer-Policy: no-referrer hoặc strict-origin-when-cross-origin."),
}


def _host(url: str) -> str:
    return (urlparse(url).hostname or url).lower()


def analyze_headers(url: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """Pure: từ headers (dict lower-case) → list finding thiếu header."""
    present = {k.lower() for k in (headers or {})}
    host = _host(url)
    out = []
    for hdr, (sev, name, fix) in _CHECKS.items():
        if hdr not in present:
            out.append({
                "template_id": f"vulnguard-missing-header-{hdr}",
                "name": name, "severity": sev, "type": "http",
                "matched_at": url, "host": host, "matcher_name": hdr,
                "description": f"Response không có header bảo mật '{hdr}'.",
                "remediation": fix, "tags": ["misconfig", "headers"],
            })
    return out


async def check_targets(targets: List[str], on_finding: Callable[[Dict[str, Any]], Awaitable[None]],
                        max_hosts: int = 25, _fetcher=None) -> int:
    """Kiểm 1 URL đại diện cho mỗi host (tránh trùng). Trả số finding phát sinh."""
    seen_hosts, n = set(), 0
    for url in targets:
        h = _host(url)
        if h in seen_hosts:
            continue
        seen_hosts.add(h)
        if len(seen_hosts) > max_hosts:
            break
        try:
            if _fetcher is not None:
                headers = await _fetcher(url)
            else:
                import httpx
                async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as c:  # nosec B501
                    r = await c.get(url)
                    headers = dict(r.headers)
        except Exception:
            continue
        for f in analyze_headers(url, headers):
            await on_finding(f)
            n += 1
    return n
