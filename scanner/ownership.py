"""
Xác minh quyền sở hữu domain (P0.4) — bằng chứng, không chỉ một ô tick.

Hai cách:
  1. DNS TXT:   bản ghi TXT `vulnguard-verify=<token>` trên domain.
  2. .well-known: file https://<domain>/.well-known/vulnguard.txt chứa đúng <token>.

Dùng để chặn web scan / crawl / pentest khi domain CHƯA được xác minh sở hữu.
"""
import secrets
from typing import Tuple
from urllib.parse import urlparse


def gen_token() -> str:
    return "vulnguard-" + secrets.token_hex(16)


def host_of(url: str) -> str:
    u = (url or "").strip()
    if "://" not in u:
        u = "https://" + u
    return (urlparse(u).hostname or "").lower()


def verify_dns_txt(domain_host: str, token: str, _resolver=None) -> bool:
    """Tìm token trong các bản ghi TXT của domain."""
    records = []
    try:
        if _resolver is not None:
            records = _resolver(domain_host)
        else:
            import dns.resolver  # dnspython nếu có
            answers = dns.resolver.resolve(domain_host, "TXT")
            records = [b"".join(r.strings).decode("utf-8", "replace") if hasattr(r, "strings")
                       else str(r).strip('"') for r in answers]
    except Exception:
        return False
    needle = f"vulnguard-verify={token}"
    return any(needle in (rec or "") or token in (rec or "") for rec in records)


async def verify_well_known(domain_url: str, token: str, _fetcher=None) -> bool:
    """Tải https://<domain>/.well-known/vulnguard.txt và so khớp token."""
    host = host_of(domain_url)
    url = f"https://{host}/.well-known/vulnguard.txt"
    try:
        if _fetcher is not None:
            body = await _fetcher(url)
        else:
            import httpx
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as c:
                r = await c.get(url)
                r.raise_for_status()
                body = r.text
        return token.strip() in (body or "")
    except Exception:
        return False
