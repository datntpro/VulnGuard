"""[AI PR-7] Đánh dấu endpoint AI cũ là deprecated — CHỈ thêm header + log, không đổi hành vi.

  Deprecation: true                      (RFC 9745 dạng boolean đơn giản)
  Sunset: <HTTP-date>                    (RFC 8594) — ngày dự kiến gỡ
  Link: <successor>; rel="successor-version"

Log `vulnguard.deprecation` ở WARNING, mỗi (method, route) một lần mỗi process (không spam, không log query/body/user).
Ngày gỡ là cam kết tối thiểu: chỉ gỡ ở bản phát hành SAU ngày này, và sau khi CHANGELOG ghi rõ.
Endpoint /api/ollama/{models,pull,models/{name}} CHƯA deprecated vì trang Settings › AI vẫn dùng (chưa có thay thế).
"""
from __future__ import annotations

import logging
from typing import Dict, Optional, Tuple

SUNSET_DATE = "2027-03-31"
SUNSET_HTTP = "Wed, 31 Mar 2027 00:00:00 GMT"
DOC_URL = "docs/wiki/AI-Per-User-Keys.md#deprecated-endpoints"

log = logging.getLogger("vulnguard.deprecation")
_seen: set = set()

# (method hoặc "*", path tuyệt đối hoặc tiền tố kết thúc "/") → successor
_RULES: Tuple[Tuple[str, str, str], ...] = (
    ("GET", "/api/ai/config", "/api/ai/settings"),
    ("PUT", "/api/ai/config", "/api/ai/settings"),
    ("GET", "/api/ollama/endpoint", "/api/ai/settings"),
    ("PUT", "/api/ollama/endpoint", "/api/ai/settings"),
    ("PUT", "/api/ollama/active-model", "/api/ai/settings"),
    ("GET", "/api/ollama/vision-model", "/api/ai/settings"),
    ("PUT", "/api/ollama/vision-model", "/api/ai/settings"),
    ("GET", "/api/ollama/health", "/api/ai/ollama/check"),
)


def lookup(method: str, path: str) -> Optional[str]:
    path = path.rstrip("/") or "/"
    for m, p, succ in _RULES:
        if m in ("*", method.upper()) and path == p:
            return succ
    return None


def apply(method: str, path: str, headers) -> None:
    succ = lookup(method, path)
    if not succ:
        return
    headers["Deprecation"] = "true"
    headers["Sunset"] = SUNSET_HTTP
    headers["Link"] = f'<{succ}>; rel="successor-version", <{DOC_URL}>; rel="deprecation"'
    key = (method.upper(), path.rstrip("/"))
    if key not in _seen:
        _seen.add(key)
        log.warning("[deprecated] %s %s sẽ bị gỡ sau %s — dùng %s", key[0], key[1], SUNSET_DATE, succ)


async def deprecation_middleware(request, call_next):
    resp = await call_next(request)
    path = request.url.path
    if path.startswith(("/api/ai/config", "/api/ollama/")):
        apply(request.method, path, resp.headers)
    return resp
