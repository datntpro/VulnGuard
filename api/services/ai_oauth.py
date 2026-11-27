"""[AI PR-6] Cấp access token ngắn hạn cho Azure OpenAI (Entra ID) và Vertex AI (service account) — không thêm SDK.

  entra_token_provider(tenant, client_id, client_secret)  → async callable () -> str   (cho client Azure của SDK)
  google_token_provider(service_account_json)             → async callable () -> str   (cho tham số api_key của SDK)

Bất biến:
  * Host của endpoint token là HẰNG SỐ (login.microsoftonline.com / oauth2.googleapis.com); `token_uri` trong SA JSON
    bị bỏ qua. trust_env=False, không redirect, giới hạn kích thước phản hồi, timeout 10s.
  * Secret nằm trong closure (không có thuộc tính/ repr); token cache trong RAM đến hết hạn − 60s.
  * Lỗi = `OAuthError` với thông điệp cố định + `status_code` chuẩn hoá (401 = secret bị từ chối) — KHÔNG kèm body
    của provider, nên probe phân loại thành INVALID_KEY/PROVIDER_ERROR và log/UI không lộ gì.
"""
from __future__ import annotations

import asyncio
import base64
import json
import time
from typing import Awaitable, Callable, Dict, Optional
from urllib.parse import urlencode

from api.services import url_guard

ENTRA_HOST = "login.microsoftonline.com"
ENTRA_SCOPE = "https://cognitiveservices.azure.com/.default"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"   # nosec B105 — URL công khai, không phải secret
GOOGLE_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
_SKEW = 60.0


class OAuthError(RuntimeError):
    """Không lấy được token. `status_code` đã chuẩn hoá (401 / 502 / 504) để classify() ra mã đúng."""
    def __init__(self, status_code: int):
        super().__init__("không lấy được access token từ nhà cung cấp danh tính")
        self.status_code = status_code


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


async def _post_form(url: str, form: Dict[str, str]) -> dict:
    import httpx
    c = url_guard.plain_async_client("httpx", timeout=10.0)
    try:
        async with c.stream("POST", url, content=urlencode(form).encode(),
                            headers={"content-type": "application/x-www-form-urlencoded"}) as r:
            if r.status_code != 200:
                raise OAuthError(401 if r.status_code in (400, 401, 403) else 502)
            data = json.loads(await url_guard.read_capped(r, 64 * 1024))
    except OAuthError:
        raise
    except httpx.TimeoutException:
        raise OAuthError(504) from None
    except Exception:      # noqa: BLE001 — mạng/JSON/guard: thông điệp cố định
        raise OAuthError(502) from None
    finally:
        await c.aclose()
    tok = data.get("access_token") if isinstance(data, dict) else None
    if not isinstance(tok, str) or not tok:
        raise OAuthError(502)
    try:
        ttl = float(data.get("expires_in") or 3600)
    except (TypeError, ValueError):
        ttl = 3600.0
    return {"token": tok, "ttl": max(60.0, min(ttl, 3600.0))}


class _Cached:
    def __init__(self, fetch: Callable[[], Awaitable[dict]]):
        self._fetch = fetch
        self._tok: Optional[str] = None
        self._exp = 0.0
        self._lock: Optional[asyncio.Lock] = None

    async def __call__(self) -> str:
        if self._tok and time.monotonic() < self._exp - _SKEW:
            return self._tok
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            if self._tok and time.monotonic() < self._exp - _SKEW:
                return self._tok
            got = await self._fetch()
            self._tok, self._exp = got["token"], time.monotonic() + got["ttl"]
            return self._tok

    def __repr__(self) -> str:
        return "<token-provider>"


def entra_token_provider(tenant_id: str, client_id: str, client_secret: str) -> Callable[[], Awaitable[str]]:
    from api.services.ai_provider_params import check_guid
    tenant, cid = check_guid(tenant_id, "tenant_id"), check_guid(client_id, "client_id")
    url = f"https://{ENTRA_HOST}/{tenant}/oauth2/v2.0/token"

    async def fetch() -> dict:
        return await _post_form(url, {"grant_type": "client_credentials", "client_id": cid,
                                      "client_secret": client_secret, "scope": ENTRA_SCOPE})
    return _Cached(fetch)


def _sign_jwt(sa: Dict[str, str], now: Optional[float] = None) -> str:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    iat = int(now if now is not None else time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    if sa.get("private_key_id"):
        header["kid"] = sa["private_key_id"]
    claims = {"iss": sa["client_email"], "scope": GOOGLE_SCOPE, "aud": GOOGLE_TOKEN_URL, "iat": iat, "exp": iat + 3600}
    signing = f"{_b64(json.dumps(header, separators=(',', ':')).encode())}.{_b64(json.dumps(claims, separators=(',', ':')).encode())}"
    try:
        key = serialization.load_pem_private_key(sa["private_key"].encode(), password=None)
        sig = key.sign(signing.encode(), padding.PKCS1v15(), hashes.SHA256())
    except Exception:      # noqa: BLE001 — khoá hỏng: không lộ chi tiết
        raise OAuthError(401) from None
    return f"{signing}.{_b64(sig)}"


def google_token_provider(service_account_json: str) -> Callable[[], Awaitable[str]]:
    from api.services.ai_provider_params import parse_service_account
    sa = parse_service_account(service_account_json)

    async def fetch() -> dict:
        assertion = await asyncio.to_thread(_sign_jwt, sa)
        return await _post_form(GOOGLE_TOKEN_URL, {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                                  "assertion": assertion})
    return _Cached(fetch)
