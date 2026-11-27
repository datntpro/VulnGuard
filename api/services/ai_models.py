"""
Liệt kê model mà license/API key của provider hỗ trợ — để UI cho CHỌN thay vì gõ tay.

[AI PR-4] Không đọc key trực tiếp từ cấu hình nữa: nhận một `Route` do llm_resolver chọn
(resolve_provider) và dùng client SDK của resolver (open_client(probe=True): trust_env=False, không
redirect, guard SSRF). Offline / chưa có key / lỗi → trả danh sách static kèm source="static".
Không bao giờ ném lỗi ra ngoài; ghi chú lỗi KHÔNG chứa văn bản của provider.
"""
import asyncio
import json
import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# Fallback tĩnh khi không gọi được API provider (offline / chưa nhập key).
STATIC_MODELS: Dict[str, List[str]] = {
    "anthropic": [
        "claude-opus-4-8", "claude-opus-5-5", "claude-sonnet-5-5",
        "claude-haiku-5-5", "claude-3-7-sonnet-latest", "claude-3-5-haiku-latest",
    ],
    "bedrock": [
        "anthropic.claude-opus-5-5", "anthropic.claude-sonnet-5-5",
        "anthropic.claude-haiku-5-5", "anthropic.claude-opus-4-8",
        "us.anthropic.claude-opus-5-5", "us.anthropic.claude-sonnet-5-5",
    ],
    "openai": [
        "gpt-4o", "gpt-4o-mini", "gpt-4.1", "gpt-4.1-mini", "o3", "o4-mini",
    ],
    "openrouter": [
        "anthropic/claude-3.5-sonnet", "anthropic/claude-sonnet-4",
        "openai/gpt-4o", "openai/o4-mini", "google/gemini-2.5-pro",
        "meta-llama/llama-3.1-70b-instruct", "deepseek/deepseek-chat",
    ],
}


def _ok(models: List[str], source: str, note: str = "") -> Dict[str, Any]:
    # bỏ trùng, giữ thứ tự
    seen, out = set(), []
    for m in models:
        if m and m not in seen:
            seen.add(m); out.append(m)
    return {"models": out, "source": source, "note": note, "error": None}


def _static(provider: str, note: str = "") -> Dict[str, Any]:
    return _ok(STATIC_MODELS.get(provider, []), "static", note)


async def list_models(provider: str, route) -> Dict[str, Any]:
    """Trả {models, source, note, error}. source ∈ {api, static}. `route`: Cloud|Refuse từ resolver."""
    from api.services.llm_resolver import Cloud
    try:
        if provider == "openrouter":
            return await _openrouter()          # danh sách công khai — không cần key
        if not isinstance(route, Cloud) or route.provider != provider:
            return _static(provider, "Chưa có credential — dùng danh sách mặc định")
        if provider == "bedrock":
            return await asyncio.to_thread(_bedrock, route)
        return await _via_sdk(provider, route)
    except Exception as e:
        from api.services.ai_probe import classify
        logger.info("list_models(%s) lỗi, dùng static: %s", provider, type(e).__name__)
        return _static(provider, f"Không gọi được API ({classify(e)}) — dùng danh sách mặc định")


async def _via_sdk(provider: str, route) -> Dict[str, Any]:
    from api.services.llm_resolver import open_client
    if provider == "anthropic" and route.credential.public_params().get("auth_mode", "api_key") != "api_key":
        return _static("anthropic", "Auth không phải API key — dùng danh sách mặc định")
    client, _model, _family = open_client(route, probe=True)
    try:
        if provider == "anthropic":
            page = await asyncio.wait_for(client.models.list(limit=100), timeout=20)
            ids = [m.id for m in page.data if getattr(m, "id", None)]
            return _ok(ids or STATIC_MODELS["anthropic"], "api" if ids else "static")
        page = await asyncio.wait_for(client.models.list(), timeout=20)
        ids = sorted(m.id for m in page.data if getattr(m, "id", None))
        chat = [i for i in ids if i.startswith(("gpt-", "o1", "o3", "o4", "chatgpt"))]
        return _ok((chat + ids) or STATIC_MODELS["openai"], "api" if ids else "static")
    finally:
        await client.close()


async def _openrouter() -> Dict[str, Any]:
    from api.services import url_guard
    from api.services.ai_config import OPENROUTER_BASE_URL
    async with url_guard.guarded_async_client("cloud", timeout=20) as c:
        async with c.stream("GET", f"{OPENROUTER_BASE_URL}/models") as r:
            r.raise_for_status()
            data = json.loads(await url_guard.read_capped(r))
    ids = sorted(m["id"] for m in data.get("data", []) if m.get("id"))
    return _ok(ids or STATIC_MODELS["openrouter"], "api" if ids else "static")


def _bedrock(route) -> Dict[str, Any]:
    """Liệt kê foundation model của Anthropic trên Bedrock qua boto3 (profile/region từ credential của resolver)."""
    b = route.credential.public_params()
    try:
        import boto3
        sess = boto3.Session(profile_name=(b.get("aws_profile") or None)
                             if b.get("auth_mode") == "profile" else None,
                             region_name=b.get("region") or "us-east-1")
        cli = sess.client("bedrock")
        resp = cli.list_foundation_models(byProvider="Anthropic")
        ids = [m["modelId"] for m in resp.get("modelSummaries", []) if m.get("modelId")]
        return _ok(ids or STATIC_MODELS["bedrock"], "api" if ids else "static")
    except Exception as e:
        return _static("bedrock", f"Không liệt kê được qua boto3 ({type(e).__name__}) — dùng danh sách mặc định")
