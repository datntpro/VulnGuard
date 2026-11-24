"""
Liệt kê model mà license/API key của provider hỗ trợ — để UI cho CHỌN thay vì gõ tay.

Gọi API provider bằng key đã lưu; nếu không có key hoặc API lỗi/offline → trả danh
sách static (những model phổ biến đã biết) kèm source="static" để UI vẫn dùng được.
Không bao giờ ném lỗi ra ngoài.
"""
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


def list_models(provider: str, cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Trả {models, source, note, error}. source ∈ {api, static}."""
    try:
        if provider == "anthropic":
            return _anthropic(cfg)
        if provider == "openai":
            return _openai(cfg)
        if provider == "openrouter":
            return _openrouter(cfg)
        if provider == "bedrock":
            return _bedrock(cfg)
    except Exception as e:
        logger.info("list_models(%s) lỗi, dùng static: %s", provider, e)
        return _static(provider, f"Không gọi được API ({str(e)[:120]}) — dùng danh sách mặc định")
    return _static(provider)


def _anthropic(cfg) -> Dict[str, Any]:
    import httpx
    from api.services.ai_config import get_anthropic_api_key
    a = cfg.get("anthropic", {})
    # Chỉ gọi API khi auth bằng api_key; wif/environment → static
    if a.get("auth_mode") != "api_key":
        return _static("anthropic", "Auth không phải API key — dùng danh sách mặc định")
    key = get_anthropic_api_key(cfg)
    if not key:
        return _static("anthropic", "Chưa nhập API key — dùng danh sách mặc định")
    r = httpx.get("https://api.anthropic.com/v1/models",
                  headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
                  params={"limit": 100}, timeout=20)
    r.raise_for_status()
    ids = [m["id"] for m in r.json().get("data", []) if m.get("id")]
    return _ok(ids or STATIC_MODELS["anthropic"], "api" if ids else "static")


def _openai(cfg) -> Dict[str, Any]:
    import httpx
    from api.services.ai_config import get_api_key
    sec = cfg.get("openai", {})
    key = get_api_key("openai", cfg)
    if not key:
        return _static("openai", "Chưa nhập API key — dùng danh sách mặc định")
    base = (sec.get("base_url") or "https://api.openai.com/v1").rstrip("/")
    r = httpx.get(f"{base}/models", headers={"Authorization": f"Bearer {key}"}, timeout=20)
    r.raise_for_status()
    ids = sorted(m["id"] for m in r.json().get("data", []) if m.get("id"))
    # ưu tiên các model chat gpt/o* lên đầu
    chat = [i for i in ids if i.startswith(("gpt-", "o1", "o3", "o4", "chatgpt"))]
    return _ok((chat + ids) or STATIC_MODELS["openai"], "api" if ids else "static")


def _openrouter(cfg) -> Dict[str, Any]:
    import httpx
    from api.services.ai_config import get_api_key, OPENROUTER_BASE_URL
    key = get_api_key("openrouter", cfg)
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    r = httpx.get(f"{OPENROUTER_BASE_URL}/models", headers=headers, timeout=20)
    r.raise_for_status()
    ids = sorted(m["id"] for m in r.json().get("data", []) if m.get("id"))
    return _ok(ids or STATIC_MODELS["openrouter"], "api" if ids else "static")


def _bedrock(cfg) -> Dict[str, Any]:
    """Liệt kê foundation model của Anthropic trên Bedrock qua boto3 (nếu có credential)."""
    b = cfg.get("bedrock", {})
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
        return _static("bedrock", f"Không liệt kê được qua boto3 ({str(e)[:100]}) — dùng danh sách mặc định")
