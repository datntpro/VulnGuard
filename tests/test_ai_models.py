"""Danh sách model cho dropdown — fallback static khi không có key / offline."""
import asyncio

from api.services.ai_models import STATIC_MODELS, list_models as _list_models
from api.services.llm_resolver import cloud_route_for



def _arun(coro):
    """Không dùng asyncio.run: nó bỏ event loop hiện tại của thread và làm hỏng các test dùng get_event_loop()."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()

def list_models(provider, cfg):
    """[PR-4] list_models nhận Route của resolver (không đọc key trực tiếp)."""
    cfg = dict(cfg); cfg["provider"] = provider
    return _arun(_list_models(provider, cloud_route_for(cfg)))


def _cfg():
    # config tối thiểu, không có api_key_enc → buộc fallback static
    return {
        "anthropic": {"auth_mode": "api_key", "api_key_enc": None},
        "openai": {"api_key_enc": None, "base_url": ""},
        "openrouter": {"api_key_enc": None},
        "bedrock": {"auth_mode": "aws_chain", "region": "us-east-1"},
    }


def test_static_fallback_no_key():
    # anthropic & openai KHÓA theo key: không key → static, KHÔNG gọi mạng (tất định).
    # (openrouter /models là public nên có thể trả 'api' khi CI có mạng → không test ở đây)
    for prov in ("anthropic", "openai"):
        r = list_models(prov, _cfg())
        assert r["source"] == "static", f"{prov} phải fallback static khi không có key"
        assert set(r["models"]) == set(STATIC_MODELS[prov])
        assert r["error"] is None
        assert r["models"], "phải có ít nhất 1 model mặc định"


def test_openrouter_always_returns_models():
    # OpenRouter liệt kê model công khai (không cần key). Dù online (source=api) hay
    # offline (source=static) đều phải trả danh sách dùng được, không raise.
    r = list_models("openrouter", _cfg())
    assert r["source"] in ("api", "static")
    assert r["models"], "phải luôn có model để chọn"
    assert r["error"] is None


def test_anthropic_wif_uses_static():
    cfg = _cfg(); cfg["anthropic"]["auth_mode"] = "wif"
    r = list_models("anthropic", cfg)
    assert r["source"] == "static"


def test_dedup_preserves_order():
    from api.services.ai_models import _ok
    r = _ok(["a", "b", "a", "c", "b"], "api")
    assert r["models"] == ["a", "b", "c"]


def test_bedrock_without_boto3_is_safe():
    # Không có credential boto3 trong CI → phải trả static, không raise
    r = list_models("bedrock", _cfg())
    assert r["source"] == "static" and r["models"]
