"""Danh sách model cho dropdown — fallback static khi không có key / offline."""
from api.services.ai_models import STATIC_MODELS, list_models


def _cfg():
    # config tối thiểu, không có api_key_enc → buộc fallback static
    return {
        "anthropic": {"auth_mode": "api_key", "api_key_enc": None},
        "openai": {"api_key_enc": None, "base_url": ""},
        "openrouter": {"api_key_enc": None},
        "bedrock": {"auth_mode": "aws_chain", "region": "us-east-1"},
    }


def test_static_fallback_no_key():
    for prov in ("anthropic", "openai", "openrouter"):
        r = list_models(prov, _cfg())
        assert r["source"] == "static"
        assert r["models"] == STATIC_MODELS[prov] or set(r["models"]) == set(STATIC_MODELS[prov])
        assert r["error"] is None
        assert r["models"], "phải có ít nhất 1 model mặc định"


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
