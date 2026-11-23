"""Test cấu hình đa provider AI + override endpoint Ollama (bền vững)."""
import importlib
import os

import pytest


@pytest.fixture
def ai_cfg(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_CONFIG_FILE", str(tmp_path / "ai.json"))
    from api.services import ai_config
    importlib.reload(ai_config)
    return ai_config


@pytest.fixture
def rt(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNTIME_SETTINGS_FILE", str(tmp_path / "rt.json"))
    from api.services import runtime_settings
    importlib.reload(runtime_settings)
    return runtime_settings


def test_openai_provider_roundtrip(ai_cfg):
    c = ai_cfg.validate_and_save({"provider": "openai", "mode": "cloud_only",
                                  "openai": {"api_key": "sk-abc123", "model": "gpt-4o"}})
    assert c["provider"] == "openai"
    pub = ai_cfg.public_config(c)
    assert pub["openai"]["api_key_set"] is True
    assert "api_key_enc" not in pub["openai"]           # không lộ secret
    assert ai_cfg.get_api_key("openai") == "sk-abc123"  # giải mã đúng


def test_openrouter_defaults(ai_cfg):
    c = ai_cfg.validate_and_save({"provider": "openrouter", "openrouter": {"api_key": "sk-or-x"}})
    assert c["openrouter"]["model"] == ai_cfg.DEFAULT_OPENROUTER_MODEL
    assert ai_cfg.get_api_key("openrouter") == "sk-or-x"


def test_bedrock_auth_modes(ai_cfg):
    c = ai_cfg.validate_and_save({"provider": "bedrock",
                                  "bedrock": {"auth_mode": "bedrock_api_key", "api_key": "tok-1"}})
    assert c["bedrock"]["auth_mode"] == "bedrock_api_key"
    assert ai_cfg.get_api_key("bedrock") == "tok-1"
    with pytest.raises(ValueError):
        ai_cfg.validate_and_save({"bedrock": {"auth_mode": "nope"}})


def test_invalid_provider_rejected(ai_cfg):
    with pytest.raises(ValueError):
        ai_cfg.validate_and_save({"provider": "gemini"})


def test_clear_key_per_section(ai_cfg):
    ai_cfg.validate_and_save({"openai": {"api_key": "sk-z"}})
    assert ai_cfg.get_api_key("openai") == "sk-z"
    ai_cfg.validate_and_save({"openai": {"clear_api_key": True}})
    assert ai_cfg.get_api_key("openai") is None


def test_ollama_endpoint_override(rt):
    # mặc định khi chưa set
    assert rt.ollama_url_is_custom() is False
    rt.set_ollama(url="http://192.168.1.50:11434/")
    assert rt.ollama_url() == "http://192.168.1.50:11434"   # bỏ dấu / cuối
    assert rt.ollama_url_is_custom() is True
    # model bền vững
    rt.set_ollama(model="qwen2.5-coder:7b")
    assert rt.ollama_model() == "qwen2.5-coder:7b"
    # xóa override → về default (không còn custom)
    rt.set_ollama(url="")
    assert rt.ollama_url_is_custom() is False
