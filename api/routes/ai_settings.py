"""[AI PR-3] GET/PUT /api/ai/settings — trang Settings › AI hợp nhất (§6).

GET: mọi role đăng nhập. `policy` + `advanced` chỉ ADMIN; role khác chỉ thấy `policy_public`.
PUT: ADMIN. Cùng body với PUT /api/ai/config + `ollama{url,model,vision_model}` + `policy` + `hybrid.tasks.coworker`.
KHÔNG gọi mạng ở đây (reachability/tool-calling thuộc POST /api/ai/ollama/check của PR-4).
"""
from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException

from api.auth_models import User, UserRole
from api.routes.auth import current_user, require_admin
from api.services import ai_policy, runtime_settings
from api.services.ai_config import PROVIDERS, load_config, public_config, validate_and_save

router = APIRouter(tags=["ai-settings"])


def _guard_urls(payload: Dict[str, Any]) -> None:
    """SSRF-guard (PR-4 url_guard) cho base_url + region; policy custom_base_url=off cấm đặt base_url."""
    from api.services import url_guard
    from api.services.llm_resolver import valid_region
    pol = ai_policy.normalize({**(load_config().get("policy") or {}), **(payload.get("policy") or {})}) \
        if isinstance(payload.get("policy"), dict) else ai_policy.get_policy()
    oa = payload.get("openai")
    if isinstance(oa, dict) and (oa.get("base_url") or "").strip():
        if pol["custom_base_url"] == "off" and (oa["base_url"] or "").strip() != str(
                (load_config().get("openai") or {}).get("base_url") or "").strip():
            raise HTTPException(status_code=422, detail="BAD_BASE_URL: custom base_url bị policy tắt")
        try:
            oa["base_url"] = url_guard.check_url(oa["base_url"], "cloud")
        except url_guard.UrlRejected as e:
            raise HTTPException(status_code=422, detail=f"BAD_BASE_URL: {e.reason}")
    br = payload.get("bedrock")
    if isinstance(br, dict) and br.get("region") and not valid_region(br["region"]):
        raise HTTPException(status_code=422, detail="BAD_BASE_URL: region AWS không hợp lệ")


def _mine(user: User) -> Dict[str, Any]:
    from api.services.llm_resolver import describe_effective
    if user.role == UserRole.VIEWER:
        return {"source": "none", "provider": None, "hint": ""}
    return describe_effective(getattr(user, "id", None))


@router.get("/api/ai/settings")
def get_settings(user: User = Depends(current_user)):
    cfg = load_config()
    pub = public_config(cfg)
    pol = ai_policy.get_policy(cfg)
    prov = cfg.get("provider")
    sec = pub.get(prov) or {}
    out: Dict[str, Any] = dict(pub)
    from api.services.llm_resolver import LLMContext, ollama_default_url, resolve_local
    loc = resolve_local(LLMContext(feature="test"))      # URL/model hiệu lực chỉ lấy qua resolver
    out["ollama"] = {"url": loc.url, "custom": runtime_settings.ollama_url_is_custom(),
                     "default_url": ollama_default_url(), "model": loc.model, "vision_model": loc.vision_model}
    out["providers_available"] = list(PROVIDERS)
    out["policy_public"] = ai_policy.public_policy(pol)
    out["status"] = {"cloud": {"provider": prov, "last_test_at": None, "last_test_ok": None,
                               "configured": bool(sec.get("api_key_set") or sec.get("auth_mode") in
                                                  ("wif", "environment", "aws_chain", "profile"))},
                     "mine": _mine(user)}
    if user.role == UserRole.ADMIN:
        from scanner.pentest.settings import pentest_settings as ps
        out["policy"] = pol
        out["advanced"] = {"pentest_models": {"planner": ps.llm_planner_model, "executor": ps.llm_executor_model,
                                              "summarizer": ps.llm_summarizer_model}}
    return out


@router.put("/api/ai/settings")
def put_settings(payload: Dict[str, Any], admin: User = Depends(require_admin)):
    payload = dict(payload or {})
    ollama = payload.pop("ollama", None)
    payload.pop("advanced", None)               # per-role model vẫn do env (D9-b); chưa lưu từ UI ở PR này
    payload.pop("policy_public", None)
    payload.pop("status", None)
    payload.pop("providers_available", None)
    try:
        _guard_urls(payload)
        if isinstance(ollama, dict):
            url = ollama.get("url")
            if isinstance(url, str) and url.strip():
                from api.services import url_guard
                try:
                    url = url_guard.check_url(url.strip(), "ollama", explicit_ollama=True)
                except url_guard.UrlRejected as e:
                    raise HTTPException(status_code=422, detail=f"BAD_BASE_URL: {e.reason}")
            validate_and_save(payload)       # lưu cấu hình cloud/policy trước; ollama chỉ ghi khi phần trên hợp lệ
            runtime_settings.set_ollama(url=url if isinstance(url, str) else None,
                                        model=ollama.get("model") if isinstance(ollama.get("model"), str) else None,
                                        vision_model=ollama.get("vision_model") if isinstance(ollama.get("vision_model"), str) else None)
        else:
            validate_and_save(payload)
    except (ValueError, TypeError, KeyError) as e:
        raise HTTPException(status_code=422, detail=str(e))
    return get_settings(admin)
