"""
Cloud AI provider API.
  GET  /api/ai/config            — cấu hình hiện tại (không lộ secret)
  PUT  /api/ai/config            — cập nhật (ADMIN; api_key là write-only)
  POST /api/ai/test              — probe provider cloud (nhận giá trị chưa lưu)
  POST /api/ai/ollama/check      — capability check Ollama (tools / JSON)
  GET  /api/ai/models            — model provider hỗ trợ (cho dropdown)
  POST /api/vulns/{id}/reanalyze — phân tích lại 1 vuln bằng cloud AI
"""
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from api.database import get_db
from api.models import Vulnerability
from api.routes.auth import current_user, require_admin
from api.services.ai_config import load_config, public_config, validate_and_save

router = APIRouter(tags=["ai"])


@router.get("/api/ai/config")
def get_ai_config():
    return public_config()


@router.put("/api/ai/config")
def put_ai_config(payload: Dict[str, Any], _=Depends(require_admin)):
    from api.services import url_guard
    try:
        # [PR-4] base_url do ADMIN đặt: kiểm SSRF khi LƯU (và lưu bản đã chuẩn hoá); kiểm lại ở mỗi lần gọi
        oa = payload.get("openai") if isinstance(payload, dict) else None
        if isinstance(oa, dict) and (oa.get("base_url") or "").strip():
            oa["base_url"] = url_guard.check_url(oa["base_url"], "cloud")
        br = payload.get("bedrock") if isinstance(payload, dict) else None
        if isinstance(br, dict) and br.get("region"):
            from api.services.llm_resolver import valid_region
            if not valid_region(br["region"]):
                raise url_guard.UrlRejected("region AWS không hợp lệ")
        return public_config(validate_and_save(payload))
    except url_guard.UrlRejected as e:
        raise HTTPException(status_code=422, detail=f"BAD_BASE_URL: {e.reason}")
    except (ValueError, TypeError, KeyError) as e:
        raise HTTPException(status_code=422, detail=str(e))


@router.get("/api/ai/models")
async def list_ai_models(provider: str, credential_id: Optional[str] = None, user=Depends(current_user),
                         db: Session = Depends(get_db)):
    """Danh sách model provider hỗ trợ (để UI chọn dropdown thay vì gõ tay).

    provider ∈ anthropic | bedrock | openai | openrouter. Không có `credential_id` → credential ORG (chỉ ADMIN).
    Có `credential_id` → CHỦ credential đó (ANALYST/ADMIN, key của chính mình; người khác/admin → 404).
    Offline hoặc chưa có key → danh sách mặc định (source=static)."""
    from api.auth_models import UserRole
    from api.services.ai_models import STATIC_MODELS, list_models
    from api.services.llm_resolver import Cloud, resolve_provider, route_for_own_credential
    if provider not in STATIC_MODELS:
        raise HTTPException(status_code=422, detail="provider không hợp lệ")
    if credential_id:
        if user.role == UserRole.VIEWER or not getattr(user, "id", None):
            raise HTTPException(status_code=403, detail="Không có khoá AI cá nhân")
        from api.ai_cred_models import AiCredential
        row = db.get(AiCredential, credential_id)
        if row is None or row.scope != "user" or row.owner_user_id != user.id or row.provider != provider:
            raise HTTPException(status_code=404, detail={"code": "AI_CRED_NOT_FOUND"})
        route = route_for_own_credential(db, credential_id, user.id, feature="models_list")
        if not isinstance(route, Cloud):
            raise HTTPException(status_code=409, detail={"code": getattr(route, "code", "AI_CRED_REVOKED")})
        return {"provider": provider, **await list_models(provider, route)}
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Chỉ ADMIN")
    return {"provider": provider, **await list_models(provider, resolve_provider(provider))}


# Trường được phép ghi đè khi test giá trị CHƯA LƯU (không có secret nào ngoài api_key — chỉ nằm trong RAM)
_TEST_FIELDS = ("model", "base_url", "auth_mode", "region", "aws_profile")


def _user_id(request: Request):
    return getattr(getattr(request.state, "user", None), "id", None)


def _throttled(request: Request):
    from api.services.ai_probe import ThrottleError, throttle
    try:
        throttle(_user_id(request))
    except ThrottleError as e:
        raise HTTPException(status_code=429, detail=str(e))


@router.post("/api/ai/test")
async def test_ai(request: Request, payload: Optional[Dict[str, Any]] = Body(None)):
    """Probe nhỏ nhất (0-1 token) → {ok, code, provider, model, latency_ms, tools, json, error}.
    Body tuỳ chọn = giá trị CHƯA LƯU của form (provider, model, api_key, base_url, auth_mode, region,
    aws_profile); trường vắng lấy từ cấu hình đã lưu. Không bao giờ trả văn bản của provider."""
    import copy
    from api.security import encrypt_secret
    from api.services.ai_config import PROVIDERS
    from api.services.ai_probe import probe_cloud
    from api.services.llm_resolver import cloud_route_for
    _throttled(request)
    cfg = copy.deepcopy(load_config())
    body = payload if isinstance(payload, dict) else {}
    provider = body.get("provider") or cfg.get("provider")
    if provider not in PROVIDERS:
        raise HTTPException(status_code=422, detail="provider không hợp lệ")
    cfg["provider"] = provider
    sec = cfg[provider]
    # Khoá đã LƯU là write-only: chỉ dùng lại khi request KHÔNG đổi nơi gửi khoá (provider/base_url/region/auth_mode/profile).
    # Nếu đổi bất kỳ trường nào trong số đó thì phải gửi kèm api_key trong chính request này.
    saved = load_config()
    moved = provider != saved.get("provider")
    for k in _TEST_FIELDS:
        v = body.get(k)
        if isinstance(v, str):
            if k != "model" and v.strip() != str(saved.get(provider, {}).get(k) or "").strip():
                moved = True
            sec[k] = v
    for k in body:                       # trường lạ (deployment/project/endpoint/…) cũng được coi là đổi nơi gửi
        if k not in _TEST_FIELDS and k not in ("provider", "api_key"):
            moved = True
    key = body.get("api_key")
    if isinstance(key, str) and key.strip():
        sec["api_key_enc"] = encrypt_secret(key.strip())
    elif moved:
        sec["api_key_enc"] = None
    res = await probe_cloud(cloud_route_for(cfg))
    if res.ok and res.tools is not None and res.model:     # [AI PR-3] Co-work cloud chỉ dùng model đã qua probe tool-calling
        try:
            from api.services.ai_policy import record_cloud_probe
            record_cloud_probe(provider, res.model, bool(res.tools))
        except Exception:      # nosec B110 — ghi nhận best-effort, không làm hỏng test
            pass
    return {"provider": provider, **res.to_dict()}


@router.post("/api/ai/ollama/check")
async def ollama_capability_check(request: Request, payload: Optional[Dict[str, Any]] = Body(None),
                                  _=Depends(require_admin)):
    """Kiểm tra Ollama: /api/version, /api/tags, tool-calling, JSON mode. Cache 1 giờ theo (url, model)."""
    from api.services.ai_probe import ollama_check
    _throttled(request)
    body = payload if isinstance(payload, dict) else {}
    url = body.get("url") if isinstance(body.get("url"), str) else ""
    model = body.get("model") if isinstance(body.get("model"), str) else ""
    return await ollama_check(url, model, force=bool(body.get("force")))


@router.post("/api/vulns/{vuln_id}/reanalyze")
async def reanalyze_vuln(vuln_id: str, request: Request, db: Session = Depends(get_db)):
    from scanner.ai_analyzer import AIAnalyzer

    v = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="Vulnerability không tồn tại")
    data = {
        "tool": v.tool,
        "scan_type": v.scan_type.value if hasattr(v.scan_type, "value") else str(v.scan_type),
        "rule_id": v.rule_id or "", "title": v.title,
        "severity": v.severity.value if hasattr(v.severity, "value") else str(v.severity),
        "file_path": v.file_path or "", "line_start": v.line_start or 0,
        "description": (v.description or "")[:2000], "code_snippet": (v.code_snippet or "")[:1500],
        "cwe": v.cwe or "", "cve": v.cve or "",
        "package_name": v.package_name or "", "package_version": v.package_version or "",
        "fixed_version": v.fixed_version or "",
        "scan_path": v.scan.scan_path if v.scan else "",
    }
    local = {"false_positive_likelihood": v.ai_false_positive_likelihood,
             "false_positive_reason": v.ai_false_positive_reason}
    uid = getattr(getattr(request.state, "user", None), "id", None)
    result = await AIAnalyzer(user_id=uid, job_kind="reanalyze", job_id=vuln_id).analyze_cloud(data, local_opinion=local)
    if result.get("error"):
        raise HTTPException(status_code=502, detail=result["error"])

    v.ai_false_positive_likelihood = result["false_positive_likelihood"]
    v.ai_false_positive_reason = result["false_positive_reason"]
    v.ai_exploitability_public = result["exploitability_public"]
    v.ai_exploitability_private = result["exploitability_private"]
    v.ai_explanation = result["explanation"]
    v.ai_fix_suggestion = result["fix_suggestion"]
    v.ai_provider = result["provider"]
    v.ai_analyzed_at = datetime.utcnow()
    db.commit()
    return {
        "id": v.id,
        "ai_false_positive_likelihood": v.ai_false_positive_likelihood,
        "ai_false_positive_reason": v.ai_false_positive_reason,
        "ai_exploitability_public": v.ai_exploitability_public,
        "ai_exploitability_private": v.ai_exploitability_private,
        "ai_explanation": v.ai_explanation,
        "ai_fix_suggestion": v.ai_fix_suggestion,
        "ai_provider": v.ai_provider,
        "ai_analyzed_at": v.ai_analyzed_at,
        "verdict": result.get("verdict"),
    }
