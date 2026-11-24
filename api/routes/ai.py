"""
Cloud AI provider API.
  GET  /api/ai/config            — cấu hình hiện tại (không lộ secret)
  PUT  /api/ai/config            — cập nhật (ADMIN; api_key là write-only)
  POST /api/ai/test              — gọi thử provider cloud
  GET  /api/ai/models            — model provider hỗ trợ (cho dropdown)
  POST /api/vulns/{id}/reanalyze — phân tích lại 1 vuln bằng cloud AI
"""
import time
from datetime import datetime
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.database import get_db
from api.models import Vulnerability
from api.routes.auth import require_admin
from api.services.ai_config import load_config, public_config, validate_and_save

router = APIRouter(tags=["ai"])


@router.get("/api/ai/config")
def get_ai_config():
    return public_config()


@router.put("/api/ai/config")
def put_ai_config(payload: Dict[str, Any], _=Depends(require_admin)):
    try:
        return public_config(validate_and_save(payload))
    except (ValueError, TypeError, KeyError) as e:
        raise HTTPException(status_code=422, detail=str(e))


@router.get("/api/ai/models")
def list_ai_models(provider: str, _=Depends(require_admin)):
    """Danh sách model provider hỗ trợ (để UI chọn dropdown thay vì gõ tay).

    provider ∈ anthropic | bedrock | openai | openrouter. Dùng key đã lưu; offline
    hoặc chưa có key → trả danh sách mặc định (source=static)."""
    from api.services.ai_models import STATIC_MODELS, list_models
    if provider not in STATIC_MODELS:
        raise HTTPException(status_code=422, detail="provider không hợp lệ")
    return {"provider": provider, **list_models(provider, load_config())}


@router.post("/api/ai/test")
async def test_ai():
    from scanner.cloud_ai import CloudAnalyzer
    cfg = load_config()
    t0 = time.monotonic()
    try:
        analyzer = CloudAnalyzer(cfg)
        await analyzer.ping()
        return {"ok": True, "provider": cfg["provider"], "model": analyzer.model,
                "latency_ms": int((time.monotonic() - t0) * 1000), "error": None}
    except Exception as e:
        return {"ok": False, "provider": cfg["provider"], "model": None,
                "latency_ms": int((time.monotonic() - t0) * 1000), "error": str(e)[:500]}


@router.post("/api/vulns/{vuln_id}/reanalyze")
async def reanalyze_vuln(vuln_id: str, db: Session = Depends(get_db)):
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
    result = await AIAnalyzer().analyze_cloud(data, local_opinion=local)
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
