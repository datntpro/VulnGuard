"""[AI PR-3] Credential AI theo từng user + quản trị + usage.

  GET/POST   /api/me/ai-credentials                  — danh sách / tạo (validate rồi mới lưu)    ANALYST, ADMIN (chính họ)
  PATCH      /api/me/ai-credentials/{id}             — label, model, region, is_default           chủ
  PUT        /api/me/ai-credentials/{id}/secret      — xoay key (validate trước)                  chủ
  DELETE     /api/me/ai-credentials/{id}             — xoá (tombstone 30 ngày)                    chủ
  POST       /api/me/ai-credentials/test, /{id}/test — kiểm tra (key chưa lưu / đã lưu)           chủ
  GET        /api/ai/credentials                     — metadata mọi credential của user           ADMIN
  POST       /api/ai/credentials/{id}/revoke         — thu hồi                                    ADMIN
  GET        /api/ai/usage?scope=me|all&days=30      — bảng usage (me: non-viewer; all: ADMIN)

Bất biến: KHÔNG endpoint nào trả secret / ciphertext. Credential của người khác = 404 (không lộ tồn tại), kể cả với
ADMIN ở nhóm /api/me. Admin chỉ có liệt kê metadata + thu hồi; không đọc / test / dùng key của user khác.
Mọi lỗi trả mã chuẩn hoá — không bao giờ văn bản của provider. Probe/SSRF-guard là của PR-4 (api.services.ai_probe).
"""
from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from api.ai_cred_models import AiCredential, AiUsageEvent
from api.auth_models import User, UserRole
from api.database import get_db
from api.routes.auth import current_user, require_admin
from api.services import ai_credentials as creds
from api.services import ai_policy, ai_usage
from api.services.ai_config import (DEFAULT_BEDROCK_MODEL, DEFAULT_CLAUDE_MODEL, DEFAULT_GEMINI_MODEL, DEFAULT_OPENAI_MODEL,
                                    DEFAULT_OPENROUTER_MODEL)

router = APIRouter(tags=["ai-credentials"])
audit = logging.getLogger("vulnguard.audit.ai")

# [PR-6] thêm azure_openai (key theo deployment; user chỉ đưa TÊN resource) và gemini. Vertex / openai_compatible chỉ ADMIN.
USER_PROVIDERS = ("anthropic", "bedrock", "openai", "openrouter", "azure_openai", "gemini")
_AUTH_MODE = {"anthropic": "api_key", "bedrock": "bedrock_api_key", "openai": "api_key", "openrouter": "api_key",
              "azure_openai": "api_key", "gemini": "api_key"}
_DEFAULT_MODEL = {"anthropic": DEFAULT_CLAUDE_MODEL, "bedrock": DEFAULT_BEDROCK_MODEL,
                  "openai": DEFAULT_OPENAI_MODEL, "openrouter": DEFAULT_OPENROUTER_MODEL,
                  "gemini": DEFAULT_GEMINI_MODEL, "azure_openai": ""}
MAX_PER_USER = 20
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/\-]{0,119}$")
_REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d{1,2}$")
_LABEL_RE = re.compile(r"^[^\x00-\x1f]{1,80}$")


# ── dependencies ─────────────────────────────────────────
def byok_user(user: User = Depends(current_user)) -> User:
    """D10: VIEWER không có khoá cá nhân. Cần user thật (AUTH tắt → không có id → không dùng được)."""
    if user.role == UserRole.VIEWER:
        raise HTTPException(status_code=403, detail="Tài khoản VIEWER không có khoá AI cá nhân")
    if not getattr(user, "id", None):
        raise HTTPException(status_code=400, detail="Cần đăng nhập bằng tài khoản thật (AUTH đang tắt)")
    return user


def _err(status: int, code: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code})


# ── seams cho PR-4 (probe + throttle) — test thay thế được ──
def _throttle(user_id: Optional[str]) -> None:
    from api.services.ai_probe import ThrottleError, throttle
    try:
        throttle(user_id)
    except ThrottleError:
        raise _err(429, "RATE_LIMITED") from None


async def _probe(route) -> Dict[str, Any]:
    """Probe nhỏ nhất (PR-4). Chỉ trả các trường đã chuẩn hoá — không văn bản provider."""
    from api.services.ai_probe import probe_cloud
    d = (await probe_cloud(route)).to_dict()
    return {k: d.get(k) for k in ("ok", "code", "model", "latency_ms", "tools", "json", "real_model")}


# ── schemas ──────────────────────────────────────────────
class CredCreate(BaseModel):
    provider: str
    secret: str = Field(min_length=1, max_length=4096)
    model: Optional[str] = None
    label: Optional[str] = None
    region: Optional[str] = None
    resource: Optional[str] = Field(default=None, max_length=64)       # azure_openai: tên resource (host do server dựng)
    deployment: Optional[str] = Field(default=None, max_length=64)     # azure_openai
    api_version: Optional[str] = Field(default=None, max_length=32)    # azure_openai
    is_default: bool = False


class CredPatch(BaseModel):
    label: Optional[str] = None
    model: Optional[str] = None
    region: Optional[str] = None
    deployment: Optional[str] = Field(default=None, max_length=64)
    api_version: Optional[str] = Field(default=None, max_length=32)
    is_default: Optional[bool] = None


class SecretIn(BaseModel):
    secret: str = Field(min_length=1, max_length=4096)


class CredTest(BaseModel):
    provider: str
    secret: str = Field(min_length=1, max_length=4096)
    model: Optional[str] = None
    region: Optional[str] = None
    resource: Optional[str] = Field(default=None, max_length=64)
    deployment: Optional[str] = Field(default=None, max_length=64)
    api_version: Optional[str] = Field(default=None, max_length=32)


# ── validation ───────────────────────────────────────────
def _clean_secret(provider: str, secret: str) -> str:
    s = (secret or "").strip()
    if not s or len(s) < 8 or re.search(r"\s", s) or re.search(r"[\x00-\x1f]", s):
        raise _err(422, "AI_KEY_INVALID_FORMAT")
    if s.startswith("sk-ant-oat"):          # token OAuth của gói Claude.ai: không dùng ngoài sản phẩm của Anthropic
        raise _err(422, "AI_KEY_UNSUPPORTED")
    if provider == "gemini" and s.startswith("{"):   # service-account JSON thuộc Vertex (chỉ ADMIN), không phải key Gemini API
        raise _err(422, "AI_KEY_INVALID_FORMAT")
    return s


def _clean_azure(deployment: Optional[str], resource: Optional[str], api_version: Optional[str],
                 existing: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """User đưa TÊN resource (không phải URL) → endpoint dựng ở server, host cố định *.openai.azure.com (D4)."""
    from api.services import ai_provider_params as pp
    from api.services.url_guard import UrlRejected
    ex = existing or {}
    try:
        endpoint = pp.azure_endpoint_from_resource(resource.strip().lower()) if resource else ex.get("endpoint")
        dep = pp.check_deployment((deployment or ex.get("deployment") or "").strip())
        ver = pp.check_api_version(api_version or ex.get("api_version"))
        endpoint = pp.check_azure_endpoint(endpoint)
    except UrlRejected:
        raise _err(422, "AI_BAD_AZURE_PARAMS") from None
    return {"endpoint": endpoint, "deployment": dep, "api_version": ver, "model": dep}


def _clean_params(provider: str, model: Optional[str], region: Optional[str], *, resource: Optional[str] = None,
                  deployment: Optional[str] = None, api_version: Optional[str] = None,
                  existing: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if provider not in USER_PROVIDERS:
        raise _err(422, "AI_BAD_PROVIDER")
    if provider == "azure_openai":
        return _clean_azure(deployment or model, resource, api_version, existing)
    model = (model or "").strip() or _DEFAULT_MODEL[provider]
    if not _MODEL_RE.match(model):
        raise _err(422, "AI_BAD_MODEL")
    params: Dict[str, Any] = {"model": model}
    if provider == "bedrock":
        region = (region or "").strip() or "us-east-1"
        if not _REGION_RE.match(region):
            raise _err(422, "AI_BAD_REGION")
        params["region"] = region
    # D4: user KHÔNG đặt được base_url / aws_profile / endpoint — các tham số đó chỉ có ở cấu hình org (ADMIN)
    return params


def _check_policy(provider: str, model: str, params: Optional[Dict[str, Any]] = None) -> None:
    pol = ai_policy.get_policy()
    if pol["byok"] == "off":
        raise _err(403, "AI_BYOK_OFF")
    # [PR-6 S2] Azure: allowlist theo model THẬT của deployment (ánh xạ ADMIN), không theo tên do user đặt
    if not ai_policy.is_allowed(pol, provider, ai_policy.policy_model(pol, provider, params, model)):
        raise _err(422, "AI_NOT_ALLOWED")


def _public(m: Dict[str, Any]) -> Dict[str, Any]:
    """Thông tin cho CHỦ (có key_hint 4 ký tự cuối). Không owner id, không auth_mode nội bộ, không secret."""
    p = m.get("params") or {}
    return {"id": m["id"], "provider": m["provider"], "label": m["label"], "key_hint": m["key_hint"],
            "model": p.get("model"), "region": p.get("region"), "deployment": p.get("deployment"),
            "endpoint": p.get("endpoint"), "api_version": p.get("api_version"), "status": m["status"],
            "last_validated_at": m["last_validated_at"], "last_error_code": m["last_error_code"],
            "last_used_at": m["last_used_at"], "is_default": m["is_default"], "created_at": m["created_at"],
            "rotated_at": m["rotated_at"]}


def _own_row(db: Session, user: User, cred_id: str) -> AiCredential:
    row = db.get(AiCredential, cred_id)
    # Không phải của mình (kể cả ADMIN) / hàng org / đã thu hồi → 404, không lộ sự tồn tại
    if row is None or row.scope != "user" or row.owner_user_id != user.id or row.status in ("revoked", "disabled"):
        raise _err(404, "AI_CRED_NOT_FOUND")
    return row


def _audit_test(action: str, user: User, row: Optional[AiCredential], provider: str, outcome: str) -> None:
    audit.info("ai_cred action=%s actor=%s owner=%s cred=%s provider=%s hint=%s outcome=%s", action, user.id, user.id,
               getattr(row, "id", "-"), provider, getattr(row, "key_hint", ""), outcome)


async def _test_route(route, user: User, row: Optional[AiCredential], provider: str, db: Session) -> Dict[str, Any]:
    from api.services.llm_resolver import Refuse
    t0 = time.monotonic()
    if isinstance(route, Refuse):
        return {"ok": False, "code": route.code, "model": None, "latency_ms": 0, "tools": None, "json": None}
    res = await _probe(route)
    res["code"] = res.get("code") or ("VALID" if res.get("ok") else "NETWORK")
    ai_usage.record(user_id=user.id, credential_id=getattr(row, "id", None), scope="user", provider=provider,
                    model=res.get("model") or getattr(route, "model", None), feature="test", job_kind="credential_test",
                    latency_ms=res.get("latency_ms") or int((time.monotonic() - t0) * 1000),
                    outcome="ok" if res.get("ok") else "error", error_code=None if res.get("ok") else res["code"])
    if res.get("ok") and res.get("tools") is not None:
        try:
            ai_policy.record_cloud_probe(provider, res.get("model") or route.model, bool(res["tools"]))
        except Exception:
            pass
    _audit_test("test", user, row, provider, res["code"])
    return res


# ── user self-service ────────────────────────────────────
@router.get("/api/me/ai-credentials")
def list_mine(user: User = Depends(byok_user), db: Session = Depends(get_db)):
    rows = [creds._meta(r) for r in db.query(AiCredential)
            .filter(AiCredential.scope == "user", AiCredential.owner_user_id == user.id,
                    AiCredential.status.notin_(("revoked", "disabled"))).order_by(AiCredential.created_at, AiCredential.id)]
    return {"credentials": [_public(m) for m in rows], "policy": ai_policy.public_policy(ai_policy.get_policy())}


@router.post("/api/me/ai-credentials", status_code=201)
async def create_mine(body: CredCreate, user: User = Depends(byok_user), db: Session = Depends(get_db)):
    from api.services.llm_resolver import ephemeral_route
    params = _clean_params(body.provider, body.model, body.region, resource=body.resource,
                           deployment=body.deployment, api_version=body.api_version)
    _check_policy(body.provider, params["model"], params)
    secret = _clean_secret(body.provider, body.secret)
    if creds.count_active(db, user.id) >= MAX_PER_USER:
        raise _err(409, "AI_CRED_LIMIT")
    label = (body.label or "").strip() or f"{body.provider} – …{secret[-4:]}"
    if not _LABEL_RE.match(label):
        raise _err(422, "AI_BAD_LABEL")
    _throttle(user.id)
    route = ephemeral_route(body.provider, _AUTH_MODE[body.provider], params, secret, user.id)
    res = await _test_route(route, user, None, body.provider, db)   # validate TRƯỚC khi lưu
    if not res.get("ok"):
        raise HTTPException(status_code=422, detail={"code": res.get("code") or "NETWORK"})
    exists = (db.query(AiCredential.id).filter(AiCredential.scope == "user", AiCredential.owner_user_id == user.id,
                                               AiCredential.provider == body.provider, AiCredential.label == label)
              .first())
    if exists:
        raise _err(409, "AI_CRED_DUPLICATE_LABEL")
    first = creds.count_active(db, user.id) == 0
    try:
        m = creds.create(db, scope="user", owner_user_id=user.id, provider=body.provider, label=label,
                         auth_mode=_AUTH_MODE[body.provider], secret=secret, params=params, created_by=user.id,
                         status="valid")
        if body.is_default or first:
            creds.set_default(db, user.id, m["id"])
        creds.record_validation(db, m["id"], "VALID", actor=user.id)
        db.commit()
    except creds.CredentialError as e:
        db.rollback()
        raise _err(409 if e.code != "AI_CRED_BAD_ARGUMENT" else 422, e.code) from None
    return _public(creds._meta(_own_row(db, user, m["id"])))


@router.post("/api/me/ai-credentials/test")
async def test_unsaved(body: CredTest, user: User = Depends(byok_user), db: Session = Depends(get_db)):
    from api.services.llm_resolver import ephemeral_route
    params = _clean_params(body.provider, body.model, body.region, resource=body.resource,
                           deployment=body.deployment, api_version=body.api_version)
    _check_policy(body.provider, params["model"], params)
    secret = _clean_secret(body.provider, body.secret)
    _throttle(user.id)
    route = ephemeral_route(body.provider, _AUTH_MODE[body.provider], params, secret, user.id)
    return await _test_route(route, user, None, body.provider, db)


@router.patch("/api/me/ai-credentials/{cred_id}")
def patch_mine(cred_id: str, body: CredPatch, user: User = Depends(byok_user), db: Session = Depends(get_db)):
    row = _own_row(db, user, cred_id)
    if body.label is not None:
        label = body.label.strip()
        if not _LABEL_RE.match(label):
            raise _err(422, "AI_BAD_LABEL")
        dup = (db.query(AiCredential.id).filter(AiCredential.scope == "user", AiCredential.owner_user_id == user.id,
                                                AiCredential.provider == row.provider, AiCredential.label == label,
                                                AiCredential.id != row.id).first())
        if dup:
            raise _err(409, "AI_CRED_DUPLICATE_LABEL")
        row.label = label
    if any(v is not None for v in (body.model, body.region, body.deployment, body.api_version)):
        params = dict(row.params or {})
        np = _clean_params(row.provider, body.model if body.model is not None else params.get("model"),
                           body.region if body.region is not None else params.get("region"),
                           deployment=body.deployment, api_version=body.api_version, existing=params)
        _check_policy(row.provider, np["model"], {**params, **np})
        creds.update_params(db, row.id, {**params, **np}, actor=user.id)   # re-seal envelope với params mới
        row.status = "unknown"        # model/region mới chưa được kiểm tra
    if body.is_default is not None:
        creds.set_default(db, user.id, row.id if body.is_default else None)
    db.commit()
    return _public(creds._meta(row))


@router.put("/api/me/ai-credentials/{cred_id}/secret")
async def rotate_mine(cred_id: str, body: SecretIn, user: User = Depends(byok_user), db: Session = Depends(get_db)):
    from api.services.llm_resolver import ephemeral_route
    row = _own_row(db, user, cred_id)
    secret = _clean_secret(row.provider, body.secret)
    _throttle(user.id)
    route = ephemeral_route(row.provider, row.auth_mode, dict(row.params or {}), secret, user.id)
    res = await _test_route(route, user, row, row.provider, db)       # validate key MỚI trước khi thay
    if not res.get("ok"):
        raise HTTPException(status_code=422, detail={"code": res.get("code") or "NETWORK"})
    creds.rotate(db, row.id, secret, actor=user.id)
    creds.record_validation(db, row.id, "VALID", actor=user.id)
    db.commit()
    return _public(creds._meta(row))


@router.delete("/api/me/ai-credentials/{cred_id}", status_code=204)
def delete_mine(cred_id: str, user: User = Depends(byok_user), db: Session = Depends(get_db)):
    row = _own_row(db, user, cred_id)
    creds.delete(db, row.id, actor=user.id)
    db.commit()
    return None


@router.post("/api/me/ai-credentials/{cred_id}/test")
async def test_mine(cred_id: str, user: User = Depends(byok_user), db: Session = Depends(get_db)):
    from api.services.llm_resolver import route_for_own_credential
    row = _own_row(db, user, cred_id)
    _throttle(user.id)
    route = route_for_own_credential(db, row.id, user.id)
    res = await _test_route(route, user, row, row.provider, db)
    if res.get("code") not in ("AI_NOT_ALLOWED", "AI_CRED_REVOKED", "AI_CRED_FORBIDDEN"):
        creds.record_validation(db, row.id, res["code"], actor=user.id)
        db.commit()
    return res


# ── admin ────────────────────────────────────────────────
def _usage_30d(db: Session) -> Dict[str, Dict[str, float]]:
    cut = datetime.utcnow() - timedelta(days=30)
    q = (db.query(AiUsageEvent.credential_id, func.count(AiUsageEvent.id), func.coalesce(func.sum(AiUsageEvent.est_cost_usd), 0.0))
         .filter(AiUsageEvent.credential_id.isnot(None), AiUsageEvent.ts >= cut, AiUsageEvent.feature != "test")
         .group_by(AiUsageEvent.credential_id))
    return {cid: {"calls": int(n), "est_cost_usd": round(float(c), 4)} for cid, n, c in q}


@router.get("/api/ai/credentials")
def admin_list(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    """ADMIN: metadata credential của MỌI user (chủ, provider, …last4, trạng thái, lần dùng cuối, usage 30 ngày)."""
    emails = {u.id: u.email for u in db.query(User.id, User.email)}
    use = _usage_30d(db)
    out = []
    for m in creds.list_meta(db, scope="user"):
        u = use.get(m["id"], {"calls": 0, "est_cost_usd": 0.0})
        out.append({"id": m["id"], "owner": {"id": m["owner_user_id"], "email": emails.get(m["owner_user_id"], "")},
                    "provider": m["provider"], "label": m["label"], "key_hint": m["key_hint"],
                    "model": (m["params"] or {}).get("model"), "status": m["status"], "is_default": m["is_default"],
                    "last_used_at": m["last_used_at"], "last_validated_at": m["last_validated_at"],
                    "created_at": m["created_at"], "calls_30d": u["calls"], "est_cost_usd_30d": u["est_cost_usd"]})
    return {"credentials": out}


@router.post("/api/ai/credentials/{cred_id}/revoke")
def admin_revoke(cred_id: str, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """ADMIN thu hồi credential của user (xoá secret ngay, tombstone 30 ngày). Không đọc/test/dùng được key."""
    row = db.get(AiCredential, cred_id)
    if row is None or row.scope != "user":
        raise _err(404, "AI_CRED_NOT_FOUND")
    if row.status not in ("revoked", "disabled"):
        creds.revoke(db, cred_id, actor=admin.id)
        db.commit()
    m = creds._meta(row)
    return {"id": m["id"], "owner": {"id": m["owner_user_id"]}, "provider": m["provider"], "status": m["status"]}


@router.get("/api/ai/usage")
def usage(scope: str = Query("me", pattern="^(me|all)$"), days: int = Query(30, ge=1, le=180),
          user: User = Depends(current_user), db: Session = Depends(get_db)):
    if user.role == UserRole.VIEWER:
        raise HTTPException(status_code=403, detail="Tài khoản VIEWER không xem được usage")
    if scope == "all" and user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Chỉ ADMIN xem usage toàn bộ")
    if scope == "me" and not getattr(user, "id", None):
        raise HTTPException(status_code=400, detail="Cần đăng nhập bằng tài khoản thật")
    cut = datetime.utcnow() - timedelta(days=days)
    E = AiUsageEvent
    q = (db.query(E.user_id, E.credential_id, E.credential_scope, E.provider, func.count(E.id),
                  func.coalesce(func.sum(E.est_cost_usd), 0.0), func.coalesce(func.sum(E.tokens_in), 0),
                  func.coalesce(func.sum(E.tokens_out), 0))
         .filter(E.ts >= cut, E.outcome == "ok", E.feature != "test"))
    if scope == "me":
        q = q.filter(E.user_id == user.id)
    q = q.group_by(E.user_id, E.credential_id, E.credential_scope, E.provider)
    emails = {u.id: u.email for u in db.query(User.id, User.email)} if scope == "all" else {}
    hints = {r.id: r.key_hint for r in db.query(AiCredential.id, AiCredential.key_hint)}
    limit = ai_policy.get_policy()["org_quota"]["usd_per_user_month"]
    rows: List[Dict[str, Any]] = []
    for uid, cid, sc, prov, n, cost, tin, tout in q:
        r: Dict[str, Any] = {"credential_scope": sc if uid else "system", "provider": prov, "calls": int(n),
                             "est_cost_usd": round(float(cost), 4), "tokens_in": int(tin), "tokens_out": int(tout)}
        if scope == "all":
            r["user_email"] = emails.get(uid, "") if uid else ""
            r["key_hint"] = hints.get(cid, "") if sc == "user" else ""
        else:
            r["key_hint"] = hints.get(cid, "") if sc == "user" else ""
        if sc == "org" and uid and limit:
            r["quota_pct"] = round(100.0 * ai_usage.spent_usd(db, uid, "org") / float(limit), 1)
        rows.append(r)
    return {"rows": rows, "days": days, "scope": scope}
