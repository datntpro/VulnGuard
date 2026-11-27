"""[AI PR-3] Usage events, hạn mức org-key (USD/tháng + rpm), và Meter gắn vào mỗi lần gọi cloud.

  * `ai_usage_events` append-only: credential_id + scope + provider/model + token + ước lượng USD. KHÔNG có trường
    secret/hint (hint chỉ ở bảng credential, owner xem).
  * Quota (org key): tổng est_cost_usd tháng hiện tại của user (scope='org') so với policy.org_quota.usd_per_user_month;
    rpm = token bucket trong bộ nhớ (cửa sổ 60 s) theo (user, scope).
  * `Meter` (tạo từ Route) kiểm lại TRƯỚC MỖI lần gọi: credential còn hiệu lực + còn được policy cho phép + rpm + quota,
    rồi ghi event SAU lần gọi. Vi phạm → RouteRefused (pentest: PAUSED, không bao giờ đổi sang key khác).
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)
RETENTION_DAYS = 180   # D11
_RPM_WINDOW = 60                 # giây
_RESERVE_TTL = timedelta(minutes=15)   # reservation mồ côi (crash giữa lần gọi) hết hiệu lực sau 15 phút
_COUNTED = ("ok", "reserved")    # outcome tính vào hạn mức USD
_CALLS = ("ok", "reserved", "error")   # outcome tính vào rpm


def reset_rpm() -> None:
    """Test helper: xoá các reservation đang treo (rpm/quota đếm từ DB, không còn bucket trong bộ nhớ)."""
    from api.ai_cred_models import AiUsageEvent
    from api.database import SessionLocal
    db = SessionLocal()
    try:
        db.query(AiUsageEvent).filter(AiUsageEvent.outcome == "reserved").delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def month_start(now: Optional[datetime] = None) -> datetime:
    now = now or datetime.utcnow()
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def spent_usd(db, user_id: str, scope: str = "org", now: Optional[datetime] = None) -> float:
    from sqlalchemy import func
    from api.ai_cred_models import AiUsageEvent as E
    v = (db.query(func.coalesce(func.sum(E.est_cost_usd), 0.0))
         .filter(E.user_id == user_id, E.credential_scope == scope, E.ts >= month_start(now),
                 (E.outcome == "ok") | ((E.outcome == "reserved") & (E.ts >= (now or datetime.utcnow()) - _RESERVE_TTL)))
         ).scalar()
    return float(v or 0.0)


def quota_exhausted(db, user_id: Optional[str], policy: Dict[str, Any], now: Optional[datetime] = None) -> bool:
    limit = (policy.get("org_quota") or {}).get("usd_per_user_month")
    if not user_id or not limit:
        return False
    return spent_usd(db, user_id, "org", now) >= float(limit)


def record(*, user_id: Optional[str], credential_id: Optional[str], scope: Optional[str], provider: Optional[str],
           model: Optional[str], feature: Optional[str], job_kind: Optional[str] = None, job_id: Optional[str] = None,
           tokens_in: int = 0, tokens_out: int = 0, cache_read: int = 0, cache_write: int = 0,
           latency_ms: Optional[int] = None, outcome: str = "ok", error_code: Optional[str] = None,
           db=None) -> None:
    """Ghi một event. KHÔNG BAO GIỜ raise (không để audit làm hỏng job). `error_code` chỉ là mã chuẩn hoá."""
    from api.ai_cred_models import AiUsageEvent
    from api.services.ai_prices import est_cost_usd
    own = db is None
    try:
        if own:
            from api.database import SessionLocal
            db = SessionLocal()
        cost = est_cost_usd(model or "", tokens_in, tokens_out, cache_read, cache_write) if outcome == "ok" else 0.0
        db.add(AiUsageEvent(user_id=user_id, credential_id=credential_id, credential_scope=scope, provider=provider,
                            model=(model or "")[:120], feature=feature, job_kind=job_kind,
                            job_id=(str(job_id)[:64] if job_id else None), tokens_in=int(tokens_in or 0),
                            tokens_out=int(tokens_out or 0), tokens_cache_read=int(cache_read or 0),
                            tokens_cache_write=int(cache_write or 0), est_cost_usd=cost, latency_ms=latency_ms,
                            outcome=outcome, error_code=(error_code or None)))
        db.commit()
    except Exception:
        logger.warning("[ai-usage] không ghi được usage event")
        try:
            db.rollback()
        except Exception:
            pass
    finally:
        if own and db is not None:
            db.close()


def purge_old(db, now: Optional[datetime] = None) -> int:
    from api.ai_cred_models import AiUsageEvent
    n = db.query(AiUsageEvent).filter(AiUsageEvent.ts < (now or datetime.utcnow()) - timedelta(days=RETENTION_DAYS)
                                      ).delete(synchronize_session=False)
    db.commit()
    return n


def _extract_usage(raw: Any) -> Dict[str, int]:
    """Đọc token từ response SDK (anthropic / openai) — thiếu trường → 0."""
    u = getattr(raw, "usage", None)
    if u is None:
        return {}
    g = lambda *names: next((int(getattr(u, n)) for n in names if isinstance(getattr(u, n, None), (int, float))), 0)  # noqa: E731
    return {"tokens_in": g("input_tokens", "prompt_tokens"), "tokens_out": g("output_tokens", "completion_tokens"),
            "cache_read": g("cache_read_input_tokens"), "cache_write": g("cache_creation_input_tokens")}


def reserve(db, *, user_id: str, scope: str, credential_id: Optional[str], provider: Optional[str],
            model: Optional[str], feature: Optional[str], job_kind: Optional[str], job_id: Optional[str],
            est_usd: float, usd_limit: Optional[float], rpm_limit: Optional[float]) -> Optional[str]:
    """Reserve-then-settle NGUYÊN TỬ: một câu INSERT…SELECT chỉ chèn dòng `reserved` (đã tính est_usd) khi cả quota USD tháng
    lẫn rpm (đếm từ DB → đúng giữa nhiều process/worker) còn chỗ. Postgres: khoá advisory theo user để tuần tự hoá.
    Trả id reservation, hoặc None nếu bị chặn (gọi `blocked_reason` để biết lý do)."""
    from sqlalchemy import and_, func, literal, select
    from api.ai_cred_models import AiUsageEvent as E, gen_id
    now = datetime.utcnow()
    if db.bind.dialect.name == "postgresql":
        from sqlalchemy import text
        db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"ai-usage:{user_id}"})
    conds = []
    if usd_limit:
        spent = (select(func.coalesce(func.sum(E.est_cost_usd), 0.0))
                 .where(E.user_id == user_id, E.credential_scope == scope, E.ts >= month_start(now),
                        (E.outcome == "ok") | ((E.outcome == "reserved") & (E.ts >= now - _RESERVE_TTL)))
                 .scalar_subquery())
        conds.append(spent < float(usd_limit))
    if rpm_limit:
        n = (select(func.count(E.id))
             .where(E.user_id == user_id, E.credential_scope == scope, E.outcome.in_(_CALLS),
                    E.ts >= now - timedelta(seconds=_RPM_WINDOW))
             .scalar_subquery())
        conds.append(n < int(rpm_limit))
    rid = gen_id()
    cols = ["id", "ts", "user_id", "credential_id", "credential_scope", "provider", "model", "feature", "job_kind",
            "job_id", "tokens_in", "tokens_out", "tokens_cache_read", "tokens_cache_write", "est_cost_usd", "outcome"]
    vals = [literal(rid), literal(now), literal(user_id), literal(credential_id), literal(scope), literal(provider),
            literal((model or "")[:120]), literal(feature), literal(job_kind), literal(str(job_id)[:64] if job_id else None),
            literal(0), literal(0), literal(0), literal(0), literal(float(est_usd)), literal("reserved")]
    sel = select(*vals)
    if conds:
        sel = sel.where(and_(*conds))
    res = db.execute(E.__table__.insert().from_select(cols, sel))
    db.commit()
    return rid if res.rowcount else None


def blocked_reason(db, user_id: str, scope: str, usd_limit, rpm_limit) -> str:
    """Sau khi reserve() bị chặn: AI_QUOTA nếu hết USD, ngược lại AI_RATE_LIMIT."""
    if usd_limit and spent_usd(db, user_id, scope) >= float(usd_limit):
        return "AI_QUOTA"
    return "AI_RATE_LIMIT"


def settle(token: str, *, outcome: str, error_code: Optional[str] = None, tokens_in=0, tokens_out=0, cache_read=0,
           cache_write=0, latency_ms: Optional[int] = None, model: Optional[str] = None) -> None:
    """Chốt reservation theo usage THẬT (giá theo model hiệu lực). Không raise."""
    from api.ai_cred_models import AiUsageEvent
    from api.database import SessionLocal
    from api.services.ai_prices import est_cost_usd
    db = SessionLocal()
    try:
        row = db.get(AiUsageEvent, token)
        if row is None:
            return
        m = model or row.model or ""
        row.outcome = outcome
        row.error_code = error_code
        row.tokens_in, row.tokens_out = int(tokens_in or 0), int(tokens_out or 0)
        row.tokens_cache_read, row.tokens_cache_write = int(cache_read or 0), int(cache_write or 0)
        row.est_cost_usd = est_cost_usd(m, tokens_in, tokens_out, cache_read, cache_write) if outcome == "ok" else 0.0
        row.latency_ms = latency_ms
        db.commit()
    except Exception:
        logger.warning("[ai-usage] không chốt được reservation")
        db.rollback()
    finally:
        db.close()


class Meter:
    """Gắn vào một Cloud route. `pre()` trước mỗi lần gọi (trả token reservation), `post(token=…)` sau.
    `model` = model HIỆU LỰC của driver (planner/executor/summarizer có thể khác route.model) → giá + policy đúng model."""

    def __init__(self, route, model: Optional[str] = None):
        self.ctx = getattr(route, "ctx", None)
        cred = getattr(route, "credential", None)
        self.cid = getattr(cred, "cid", None)
        self.scope = getattr(cred, "scope", None)
        self.provider = getattr(route, "provider", None)
        self.model = (model or "").strip() or getattr(route, "model", None)

    @property
    def _uid(self) -> Optional[str]:
        """User bị tính hạn mức/rpm: chủ job; job lịch dùng key CÁ NHÂN của chủ lịch → tính cho chủ lịch."""
        uid = getattr(self.ctx, "user_id", None)
        if uid is None and self.scope == "user":
            uid = getattr(self.ctx, "sched_owner_id", None)
        return uid

    def _event(self, outcome: str, code: Optional[str] = None, **kw) -> None:
        c = self.ctx
        record(user_id=self._uid, credential_id=self.cid, scope=self.scope, provider=self.provider, model=self.model,
               feature=getattr(c, "feature", None), job_kind=getattr(c, "job_kind", None),
               job_id=getattr(c, "job_id", None), outcome=outcome, error_code=code, **kw)

    def pre(self) -> Optional[str]:
        from api.services import ai_policy
        from api.services.ai_prices import est_cost_usd
        from api.services.llm_resolver import (AI_CRED_REVOKED, AI_QUOTA, AI_RATE_LIMIT, RouteRefused)
        if self.ctx is None:
            return None
        policy = ai_policy.get_policy()
        uid = self._uid
        from api.database import SessionLocal
        db = SessionLocal()
        try:
            # 1. credential còn hiệu lực + chủ còn active (revoke/disable/deactivate GIỮA job → dừng, không đổi key)
            if self.cid:
                from api.ai_cred_models import AiCredential
                from api.auth_models import User
                row = db.get(AiCredential, self.cid)
                dead = row is None or row.status in ("revoked", "disabled")
                if not dead and row.scope == "user":
                    dead = (policy["byok"] == "off"
                            or (uid is not None and row.owner_user_id != uid))
                    if not dead:
                        owner = db.get(User, row.owner_user_id)
                        dead = owner is None or not owner.is_active or owner.role.value == "VIEWER"   # fail closed
                if dead:
                    self._event("refused", AI_CRED_REVOKED)
                    raise RouteRefused(AI_CRED_REVOKED, "ai.error.cred_revoked")
            if self.provider and not ai_policy.is_allowed(policy, self.provider, self.model):
                self._event("refused", AI_CRED_REVOKED)
                raise RouteRefused(AI_CRED_REVOKED, "ai.error.cred_revoked")
            # 2. reserve nguyên tử (USD tháng của key org + rpm) — job không có user: không giới hạn theo user
            if not uid:
                return None
            q = policy["org_quota"] if self.scope == "org" else policy["user_quota_own_keys"]
            usd = q.get("usd_per_user_month") if self.scope == "org" else None
            rpm = q.get("rpm_per_user")
            if not usd and not rpm:
                return None
            c = self.ctx
            est = est_cost_usd(self.model or "", 4000, 2000)      # ước lượng một lượt; chốt theo usage thật ở settle()
            token = reserve(db, user_id=uid, scope=self.scope or "org", credential_id=self.cid, provider=self.provider,
                            model=self.model, feature=getattr(c, "feature", None), job_kind=getattr(c, "job_kind", None),
                            job_id=getattr(c, "job_id", None), est_usd=est, usd_limit=usd, rpm_limit=rpm)
            if token is None:
                code = blocked_reason(db, uid, self.scope or "org", usd, rpm)
                self._event("quota_blocked" if code == AI_QUOTA else "refused", code)
                raise RouteRefused(code, "ai.error.quota" if code == AI_QUOTA else "ai.error.rate_limit")
            return token
        finally:
            db.close()

    def post(self, raw: Any = None, *, started: Optional[float] = None, error_code: Optional[str] = None,
             token: Optional[str] = None) -> None:
        lat = int((time.monotonic() - started) * 1000) if started else None
        if token:
            if error_code:
                settle(token, outcome="error", error_code=error_code, latency_ms=lat)
            else:
                settle(token, outcome="ok", latency_ms=lat, model=self.model, **{
                    k: v for k, v in _extract_usage(raw).items() if k in ("tokens_in", "tokens_out", "cache_read", "cache_write")})
                if self.cid:
                    self._touch()
            return
        if error_code:
            self._event("error", error_code, latency_ms=lat)
            return
        self._event("ok", None, latency_ms=lat, **_extract_usage(raw))
        if self.cid:
            self._touch()

    def _touch(self) -> None:
        try:
            from api.ai_cred_models import AiCredential
            from api.database import SessionLocal
            db = SessionLocal()
            try:
                row = db.get(AiCredential, self.cid)
                if row is not None:
                    row.last_used_at = datetime.utcnow()
                    db.commit()
            finally:
                db.close()
        except Exception:
            pass


def meter_for(route, model: Optional[str] = None) -> Optional[Meter]:
    return Meter(route, model) if getattr(route, "kind", None) == "cloud" and getattr(route, "ctx", None) is not None else None
