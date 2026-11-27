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
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, Deque, Dict, Optional

logger = logging.getLogger(__name__)
RETENTION_DAYS = 180   # D11
_RPM_WINDOW = 60.0
_lock = threading.Lock()
_buckets: Dict[str, Deque[float]] = defaultdict(deque)


def reset_rpm() -> None:
    with _lock:
        _buckets.clear()


def rpm_take(key: str, limit: Optional[float], now: Optional[float] = None) -> bool:
    """Lấy 1 token; False nếu đã đủ `limit` lần trong 60 s gần nhất. limit None/0 = không giới hạn."""
    if not limit:
        return True
    now = time.monotonic() if now is None else now
    with _lock:
        q = _buckets[key]
        while q and now - q[0] >= _RPM_WINDOW:
            q.popleft()
        if len(q) >= int(limit):
            return False
        q.append(now)
        return True


def month_start(now: Optional[datetime] = None) -> datetime:
    now = now or datetime.utcnow()
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def spent_usd(db, user_id: str, scope: str = "org", now: Optional[datetime] = None) -> float:
    from sqlalchemy import func
    from api.ai_cred_models import AiUsageEvent as E
    v = (db.query(func.coalesce(func.sum(E.est_cost_usd), 0.0))
         .filter(E.user_id == user_id, E.credential_scope == scope, E.outcome == "ok", E.ts >= month_start(now))
         .scalar())
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


class Meter:
    """Gắn vào một Cloud route. `pre()` trước mỗi lần gọi, `post()` sau."""

    def __init__(self, route):
        self.ctx = getattr(route, "ctx", None)
        cred = getattr(route, "credential", None)
        self.cid = getattr(cred, "cid", None)
        self.scope = getattr(cred, "scope", None)
        self.provider = getattr(route, "provider", None)
        self.model = getattr(route, "model", None)

    @property
    def _uid(self) -> Optional[str]:
        return getattr(self.ctx, "user_id", None)

    def _event(self, outcome: str, code: Optional[str] = None, **kw) -> None:
        c = self.ctx
        record(user_id=self._uid, credential_id=self.cid, scope=self.scope, provider=self.provider, model=self.model,
               feature=getattr(c, "feature", None), job_kind=getattr(c, "job_kind", None),
               job_id=getattr(c, "job_id", None), outcome=outcome, error_code=code, **kw)

    def pre(self) -> None:
        from api.services import ai_policy
        from api.services.llm_resolver import (AI_CRED_REVOKED, AI_QUOTA, AI_RATE_LIMIT, RouteRefused)
        if self.ctx is None:
            return
        policy = ai_policy.get_policy()
        # 1. credential còn hiệu lực (revoke/disable GIỮA job → dừng, không đổi key)
        if self.cid:
            from api.ai_cred_models import AiCredential
            from api.database import SessionLocal
            db = SessionLocal()
            try:
                row = db.get(AiCredential, self.cid)
                dead = (row is None or row.status in ("revoked", "disabled")
                        or (row.scope == "user" and (policy["byok"] == "off" or row.owner_user_id != self._uid
                                                      and self._uid is not None)))
            finally:
                db.close()
            if dead:
                self._event("refused", AI_CRED_REVOKED)
                raise RouteRefused(AI_CRED_REVOKED, "ai.error.cred_revoked")
        if self.provider and not ai_policy.is_allowed(policy, self.provider, self.model):
            self._event("refused", AI_CRED_REVOKED)
            raise RouteRefused(AI_CRED_REVOKED, "ai.error.cred_revoked")
        # 2. rpm + quota (chỉ job có user; job hệ thống không bị giới hạn theo user)
        uid = self._uid
        if uid:
            q = policy["org_quota"] if self.scope == "org" else policy["user_quota_own_keys"]
            if not rpm_take(f"{uid}:{self.scope}", q.get("rpm_per_user")):
                self._event("refused", AI_RATE_LIMIT)
                raise RouteRefused(AI_RATE_LIMIT, "ai.error.rate_limit")
            if self.scope == "org":
                from api.database import SessionLocal
                db = SessionLocal()
                try:
                    over = quota_exhausted(db, uid, policy)
                finally:
                    db.close()
                if over:
                    self._event("quota_blocked", AI_QUOTA)
                    raise RouteRefused(AI_QUOTA, "ai.error.quota")

    def post(self, raw: Any = None, *, started: Optional[float] = None, error_code: Optional[str] = None) -> None:
        lat = int((time.monotonic() - started) * 1000) if started else None
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


def meter_for(route) -> Optional[Meter]:
    return Meter(route) if getattr(route, "kind", None) == "cloud" and getattr(route, "ctx", None) is not None else None
