"""[AI PR-3] Chính sách AI của tổ chức (ADMIN): BYOK, provider/model được phép, hạn mức, job theo lịch.

Lưu trong ai_config.json dưới khoá "policy" (app đơn instance, như phần còn lại của cấu hình). Mặc định chọn sao cho
HÀNH VI KHÔNG ĐỔI sau nâng cấp (D1/D2/D12): byok=allowed, fallback_to_org=true, job theo lịch dùng key org,
hạn mức org KHÔNG GIỚI HẠN cho tới khi admin đặt.
"""
from __future__ import annotations

import copy
import fnmatch
import re
from typing import Any, Dict, Optional

BYOK_MODES = ("allowed", "required", "off")
SCHED_CREDENTIALS = ("org", "owner", "local_only")
SCHEDULE_POLICIES = SCHED_CREDENTIALS + ("inherit",)
COWORKER_ROUTES = ("local", "cloud")

DEFAULT_POLICY: Dict[str, Any] = {
    "byok": "allowed",
    "fallback_to_org": True,
    "allowed": [],                                   # glob "provider:model"; rỗng = không giới hạn
    "org_quota": {"usd_per_user_month": None, "rpm_per_user": None},       # None = không giới hạn (D12)
    "user_quota_own_keys": {"rpm_per_user": 120},    # bảo vệ server, không phải chi phí
    "scheduled_jobs_credential": "org",
    "custom_base_url": "admin_only",
    "base_url_allowlist": [],
    # [AI PR-6 S2] Azure: tên deployment do NGƯỜI DÙNG đặt nên không đáng tin để định giá/allowlist. ADMIN ánh xạ
    # "<resource>/<deployment>" → model thật (vd {"myres/prod-chat": "gpt-4o"}). Chưa ánh xạ = "unmapped/<deployment>":
    # không khớp allowlist cụ thể nào, và giá tính theo mức đắt nhất của họ OpenAI.
    "azure_deployment_models": {},
}
_AZ_KEY = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?/[a-z0-9][a-z0-9._\-]{0,63}$")
_MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/\-]{0,119}$")


def _num(v: Any, name: str, *, integer: bool = False, maximum: float = 1e6) -> Optional[float]:
    if v is None or v == "":
        return None
    if isinstance(v, bool):
        raise ValueError(f"{name} phải là số")
    try:
        n = int(v) if integer else float(v)
    except (TypeError, ValueError):
        raise ValueError(f"{name} phải là số") from None
    if n < 0 or n > maximum:
        raise ValueError(f"{name} ngoài khoảng cho phép")
    return n


def _str_list(v: Any, name: str, limit: int = 100) -> list:
    if v in (None, ""):
        return []
    if not isinstance(v, list) or len(v) > limit or not all(isinstance(x, str) and 0 < len(x.strip()) <= 200 for x in v):
        raise ValueError(f"{name} phải là danh sách chuỗi")
    return [x.strip() for x in v]


def normalize(raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Merge với mặc định + validate. Raise ValueError."""
    raw = raw or {}
    if not isinstance(raw, dict):
        raise ValueError("policy phải là object")
    p = copy.deepcopy(DEFAULT_POLICY)
    for k, v in raw.items():
        if k in ("org_quota", "user_quota_own_keys") and isinstance(v, dict):
            p[k].update(v)
        elif k in p:
            p[k] = v
    if p["byok"] not in BYOK_MODES:
        raise ValueError("policy.byok phải là allowed | required | off")
    p["fallback_to_org"] = bool(p["fallback_to_org"])
    p["allowed"] = _str_list(p["allowed"], "policy.allowed")
    if p["scheduled_jobs_credential"] not in SCHED_CREDENTIALS:
        raise ValueError("policy.scheduled_jobs_credential phải là org | owner | local_only")
    if p["custom_base_url"] not in ("admin_only", "off"):
        raise ValueError("policy.custom_base_url phải là admin_only | off")
    p["base_url_allowlist"] = _str_list(p["base_url_allowlist"], "policy.base_url_allowlist")
    m = p["azure_deployment_models"]
    if not isinstance(m, dict) or len(m) > 200:
        raise ValueError("policy.azure_deployment_models phải là object <resource>/<deployment> → model")
    clean = {}
    for k, v in m.items():
        k2 = str(k).strip().lower()
        if not _AZ_KEY.match(k2) or not isinstance(v, str) or not _MODEL_ID.match(v.strip()):
            raise ValueError("policy.azure_deployment_models: khoá phải dạng <resource>/<deployment>, giá trị là model id hợp lệ")
        clean[k2] = v.strip()
    p["azure_deployment_models"] = clean
    oq, uq = p["org_quota"], p["user_quota_own_keys"]
    p["org_quota"] = {"usd_per_user_month": _num(oq.get("usd_per_user_month"), "org_quota.usd_per_user_month"),
                      "rpm_per_user": _num(oq.get("rpm_per_user"), "org_quota.rpm_per_user", integer=True, maximum=100000)}
    p["user_quota_own_keys"] = {"rpm_per_user": _num(uq.get("rpm_per_user"), "user_quota_own_keys.rpm_per_user",
                                                      integer=True, maximum=100000)}
    return p


def get_policy(cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Policy hiệu lực từ cấu hình (không raise: giá trị hỏng → mặc định an toàn)."""
    if cfg is None:
        from api.services.ai_config import load_config
        cfg = load_config()
    try:
        return normalize(cfg.get("policy"))
    except ValueError:
        return copy.deepcopy(DEFAULT_POLICY)


def public_policy(policy: Dict[str, Any]) -> Dict[str, Any]:
    """Phần mọi role đăng nhập đều được thấy (không lộ danh sách allowlist base_url, rpm…)."""
    return {"byok": policy["byok"], "allowed": list(policy["allowed"]),
            "fallback_to_org": policy["fallback_to_org"],
            "usd_per_user_month": policy["org_quota"]["usd_per_user_month"]}


def is_allowed(policy: Dict[str, Any], provider: str, model: Optional[str]) -> bool:
    """`provider:model` khớp ít nhất một glob. Danh sách rỗng = cho phép hết. Mẫu không có ':' = `mẫu:*`."""
    pats = policy.get("allowed") or []
    if not pats:
        return True
    target = f"{(provider or '').lower()}:{(model or '').lower()}"
    for pat in pats:
        pat = pat.lower()
        if ":" not in pat:
            pat += ":*"
        if fnmatch.fnmatchcase(target, pat):
            return True
    return False


def azure_real_model(policy: Dict[str, Any], endpoint: Optional[str], deployment: Optional[str]) -> str:
    """Model THẬT của một deployment Azure theo ánh xạ của ADMIN; chưa ánh xạ → "unmapped/<deployment>"
    (không bao giờ tin tên deployment do người dùng đặt)."""
    host = re.sub(r"^https?://", "", (endpoint or "").strip().lower()).split("/")[0].split(":")[0]
    resource = host.split(".")[0]
    dep = (deployment or "").strip()
    real = (policy.get("azure_deployment_models") or {}).get(f"{resource}/{dep.lower()}")
    return real or f"unmapped/{dep}"


def policy_model(policy: Dict[str, Any], provider: str, params: Optional[Dict[str, Any]], call_model: str) -> str:
    """Model dùng cho allowlist + định giá. Với Azure là model thật theo ánh xạ; provider khác là chính model gọi."""
    if provider == "azure_openai":
        p = params or {}
        return azure_real_model(policy, p.get("endpoint"), p.get("deployment") or call_model)
    return call_model


def coworker_route(cfg: Dict[str, Any]) -> str:
    """§4.11.1: 'local' | 'cloud' mà Settings › AI quy định cho Co-work (không có picker/toggle riêng)."""
    mode = cfg.get("mode", "local_only")
    if mode == "cloud_only":
        return "cloud"
    if mode == "hybrid" and ((cfg.get("hybrid") or {}).get("tasks") or {}).get("coworker") == "cloud":
        return "cloud"
    return "local"


# ── Kết quả probe tool-calling của model cloud (PR-4 probe ghi vào đây; Co-work cloud bắt buộc tools=true) ──
def _probe_key(provider: str, model: str) -> str:
    return f"{(provider or '').lower()}:{model or ''}"


def record_cloud_probe(provider: str, model: str, tools: Optional[bool]) -> None:
    if tools is None:
        return
    from datetime import datetime
    from api.services import ai_config

    def _m(c):
        c.setdefault("probe", {})[_probe_key(provider, model)] = {"tools": bool(tools), "at": datetime.utcnow().isoformat()}
    ai_config.update_raw(_m)


def cloud_tools_ok(provider: str, model: str) -> bool:
    """True chỉ khi model ĐÃ qua probe tool-calling (chưa probe = chưa biết = không dùng cho Co-work)."""
    from api.services.ai_config import load_config
    rec = (load_config().get("probe") or {}).get(_probe_key(provider, model))
    return bool(rec and rec.get("tools"))
