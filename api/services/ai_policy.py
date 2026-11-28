"""[AI PR-3] Chính sách AI của tổ chức (ADMIN): BYOK, provider/model được phép, hạn mức, job theo lịch.

Lưu trong ai_config.json dưới khoá "policy" (app đơn instance, như phần còn lại của cấu hình). Mặc định chọn sao cho
HÀNH VI KHÔNG ĐỔI sau nâng cấp (D1/D2/D12): byok=allowed, fallback_to_org=true, job theo lịch dùng key org,
hạn mức org KHÔNG GIỚI HẠN cho tới khi admin đặt.
"""
from __future__ import annotations

import copy
import fnmatch
import logging
import re
from typing import Any, Dict, Optional

_log = logging.getLogger(__name__)

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
# [PR-7] base_url_allowlist: "host" | "host:port" | "*.suffix[:port]" — wildcard chỉ ở đầu, không scheme/path/userinfo
_ALLOW_ENTRY = re.compile(
    r"(\*\.)?[a-z0-9]([a-z0-9_-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9_-]*[a-z0-9])?)*(:[0-9]{1,5})?", re.ASCII)
# Heuristic (không dùng Public Suffix List): "*.x" cần >=2 nhãn sau "*." và nhãn đầu của hậu tố 2 nhãn không phải
# nhãn đăng ký dùng chung (co/com/net/org/gov/edu/ac/or/ne/go) → từ chối *.com, *.co.uk, *.com.vn.
_SHARED_SUFFIX_LABELS = frozenset({"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go"})
# Dịch vụ wildcard-DNS / nền tảng dùng chung: wildcard trên các miền này bị từ chối (chỉ cho phép host cụ thể).
_NO_WILDCARD_DOMAINS = ("nip.io", "sslip.io", "xip.io", "localtest.me", "lvh.me", "traefik.me", "github.io",
                        "amazonaws.com", "herokuapp.com", "azurewebsites.net", "cloudfront.net", "vercel.app",
                        "netlify.app")


def valid_allow_entry(e: Any) -> bool:
    """Mục allowlist hợp lệ: "host" | "host:port" | "*.suffix[:port]" (chữ thường, ASCII, không strip)."""
    if not isinstance(e, str) or not _ALLOW_ENTRY.fullmatch(e):
        return False
    host, sep, port = e.partition(":")
    if sep and not 0 < int(port) < 65536:
        return False
    if host.startswith("*."):
        labels = host[2:].split(".")
        if len(labels) < 2 or labels[-2] in _SHARED_SUFFIX_LABELS or labels[-1].isdigit():
            return False   # nhãn cuối toàn số (vd *.9.9) sẽ khớp địa chỉ IP
        dom = ".".join(labels)
        if any(dom == d or dom.endswith("." + d) for d in _NO_WILDCARD_DOMAINS):
            return False
    return True


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
    p["base_url_allowlist"] = [e.lower() for e in _str_list(p["base_url_allowlist"], "policy.base_url_allowlist")]
    for e in p["base_url_allowlist"]:
        if not valid_allow_entry(e):
            raise ValueError("policy.base_url_allowlist: mỗi mục phải là host hoặc host:port, wildcard chỉ dạng *.suffix ở đầu "
                             "(không nhận *.com, *.co.uk…)")
    m = p["azure_deployment_models"]
    if not isinstance(m, dict) or len(m) > 200:
        raise ValueError("policy.azure_deployment_models phải là object <resource>/<deployment> → model")
    clean = {}
    for k, v in m.items():
        if v is None:                      # null = xoá mục này (semantics xoá tường minh)
            continue
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


def _sanitize_allowlist(v: Any, limit: int = 100) -> list:
    """Hàm toàn phần (không raise): không phải list → []; bỏ từng mục không phải str / rỗng / >200 ký tự / không hợp lệ;
    cắt còn `limit` mục. Chỉ log số lượng."""
    if v in (None, ""):
        return []
    if not isinstance(v, list):
        _log.warning("ai_policy: base_url_allowlist đã lưu không phải danh sách, bỏ qua")
        return []
    kept = []
    for e in v:
        if isinstance(e, str):
            e = e.strip().lower()
            if 0 < len(e) <= 200 and valid_allow_entry(e):
                kept.append(e)
    if len(kept) != len(v):
        _log.warning("ai_policy: bỏ %d mục base_url_allowlist không hợp lệ đã lưu", len(v) - len(kept))
    if len(kept) > limit:
        _log.warning("ai_policy: base_url_allowlist vượt %d mục, cắt bớt", limit)
        kept = kept[:limit]
    return kept


def get_policy(cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Policy hiệu lực từ cấu hình (không raise: giá trị hỏng → mặc định an toàn)."""
    if cfg is None:
        from api.services.ai_config import load_config
        cfg = load_config()
    raw = cfg.get("policy")
    if isinstance(raw, dict) and "base_url_allowlist" in raw:
        # Dữ liệu cũ/hỏng trong allowlist không được làm policy rơi về mặc định: làm sạch RIÊNG trường này.
        raw = {**raw, "base_url_allowlist": _sanitize_allowlist(raw["base_url_allowlist"])}
    try:
        return normalize(raw)
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


def is_allowed_model(policy: Dict[str, Any], provider: str, model: Optional[str]) -> bool:
    """is_allowed theo id gốc HOẶC (Azure) id đã chuẩn hoá: Azure báo model có hậu tố ngày (`gpt-4o-2024-08-06`) nên mục
    allowlist `azure_openai:gpt-4o` phải khớp. Marker `unmapped/…` được giữ nguyên qua chuẩn hoá (không bao giờ khớp rẻ)."""
    if is_allowed(policy, provider, model):
        return True
    if provider == "azure_openai" and model:
        from api.services.ai_prices import normalize_model
        n = normalize_model(model)
        return n != (model or "").lower() and is_allowed(policy, provider, n)
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
