"""[AI PR-1] LLM resolver seam — con đường DUY NHẤT tới một LLM client.

Mọi call site (triage, reanalyze, pentest, doc review, Co-work, File Assistant, test) gọi
`resolve(LLMContext)` để lấy một `Route`, rồi (với cloud) `open_client(route)` để dựng client.
PR-1 KHÔNG đổi hành vi: vẫn chỉ cấu hình org (ai_config.json + runtime_settings). Credential theo
từng user, policy, quota… là PR-2/PR-3 — chúng chỉ sửa trong file này.

Route:
  LocalOllama(url, model, vision_model)   — Ollama
  Cloud(credential, provider, model, family) — provider cloud; `credential` là ResolvedCredential
  Refuse(code, message_key)               — không được phép / không có credential

Bất biến an toàn:
  * plaintext KHÔNG nằm trong Route, cfg, checkpoint hay repr; ResolvedCredential giữ secret (đã mã
    hoá) ở thuộc tính private, repr che, không pickle / deepcopy / JSON được, và chỉ mở khoá (decrypt)
    tại thời điểm dựng client.
  * Test `tests/test_llm_resolver.py` quét mã nguồn: chỉ module này (và cloud_ai nội bộ) được dựng
    client SDK / lấy URL Ollama hiệu lực.
"""
from __future__ import annotations

import copy
import logging
import re
from dataclasses import dataclass, replace
from typing import Any, Dict, Literal, Optional, Tuple, Union

logger = logging.getLogger(__name__)

Feature = Literal["triage", "reanalyze", "pentest", "pentest_summarizer", "docreview",
                  "coworker", "file_assistant", "test"]

# Feature luôn chạy Ollama (theo thiết kế hiện tại: không bao giờ cloud)
_LOCAL_ONLY_FEATURES = frozenset({"docreview", "coworker", "file_assistant"})
_CLOUD_PROVIDERS = ("anthropic", "bedrock", "openai", "openrouter", "azure_openai", "gemini", "vertex", "openai_compatible")
# [AI PR-6] provider đi qua SDK openai (Chat Completions) — dùng chung driver/probe family "openai"
_OPENAI_FAMILY = ("openai", "openrouter", "azure_openai", "gemini", "vertex", "openai_compatible")

# Mã refuse (message_key do UI dịch ở PR-5)
AI_NO_CREDENTIAL = "AI_NO_CREDENTIAL"
AI_BAD_PROVIDER = "AI_BAD_PROVIDER"
AI_UNKNOWN_FEATURE = "AI_UNKNOWN_FEATURE"
AI_CRED_REVOKED = "AI_CRED_REVOKED"        # [AI PR-2] credential đã revoked/disabled
AI_CRED_FORBIDDEN = "AI_CRED_FORBIDDEN"    # [AI PR-2] credential của user khác
AI_QUOTA = "AI_QUOTA"                      # [AI PR-3] hết hạn mức org-key tháng
AI_RATE_LIMIT = "AI_RATE_LIMIT"            # [AI PR-3] vượt rpm
AI_NOT_ALLOWED = "AI_NOT_ALLOWED"          # [AI PR-3] provider/model ngoài policy.allowed
AI_ROUTE_CHANGED = "AI_ROUTE_CHANGED"      # [AI PR-3] Co-work: cuộc hội thoại cloud nhưng Settings giờ là local
AI_CLOUD_NO_TOOLS = "AI_CLOUD_NO_TOOLS"    # [AI PR-3] Co-work cloud: model chưa qua probe tool-calling

_OLLAMA_DUMMY_KEY = "ollama"   # SDK openai bắt buộc api_key khác rỗng; Ollama bỏ qua — người dùng KHÔNG phải nhập


@dataclass(frozen=True)
class LLMContext:
    feature: str
    user_id: Optional[str] = None        # chủ job / người gọi; None = hệ thống
    job_kind: Optional[str] = None       # 'scan' | 'schedule' | 'pentest_run' | ...
    job_id: Optional[str] = None
    pinned_credential_id: Optional[str] = None
    needs_tools: bool = False
    escalate: bool = False               # triage hybrid: bước leo thang lên cloud (luật vẫn ở AIAnalyzer)
    # [AI PR-3] job hệ thống/lịch: policy hiệu lực (org|owner|local_only) + chủ lịch; Co-work: route đã ghim của hội thoại
    sched_policy: Optional[str] = None
    sched_owner_id: Optional[str] = None
    pinned_route_kind: Optional[str] = None   # 'local' | 'cloud' (Co-work, §4.11.1)


class RouteRefused(RuntimeError):
    """open_client() / require_cloud() gặp Refuse. Thông điệp không chứa secret."""
    def __init__(self, code: str, message_key: str = ""):
        super().__init__(f"{code}: {message_key or code}")
        self.code = code
        self.message_key = message_key or code


class ResolvedCredential:
    """Credential đã chọn cho MỘT lần gọi. Không có getter plaintext; không serialise được."""
    __slots__ = ("_provider", "_section", "_scope", "_cid", "_hint_cache")

    def __init__(self, provider: str, section: Dict[str, Any], scope: str = "org", cid: Optional[str] = None):
        object.__setattr__(self, "_provider", provider)
        object.__setattr__(self, "_section", section)   # section cấu hình provider (secret còn ở dạng Fernet)
        object.__setattr__(self, "_scope", scope)
        object.__setattr__(self, "_cid", cid)
        object.__setattr__(self, "_hint_cache", None)

    def __setattr__(self, k, v):
        raise AttributeError("ResolvedCredential là bất biến")

    @property
    def provider(self) -> str:
        return self._provider

    @property
    def scope(self) -> str:
        return self._scope

    @property
    def cid(self) -> Optional[str]:
        """Id credential (không phải secret) — cho ghim job, usage event, audit."""
        return self._cid

    @property
    def hint(self) -> str:
        """`…abcd` (4 ký tự cuối) — hiển thị cho CHỦ; không phải secret."""
        return self._hint()

    def _hint(self) -> str:
        """Hint cuối key (…abcd), tính MỘT lần rồi nhớ — repr không giải mã lại mỗi lần."""
        if self._hint_cache is None:
            h = "…"
            try:
                enc = self._section.get("api_key_enc")
                if not enc:
                    h = "keyless"
                else:
                    from api.security import decrypt_secret
                    tok = decrypt_secret(enc)
                    h = ("json" if tok and tok.lstrip().startswith("{")      # SA JSON: không lộ ký tự nào
                         else f"…{tok[-4:]}" if tok and len(tok) >= 8 else "…")
            except Exception:
                pass
            object.__setattr__(self, "_hint_cache", h)
        return self._hint_cache

    def __repr__(self) -> str:
        return f"<cred {self._hint()} {self._provider} {self._scope}>"

    __str__ = __repr__

    # Không cho pickle / copy / json — secret không được lọt vào checkpoint, cache, log
    def __reduce_ex__(self, protocol):
        raise TypeError("ResolvedCredential không serialise được")

    def __reduce__(self):
        raise TypeError("ResolvedCredential không serialise được")

    def __copy__(self):
        raise TypeError("ResolvedCredential không copy được")

    def __deepcopy__(self, memo):
        raise TypeError("ResolvedCredential không copy được")

    def public_params(self) -> Dict[str, Any]:
        """Tham số KHÔNG bí mật của credential (region, profile, auth_mode, base_url…) — cho liệt kê model/UI."""
        return {k: copy.deepcopy(v) for k, v in self._section.items() if k != "api_key_enc"}

    def _cfg(self) -> Dict[str, Any]:
        """CHỈ dùng nội bộ module này để dựng client."""
        return {"provider": self._provider, self._provider: self._section}


@dataclass(frozen=True)
class LocalOllama:
    url: str
    model: str
    vision_model: str = ""
    kind: str = "local"

    @property
    def label(self) -> str:
        return f"ollama:{self.model}"


@dataclass(frozen=True)
class Cloud:
    credential: ResolvedCredential
    provider: str
    model: str
    family: str          # 'anthropic_first' | 'bedrock' | 'openai'
    kind: str = "cloud"
    ctx: Optional[LLMContext] = None     # [AI PR-3] để Meter ghi usage / kiểm hạn mức mỗi lần gọi

    @property
    def credential_id(self) -> Optional[str]:
        return self.credential.cid

    @property
    def label(self) -> str:
        return f"{self.provider}:{self.model}"


@dataclass(frozen=True)
class Refuse:
    code: str
    message_key: str = ""
    kind: str = "refuse"


Route = Union[LocalOllama, Cloud, Refuse]


def with_model(route: Route, model: Optional[str]) -> Route:
    """Ghi đè model (vd vai trò planner/executor của Pentest). Không đổi credential."""
    model = (model or "").strip()
    if not model or isinstance(route, Refuse):
        return route
    return replace(route, model=model)


# ─────────────────────────────────────────────
# resolve()
# ─────────────────────────────────────────────
def _local_route() -> LocalOllama:
    from api.services import runtime_settings
    return LocalOllama(url=runtime_settings.ollama_url(), model=runtime_settings.ollama_model(),
                       vision_model=runtime_settings.ollama_vision_model())


def _model_family(provider: str, sec: Dict[str, Any]) -> Tuple[str, str]:
    if provider == "openrouter":
        from api.services.ai_config import DEFAULT_OPENROUTER_MODEL
        return sec.get("model") or DEFAULT_OPENROUTER_MODEL, "openai"
    if provider == "openai":
        return sec.get("model") or "gpt-4o", "openai"
    if provider == "azure_openai":     # [PR-6] "model" của lời gọi = tên deployment
        return sec.get("deployment") or sec.get("model") or "", "openai"
    if provider == "gemini":
        from api.services.ai_provider_params import DEFAULT_GEMINI_MODEL
        return sec.get("model") or DEFAULT_GEMINI_MODEL, "openai"
    if provider == "vertex":
        from api.services.ai_provider_params import DEFAULT_VERTEX_MODEL
        return sec.get("model") or DEFAULT_VERTEX_MODEL, "openai"
    if provider == "openai_compatible":
        return sec.get("model") or "", "openai"
    if provider == "bedrock":
        return sec.get("model") or "anthropic.claude-opus-5-5", "bedrock"
    return sec.get("model") or "claude-opus-5-5", "anthropic_first"


def _cloud_route(cfg: Dict[str, Any], ctx: Optional[LLMContext] = None) -> Route:
    """Route org (cấu hình ai_config). `cid` = hàng ai_credentials(scope='org') tương ứng nếu đã migrate."""
    provider = cfg.get("provider")
    if provider not in _CLOUD_PROVIDERS or not isinstance(cfg.get(provider), dict):
        return Refuse(AI_BAD_PROVIDER, "ai.error.bad_provider")
    sec = cfg[provider]
    model, family = _model_family(provider, sec)
    # Chỉ giữ section của provider được chọn (không kéo key của provider khác vào route)
    cred = ResolvedCredential(provider, copy.deepcopy(sec), scope="org", cid=cfg.get("org_credential_id"))
    return Cloud(credential=cred, provider=provider, model=model, family=family, ctx=ctx)


# ── [AI PR-3] precedence: pinned → default của người khởi chạy → org (nếu policy cho + còn hạn mức) → refuse ──
_USABLE = ("valid", "unknown")


def _org_cloud(ctx: LLMContext, cfg: Dict[str, Any], policy: Dict[str, Any], *, check_quota: bool) -> Route:
    from api.services import ai_policy, ai_usage
    r = _cloud_route(cfg, ctx)
    if isinstance(r, Refuse):
        return r
    if not ai_policy.is_allowed(policy, r.provider, r.model):
        return Refuse(AI_NOT_ALLOWED, "ai.error.not_allowed")
    if check_quota and ctx.user_id:
        from api.database import SessionLocal
        db = SessionLocal()
        try:
            if ai_usage.quota_exhausted(db, ctx.user_id, policy):
                return Refuse(AI_QUOTA, "ai.error.quota")
        finally:
            db.close()
    return r


def _user_cloud(db, row, ctx: LLMContext, policy: Dict[str, Any], *, act_as: Optional[str] = None,
                deny_code: str = AI_NOT_ALLOWED) -> Route:
    """Dựng route từ MỘT hàng credential của user (đã chọn). Giải mã đúng lúc qua open_for_call."""
    from api.services import ai_credentials
    from api.services.ai_credentials import CredentialError
    model, family = _model_family(row.provider, row.params or {})
    from api.services import ai_policy
    if not ai_policy.is_allowed(policy, row.provider, model):
        return Refuse(deny_code, "ai.error.cred_revoked" if deny_code == AI_CRED_REVOKED else "ai.error.not_allowed")
    from api.auth_models import User
    owner = db.get(User, row.owner_user_id)
    if owner is None or not owner.is_active or owner.role.value == "VIEWER":   # chủ không tồn tại / bị vô hiệu hoá / hạ VIEWER → fail closed
        return Refuse(AI_CRED_REVOKED, "ai.error.cred_revoked")
    cctx = replace(ctx, user_id=act_as) if act_as else ctx
    try:
        cred = ai_credentials.open_for_call(db, row.id, cctx)
    except RouteRefused as e:
        return Refuse(e.code, e.message_key)
    except CredentialError:
        return Refuse(AI_CRED_REVOKED, "ai.error.cred_revoked")
    return Cloud(credential=cred, provider=row.provider, model=model, family=family, ctx=ctx)


def _default_row(db, user_id: str, policy: Dict[str, Any]):
    """Credential mặc định hợp lệ của user (valid|unknown), hoặc None."""
    from api.ai_cred_models import AiCredential
    return (db.query(AiCredential)
            .filter(AiCredential.scope == "user", AiCredential.owner_user_id == user_id,
                    AiCredential.is_default.is_(True), AiCredential.status.in_(_USABLE),
                    AiCredential.secret_enc.isnot(None)).first())


def _resolve_pinned(db, ctx: LLMContext, cfg, policy) -> Route:
    from api.ai_cred_models import AiCredential
    row = db.get(AiCredential, ctx.pinned_credential_id)
    if row is None or row.status not in _USABLE:
        # revoked/disabled/invalid/forbidden…: dừng, KHÔNG rơi sang key khác giữa job
        return Refuse(AI_CRED_REVOKED, "ai.error.cred_revoked")
    if row.scope == "user":
        if row.owner_user_id != ctx.user_id:
            return Refuse(AI_CRED_FORBIDDEN, "ai.error.cred_forbidden")
        if policy["byok"] == "off":
            return Refuse(AI_CRED_REVOKED, "ai.error.cred_revoked")
        return _user_cloud(db, row, ctx, policy, deny_code=AI_CRED_REVOKED)
    # org: job của user chỉ dùng org khi policy cho; provider org đổi giữa job → dừng (không tự chuyển provider)
    if policy["byok"] == "required" or not policy["fallback_to_org"]:
        return Refuse(AI_NO_CREDENTIAL, "ai.error.no_credential")
    r = _org_cloud(ctx, cfg, policy, check_quota=True)
    if isinstance(r, Cloud) and row.provider != r.provider:
        return Refuse(AI_CRED_REVOKED, "ai.error.cred_revoked")
    return r


def _resolve_user_cloud(ctx: LLMContext, cfg, policy) -> Route:
    from api.database import SessionLocal
    db = SessionLocal()
    try:
        if ctx.pinned_credential_id:
            return _resolve_pinned(db, ctx, cfg, policy)      # KHÔNG rơi tiếp sang key khác
        if policy["byok"] != "off":
            row = _default_row(db, ctx.user_id, policy)
            if row is not None:
                from api.services import ai_policy
                model, _ = _model_family(row.provider, row.params or {})
                if ai_policy.is_allowed(policy, row.provider, model):
                    return _user_cloud(db, row, ctx, policy)
                # default bị policy chặn → coi như không có (rơi sang org nếu policy cho)
        if policy["byok"] != "required" and policy["fallback_to_org"]:
            return _org_cloud(ctx, cfg, policy, check_quota=True)
        return Refuse(AI_NO_CREDENTIAL, "ai.error.no_credential")
    finally:
        db.close()


def _resolve_system_cloud(ctx: LLMContext, cfg, policy) -> Route:
    """Job không có user (lịch/hệ thống): key org, hoặc key của CHỦ LỊCH khi policy 'owner'. Không bao giờ key user khác."""
    eff = ctx.sched_policy or policy["scheduled_jobs_credential"]
    if eff == "local_only":
        return Refuse(AI_NO_CREDENTIAL, "ai.error.sched_local_only")
    if eff == "owner":
        owner = ctx.sched_owner_id
        if not owner or policy["byok"] == "off":
            return Refuse(AI_NO_CREDENTIAL, "ai.error.no_credential")
        from api.ai_cred_models import AiCredential
        from api.database import SessionLocal
        db = SessionLocal()
        try:
            row = None
            if ctx.pinned_credential_id:
                row = db.get(AiCredential, ctx.pinned_credential_id)
                if row is None or row.scope != "user" or row.owner_user_id != owner:
                    return Refuse(AI_CRED_FORBIDDEN, "ai.error.cred_forbidden")
                if row.status in ("revoked", "disabled"):
                    return Refuse(AI_CRED_REVOKED, "ai.error.cred_revoked")
            else:
                row = _default_row(db, owner, policy)
            if row is None:
                return Refuse(AI_NO_CREDENTIAL, "ai.error.no_credential")
            return _user_cloud(db, row, ctx, policy, act_as=owner)
        finally:
            db.close()
    return _org_cloud(ctx, cfg, policy, check_quota=False)


def _resolve_cloud(ctx: LLMContext, cfg: Dict[str, Any]) -> Route:
    from api.services import ai_policy
    policy = ai_policy.get_policy(cfg)
    if ctx.user_id is None:
        return _resolve_system_cloud(ctx, cfg, policy)
    return _resolve_user_cloud(ctx, cfg, policy)


def _tools_ok(route: Cloud) -> bool:
    from api.services import ai_policy
    return ai_policy.cloud_tools_ok(route.provider, route.model)


def _resolve_coworker(ctx: LLMContext, cfg: Dict[str, Any]) -> Route:
    """§4.11: Co-work đi theo Settings › AI. Route được ghim theo hội thoại; không bao giờ tự leo local→cloud
    và không bao giờ rơi cloud→local/key khác."""
    from api.services import ai_policy
    if ctx.job_kind != "coworker_conversation":      # suggest / vision / health: luôn Ollama (D15)
        return _local_route()
    desired = ai_policy.coworker_route(cfg)
    pinned = ctx.pinned_route_kind
    if pinned == "local" or (pinned is None and desired == "local"):
        return _local_route()                         # pinned local + Settings đã sang cloud → vẫn local
    if pinned == "cloud" and desired == "local":
        return Refuse(AI_ROUTE_CHANGED, "ai.error.route_changed")
    r = _resolve_cloud(replace(ctx, needs_tools=True), cfg)
    if isinstance(r, Cloud) and not _tools_ok(r):
        return Refuse(AI_CLOUD_NO_TOOLS, "ai.error.cloud_no_tools")
    return r


def ollama_default_url() -> str:
    """URL Ollama mặc định (env) — chỉ để UI hiển thị 'mặc định'."""
    from api.config import settings
    return settings.ollama_url


def cloud_route_for(cfg: Dict[str, Any]) -> Route:
    """Route cloud từ một cfg bất kỳ (vd cfg đã gộp giá trị CHƯA LƯU để test). Dùng cho probe / liệt kê model."""
    return _cloud_route(cfg)


def resolve_provider(provider: str) -> Route:
    """Route cloud của MỘT provider cụ thể (liệt kê model cho dropdown) — credential vẫn do resolver chọn."""
    from api.services.ai_config import load_config
    cfg = load_config()
    cfg["provider"] = provider
    return _cloud_route(cfg)


def resolve_local(ctx: LLMContext) -> LocalOllama:
    """Tuyến Ollama của tổ chức (bước local của triage; URL/model hiệu lực). Không đổi theo mode."""
    return _local_route()


def resolve(ctx: LLMContext) -> Route:
    """Chọn route cho một lần gọi LLM (§4.3): mode/task → pinned → default của người khởi chạy → org → refuse."""
    f = ctx.feature
    if f == "coworker":
        from api.services.ai_config import load_config
        return _resolve_coworker(ctx, load_config())
    if f in _LOCAL_ONLY_FEATURES:
        return _local_route()
    from api.services.ai_config import load_config
    cfg = load_config()
    if f == "triage":
        mode = cfg.get("mode", "local_only")
        if mode == "cloud_only" or (mode == "hybrid" and ctx.escalate):
            return _resolve_cloud(ctx, cfg)
        return _local_route()
    if f in ("reanalyze", "pentest", "pentest_summarizer", "test"):
        # Hôm nay các feature này luôn dùng cloud provider đã cấu hình, bất kể `mode`
        return _resolve_cloud(ctx, cfg)
    return Refuse(AI_UNKNOWN_FEATURE, "ai.error.unknown_feature")


def route_for_own_credential(db, cred_id: str, user_id: str, feature: str = "test") -> Route:
    """Route từ MỘT credential của chính user (test/liệt kê model). Không áp precedence; credential của người khác,
    đã thu hồi, hoặc ngoài policy → Refuse. Admin KHÔNG có đường này cho key của user khác."""
    from api.ai_cred_models import AiCredential
    from api.services import ai_policy
    row = db.get(AiCredential, cred_id)
    if row is None or row.scope != "user" or row.owner_user_id != user_id:
        return Refuse(AI_CRED_FORBIDDEN, "ai.error.cred_forbidden")
    if row.status in ("revoked", "disabled"):
        return Refuse(AI_CRED_REVOKED, "ai.error.cred_revoked")
    return _user_cloud(db, row, LLMContext(feature=feature, user_id=user_id), ai_policy.get_policy())


def ephemeral_route(provider: str, auth_mode: str, params: Dict[str, Any], secret: str,
                    user_id: Optional[str]) -> Route:
    """Route cho key CHƯA LƯU (kiểm tra trước khi lưu). Secret chỉ ở RAM, được bọc ngay (Fernet hộp chung)."""
    from api.security import encrypt_secret
    if provider not in _CLOUD_PROVIDERS:
        return Refuse(AI_BAD_PROVIDER, "ai.error.bad_provider")
    section = dict(params or {})
    section["auth_mode"] = auth_mode
    section["api_key_enc"] = encrypt_secret(secret)
    model, family = _model_family(provider, section)
    cred = ResolvedCredential(provider, section, scope="user", cid=None)
    return Cloud(credential=cred, provider=provider, model=model, family=family,
                 ctx=LLMContext(feature="test", user_id=user_id))


def describe_effective(user_id: Optional[str]) -> Dict[str, Any]:
    """Cho status 'Khoá của bạn': {source: own|org|none, provider, hint} — chỉ đọc metadata, KHÔNG giải mã/không đụng last_used."""
    from api.database import SessionLocal
    from api.services import ai_policy
    from api.services.ai_config import load_config, public_config
    cfg = load_config()
    policy = ai_policy.get_policy(cfg)
    if user_id:
        db = SessionLocal()
        try:
            if policy["byok"] != "off":
                row = _default_row(db, user_id, policy)
                if row is not None and ai_policy.is_allowed(policy, row.provider, _model_family(row.provider, row.params or {})[0]):
                    return {"source": "own", "provider": row.provider, "hint": row.key_hint}
        finally:
            db.close()
    if (not user_id or (policy["byok"] != "required" and policy["fallback_to_org"])):
        prov = cfg.get("provider")
        sec = public_config(cfg).get(prov) or {}
        if sec.get("api_key_set") or sec.get("auth_mode") in ("wif", "environment", "aws_chain", "profile"):
            return {"source": "org", "provider": prov, "hint": ""}
    return {"source": "none", "provider": None, "hint": ""}


def pin_for_user(user_id: Optional[str], *, include_org: bool = False) -> Optional[str]:
    """Id credential để GHIM vào job lúc tạo: default hợp lệ + được policy cho phép của user; nếu không có và
    `include_org` → hàng org (nếu policy cho dùng org). None = để resolver chọn lúc chạy."""
    if not user_id:
        return None
    from api.database import SessionLocal
    from api.services import ai_policy
    from api.services.ai_config import load_config
    cfg = load_config()
    policy = ai_policy.get_policy(cfg)
    db = SessionLocal()
    try:
        if policy["byok"] != "off":
            row = _default_row(db, user_id, policy)
            if row is not None and ai_policy.is_allowed(policy, row.provider, _model_family(row.provider, row.params or {})[0]):
                return row.id
        if include_org and policy["byok"] != "required" and policy["fallback_to_org"]:
            return cfg.get("org_credential_id") or None
        return None
    finally:
        db.close()


def schedule_pin(created_by_user_id: Optional[str], schedule_policy: Optional[str],
                 owner_consent: Optional[bool] = True) -> Tuple[str, Optional[str], Optional[str]]:
    """Cho scan do lịch/hệ thống: (policy hiệu lực, chủ lịch nếu 'owner', credential ghim nếu 'owner').
    Lịch mà lần sửa cuối KHÔNG phải của chủ (owner_consent=False) không bao giờ chạy bằng key cá nhân của chủ → local_only."""
    from api.services import ai_policy
    pol = ai_policy.get_policy()
    eff = schedule_policy if schedule_policy in ai_policy.SCHED_CREDENTIALS else pol["scheduled_jobs_credential"]
    if eff == "owner" and owner_consent is False:
        return "local_only", None, None
    if eff == "owner" and created_by_user_id:
        return eff, created_by_user_id, pin_for_user(created_by_user_id)
    return eff, None, None


# ─────────────────────────────────────────────
# open_client() — nơi DUY NHẤT dựng client SDK
# ─────────────────────────────────────────────
def open_client(route: Route, *, probe: bool = False) -> Tuple[Any, str, str]:
    """Trả (async_client, model, family). family ∈ {'anthropic_first','bedrock','openai'}.

    [PR-4] probe=True: httpx client riêng (trust_env=False, không redirect, timeout 10s, guard SSRF).
    Ollama và OpenAI-compatible base_url tuỳ chỉnh LUÔN đi qua transport guard (kiểm lại IP ở mỗi request)."""
    if isinstance(route, Refuse):
        raise RouteRefused(route.code, route.message_key)
    if isinstance(route, LocalOllama):
        # Ollama native cho agent tool-use: endpoint tương thích OpenAI `{url}/v1`, không cần key thật
        from openai import AsyncOpenAI
        from api.services import url_guard
        client = AsyncOpenAI(api_key=_OLLAMA_DUMMY_KEY, base_url=route.url.rstrip("/") + "/v1", timeout=180.0,
                             http_client=url_guard.guarded_async_client("ollama", timeout=180.0))
        return client, route.model, "openai"
    if isinstance(route, Cloud):
        client, _model, family = _build_cloud_client(route.credential._cfg(), probe=probe)
        return client, route.model, family
    raise TypeError(f"route không hợp lệ: {type(route).__name__}")


_REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d$")


def valid_region(region: str) -> bool:
    """Region AWS hợp lệ (vd us-east-1, us-gov-west-1). Region đi vào hostname nên PHẢI khớp chặt."""
    return bool(isinstance(region, str) and len(region) <= 32 and _REGION_RE.fullmatch(region))


def _sdk_http_client(cfg: Dict[str, Any], timeout: float):
    """httpx client cho SDK: KHÔNG đọc proxy env, KHÔNG follow redirect; base_url tuỳ chỉnh đi qua guard SSRF.
    Anthropic/Bedrock (SDK 2.x) dùng httpx2; OpenAI-compatible dùng httpx."""
    from api.services import url_guard
    provider = cfg.get("provider")
    lib = "httpx" if provider in _OPENAI_FAMILY else "httpx2"
    if provider == "openai" and (cfg["openai"].get("base_url") or "").strip():
        return url_guard.guarded_async_client("cloud", timeout=timeout, lib=lib)
    if provider in ("azure_openai", "vertex", "openai_compatible"):    # [PR-6] host dựng từ tham số do người dùng/ADMIN đặt → kiểm IP + ghim ở MỖI request
        return url_guard.guarded_async_client("cloud", timeout=timeout, lib=lib)
    return url_guard.plain_async_client(lib, timeout=timeout)


def _build_cloud_client(cfg: Dict[str, Any], probe: bool = False) -> Tuple[Any, str, str]:
    """Dựng client cloud từ cfg một-provider. Secret chỉ được giải mã ở đây, vào thẳng client."""
    provider = cfg["provider"]
    http_client = _sdk_http_client(cfg, 10.0 if probe else 180.0)

    # ── OpenAI (ChatGPT) & OpenRouter — SDK openai, API tương thích ──
    if provider in ("openai", "openrouter"):
        from openai import AsyncOpenAI
        from api.services.ai_config import get_api_key, OPENROUTER_BASE_URL
        sec = cfg[provider]
        key = get_api_key(provider, cfg)
        if not key:
            raise RuntimeError(f"Chưa cấu hình API key cho {provider} (Settings → AI Provider)")
        if provider == "openrouter":
            base_url = OPENROUTER_BASE_URL
            default_headers = {"HTTP-Referer": "https://github.com/datntpro/VulnGuard",
                               "X-Title": "VulnGuard"}
            model = sec.get("model") or "anthropic/claude-3.5-sonnet"
        else:
            base_url = (sec.get("base_url") or "").strip() or None
            default_headers = None
            if base_url:    # [PR-4] URL do ADMIN đặt: kiểm SSRF lúc lưu VÀ lúc gọi (IP ghim, không redirect)
                from api.services import url_guard
                base_url = url_guard.check_url(base_url, "cloud")
            model = sec.get("model") or "gpt-4o"
        client = AsyncOpenAI(api_key=key, base_url=base_url, timeout=180.0,
                             default_headers=default_headers, http_client=http_client)
        return client, model, "openai"

    if provider in ("azure_openai", "gemini", "vertex", "openai_compatible"):
        return _build_extended_openai_client(cfg, http_client)

    import anthropic

    timeout = anthropic.Timeout(180.0, connect=10.0)
    if provider == "bedrock":
        b = cfg["bedrock"]
        if b.get("region") and not valid_region(b["region"]):
            from api.services import url_guard
            raise url_guard.UrlRejected("region AWS không hợp lệ")   # region đi vào hostname → chặn injection
        auth_mode = b.get("auth_mode", "aws_chain")
        bedrock_tok = None
        if auth_mode == "bedrock_api_key":
            from api.services.ai_config import get_api_key
            tok = get_api_key("bedrock", cfg)
            if not tok:
                raise RuntimeError("Chưa cấu hình Bedrock API key (Settings → AI Provider)")
            # Truyền token theo TỪNG client — KHÔNG ghi os.environ (tiến trình con sẽ thừa hưởng)
            bedrock_tok = tok
        client = anthropic.AsyncAnthropicBedrockMantle(
            api_key=bedrock_tok,
            aws_region=b.get("region") or None,
            aws_profile=(b.get("aws_profile") or None) if auth_mode == "profile" else None,
            timeout=timeout, http_client=http_client,
            # Bedrock không có server-side `fallbacks` → dùng middleware phía client
            middleware=[anthropic.BetaRefusalFallbackMiddleware([{"model": "anthropic.claude-opus-4-8"}])],
        )
        return client, b.get("model") or "anthropic.claude-opus-5-5", "bedrock"

    a = cfg["anthropic"]
    mode = a.get("auth_mode", "api_key")
    if mode == "api_key":
        from api.services.ai_config import get_anthropic_api_key
        key = get_anthropic_api_key(cfg)
        if not key:
            raise RuntimeError("Chưa cấu hình Anthropic API key (Settings → AI Provider)")
        client = anthropic.AsyncAnthropic(api_key=key, timeout=timeout, http_client=http_client)
    elif mode == "wif":
        w = a.get("wif") or {}
        for k in ("federation_rule_id", "organization_id", "identity_token_file"):
            if not w.get(k):
                raise RuntimeError(f"WIF thiếu trường {k}")
        creds = anthropic.WorkloadIdentityCredentials(
            identity_token_provider=anthropic.IdentityTokenFile(w["identity_token_file"]),
            federation_rule_id=w["federation_rule_id"],
            organization_id=w["organization_id"],
            service_account_id=w.get("service_account_id") or None,
            workspace_id=w.get("workspace_id") or None,
        )
        client = anthropic.AsyncAnthropic(credentials=creds, timeout=timeout, http_client=http_client)
    else:  # environment — ANTHROPIC_API_KEY / ant auth login profile
        client = anthropic.AsyncAnthropic(timeout=timeout, http_client=http_client)
    return client, a.get("model") or "claude-opus-5-5", "anthropic_first"


# ─────────────────────────────────────────────
# [AI PR-6] Azure OpenAI / Gemini / Vertex / OpenAI-compatible — SDK openai, family "openai"
# ─────────────────────────────────────────────
def _build_extended_openai_client(cfg: Dict[str, Any], http_client) -> Tuple[Any, str, str]:
    """Tham số quyết định NƠI gửi khoá được kiểm lại ở ĐÂY (hàng DB / body test có thể bị sửa)."""
    from openai import AsyncAzureOpenAI, AsyncOpenAI
    from api.services import ai_oauth, ai_provider_params as pp, url_guard
    from api.services.ai_config import get_api_key
    provider = cfg["provider"]
    sec = cfg[provider]
    key = get_api_key(provider, cfg)
    model, _family = _model_family(provider, sec)

    if provider == "azure_openai":
        endpoint = pp.check_azure_endpoint(sec.get("endpoint"))
        deployment = pp.check_deployment(sec.get("deployment") or sec.get("model"))
        api_version = pp.check_api_version(sec.get("api_version"))
        if sec.get("auth_mode", "api_key") == "entra":
            if not key:
                raise RuntimeError("Chưa cấu hình client secret Entra cho Azure OpenAI")
            provider_fn = ai_oauth.entra_token_provider(sec.get("tenant_id"), sec.get("client_id"), key)
            client = AsyncAzureOpenAI(azure_endpoint=endpoint, api_version=api_version, azure_ad_token_provider=provider_fn,
                                      timeout=180.0, http_client=http_client)
        else:
            if not key:
                raise RuntimeError("Chưa cấu hình API key cho Azure OpenAI (Settings → AI Provider)")
            client = AsyncAzureOpenAI(azure_endpoint=endpoint, api_version=api_version, api_key=key,
                                      timeout=180.0, http_client=http_client)
        return client, deployment, "openai"

    if provider == "gemini":
        if not key:
            raise RuntimeError("Chưa cấu hình API key Gemini (Settings → AI Provider)")
        client = AsyncOpenAI(api_key=key, base_url=pp.GEMINI_BASE_URL, timeout=180.0, http_client=http_client)
        return client, model, "openai"

    if provider == "vertex":
        if not key:
            raise RuntimeError("Chưa cấu hình service account JSON cho Vertex AI (Settings → AI Provider)")
        base_url = pp.vertex_base_url(sec.get("project"), sec.get("location"))
        client = AsyncOpenAI(api_key=ai_oauth.google_token_provider(key), base_url=base_url, timeout=180.0,
                             http_client=http_client)
        return client, model, "openai"

    # openai_compatible: ADMIN đặt base_url (bắt buộc) → check_url khi dựng + guard ở mỗi request
    base = (sec.get("base_url") or "").strip()
    if not base:
        raise RuntimeError("Chưa cấu hình base_url cho endpoint OpenAI-compatible")
    base_url = url_guard.check_url(base, "cloud")
    if not model:
        raise RuntimeError("Chưa cấu hình model cho endpoint OpenAI-compatible")
    client = AsyncOpenAI(api_key=key or "no-key", base_url=base_url, timeout=180.0, http_client=http_client)
    return client, model, "openai"
