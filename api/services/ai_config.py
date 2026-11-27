"""
Cấu hình AI provider (Ollama local / Claude API / Amazon Bedrock) — lưu ở
<storage>/ai_config.json. API key được mã hoá (Fernet) trước khi ghi file,
không bao giờ trả lại nguyên văn qua API.

Chế độ (mode):
  local_only — chỉ Ollama, dữ liệu không rời máy (mặc định, giữ hành vi cũ)
  hybrid     — Ollama chấm trước; finding severity ≥ ngưỡng HOẶC FP% rơi vào
               vùng không chắc chắn [fp_band_low, fp_band_high] → gửi Claude xác minh
  cloud_only — mọi finding dùng cloud provider
"""
import copy
import json
import os
import threading
from typing import Any, Dict, Optional

from api.config import settings
from api.security import decrypt_secret, encrypt_secret, mask_secret

DEFAULT_CLAUDE_MODEL = "claude-opus-5-5"
DEFAULT_BEDROCK_MODEL = "anthropic.claude-opus-5-5"
DEFAULT_OPENAI_MODEL = "gpt-4o"
DEFAULT_OPENROUTER_MODEL = "anthropic/claude-3.5-sonnet"
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
# [AI PR-6]
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"
DEFAULT_VERTEX_MODEL = "google/gemini-2.5-flash"
DEFAULT_AZURE_API_VERSION = "2024-10-21"

# Các section provider có chứa API key (được mã hoá → <section>.api_key_enc)
_KEYED_SECTIONS = ("anthropic", "openai", "openrouter", "bedrock", "azure_openai", "gemini", "vertex", "openai_compatible")
PROVIDERS = ("anthropic", "bedrock", "openai", "openrouter", "azure_openai", "gemini", "vertex", "openai_compatible")

DEFAULT_CONFIG: Dict[str, Any] = {
    "provider": "anthropic",          # cloud provider dùng cho hybrid / cloud_only
    "mode": "local_only",
    "anthropic": {
        "auth_mode": "api_key",       # api_key | wif | environment
        "model": DEFAULT_CLAUDE_MODEL,
        "api_key_enc": None,
        "wif": {
            "federation_rule_id": "",
            "organization_id": "",
            "identity_token_file": "",
            "workspace_id": "",
            "service_account_id": "",
        },
    },
    "bedrock": {
        # auth_mode: aws_chain = env/role/default chain · profile = AWS profile do
        #   `aws sso login` / `aws configure` tạo · bedrock_api_key = Bedrock API key
        #   (AWS_BEARER_TOKEN_BEDROCK), dùng cho headless/CI
        "auth_mode": "aws_chain",
        "region": "us-east-1",
        "aws_profile": "",            # tên profile (khi auth_mode=profile)
        "api_key_enc": None,          # Bedrock API key (khi auth_mode=bedrock_api_key)
        "model": DEFAULT_BEDROCK_MODEL,
    },
    "openai": {                       # ChatGPT API (hoặc Azure/endpoint tương thích)
        "model": DEFAULT_OPENAI_MODEL,
        "base_url": "",               # trống = https://api.openai.com/v1
        "api_key_enc": None,
    },
    "openrouter": {                   # OpenRouter — 1 key, nhiều model nhà cung cấp
        "model": DEFAULT_OPENROUTER_MODEL,
        "api_key_enc": None,
    },
    # [AI PR-6] Azure OpenAI: key (user/org) hoặc Entra client-credentials (org). `deployment` là tên gọi trong URL.
    "azure_openai": {
        "auth_mode": "api_key",       # api_key | entra
        "endpoint": "",               # https://<resource>.openai.azure.com (host kiểm chặt)
        "deployment": "",
        "api_version": DEFAULT_AZURE_API_VERSION,
        "tenant_id": "", "client_id": "",     # chỉ khi auth_mode=entra (api_key_enc = client secret)
        "api_key_enc": None,          # `model` của lời gọi = tên deployment (giá ước lượng/policy theo tên đó)
    },
    "gemini": {                       # Gemini API (AI Studio) — endpoint OpenAI-compatible cố định
        "model": DEFAULT_GEMINI_MODEL,
        "api_key_enc": None,
    },
    "vertex": {                       # Vertex AI (org): api_key_enc = service-account JSON
        "auth_mode": "service_account",
        "project": "", "location": "us-central1",
        "model": DEFAULT_VERTEX_MODEL,
        "api_key_enc": None,
    },
    "openai_compatible": {            # endpoint tương thích OpenAI tuỳ chỉnh (vLLM, LiteLLM, …) — ADMIN, qua url_guard
        "base_url": "",
        "model": "",
        "api_key_enc": None,
    },
    "hybrid": {
        "escalate_min_severity": "HIGH",
        "fp_band_low": 15,
        "fp_band_high": 85,
        "tasks": {"coworker": "local"},   # [AI PR-3] A1: dòng Co-work của bảng Hybrid (local mặc định; chỉ ADMIN sửa)
    },
    "policy": {                       # [AI PR-3] xem api/services/ai_policy.py — mặc định = hành vi không đổi
        "byok": "allowed",
        "fallback_to_org": True,
        "allowed": [],
        "org_quota": {"usd_per_user_month": None, "rpm_per_user": None},
        "user_quota_own_keys": {"rpm_per_user": 120},
        "scheduled_jobs_credential": "org",
        "custom_base_url": "admin_only",
        "base_url_allowlist": [],
    },
    "privacy": {
        "send_code_context": True,
        "context_lines": 15,
        "redact_secrets": True,
    },
}

_lock = threading.Lock()


def _path() -> str:
    return os.environ.get("AI_CONFIG_FILE") or os.path.join(settings.storage_dir, "ai_config.json")


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config() -> Dict[str, Any]:
    """Config đầy đủ (internal, còn api_key_enc)."""
    try:
        with open(_path(), "r", encoding="utf-8") as f:
            return _deep_merge(DEFAULT_CONFIG, json.load(f))
    except (FileNotFoundError, json.JSONDecodeError):
        return copy.deepcopy(DEFAULT_CONFIG)


def get_api_key(section: str, cfg: Optional[dict] = None) -> Optional[str]:
    cfg = cfg or load_config()
    return decrypt_secret((cfg.get(section) or {}).get("api_key_enc"))


def get_anthropic_api_key(cfg: Optional[dict] = None) -> Optional[str]:
    return get_api_key("anthropic", cfg)


def public_config(cfg: Optional[dict] = None) -> Dict[str, Any]:
    """Config an toàn để trả về UI — bỏ secret mọi provider, chỉ để lại hint."""
    cfg = copy.deepcopy(cfg or load_config())
    # [AI PR-3] policy chỉ ADMIN thấy (qua /api/ai/settings); id credential org / cờ migrate / kết quả probe là nội bộ
    for k in ("policy", "org_credential_id", "migrations", "probe"):
        cfg.pop(k, None)
    for sec in _KEYED_SECTIONS:
        if not isinstance(cfg.get(sec), dict):
            continue
        key = decrypt_secret(cfg[sec].get("api_key_enc"))
        enc = cfg[sec].pop("api_key_enc", None)
        cfg[sec]["api_key_set"] = bool(enc)
        cfg[sec]["api_key_hint"] = "" if sec == "vertex" else (mask_secret(key) if key else "")   # SA JSON: không hint
    return cfg


_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def validate_and_save(update: Dict[str, Any]) -> Dict[str, Any]:
    cfg = _validate_and_save(update)
    try:   # [AI PR-2] đồng bộ một chiều sang ai_credentials (sau khi nhả lock)
        from api.services import ai_credentials
        ai_credentials.sync_after_save(cfg)
    except Exception:
        pass
    return cfg


def _validate_and_save(update: Dict[str, Any]) -> Dict[str, Any]:
    """Merge update vào config hiện tại, validate, mã hoá api_key mới (nếu có), ghi file."""
    with _lock:
        cfg = load_config()
        old_base_url = str((cfg.get("openai") or {}).get("base_url") or "").strip()
        old_compat_url = str((cfg.get("openai_compatible") or {}).get("base_url") or "").strip()
        update = copy.deepcopy(update or {})
        for k in ("migrations", "org_credential_id", "probe"):   # [AI PR-3] nội bộ — không nhận từ client
            update.pop(k, None)
        # Tách api_key (write-only) của MỌI provider section trước khi merge
        new_keys: Dict[str, Optional[str]] = {}
        for sec in _KEYED_SECTIONS:
            if isinstance(update.get(sec), dict):
                new_keys[sec] = (update[sec].pop("api_key", None) or "").strip() or None
                update[sec].pop("api_key_set", None)
                update[sec].pop("api_key_hint", None)
                update[sec].pop("api_key_enc", None)
                if update[sec].pop("clear_api_key", False):
                    cfg[sec]["api_key_enc"] = None
        cfg = _deep_merge(cfg, update)
        up = update.get("policy")
        if isinstance(up, dict) and "azure_deployment_models" in up:
            # [re-verify L2] ánh xạ deployment→model là REPLACE (không merge) để ADMIN xoá được mục; giá trị null cũng xoá
            cfg.setdefault("policy", {})["azure_deployment_models"] = copy.deepcopy(up["azure_deployment_models"])

        if cfg["provider"] not in PROVIDERS:
            raise ValueError("provider phải thuộc: " + ", ".join(PROVIDERS))
        if cfg["mode"] not in ("local_only", "hybrid", "cloud_only"):
            raise ValueError("mode phải là local_only | hybrid | cloud_only")
        if cfg["anthropic"]["auth_mode"] not in ("api_key", "wif", "environment"):
            raise ValueError("anthropic.auth_mode phải là api_key | wif | environment")
        if cfg["bedrock"].get("auth_mode") not in ("aws_chain", "profile", "bedrock_api_key"):
            raise ValueError("bedrock.auth_mode phải là aws_chain | profile | bedrock_api_key")
        if str(cfg["hybrid"]["escalate_min_severity"]).upper() not in _SEVERITIES:
            raise ValueError("hybrid.escalate_min_severity không hợp lệ")
        cfg["hybrid"]["escalate_min_severity"] = cfg["hybrid"]["escalate_min_severity"].upper()
        lo, hi = int(cfg["hybrid"]["fp_band_low"]), int(cfg["hybrid"]["fp_band_high"])
        if not (0 <= lo <= hi <= 100):
            raise ValueError("fp_band phải thoả 0 ≤ low ≤ high ≤ 100")
        cfg["hybrid"]["fp_band_low"], cfg["hybrid"]["fp_band_high"] = lo, hi
        tasks = cfg["hybrid"].get("tasks")
        if not isinstance(tasks, dict) or tasks.get("coworker", "local") not in ("local", "cloud"):
            raise ValueError("hybrid.tasks.coworker phải là local | cloud")
        from api.services import ai_policy   # [AI PR-3]
        cfg["policy"] = ai_policy.normalize(cfg.get("policy"))
        oa_url = ((update.get("openai") or {}).get("base_url") if isinstance(update.get("openai"), dict) else None)
        if cfg["policy"]["custom_base_url"] == "off" and isinstance(oa_url, str) and oa_url.strip() \
                and oa_url.strip() != old_base_url:       # lưu lại đúng URL cũ không đổi thì được
            raise ValueError("BAD_BASE_URL: custom base_url bị policy tắt")   # áp cho MỌI đường lưu (cả PUT /api/ai/config cũ)
        from api.services import ai_provider_params   # [AI PR-6] tham số nơi gửi khoá của provider mới (kiểm chặt, không DNS)
        for sec in ("azure_openai", "vertex", "openai_compatible"):
            if isinstance(update.get(sec), dict):
                ai_provider_params.validate_section(sec, cfg[sec], secret=new_keys.get(sec))
        ob = ((update.get("openai_compatible") or {}).get("base_url") if isinstance(update.get("openai_compatible"), dict) else None)
        if cfg["policy"]["custom_base_url"] == "off" and isinstance(ob, str) and ob.strip() \
                and ob.strip() != old_compat_url:
            raise ValueError("BAD_BASE_URL: custom base_url bị policy tắt")
        cfg["privacy"]["context_lines"] = max(0, min(int(cfg["privacy"]["context_lines"]), 80))
        for k in ("send_code_context", "redact_secrets"):
            cfg["privacy"][k] = bool(cfg["privacy"][k])
        if not str(cfg["anthropic"]["model"]).strip():
            cfg["anthropic"]["model"] = DEFAULT_CLAUDE_MODEL
        if not str(cfg["bedrock"]["model"]).strip():
            cfg["bedrock"]["model"] = DEFAULT_BEDROCK_MODEL
        if not str(cfg["openai"]["model"]).strip():
            cfg["openai"]["model"] = DEFAULT_OPENAI_MODEL
        if not str(cfg["openrouter"]["model"]).strip():
            cfg["openrouter"]["model"] = DEFAULT_OPENROUTER_MODEL

        if not str(cfg["gemini"]["model"]).strip():
            cfg["gemini"]["model"] = DEFAULT_GEMINI_MODEL
        if not str(cfg["vertex"]["model"]).strip():
            cfg["vertex"]["model"] = DEFAULT_VERTEX_MODEL
        for sec, key in new_keys.items():
            if key and key.startswith("sk-ant-oat"):     # token OAuth gói Claude.ai: không dùng ngoài sản phẩm của Anthropic
                raise ValueError("AI_KEY_UNSUPPORTED: token OAuth của gói Claude.ai (sk-ant-oat…) không dùng được ở đây — "
                                 "hãy tạo API key tại console.anthropic.com")
        for sec, key in new_keys.items():
            if key:
                cfg[sec]["api_key_enc"] = encrypt_secret(key)

        _write_raw(cfg)
        return cfg


def _write_raw(cfg: Dict[str, Any]) -> None:
    path = _path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def update_raw(mutator) -> Dict[str, Any]:
    """[AI PR-2] Đọc-sửa-ghi nguyên tử (cùng lock với validate_and_save) cho dữ liệu nội bộ không qua validate
    (cờ migrations, org_credential_id). `mutator(cfg)` sửa tại chỗ; KHÔNG đụng api_key_enc cũ (giữ để rollback)."""
    with _lock:
        cfg = load_config()
        mutator(cfg)
        _write_raw(cfg)
        return cfg
