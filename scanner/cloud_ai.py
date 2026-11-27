"""
Cloud AI analyzer — Claude (Anthropic API / Amazon Bedrock), OpenAI (ChatGPT) & OpenRouter.

Mục tiêu chính: GIẢM FALSE POSITIVE so với model local nhỏ:
  1. Model mạnh hơn (mặc định claude-opus-5-5) + structured output (JSON schema
     được API đảm bảo → không còn lỗi "AI không parse được").
  2. Gửi NGỮ CẢNH CODE THẬT (±N dòng quanh finding, đọc từ scan_path) thay vì
     snippet 300 ký tự — phần lớn FP của SAST chỉ nhận ra được khi thấy
     input có thực sự tới sink hay không.
  3. Có verdict "needs_review" để model không phải đoán khi thiếu ngữ cảnh.

Xác thực (xem api/services/ai_config.py):
  anthropic/api_key      — API key Claude Console (org cá nhân hoặc workspace doanh nghiệp)
  anthropic/wif          — Workload Identity Federation: đổi JWT từ IdP doanh nghiệp
                           (Entra ID, Okta, Google, K8s SA…) lấy token Anthropic ngắn hạn
  anthropic/environment  — SDK tự resolve: ANTHROPIC_API_KEY / `ant auth login` profile trên host
  bedrock                — AWS credential chain / profile IAM Identity Center (aws sso login)

Privacy: secret trong code được redact trước khi gửi (privacy.redact_secrets).
"""
import json
import logging
import os
import re
import time
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """Bạn là chuyên gia AppSec senior đang TRIAGE kết quả của các công cụ quét bảo mật tự động \
(SAST, SCA, IaC, secret scanning, DAST) cho đội phát triển sở hữu chính mã nguồn/hệ thống này. \
Mục tiêu là giúp đội phòng thủ: loại bỏ báo động giả (false positive) và ưu tiên sửa lỗi thật.

Nguyên tắc đánh giá false positive:
- Truy vết luồng dữ liệu: dữ liệu không tin cậy có thực sự tới sink không? Có validate/escape/parameterize trên đường đi không?
- File test, fixture, ví dụ, mock, script dev-only, code chết → thường ít rủi ro (nhưng secret thật trong test vẫn là lỗi thật).
- Secret: giá trị placeholder/ví dụ ("changeme", "xxx", "<your-key>", biến môi trường) là FP; chuỗi có entropy cao, đúng format nhà cung cấp là lỗi thật.
- SCA: CVE chỉ quan trọng nếu hàm/tính năng bị lỗi được dùng và package nằm trong runtime (không phải devDependency).
- IaC: cân nhắc resource có public-facing không.
- Nếu ngữ cảnh KHÔNG đủ để kết luận, chọn verdict "needs_review" và nói rõ cần kiểm tra thêm gì — đừng đoán.

Trả lời bằng tiếng Việt, cụ thể theo code được cung cấp, không chung chung. \
fix_suggestion nên có đoạn code sửa nếu phù hợp."""

ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["true_positive", "false_positive", "needs_review"]},
        "false_positive_likelihood": {"type": "integer", "description": "0 = chắc chắn lỗi thật, 100 = chắc chắn false positive"},
        "false_positive_reason": {"type": "string"},
        "exploitability_public": {"type": "string"},
        "exploitability_private": {"type": "string"},
        "explanation": {"type": "string"},
        "fix_suggestion": {"type": "string"},
    },
    "required": ["verdict", "false_positive_likelihood", "false_positive_reason",
                 "exploitability_public", "exploitability_private", "explanation", "fix_suggestion"],
    "additionalProperties": False,
}

VERDICT_LABEL = {
    "true_positive": "Lỗi thật",
    "false_positive": "Khả năng cao là false positive",
    "needs_review": "Cần review thủ công",
}

# ─────────────────────────────────────────────
# Redaction — che secret trước khi gửi ra cloud
# ─────────────────────────────────────────────
_SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{10,}"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}"),
    re.compile(r"\bsk-or-v1-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"\bABSK[A-Za-z0-9+/=_\-]{20,}"),         # Bedrock API key
    re.compile(r"\bksk_[A-Za-z0-9_\-]{16,}"),             # Kiro API key
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    # [AI PR-2] Azure OpenAI key (32 hex) đứng sau `api-key`; Google service-account JSON (private_key_id / client_email)
    re.compile(r"(?i)\bapi-key[\"':= ]{1,4}[0-9a-f]{32}\b"),
    re.compile(r"\"private_key_id\"\s*:\s*\"[0-9a-f]{20,}\""),
    re.compile(r"[A-Za-z0-9\-]+@[A-Za-z0-9\-]+\.iam\.gserviceaccount\.com"),
]
_ASSIGN_PATTERN = re.compile(
    r"""(?i)((?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth)"""
    r"""[\w\-]*\s*[:=]\s*['"])([^'"\s]{4,})(['"])"""
)


_BEARER_PATTERN = re.compile(r"(?i)\b(bearer|x-api-key:?|api-key:?)\s+[A-Za-z0-9._~+/=\-]{8,}")
_URL_QS_SECRET = re.compile(r"(?i)([?&](?:key|api[_-]?key|token|access_token|sig|signature)=)[^&\s'\"]+")


def sanitize_error(exc: BaseException) -> str:
    """Thông điệp lỗi AN TOÀN để trả UI / lưu DB: mã chuẩn hoá + chi tiết đã che.
    Không bao giờ trả nguyên body/URL/key của provider."""
    status = getattr(exc, "status_code", None)
    name = type(exc).__name__
    if status in (401, 403):
        code, msg = "auth_failed", f"Provider từ chối khoá ({status}) — kiểm tra/ thay API key"
    elif status in (400, 413, 422):
        code, msg = "bad_request", f"Yêu cầu bị từ chối ({status}) — kiểm tra model id / độ dài prompt"
    elif status == 404:
        code, msg = "not_found", "Model hoặc endpoint không tồn tại (404)"
    elif status == 429:
        code, msg = "rate_limited", "Bị giới hạn tốc độ (429) — thử lại sau"
    elif isinstance(status, int) and status >= 500:
        code, msg = "provider_error", f"Provider lỗi ({status})"
    elif "timeout" in name.lower():
        code, msg = "timeout", "Hết thời gian chờ provider"
    elif "connection" in name.lower() or isinstance(exc, OSError):
        code, msg = "connection_error", "Không kết nối được provider"
    elif isinstance(exc, RuntimeError):
        # lỗi cấu hình do chính VulnGuard raise (thông điệp tự viết, không chứa body provider)
        code, msg = "config_error", redact_text_basic(str(exc))[:200]
    else:
        code, msg = "error", f"Lỗi không xác định ({name})"
    return f"[{code}] {msg}"


def redact_text_basic(text: str) -> str:
    """Che secret + bearer + query-secret (không che PII) — dùng cho thông điệp lỗi."""
    for pat in _SECRET_PATTERNS:
        text = pat.sub(lambda m: _mask(m.group(0)), text)
    text = _BEARER_PATTERN.sub(lambda m: m.group(1) + " [REDACTED]", text)
    text = _URL_QS_SECRET.sub(lambda m: m.group(1) + "[REDACTED]", text)
    return re.sub(r"https?://\S+", "[url]", text)


def _mask(value: str) -> str:
    return f"{value[:3]}…[REDACTED {len(value)} ký tự]"


# P0.7: PII tiếng Việt / nội bộ — che trước khi gửi ra cloud
_PII_PATTERNS = [
    (re.compile(r"\b\d{12}\b"), "[CCCD]"),                                   # CCCD/CMND 12 số
    (re.compile(r"\b\d{9}\b"), "[CMND]"),                                    # CMND 9 số
    (re.compile(r"(?<!\d)(?:\+?84|0)(?:\d[ .-]?){8,9}\d(?!\d)"), "[SĐT]"),   # số điện thoại VN
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[EMAIL]"),
    (re.compile(r"\b(?:10|127|192\.168|169\.254)(?:\.\d{1,3}){1,3}\b"), "[IP_NỘI_BỘ]"),
    (re.compile(r"\b172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}\b"), "[IP_NỘI_BỘ]"),
]


def redact_pii(text: str) -> str:
    if not text:
        return text
    for pat, tag in _PII_PATTERNS:
        text = pat.sub(tag, text)
    return text


def redact(text: str) -> str:
    if not text:
        return text
    for pat in _SECRET_PATTERNS:
        text = pat.sub(lambda m: _mask(m.group(0)), text)
    text = _ASSIGN_PATTERN.sub(lambda m: m.group(1) + _mask(m.group(2)) + m.group(3), text)
    return redact_pii(text)   # P0.7: che luôn PII sau secret


# ─────────────────────────────────────────────
# Code context
# ─────────────────────────────────────────────
def read_code_context(scan_path: str, file_path: str, line: int, radius: int) -> Optional[str]:
    """Đọc ±radius dòng quanh `line`, đánh số dòng, đánh dấu dòng finding bằng '>>'.
    Chỉ đọc file nằm TRONG scan_path (chống path traversal)."""
    if not scan_path or not file_path or radius <= 0:
        return None
    try:
        root = os.path.realpath(scan_path)
        cand = file_path if os.path.isabs(file_path) else os.path.join(root, file_path)
        real = os.path.realpath(cand)
        if not (real == root or real.startswith(root + os.sep)) or not os.path.isfile(real):
            return None
        if os.path.getsize(real) > 5 * 1024 * 1024:
            return None
        with open(real, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        if not lines:
            return None
        line = max(1, int(line or 1))
        start, end = max(1, line - radius), min(len(lines), line + radius)
        out = []
        for n in range(start, end + 1):
            mark = ">>" if n == line else "  "
            out.append(f"{mark}{n:5d} | {lines[n - 1].rstrip()[:400]}")
        return "\n".join(out)
    except Exception as e:
        logger.debug(f"read_code_context lỗi: {e}")
        return None


def build_user_prompt(v: Dict[str, Any], code_context: Optional[str], local_opinion: Optional[dict],
                      do_redact: bool) -> str:
    def r(s):
        s = str(s or "")
        return redact(s) if do_redact else s

    parts = [
        "## Finding",
        f"- Tool: {v.get('tool','')} ({v.get('scan_type','')})",
        f"- Rule/CVE: {v.get('rule_id','')} | CWE: {v.get('cwe','') or '-'} | CVE: {v.get('cve','') or '-'}",
        f"- Tiêu đề: {r(v.get('title',''))}",
        f"- Severity do tool gán: {v.get('severity','')}",
        f"- File: {v.get('file_path','') or '-'} (dòng {v.get('line_start', 0) or '-'})",
    ]
    if v.get("package_name"):
        parts.append(f"- Package: {v.get('package_name')} {v.get('package_version','')} "
                     f"(bản sửa: {v.get('fixed_version','') or 'chưa có'})")
    parts += ["", "## Mô tả từ tool", r(v.get("description", ""))[:2000] or "(không có)"]
    if v.get("code_snippet"):
        parts += ["", "## Snippet tool báo", "```", r(v.get("code_snippet"))[:1500], "```"]
    if code_context:
        parts += ["", "## Ngữ cảnh code thực tế (dòng đánh dấu >> là dòng finding)", "```",
                  r(code_context), "```"]
    if local_opinion and local_opinion.get("false_positive_likelihood") not in (None, "", "N/A"):
        parts += ["", "## Ý kiến sơ bộ của model local (có thể sai)",
                  f"- FP likelihood: {local_opinion.get('false_positive_likelihood')}",
                  f"- Lý do: {str(local_opinion.get('false_positive_reason',''))[:500]}"]
    parts += ["", "Hãy triage finding này."]
    return "\n".join(parts)


_PROVIDER_LABEL = {"anthropic_first": "claude-api", "bedrock": "bedrock",
                   "openai": "openai"}


class CloudAnalyzer:
    def __init__(self, route=None, cfg: Optional[Dict[str, Any]] = None):
        """route: Cloud route từ api.services.llm_resolver (client chỉ dựng qua resolver).
        cfg: chỉ để đọc `privacy` (không chứa quyết định route)."""
        from api.services.ai_config import load_config
        from api.services.llm_resolver import LLMContext, open_client, resolve
        self.cfg = cfg or load_config()
        route = route or resolve(LLMContext(feature="test"))
        self.route = route
        self.client, self.model, self.family = open_client(route)
        self.first_party = self.family == "anthropic_first"

    @property
    def provider_label(self) -> str:
        prov = getattr(self.route, "provider", None) or self.cfg.get("provider", "")
        base = _PROVIDER_LABEL.get(self.family, prov)
        # openrouter dùng family openai nhưng ghi nhãn theo provider thật
        if prov == "openrouter":
            base = "openrouter"
        return f"{base}:{self.model}"

    async def _create(self, system: str, user: str, schema: dict, max_tokens: int = 8000) -> str:
        if self.family == "openai":
            return await self._create_openai(system, user, schema, max_tokens)
        return await self._create_anthropic(system, user, schema, max_tokens)

    async def _create_anthropic(self, system: str, user: str, schema: dict, max_tokens: int) -> str:
        kwargs = dict(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
            output_config={"effort": "medium", "format": {"type": "json_schema", "schema": schema}},
        )
        if self.first_party:
            # Nội dung bảo mật đôi khi chạm classifier `cyber` → server tự chạy lại trên
            # model fallback phù hợp thay vì trả refusal trống.
            kwargs["betas"] = ["server-side-fallback-2026-07-01"]
            kwargs["fallbacks"] = "default"
        resp = await self.client.beta.messages.create(**kwargs)
        if resp.stop_reason == "refusal":
            cat = getattr(getattr(resp, "stop_details", None), "category", None)
            raise RuntimeError(f"Model từ chối phân tích (category={cat})")
        if resp.stop_reason == "max_tokens":
            raise RuntimeError("Model hết max_tokens trước khi trả đủ JSON")
        text = next((b.text for b in resp.content if b.type == "text"), "")
        return text

    async def _create_openai(self, system: str, user: str, schema: dict, max_tokens: int) -> str:
        """OpenAI / OpenRouter — Chat Completions + structured output.

        Thử json_schema (strict); nếu model/endpoint không hỗ trợ thì lùi về
        json_object + ép schema trong prompt.
        """
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        rf_schema = {"type": "json_schema",
                     "json_schema": {"name": "analysis", "schema": schema, "strict": True}}
        try:
            resp = await self.client.chat.completions.create(
                model=self.model, messages=messages,
                max_completion_tokens=max_tokens, response_format=rf_schema)
            return resp.choices[0].message.content or ""
        except Exception as e:
            msg = str(e).lower()
            if not any(k in msg for k in ("response_format", "json_schema", "schema", "unsupported", "400", "invalid")):
                raise
            # fallback: json_object
            messages[0]["content"] += ("\n\nCHỈ trả về JSON hợp lệ đúng schema sau, "
                                       "không văn bản ngoài JSON:\n" + json.dumps(schema, ensure_ascii=False))
            resp = await self.client.chat.completions.create(
                model=self.model, messages=messages,
                max_completion_tokens=max_tokens, response_format={"type": "json_object"})
            return resp.choices[0].message.content or ""

    async def analyze_finding(self, vuln: Dict[str, Any], local_opinion: Optional[dict] = None) -> Dict[str, Any]:
        privacy = self.cfg["privacy"]
        ctx = None
        if privacy.get("send_code_context"):
            ctx = read_code_context(vuln.get("scan_path", ""), vuln.get("file_path", ""),
                                    vuln.get("line_start", 0), int(privacy.get("context_lines", 15)))
        prompt = build_user_prompt(vuln, ctx, local_opinion, bool(privacy.get("redact_secrets", True)))
        t0 = time.monotonic()
        data = json.loads(await self._create(SYSTEM_PROMPT, prompt, ANALYSIS_SCHEMA))
        fp = max(0, min(100, int(data.get("false_positive_likelihood", 50))))
        verdict = data.get("verdict", "needs_review")
        logger.info(f"[CloudAI] {self.provider_label} {verdict} fp={fp}% ({time.monotonic()-t0:.1f}s)")
        return {
            "false_positive_likelihood": f"{fp}%",
            "false_positive_reason": f"[{VERDICT_LABEL.get(verdict, verdict)}] {data.get('false_positive_reason','')}",
            "exploitability_public": data.get("exploitability_public", ""),
            "exploitability_private": data.get("exploitability_private", ""),
            "explanation": data.get("explanation", ""),
            "fix_suggestion": data.get("fix_suggestion", ""),
            "verdict": verdict,
            "provider": self.provider_label,
        }

    async def ping(self) -> str:
        """Gọi thử 1 request nhỏ — dùng cho POST /api/ai/test."""
        schema = {"type": "object", "properties": {"ok": {"type": "boolean"}},
                  "required": ["ok"], "additionalProperties": False}
        return await self._create("Trả lời JSON.", "Trả về {\"ok\": true}.", schema, max_tokens=2000)
