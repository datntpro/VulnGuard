"""[AI PR-4] Probe kiểm tra key / kết nối — gọi nhỏ nhất có thể, CHỈ trả mã kết quả.

  probe_cloud(route)            → ProbeResult   (Anthropic / OpenAI-compatible / OpenRouter / Bedrock)
  ollama_check(url, model)      → dict          (version, tags, tool-calling, JSON; cache 1 giờ)
  throttle(user_id)             → raise ThrottleError nếu vượt 5 lần/phút/người dùng hoặc 20 lần/phút toàn cục

Bất biến: kết quả KHÔNG bao giờ chứa văn bản của provider (chỉ mã chuẩn hoá + số liệu); trust_env=False,
không redirect, timeout 10s (probe chat Ollama 60s vì model có thể đang nạp). Chi tiết lỗi thô chỉ ghi DEBUG
(qua filter che key ở PR-2).
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import deque
from dataclasses import asdict, dataclass
from typing import Any, Deque, Dict, Optional, Tuple

import httpx

from api.services import url_guard

logger = logging.getLogger(__name__)

VALID = "VALID"
INVALID_KEY = "INVALID_KEY"
NO_MODEL_ACCESS = "NO_MODEL_ACCESS"
RATE_LIMITED = "RATE_LIMITED"
NETWORK = "NETWORK"
TIMEOUT = "TIMEOUT"
BAD_BASE_URL = "BAD_BASE_URL"
PROVIDER_ERROR = "PROVIDER_ERROR"
NO_CREDENTIAL = "NO_CREDENTIAL"

PROBE_TIMEOUT = 10.0
OLLAMA_CHAT_TIMEOUT = 60.0
OLLAMA_CACHE_TTL = 3600.0

# Thông điệp cố định cho từng mã (UI dịch theo `code`; đây chỉ là fallback an toàn)
CODE_MESSAGES = {
    VALID: "", INVALID_KEY: "Provider từ chối khoá — kiểm tra hoặc thay API key",
    NO_MODEL_ACCESS: "Khoá không có quyền với model này, hoặc model id không tồn tại",
    RATE_LIMITED: "Bị giới hạn tốc độ — thử lại sau", NETWORK: "Không kết nối được provider",
    TIMEOUT: "Hết thời gian chờ provider", BAD_BASE_URL: "Base URL không hợp lệ hoặc bị chặn bởi chính sách an toàn",
    PROVIDER_ERROR: "Provider đang lỗi", NO_CREDENTIAL: "Chưa cấu hình khoá",
}


@dataclass
class ProbeResult:
    ok: bool
    code: str
    model: Optional[str] = None
    latency_ms: int = 0
    tools: Optional[bool] = None      # model nhận được `tools` trong request
    real_model: Optional[str] = None  # [PR-6 S2] model nền do provider báo về (Azure: không tin tên deployment)
    json: Optional[bool] = None       # cloud: không probe (None); Ollama: xem ollama_check

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["error"] = None if self.ok else CODE_MESSAGES.get(self.code, "Lỗi")
        return d


# ─────────────────────────────────────────────
# Throttle (5/phút/người dùng, 20/phút toàn cục) — bộ nhớ tiến trình
# ─────────────────────────────────────────────
class ThrottleError(RuntimeError):
    pass


_PER_USER, _GLOBAL, _WINDOW = 5, 20, 60.0
_user_hits: Dict[str, Deque[float]] = {}
_global_hits: Deque[float] = deque()


def throttle(user_id: Optional[str], now: Optional[float] = None) -> None:
    now = time.monotonic() if now is None else now
    while _global_hits and now - _global_hits[0] > _WINDOW:
        _global_hits.popleft()
    uh = _user_hits.setdefault(user_id or "-", deque())
    while uh and now - uh[0] > _WINDOW:
        uh.popleft()
    if len(uh) >= _PER_USER or len(_global_hits) >= _GLOBAL:
        raise ThrottleError("Quá nhiều lần kiểm tra — thử lại sau một phút")
    uh.append(now)
    _global_hits.append(now)


def reset_throttle() -> None:
    _user_hits.clear()
    _global_hits.clear()


# ─────────────────────────────────────────────
# Phân loại lỗi → mã chuẩn hoá (không đọc/trả body của provider)
# ─────────────────────────────────────────────
def _guard_in_chain(exc: BaseException) -> bool:
    """SDK (openai/anthropic) bọc lỗi transport thành APIConnectionError → guard nằm ở __cause__/__context__."""
    seen = set()
    while exc is not None and id(exc) not in seen and len(seen) < 8:
        if isinstance(exc, (url_guard.UrlRejected, url_guard.GuardRejected)):
            return True
        seen.add(id(exc))
        exc = exc.__cause__ or exc.__context__
    return False


def classify(exc: BaseException, stage: str = "list") -> str:
    if isinstance(exc, url_guard.UrlRejected) or _guard_in_chain(exc):
        return BAD_BASE_URL
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError, httpx.TimeoutException)):
        return TIMEOUT
    if isinstance(exc, url_guard.GuardRejected):
        return BAD_BASE_URL
    status = getattr(exc, "status_code", None) or getattr(getattr(exc, "response", None), "status_code", None)
    name = type(exc).__name__.lower()
    if isinstance(status, int):
        if 300 <= status < 400:
            return BAD_BASE_URL       # redirect không được theo
        if status == 401:
            return INVALID_KEY
        if status == 403:
            return INVALID_KEY if stage == "list" else NO_MODEL_ACCESS
        if status in (400, 404, 422):
            return NO_MODEL_ACCESS
        if status == 429:
            return RATE_LIMITED
        if status >= 500:
            return PROVIDER_ERROR
    if "timeout" in name:
        return TIMEOUT
    if "connection" in name or isinstance(exc, (OSError, httpx.TransportError)):
        return NETWORK
    if isinstance(exc, RuntimeError):
        return NO_CREDENTIAL          # lỗi cấu hình do VulnGuard tự raise (thiếu key…)
    return NETWORK


# ─────────────────────────────────────────────
# Cloud probe
# ─────────────────────────────────────────────
_PROBE_TOOL_OPENAI = {"type": "function", "function": {
    "name": "probe", "description": "probe", "parameters": {"type": "object", "properties": {}}}}
_PROBE_TOOL_ANTHROPIC = {"name": "probe", "description": "probe", "input_schema": {"type": "object", "properties": {}}}


async def probe_cloud(route, *, timeout: float = PROBE_TIMEOUT) -> ProbeResult:
    """Probe một Route cloud (hoặc Refuse). Không bao giờ raise."""
    from api.services.llm_resolver import Cloud, RouteRefused, open_client
    t0 = time.monotonic()

    def done(ok, code, model=None, tools=None, real=None):
        return ProbeResult(ok, code, model, int((time.monotonic() - t0) * 1000), tools, real, None)

    if not isinstance(route, Cloud):
        return done(False, NO_CREDENTIAL)
    model = route.model
    client = None
    stage = {"v": "list"}
    try:
        client, model, family = open_client(route, probe=True)
        mark = lambda: stage.__setitem__("v", "call")   # noqa: E731
        info: Dict[str, Any] = {}
        coro = (_openai_calls_staged(client, model, mark, route.provider, info) if family == "openai"
                else _anthropic_calls_staged(client, model, family, mark))
        tools = await asyncio.wait_for(coro, timeout=timeout)
        real = info.get("model")
        if route.provider == "azure_openai" and isinstance(real, str) and real:
            # allowlist theo model THẬT: deployment đặt tên rẻ/được phép nhưng thực chất là model khác → từ chối
            from api.services import ai_policy
            pol = ai_policy.get_policy()
            if not ai_policy.is_allowed_model(pol, "azure_openai", real):
                return done(False, NO_MODEL_ACCESS, model, tools, real)
        return done(True, VALID, model, tools, real)
    except RouteRefused:
        return done(False, NO_CREDENTIAL, model)
    except Exception as e:     # noqa: BLE001 — mọi lỗi → mã chuẩn hoá
        code = classify(e, stage["v"])
        logger.debug("probe %s lỗi: %s", route.provider, type(e).__name__)
        return done(False, code, model)
    finally:
        if client is not None:
            try:
                await client.close()
            except Exception:
                pass


# [AI PR-6] Azure (khoá theo deployment) và Vertex (không có /models) không có bước liệt kê model; endpoint
# OpenAI-compatible tuỳ chỉnh có thể không hỗ trợ /models → 404/405 ở bước list không coi là lỗi.
_NO_LIST = frozenset({"azure_openai", "vertex"})


async def _openai_calls_staged(client, model, mark, provider: str = "openai", info: Optional[Dict[str, Any]] = None):
    if provider not in _NO_LIST:
        try:
            await client.models.list()
        except Exception as e:
            if provider != "openai_compatible" or getattr(e, "status_code", None) not in (404, 405):
                raise
    mark()
    return await _openai_chat(client, model, info)


async def _openai_chat(client, model, info: Optional[Dict[str, Any]] = None) -> bool:
    msgs = [{"role": "user", "content": "hi"}]

    async def chat(**kw):
        for tok_arg in ("max_completion_tokens", "max_tokens"):
            try:
                r = await client.chat.completions.create(model=model, messages=msgs, **{tok_arg: 1}, **kw)
                if info is not None and isinstance(getattr(r, "model", None), str):
                    info["model"] = r.model[:120]
                return r
            except Exception as e:
                if getattr(e, "status_code", None) not in (400, 422) or tok_arg == "max_tokens":
                    raise
    try:
        await chat(tools=[_PROBE_TOOL_OPENAI])
        return True
    except Exception as e:
        if getattr(e, "status_code", None) not in (400, 422):
            raise
    await chat()
    return False


async def _anthropic_calls_staged(client, model, family, mark) -> bool:
    if family != "bedrock":
        await client.models.list(limit=1)
    mark()
    msgs = [{"role": "user", "content": "hi"}]
    try:
        await client.messages.create(model=model, max_tokens=1, messages=msgs, tools=[_PROBE_TOOL_ANTHROPIC])
        return True
    except Exception as e:
        if getattr(e, "status_code", None) not in (400, 422):
            raise
    await client.messages.create(model=model, max_tokens=1, messages=msgs)
    return False


# ─────────────────────────────────────────────
# Ollama capability check
# ─────────────────────────────────────────────
_ollama_cache: Dict[Tuple[str, str], Tuple[float, Dict[str, Any]]] = {}

_OLLAMA_TOOL = {"type": "function", "function": {
    "name": "get_weather", "description": "Get the weather for a city",
    "parameters": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}}}


def clear_ollama_cache() -> None:
    _ollama_cache.clear()


def cached_capability(url: str, model: str) -> Optional[Dict[str, Any]]:
    """Kết quả check còn hạn (không gọi mạng) — cho routing D7 / thẻ `tools ✓/✗`."""
    hit = _ollama_cache.get((url, model))
    if hit and time.monotonic() - hit[0] < OLLAMA_CACHE_TTL:
        return hit[1]
    return None


async def _get_json(client: httpx.AsyncClient, url: str) -> Any:
    async with client.stream("GET", url) as r:
        if 300 <= r.status_code < 400:
            raise url_guard.UrlRejected("redirect không được theo")
        r.raise_for_status()
        return json.loads(await url_guard.read_capped(r))


async def _post_json(client: httpx.AsyncClient, url: str, body: dict, timeout: float) -> Any:
    async with client.stream("POST", url, json=body, timeout=timeout) as r:
        if 300 <= r.status_code < 400:
            raise url_guard.UrlRejected("redirect không được theo")
        r.raise_for_status()
        return json.loads(await url_guard.read_capped(r))


def _installed(model: str, names: set) -> bool:
    return model in names or (":" not in model and f"{model}:latest" in names)


async def ollama_check(url: str, model: Optional[str] = None, *, force: bool = False,
                       client: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
    """Capability check. Không raise; không trả văn bản của server."""
    from api.services.llm_resolver import LLMContext, resolve_local
    eff = resolve_local(LLMContext(feature="test"))      # URL/model hiệu lực chỉ lấy qua resolver
    url = (url or eff.url).strip().rstrip("/")
    model = (model or eff.model).strip()
    if not force:
        hit = cached_capability(url, model)
        if hit is not None:
            return {**hit, "cached": True}
    t0 = time.monotonic()
    res: Dict[str, Any] = {"ok": False, "code": NETWORK, "url": url, "model": model, "version": None,
                           "model_installed": False, "tools": False, "json": False, "latency_ms": 0, "cached": False}

    def finish(code: str) -> Dict[str, Any]:
        res["code"] = code
        res["ok"] = code == VALID
        res["latency_ms"] = int((time.monotonic() - t0) * 1000)
        res["error"] = None if res["ok"] else CODE_MESSAGES.get(code, "Lỗi")
        if code in (VALID, NO_MODEL_ACCESS):      # lỗi mạng không cache — thử lại được ngay
            _ollama_cache[(url, model)] = (time.monotonic(), dict(res))
        return res

    try:
        norm = url_guard.check_url(url, "ollama")
    except url_guard.UrlRejected:
        return finish(BAD_BASE_URL)
    own = client is None
    c = client or url_guard.guarded_async_client("ollama", timeout=PROBE_TIMEOUT)
    try:
        ver = await _get_json(c, f"{norm}/api/version")
        res["version"] = str(ver.get("version"))[:32] if isinstance(ver, dict) else None
        tags = await _get_json(c, f"{norm}/api/tags")
        names = {m.get("name", "") for m in (tags.get("models") or [])} if isinstance(tags, dict) else set()
        res["model_installed"] = _installed(model, names)
        if not res["model_installed"]:
            return finish(NO_MODEL_ACCESS)
        chat = {"model": model, "stream": False, "options": {"num_predict": 64, "temperature": 0}}
        r1 = await _post_json(c, f"{norm}/api/chat", {
            **chat, "tools": [_OLLAMA_TOOL],
            "messages": [{"role": "user", "content": "What is the weather in Hanoi? Use the tool."}]}, OLLAMA_CHAT_TIMEOUT)
        calls = ((r1.get("message") or {}).get("tool_calls")) if isinstance(r1, dict) else None
        res["tools"] = bool(calls) and isinstance(calls, list)
        ok_json = 0
        for _ in range(3):
            r2 = await _post_json(c, f"{norm}/api/chat", {
                **chat, "format": "json", "options": {"num_predict": 64, "temperature": 0},
                "messages": [{"role": "user", "content": 'Reply with a JSON object {"ok": true}.'}]}, OLLAMA_CHAT_TIMEOUT)
            try:
                if isinstance(json.loads(((r2.get("message") or {}).get("content")) or ""), dict):
                    ok_json += 1
            except (ValueError, AttributeError):
                pass
        res["json"] = ok_json == 3
        return finish(VALID)
    except Exception as e:     # noqa: BLE001
        logger.debug("ollama_check lỗi: %s", type(e).__name__)
        return finish(classify(e, "call"))
    finally:
        if own:
            await c.aclose()
