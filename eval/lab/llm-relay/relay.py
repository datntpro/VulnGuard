"""Relay LLM cho run capability (P1-7): vg-under-test không có đường ra Internet, còn agent thật cần gọi API.
Relay là thành phần DUY NHẤT của lab có đường ra ngoài, nằm trên mạng riêng `llm_net` chỉ chung với vg-under-test
(KHÔNG nằm trên lab_net: DVWA / Juice Shop / XBOW không với tới được). Làm đúng một việc:
  POST /v1/messages  →  https://api.anthropic.com/v1/messages   (host cố định trong mã, KHÔNG đọc từ request)
P2-15b: (1) allowlist NHIỀU model (RELAY_MODELS, phân tách dấu phẩy; RELAY_MODEL vẫn là allowlist 1 phần tử) với MỘT đồng hồ USD chung —
mỗi model phải có giá trong prices.py (fail closed); (2) RELAY_PROVIDER=ollama (chạy local trên Mac của owner, KHÔNG dùng ở CI):
  POST /v1/chat/completions  →  http://host.docker.internal:11434/v1/chat/completions   (host cố định; không cần key; USD luôn 0, vẫn đếm token)
Kiểm soát (fail closed):
  * xác thực: header `x-api-key` phải bằng RELAY_TOKEN (token ngẫu nhiên mỗi lần chạy) — thiếu/sai ⇒ 401, TRƯỚC khi đụng key thật;
  * chính sách: `model` ∈ allowlist, max_tokens ∈ [1, 8000], không `speed`/`fallbacks`/`stream`, không header anthropic-beta;
  * đồng hồ chi tiêu: cộng USD mọi lượt từ `usage` của phản hồi (giá từ prices.py — cùng bảng với harness); chạm RELAY_BUDGET_USD
    ⇒ 402. Thiếu usage / model lạ / lỗi upstream không rõ ⇒ tính phí xấu nhất và KHÓA relay (broken) — không gọi thêm.
  * GET /_meter (cần token) trả {usd, calls, refused, broken} — harness đọc để biết chi tiêu THẬT.
API key chỉ nằm trong env của relay. Không redirect, không path nào khác, body ≤ 8 MB. Stdlib thuần."""
import hmac
import http.client
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

for _p in ("/prices",):                 # compose mount eval/harness/prices.py → /prices/prices.py (read-only)
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)
import prices  # noqa: E402

PROVIDER = os.environ.get("RELAY_PROVIDER", "anthropic")                    # "anthropic" | "ollama" (cố định theo container, không theo request)
if PROVIDER not in ("anthropic", "ollama"):
    raise SystemExit(f"RELAY_PROVIDER không hợp lệ: {PROVIDER!r}")
_LOCAL = PROVIDER == "ollama"
# Host upstream CỐ ĐỊNH trong mã theo provider; env RELAY_UPSTREAM_* chỉ để test (compose không truyền các biến này vào container).
UPSTREAM_HOST = os.environ.get("RELAY_UPSTREAM_HOST", "host.docker.internal" if _LOCAL else "api.anthropic.com")
UPSTREAM_PORT = int(os.environ.get("RELAY_UPSTREAM_PORT", "11434" if _LOCAL else "443"))
UPSTREAM_TLS = os.environ.get("RELAY_UPSTREAM_TLS", "0" if _LOCAL else "1") == "1"
ALLOWED_PATH = "/v1/chat/completions" if _LOCAL else "/v1/messages"
MAX_BODY = 8 * 1024 * 1024
MAX_TOKENS_CAP = prices.MAX_OUTPUT_TOKENS
FORWARD_HEADERS = ("content-type", "anthropic-version")
FORBIDDEN_FIELDS = ("stream", "speed", "fallbacks")
LOG = "/log/hits.jsonl"


class Meter:
    def __init__(self):
        self.lock = threading.Lock()
        self.usd = 0.0
        self.calls = 0
        self.refused = 0
        self.upstream_4xx = 0
        self.broken = ""
        self.tokens_in = 0               # token (đếm cả khi USD = 0 ở provider local)
        self.tokens_out = 0
        self.tokens_cache_read = 0
        self.tokens_cache_write = 0

    def snapshot(self):
        with self.lock:
            return {"usd": round(self.usd, 6), "calls": self.calls, "refused": self.refused, "upstream_4xx": self.upstream_4xx, "broken": self.broken,
                    "tokens_in": self.tokens_in, "tokens_out": self.tokens_out, "tokens_cache_read": self.tokens_cache_read,
                    "tokens_cache_write": self.tokens_cache_write, "provider": PROVIDER}


METER = Meter()


def _log(**rec):
    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with open(LOG, "a") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError:
        pass


def _cfg():
    """Đọc cấu hình mỗi request (test đổi env); thiếu mục nào ⇒ None ⇒ từ chối (fail closed)."""
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    token = os.environ.get("RELAY_TOKEN", "")
    models = [m.strip() for m in (os.environ.get("RELAY_MODELS") or os.environ.get("RELAY_MODEL", "")).split(",") if m.strip()]
    try:
        cap = float(os.environ.get("RELAY_BUDGET_USD", ""))
    except ValueError:
        cap = 0.0 if _LOCAL else None            # local: không có USD để giới hạn (token vẫn được đếm)
    if _LOCAL:
        key = key or "local"                     # Ollama không cần key; KHÔNG bao giờ chuyển key thật tới upstream local
    return key, token, models, cap


def _bad_cache_ttl(node) -> bool:
    """True nếu BẤT KỲ cache_control nào trong body có ttl ≠ mặc định (None / '5m')."""
    if isinstance(node, dict):
        cc = node.get("cache_control")
        if cc is not None and (not isinstance(cc, dict) or cc.get("ttl") not in (None, "5m")):
            return True
        return any(_bad_cache_ttl(v) for v in node.values())
    if isinstance(node, list):
        return any(_bad_cache_ttl(v) for v in node)
    return False


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *a):
        pass

    def _deny(self, code, msg):
        body = json.dumps({"error": msg}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self, token):
        # SDK anthropic gửi api_key dạng `Authorization: Bearer <key>` (không phải x-api-key) — chấp nhận CẢ HAI, so sánh hằng thời gian
        auth = self.headers.get("Authorization", "")
        bearer = auth[7:] if auth[:7].lower() == "bearer " else ""
        got = (self.headers.get("x-api-key", ""), bearer)
        ok = [hmac.compare_digest(g.encode(), token.encode()) for g in got]
        return bool(token) and any(ok)

    def _refuse(self, code, msg):
        with METER.lock:
            METER.refused += 1
        _log(refused=msg)
        return self._deny(code, msg)

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path != ALLOWED_PATH:
            return self._deny(404, f"relay chỉ chuyển tiếp POST {ALLOWED_PATH}")
        key, token, models, cap = _cfg()
        if not key or not token or not models or cap is None:
            return self._deny(503, "relay thiếu cấu hình (ANTHROPIC_API_KEY/RELAY_TOKEN/RELAY_MODEL(S)/RELAY_BUDGET_USD)")
        if not self._authed(token):
            return self._refuse(401, "token relay sai hoặc thiếu")
        if not _LOCAL:
            try:
                for m in models:
                    prices.require_known(m)          # MỌI model trong allowlist phải có giá (fail closed)
            except prices.UnknownModel as e:
                return self._refuse(503, str(e))
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._deny(400, "Content-Length sai")
        if n <= 0 or n > MAX_BODY:
            return self._deny(413, "body rỗng hoặc quá lớn")
        raw = self.rfile.read(n)
        try:
            req = json.loads(raw)
            assert isinstance(req, dict)
        except Exception:
            return self._deny(400, "body không phải JSON object")
        if self.headers.get("anthropic-beta"):
            return self._refuse(400, "header anthropic-beta không được phép")
        if "beta" in (self.path.split("?", 1) + [""])[1]:
            return self._refuse(400, "endpoint beta không được phép")
        if _LOCAL:
            return self._forward_local(req, models)
        if _bad_cache_ttl(req):
            return self._refuse(400, "cache_control.ttl khác mặc định 5 phút không được phép (giá ghi cache 1h = 2×, relay tính 1.25×)")
        bad = [f for f in FORBIDDEN_FIELDS if req.get(f)]
        if bad:
            return self._refuse(400, f"trường không được phép: {bad}")
        if req.get("model") not in models:
            return self._refuse(400, "model không nằm trong allowlist của run")
        model = req["model"]
        mt = req.get("max_tokens")
        if not isinstance(mt, int) or isinstance(mt, bool) or not 1 <= mt <= MAX_TOKENS_CAP:
            return self._refuse(400, f"max_tokens phải là số nguyên trong [1, {MAX_TOKENS_CAP}]")
        with METER.lock:
            if METER.broken:
                return self._deny(402, f"relay bị khoá: {METER.broken}")
            if METER.usd >= cap:
                METER.refused += 1
                return self._deny(402, f"đã chạm trần chi tiêu {cap:.2f} USD")
        headers = {h: self.headers[h] for h in FORWARD_HEADERS if self.headers.get(h)}
        headers["x-api-key"] = key
        conn_cls = http.client.HTTPSConnection if UPSTREAM_TLS else http.client.HTTPConnection
        try:
            conn = conn_cls(UPSTREAM_HOST, UPSTREAM_PORT, timeout=300)
            conn.request("POST", ALLOWED_PATH, body=raw, headers=headers)
            r = conn.getresponse()
            data = r.read()
        except Exception as e:
            # lượt gọi có thể ĐÃ bị tính phí dù không nhận được phản hồi ⇒ tính phí xấu nhất và khoá relay
            with METER.lock:
                METER.usd += prices.max_call_usd(model)
                METER.broken = f"upstream lỗi không rõ chi phí ({type(e).__name__})"
            return self._deny(502, f"upstream lỗi: {type(e).__name__}")
        self._account(r.status, data, model)
        _log(status=r.status, bytes=len(data))
        self.send_response(r.status)           # 3xx KHÔNG được theo: trả nguyên cho client (SDK không theo cross-host)
        self.send_header("Content-Type", r.getheader("Content-Type", "application/json"))
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _forward_local(self, req, models):
        """Ollama (OpenAI-compatible): cùng chính sách rút gọn — model ∈ allowlist, không stream, max_tokens ≤ trần. USD luôn 0; đếm token."""
        if req.get("model") not in models:
            return self._refuse(400, "model không nằm trong allowlist của run")
        if req.get("stream"):
            return self._refuse(400, "stream không được phép")
        mt = req.pop("max_completion_tokens", None)
        mt = req.get("max_tokens", mt)
        if not isinstance(mt, int) or isinstance(mt, bool) or not 1 <= mt <= MAX_TOKENS_CAP:
            return self._refuse(400, f"max_tokens phải là số nguyên trong [1, {MAX_TOKENS_CAP}]")
        req["max_tokens"] = mt                       # Ollama /v1 hiểu `max_tokens`
        raw = json.dumps(req).encode()
        conn_cls = http.client.HTTPSConnection if UPSTREAM_TLS else http.client.HTTPConnection
        with METER.lock:
            if METER.broken:
                return self._deny(402, f"relay bị khoá: {METER.broken}")
        try:
            conn = conn_cls(UPSTREAM_HOST, UPSTREAM_PORT, timeout=600)
            conn.request("POST", ALLOWED_PATH, body=raw, headers={"Content-Type": "application/json", "Content-Length": str(len(raw))})
            r = conn.getresponse()
            data = r.read()
        except Exception as e:
            return self._deny(502, f"upstream lỗi: {type(e).__name__}")
        with METER.lock:
            if r.status == 200:
                METER.calls += 1
                try:
                    u = json.loads(data).get("usage") or {}
                    METER.tokens_in += int(u.get("prompt_tokens") or 0)
                    METER.tokens_out += int(u.get("completion_tokens") or 0)
                except Exception:
                    pass
            elif 400 <= r.status < 500:
                METER.upstream_4xx += 1
        _log(status=r.status, bytes=len(data))
        self.send_response(r.status)
        self.send_header("Content-Type", r.getheader("Content-Type", "application/json"))
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    @staticmethod
    def _account(status, data, req_model):
        with METER.lock:
            if status != 200:                  # lỗi 4xx/5xx của Anthropic không tính phí
                if 400 <= status < 500:
                    METER.upstream_4xx += 1
                return
            METER.calls += 1
            try:
                j = json.loads(data)
                u = j["usage"]
                tin = int(u["input_tokens"])      # thiếu input_tokens ⇒ KeyError ⇒ fail closed (không đếm 0)
                cw = int(u.get("cache_creation_input_tokens") or 0)
                cr = int(u.get("cache_read_input_tokens") or 0)
                tout = int(u["output_tokens"])
                METER.usd += prices.call_usd(j.get("model") or "", tin, tout, cr, cw)     # giá theo model THỰC SỰ phản hồi
                METER.tokens_in += tin
                METER.tokens_out += tout
                METER.tokens_cache_read += cr
                METER.tokens_cache_write += cw
            except Exception as e:                # thiếu usage / model lạ ⇒ tính xấu nhất + khoá
                METER.usd += prices.max_call_usd(req_model)
                METER.broken = f"không tính được chi phí lượt gọi ({type(e).__name__})"

    def do_GET(self):
        if self.path == "/_meter":
            _, token, _, _ = _cfg()
            if not self._authed(token):
                return self._deny(401, "token relay sai hoặc thiếu")
            body = json.dumps(METER.snapshot()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self._deny(404, f"relay chỉ chuyển tiếp POST {ALLOWED_PATH}")

    do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = lambda self: self._deny(404, f"relay chỉ chuyển tiếp POST {ALLOWED_PATH}")


if __name__ == "__main__":
    if not _LOCAL:                      # fail closed ngay lúc khởi động: model nào chưa có giá ⇒ relay không chạy
        for _m in _cfg()[2]:
            prices.require_known(_m)
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
