"""Relay LLM cho run capability (P1-7): lab_net là `internal` nên vg-under-test không ra được Internet, còn agent thật cần gọi API.
Relay là thành phần DUY NHẤT của lab có đường ra ngoài, và chỉ làm đúng một việc:
  POST /v1/messages  →  https://api.anthropic.com/v1/messages   (host cố định trong mã, KHÔNG đọc từ request)
API key chỉ nằm trong env của relay (vg-under-test không bao giờ thấy key → tool của agent không thể lộ key).
Không redirect, không path nào khác, body ≤ 8 MB, không stream (SDK non-stream), header allowlist. Stdlib thuần."""
import http.client
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM_HOST = os.environ.get("RELAY_UPSTREAM_HOST", "api.anthropic.com")   # chỉ test mới đổi (xem tests)
UPSTREAM_PORT = int(os.environ.get("RELAY_UPSTREAM_PORT", "443"))
UPSTREAM_TLS = os.environ.get("RELAY_UPSTREAM_TLS", "1") == "1"
ALLOWED_PATH = "/v1/messages"
MAX_BODY = 8 * 1024 * 1024
FORWARD_HEADERS = ("content-type", "anthropic-version", "anthropic-beta")
LOG = "/log/hits.jsonl"


def _log(**rec):
    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with open(LOG, "a") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError:
        pass


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

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path != ALLOWED_PATH:
            return self._deny(404, "relay chỉ chuyển tiếp POST /v1/messages")
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            return self._deny(503, "relay chưa có ANTHROPIC_API_KEY")
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._deny(400, "Content-Length sai")
        if n <= 0 or n > MAX_BODY:
            return self._deny(413, "body rỗng hoặc quá lớn")
        body = self.rfile.read(n)
        try:
            if json.loads(body).get("stream"):
                return self._deny(400, "relay không hỗ trợ stream")
        except Exception:
            return self._deny(400, "body không phải JSON")
        headers = {h: self.headers[h] for h in FORWARD_HEADERS if self.headers.get(h)}
        headers["x-api-key"] = key
        conn_cls = http.client.HTTPSConnection if UPSTREAM_TLS else http.client.HTTPConnection
        try:
            conn = conn_cls(UPSTREAM_HOST, UPSTREAM_PORT, timeout=300)
            conn.request("POST", self.path, body=body, headers=headers)   # self.path giữ query (?beta=true)
            r = conn.getresponse()
            data = r.read()
        except Exception as e:
            return self._deny(502, f"upstream lỗi: {type(e).__name__}")
        _log(path=self.path, status=r.status, bytes=len(data))
        self.send_response(r.status)           # 3xx KHÔNG được theo: trả nguyên cho client (SDK không theo cross-host)
        self.send_header("Content-Type", r.getheader("Content-Type", "application/json"))
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._deny(404, "relay chỉ chuyển tiếp POST /v1/messages")

    do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = do_GET


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
