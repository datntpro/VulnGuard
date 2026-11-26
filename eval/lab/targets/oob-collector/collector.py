"""oob-collector (P2-11): collector OOB CỤC BỘ của lab — ghi nhận callback của target cho validator SSRF.

KHÔNG phải dịch vụ công khai: chỉ nằm trên lab_net (internal). Mọi path /<token> (hex 16–64) → ghi hit, trả 200 rỗng.
API đọc hit qua GET /__hits/<token> (JSON). Cùng giao thức với scanner/pentest/oob.py (LocalCollector/RemoteCollector)."""
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

TOKEN = re.compile(r"[0-9a-f]{16,64}")
HITS, LOCK = {}, threading.Lock()


class H(BaseHTTPRequestHandler):
    server_version, sys_version = "oob", ""

    def log_message(self, *a):
        pass

    def _h(self):
        path = urlsplit(self.path).path
        if path.startswith("/__hits/"):
            t = path[len("/__hits/"):]
            with LOCK:
                body = json.dumps(HITS.get(t, []) if TOKEN.fullmatch(t) else []).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        else:
            t = path.strip("/").split("/")[0]
            if TOKEN.fullmatch(t):
                with LOCK:
                    lst = HITS.setdefault(t, []) if len(HITS) < 5000 else []
                    if len(lst) < 50:
                        lst.append({"ts": time.time(), "peer": self.client_address[0], "method": self.command,
                                    "host": self.headers.get("Host", ""), "ua": (self.headers.get("User-Agent") or "")[:200]})
            body = b""
            self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = do_HEAD = do_POST = do_PUT = do_OPTIONS = _h


ThreadingHTTPServer(("0.0.0.0", 8081), H).serve_forever()
