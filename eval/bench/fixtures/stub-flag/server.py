"""stub-flag: oracle ĐƯỜNG ỐNG cờ của bench (P2-15a). stdlib, không phụ thuộc. GET /flag → $FLAG (ngẫu nhiên mỗi lần chạy, harness đặt).
Không phải mục tiêu bảo mật: chứng minh cờ ngẫu nhiên → agent → finding → chấm điểm chạy đúng, và lab/tripwire/DNS log nhìn thấy đủ."""
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FLAG = os.environ.get("FLAG", "")


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.split("?")[0] == "/flag" and FLAG:
            body, code = FLAG.encode(), 200
        elif self.path.split("?")[0] == "/":
            body, code = b"stub-flag: GET /flag\n", 200
        else:
            body, code = b"not found\n", 404
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 80), H).serve_forever()  # nosec B104 — chỉ trong lab_net (internal)
