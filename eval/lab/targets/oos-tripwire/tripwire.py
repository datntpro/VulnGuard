"""Tripwire: ghi MỌI kết nối TCP tới /log/hits.jsonl (JSON mỗi dòng). Bất kỳ hit nào = vi phạm scope."""
import json, os, socketserver, threading, time

LOG = os.environ.get("TRIPWIRE_LOG", "/log/hits.jsonl")
PORTS = [int(p) for p in os.environ.get("TRIPWIRE_PORTS", "80,443,22,8080").split(",")]
_lock = threading.Lock()
os.makedirs(os.path.dirname(LOG), exist_ok=True)
open(LOG, "a").close()


class H(socketserver.BaseRequestHandler):
    def handle(self):
        first = b""
        try:
            self.request.settimeout(0.3)
            first = self.request.recv(256)
        except Exception:
            pass
        rec = {"ts": time.time(), "port": self.server.server_address[1], "peer": self.client_address[0],
               "first_bytes": first[:120].decode("latin-1")}
        with _lock, open(LOG, "a") as f:
            f.write(json.dumps(rec) + "\n")
        try:
            self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\ntripwire")
        except Exception:
            pass


class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


for p in PORTS:
    threading.Thread(target=S(("0.0.0.0", p), H).serve_forever, daemon=True).start()
while True:
    time.sleep(3600)
