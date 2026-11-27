"""vg_browser hardening (#84 item 1): Worker/SharedWorker/WebSocket/WebTransport/WebRTC bị thay bằng stub ném lỗi.
Gateway vẫn là hàng rào thật; đây chỉ là defence-in-depth. Test Chromium thật bị skip khi không có Chromium."""
import importlib
import os
import pathlib
import shutil
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "docker" / "pentest-runner"))
vb = importlib.import_module("vg_browser")

TOK = "0123456789abcdef0123"
TOK2 = "fedcba9876543210fedc"      # bắn từ iframe
APIS = ["Worker", "SharedWorker", "WebSocket", "WebSocketStream", "WebTransport", "RTCPeerConnection", "webkitRTCPeerConnection",
        "TCPSocket", "UDPSocket", "TCPServerSocket", "UDPServerSocket"]


@pytest.mark.parametrize("api", APIS)
def test_init_script_defines_stub_for_each_api(api):
    assert f'"{api}"' in vb.PAGE_BLOCK_JS
    assert "configurable:false" in vb.PAGE_BLOCK_JS and "writable:false" in vb.PAGE_BLOCK_JS
    assert not hasattr(vb, "WS_BLOCK_JS")


def test_service_workers_still_blocked():
    assert 'service_workers="block"' in pathlib.Path(vb.__file__).read_text()


# Trang thử: mỗi API phải ném đúng SecurityError (không phải TypeError "không tồn tại") ở main frame, iframe about:blank (đồng bộ),
# popup window.open('') và iframe srcdoc; mỗi ngữ cảnh bắn token riêng qua __vg khi TẤT CẢ API bị chặn.
# Worker same-origin /w.js và SharedWorker /w.js trỏ cùng file → không được nạp.
PAGE = """<!doctype html><script>
var APIS = @APIS@, res = {};
function t(n, f){ try { f(); res[n] = 'allowed'; } catch(e) { res[n] = (e && e.name === 'SecurityError') ? 'blocked' : 'other:' + e; } }
function ctx(name, w){ APIS.forEach(function(a){ t(name + ':' + a, function(){ new w[a]('ws://127.0.0.1:1/'); }); }); }
function allBlocked(prefix){ return Object.keys(res).filter(function(k){ return k.indexOf(prefix) === 0; })
  .every(function(k){ return res[k] === 'blocked'; }); }
t('blob', function(){ new Worker(URL.createObjectURL(new Blob(['postMessage(1)']))); });
t('file', function(){ new Worker('/w.js'); });
t('shared', function(){ new SharedWorker('/w.js'); });
t('wt', function(){ new WebTransport('https://127.0.0.1:1/'); });
t('rtc', function(){ new RTCPeerConnection(); });
t('rtc2', function(){ new webkitRTCPeerConnection(); });
ctx('main', window);
var f = document.createElement('iframe'); document.documentElement.appendChild(f); ctx('blank', f.contentWindow);
try { Object.defineProperty(window, 'Worker', {value: function(){}}); res.redefine = 'allowed'; } catch(e) {}
var pw = window.open('');
if (pw) { var pr = {}; APIS.forEach(function(a){ try { new pw[a]('ws://127.0.0.1:1/'); pr[a] = 0; } catch(e) { pr[a] = e && e.name === 'SecurityError' ? 1 : 0; } });
  if (APIS.every(function(a){ return pr[a]; })) window.__vg('@TOK3@'); }
if (allBlocked('')) window.__vg('@TOK@');
</script><iframe src="/frame"></iframe><iframe srcdoc="<script>var ok=1;@APIS_ATTR@.forEach(function(a){try{new window[a]('ws://127.0.0.1:1/');ok=0}catch(e){if(!e||e.name!='SecurityError')ok=0}});if(ok)window.parent.__vg('@TOK4@')</script>"></iframe>"""
FRAME = """<!doctype html><script>
var ok = 0; try { new Worker('/w.js'); } catch(e) { ok = 1; }
try { new WebSocket('ws://127.0.0.1:1/'); } catch(e) { ok += 1; }
if (ok === 2) window.parent.__vg('%s');
</script>"""
TOK3, TOK4 = "1111111111111111aaaa", "2222222222222222bbbb"


def _page():
    import json
    return (PAGE.replace("@APIS_ATTR@", json.dumps(APIS).replace('"', "&quot;")).replace("@APIS@", json.dumps(APIS))
            .replace("@TOK3@", TOK3).replace("@TOK4@", TOK4).replace("@TOK@", TOK))


class _H(BaseHTTPRequestHandler):
    hits = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        _H.hits.append(self.path)
        body, ct = {"/": (_page(), "text/html"), "/frame": (FRAME % TOK2, "text/html"),
                    "/w.js": ("postMessage(1)", "text/javascript")}.get(self.path, ("", "text/plain"))
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body.encode())))
        self.end_headers()
        self.wfile.write(body.encode())


def _exe():
    pytest.importorskip("playwright")
    exe = os.environ.get("VG_CHROMIUM") or shutil.which("chromium") or shutil.which("chromium-browser")
    return exe or ""      # rỗng → vg_browser dùng Chromium của Playwright (nếu đã cài); lỗi launch → skip


def test_real_browser_blocks_workers_and_ws_but_xss_still_fires(monkeypatch):
    exe = _exe()
    monkeypatch.setattr(vb, "CHROMIUM", exe or "/nonexistent")
    _H.hits.clear()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        out = vb.run({"url": f"http://127.0.0.1:{srv.server_address[1]}/", "token": TOK, "timeout": 20,
                      "allowed_hosts": ["127.0.0.1"]})
    finally:
        srv.shutdown()
    if "error" in out and "Executable doesn't exist" in out["error"] and not os.environ.get("VG_PINNED_BROWSER"):
        pytest.skip("no Chromium available")
    assert "error" not in out, out
    # __vg gọi được hai lần (trang chính: mọi API bị chặn; iframe: Worker+WebSocket bị chặn) → token đã bắn
    assert out["fired"] is True, out
    for t in (TOK2, TOK3, TOK4):      # iframe src, popup, srcdoc
        assert t in out["fired_tokens"], (t, out)
    assert "/w.js" not in _H.hits, _H.hits      # không worker nào được nạp


def test_real_browser_benign_probe_only_contacts_target(monkeypatch, tmp_path):
    """#84 item 4: Chromium chỉ gọi host đích qua proxy — không www.google.com / background lookup.
    Khi fail, in net-log (--log-net-log) để tìm bên yêu cầu thay vì đoán cờ."""
    exe = _exe()
    monkeypatch.setattr(vb, "CHROMIUM", exe or "/nonexistent")
    netlog = tmp_path / "net.json"
    monkeypatch.setattr(vb, "LAUNCH_ARGS", vb.LAUNCH_ARGS + [f"--log-net-log={netlog}", "--net-log-capture-mode=Default"])
    seen = []

    class P(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _a(self):
            seen.append(self.path if self.command == "CONNECT" else (self.path.split("/")[2] if "//" in self.path else self.path))
            if self.command == "CONNECT":
                self.send_error(403)
                return
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        do_GET = do_POST = do_HEAD = do_CONNECT = _a

    srv = ThreadingHTTPServer(("127.0.0.1", 0), P)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{srv.server_address[1]}")
    monkeypatch.setenv("HTTPS_PROXY", f"http://127.0.0.1:{srv.server_address[1]}")
    try:
        out = vb.run({"url": "http://t.test/", "token": TOK, "timeout": 10, "allowed_hosts": ["t.test"]})
        import time
        time.sleep(2)
    finally:
        srv.shutdown()
    if "error" in out and "Executable doesn't exist" in out["error"] and not os.environ.get("VG_PINNED_BROWSER"):
        pytest.skip("no Chromium available")
    assert "error" not in out, out
    other = sorted({h.split(":")[0] for h in seen if h and h.split(":")[0] != "t.test"})
    if not os.environ.get("VG_PINNED_BROWSER"):
        # Chromium của runner CI (v157, KHÔNG phải bản pin trong image `browser`) tự gọi www.google.com/async/folae (AI-mode eligibility,
        # không có cờ ổn định để tắt) — preconnect DSE đã tắt bằng LAUNCH_ARGS. Bản pin được kiểm nghiêm ngặt ở nhánh VG_PINNED_BROWSER=1.
        other = [h for h in other if h != "www.google.com"]
    if other:
        import re
        tail = netlog.read_text(errors="replace") if netlog.exists() else ""
        ctx = [m.group(0) for m in re.finditer(r'.{0,300}(?:%s).{0,300}' % "|".join(map(re.escape, other)), tail)][:3]
        pytest.fail(f"unexpected hosts via proxy: {other}; chromium={exe or 'playwright'}; netlog excerpts: {ctx}")
    assert "t.test" in {h.split(":")[0] for h in seen}, seen
