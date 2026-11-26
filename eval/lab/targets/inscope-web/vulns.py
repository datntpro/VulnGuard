"""Endpoint có chủ đích dễ/không dễ bị tấn công cho eval validator (P2-10, P2-11). Thuần stdlib.

route(path, query) -> (status, body, headers) hoặc None nếu path không thuộc module này (P2-10: GET không trạng thái).
handle(method, path, query, headers, body) -> như route, thêm các endpoint P2-11 CÓ trạng thái/auth/fetch:
  XSS (reflected/stored), SSRF (/fetch*: gọi URL do client đưa — CHỈ tới địa chỉ nội bộ, xem lab_fetch), IDOR (/profile*).
Dùng bởi app.py (lab Docker) và tests/test_pentest_validator_lab.py (server localhost tự dựng).
Ground truth: ground_truth.json (cùng thư mục)."""
import html
import ipaddress
import json
import random
import re
import socket
import threading
import urllib.request
from urllib.parse import parse_qs, urlsplit
from typing import Dict, Optional, Tuple

USERS = {1: "alice", 2: "bob", 3: "carol"}
_ROW = "<html><body><table>" + "".join(f"<tr><td>{i}</td><td>{n}</td><td>{n}@lab.test</td></tr>" for i, n in USERS.items()) + "</table></body></html>"


def _page(ids) -> str:
    rows = "".join(f"<tr><td>user {i}</td><td>name {USERS[i]}</td><td>mail {USERS[i]}@lab.test</td></tr>" for i in ids if i in USERS)
    return "<html><head><title>users</title></head><body><h1>Directory</h1><p>Query results follow</p><table>" + rows + "</table></body></html>"


_NO_ROWS = _page([])


def _cond(a: str, b: str) -> bool:
    return a == b


def _str_ctx(v: str):
    """... WHERE id='V' — chèn nối được."""
    m = re.fullmatch(r"(\d+)'\s*AND\s*'(\d+)'\s*=\s*'(\d+)", v)
    if m:
        return [int(m.group(1))] if _cond(m.group(2), m.group(3)) else []
    return [int(v)] if v.isdigit() else []


def _num_ctx(v: str):
    """... WHERE id=V — chèn số."""
    m = re.fullmatch(r"(\d+)\s+AND\s+(\d+)\s*=\s*(\d+)", v)
    if m:
        return [int(m.group(1))] if _cond(m.group(2), m.group(3)) else []
    return [int(v)] if v.isdigit() else None   # None = lỗi cú pháp


def route(path: str, q: Dict[str, list]) -> Optional[Tuple[int, str, Dict[str, str]]]:
    g = lambda k, d="": (q.get(k) or [d])[0]  # noqa: E731
    if path == "/sqli_str":
        return 200, _page(_str_ctx(g("id", "1"))), {}
    if path == "/sqli_num":
        r = _num_ctx(g("id", "1"))
        return (500, "<html>SQL syntax error</html>", {}) if r is None else (200, _page(r), {})
    if path == "/sqli_search":     # LIKE '%V%': dấu nháy đóng bị nuốt → boolean injection không đổi kết quả (FN có chủ đích)
        return 200, _page([1] if "ali" in g("q", "ali").lower() else []), {}
    if path == "/sqli_safe":       # tham số hoá
        return 200, _page([1]), {}
    if path == "/sqli_intval":     # int() ở server
        m = re.match(r"\d+", g("id", "1"))
        return 200, _page([int(m.group(0))] if m else []), {}
    if path == "/lastnum":         # bẫy: lấy số cuối cùng trong input
        nums = re.findall(r"\d+", g("id", "1"))
        return 200, _page([int(nums[-1])] if nums else []), {}
    if path == "/dyn":             # trang động: baseline không ổn định
        return 200, "<html>" + " ".join(f"tok{random.random()}" for _ in range(60)) + "</html>", {}
    if path == "/redir_safe":
        t = g("to", "/")
        return 302, "", {"Location": t if (t.startswith("/") and not t.startswith("//")) else "/"}
    if path == "/redir_prefix":    # chỉ cho phép đích cùng site
        t = g("to", "/")
        return 302, "", {"Location": t if t.startswith("http://inscope/") else "/"}
    if path == "/redir_js":        # redirect phía client: chỉ-header không thấy → FN có chủ đích
        return 200, f'<html><meta http-equiv="refresh" content="0;url={g("to", "/")}"></html>', {}
    if path == "/hdr_good":
        return 200, "<html>ok</html>", {"Content-Security-Policy": "default-src 'self'"}
    if path == "/hdr_nocsp":
        return 200, "<html>ok</html>", {}
    if path == "/hdr_ver":
        return 200, "<html>ok</html>", {"Content-Security-Policy": "default-src 'self'", "Server": "nginx/1.18.0"}
    if path == "/hdr_cors":
        return 200, "<html>ok</html>", {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true",
                                        "Content-Security-Policy": "default-src 'self'"}
    if path == "/hdr_cors_safe":
        return 200, "<html>ok</html>", {"Access-Control-Allow-Origin": "https://trusted.example",
                                        "Access-Control-Allow-Credentials": "true", "Content-Security-Policy": "default-src 'self'"}
    return None


# ───────────────────────── P2-11: XSS / SSRF / IDOR ─────────────────────────
TOKENS = {"lab-token-a": 1, "lab-token-b": 2}      # Authorization: Bearer <token> → id người dùng
_lock = threading.Lock()
COMMENTS = {"raw": [], "safe": []}
MAX_COMMENTS = 50
_H = {"Content-Type": "text/html; charset=utf-8"}


def reset_state():
    with _lock:
        COMMENTS["raw"].clear()
        COMMENTS["safe"].clear()


def _html(b: str):
    return 200, "<html><head><title>lab</title></head><body>" + b + "</body></html>", dict(_H)


def lab_fetch(url: str) -> str:
    """Phía SSRF của lab: GET URL do client đưa, CHỈ http và CHỈ tới địa chỉ nội bộ (loopback/private) — lab không bao giờ là
    bàn đạp ra ngoài. Không theo redirect; đọc ≤1 KiB; lỗi → chuỗi lỗi ngắn."""
    sp = urlsplit(url or "")
    if sp.scheme != "http" or not sp.hostname:
        return "unsupported url"
    try:
        for fam, _t, _p, _c, sa in socket.getaddrinfo(sp.hostname, sp.port or 80, type=socket.SOCK_STREAM):
            ip = ipaddress.ip_address(sa[0])
            if ip.is_link_local or not (ip.is_private or ip.is_loopback):
                return "blocked by lab"
    except OSError:
        return "dns error"

    class _NoRedir(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    try:
        op = urllib.request.build_opener(_NoRedir, urllib.request.ProxyHandler({}))
        with op.open(url, timeout=3) as r:   # nosec B310 — scheme/host đã kiểm ở trên (lab nội bộ)
            return r.read(1024).decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return f"fetch error: {type(e).__name__}"


_PROFILES = {1: ("alice", "alice@lab.test", "1 Lab Street"), 2: ("bob", "bob@lab.test", "2 Lab Street"),
             3: ("carol", "carol@lab.test", "3 Lab Street")}


def _profile(i: int):
    if i not in _PROFILES:
        return 404, "<html>not found</html>", dict(_H)
    n, mail, addr = _PROFILES[i]
    return _html(f"<h1>Profile {i}</h1><p>name {n}</p><p>mail {mail}</p><p>address {addr}</p><p>member since 2020</p>")


def _user(headers) -> int:
    a = (headers.get("Authorization") or headers.get("authorization") or "")
    return TOKENS.get(a[7:].strip(), 0) if a.lower().startswith("bearer ") else 0


def handle(method, path, q, headers=None, body=""):
    headers = headers or {}
    g = lambda k, d="": (q.get(k) or [d])[0]  # noqa: E731
    # ── XSS ──
    if path == "/xss_reflect":                         # phản chiếu thô trong text
        return _html(f"<h1>Search</h1><p>You searched for: {g('q')}</p>")
    if path == "/xss_attr":                            # thuộc tính, không escape dấu nháy
        return _html(f'<form><input name="q" value="{g("q")}"></form>')
    if path == "/xss_js":                              # trong chuỗi JS, không escape dấu nháy
        return _html(f'<script>var q = "{g("q")}";</script><p>ok</p>')
    if path == "/xss_escaped":
        return _html(f"<p>You searched for: {html.escape(g('q'))}</p>")
    if path == "/xss_attr_safe":
        return _html(f'<form><input name="q" value="{html.escape(g("q"), quote=True)}"></form>')
    if path == "/xss_json":                            # phản chiếu thô nhưng Content-Type JSON → trình duyệt không chạy
        return 200, json.dumps({"q": g("q")}, ensure_ascii=False), {"Content-Type": "application/json"}
    if path == "/xss_filter":                          # bỏ < > → phản chiếu nhưng không thực thi
        return _html("<p>You searched for: " + re.sub(r"[<>]", "", g("q")) + "</p>")
    if path in ("/comment", "/comment_safe"):          # stored: POST text=… rồi GET danh sách
        key = "raw" if path == "/comment" else "safe"
        if method == "POST":
            t = (parse_qs(body or "").get("text") or [""])[0][:500]
            with _lock:
                if len(COMMENTS[key]) < MAX_COMMENTS:
                    COMMENTS[key].append(t)
            return 200, "<html>posted</html>", dict(_H)
        with _lock:
            items = list(COMMENTS[key])
        return _html("<h1>Comments</h1>" + "".join("<div>" + (c if key == "raw" else html.escape(c)) + "</div>" for c in items))
    # ── SSRF ──
    if path == "/fetch":                               # SSRF có phản hồi
        return _html("<pre>" + html.escape(lab_fetch(g("url"))) + "</pre>")
    if path == "/fetch_blind":                         # SSRF mù: gọi ra nhưng không trả nội dung
        lab_fetch(g("url"))
        return _html("<p>queued</p>")
    if path == "/fetch_allow":                         # chỉ gọi tới host trong allowlist
        host = (urlsplit(g("url")).hostname or "").lower()
        if host == "img.lab.example":
            return _html("<pre>" + html.escape(lab_fetch(g("url"))) + "</pre>")
        return 400, "<html>host not allowed</html>", dict(_H)
    if path == "/fetch_echo":                          # chỉ phản chiếu URL, KHÔNG gọi
        return _html("<p>preview for " + html.escape(g("url")) + "</p>")
    # ── IDOR ──
    m = re.fullmatch(r"/profile/(\d+)", path)
    if m:                                              # cần đăng nhập nhưng KHÔNG kiểm chủ sở hữu → IDOR
        return _profile(int(m.group(1))) if _user(headers) else (401, "<html>login required</html>", dict(_H))
    if path == "/profile_qs":                          # như trên, id ở query
        return _profile(int(g("id", "0") or 0)) if _user(headers) and g("id", "0").isdigit() else (401, "<html>login required</html>", dict(_H))
    m = re.fullmatch(r"/profile_safe/(\d+)", path)
    if m:                                              # kiểm chủ sở hữu
        u = _user(headers)
        if not u:
            return 401, "<html>login required</html>", dict(_H)
        return _profile(int(m.group(1))) if int(m.group(1)) == u else (403, "<html>forbidden</html>", dict(_H))
    m = re.fullmatch(r"/profile_pub/(\d+)", path)
    if m:                                              # công khai: ai cũng đọc được → không phải IDOR
        return _profile(int(m.group(1)))
    return route(path, q)
