"""Endpoint có chủ đích dễ/không dễ bị tấn công cho eval validator (P2-10). Thuần stdlib, không I/O.

route(path, query) -> (status, body, headers) hoặc None nếu path không thuộc module này.
Dùng bởi app.py (lab Docker) và tests/test_pentest_validator_lab.py (server localhost tự dựng).
Ground truth: ground_truth.json (cùng thư mục)."""
import random
import re
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
