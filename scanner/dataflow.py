"""
Rút trích đường đi data-flow (source → propagation → sink) từ raw output của
scanner (hiện hỗ trợ Semgrep taint-mode `dataflow_trace`).

Trả về list node chuẩn hoá để UI vẽ "attack vector" kiểu Checkmarx:
  [{"label": "source|propagation|sink", "file", "line", "content"}]
Dung sai cao với biến thể format của Semgrep (CliLoc/CliCall, lồng nhiều mức).
"""
from typing import Any, Dict, List, Optional, Tuple


def _find_loc(x: Any) -> Optional[dict]:
    if isinstance(x, dict) and ("start" in x or "path" in x):
        return x
    if isinstance(x, list):
        for e in x:
            r = _find_loc(e)
            if r:
                return r
    return None


def _find_str(x: Any) -> Optional[str]:
    if isinstance(x, str):
        return x.strip() or None
    if isinstance(x, list):
        for e in x:
            r = _find_str(e)
            if r:
                return r
    return None


def _parse_tuple(tup: Any) -> Tuple[Optional[str], Optional[int], Optional[str]]:
    """taint_source/taint_sink dạng [kind, payload] → (path, line, content)."""
    if not isinstance(tup, list) or len(tup) < 2:
        loc = _find_loc(tup)
        return (_path(loc), _line(loc), _find_str(tup))
    payload = tup[1]
    loc = _find_loc(payload)
    return (_path(loc), _line(loc), _find_str(payload))


def _path(loc: Optional[dict]) -> Optional[str]:
    return (loc or {}).get("path")


def _line(loc: Optional[dict]) -> Optional[int]:
    start = (loc or {}).get("start") or {}
    return start.get("line") if isinstance(start, dict) else None


def _node(label: str, path, line, content) -> Dict[str, Any]:
    return {"label": label, "file": path or "", "line": line or None,
            "content": (content or "").strip()[:300]}


def extract(raw: Any) -> List[Dict[str, Any]]:
    """Trả về chuỗi node source→sink, hoặc [] nếu không có dataflow."""
    if not isinstance(raw, dict):
        return []
    dt = (raw.get("extra") or {}).get("dataflow_trace") or raw.get("dataflow_trace")
    if not isinstance(dt, dict):
        return []

    nodes: List[Dict[str, Any]] = []
    src = dt.get("taint_source")
    if src:
        p, l, c = _parse_tuple(src)
        nodes.append(_node("source", p, l, c))
    for iv in dt.get("intermediate_vars") or []:
        loc = iv.get("location") if isinstance(iv, dict) else None
        nodes.append(_node("propagation", _path(loc), _line(loc),
                           iv.get("content") if isinstance(iv, dict) else None))
    sink = dt.get("taint_sink")
    if sink:
        p, l, c = _parse_tuple(sink)
        nodes.append(_node("sink", p, l, c))

    # bỏ node rỗng hoàn toàn
    return [n for n in nodes if n["line"] or n["content"] or n["file"]]
