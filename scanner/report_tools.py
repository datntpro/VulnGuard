"""Per-tool run status for reports (HTML + PDF share this, so both tell the same story).

Input is ``scan.summary`` (may be None, or from an older scan with no ``scanner_logs``).
Output is plain text only; escaping is the renderer's job.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Optional

STATUSES = ("ok", "error", "skipped", "partial")
GAP_STATUSES = frozenset({"error", "skipped", "partial"})
MAX_ERROR = 160
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩﻿]+")

_GENERATED = {
    "vi": "Kết quả KHÔNG đầy đủ — có công cụ bị bỏ qua, lỗi hoặc chỉ chạy một phần; \"0 lỗi\" không có nghĩa là sạch.",
    "en": "Results are INCOMPLETE — some tools were skipped, failed or ran partially; \"0 findings\" does not mean clean.",
}


def clean_error(v: Any, n: int = MAX_ERROR) -> str:
    t = _CTRL.sub(" ", "" if v is None else str(v[:4 * n] if isinstance(v, str) else v)).strip()
    return t if len(t) <= n else t[: n - 1] + "…"


def _count(v: Any) -> int:
    try:
        return max(0, int(v))
    except (TypeError, ValueError):
        return 0


def tool_status(summary: Optional[Mapping[str, Any]], lang: str = "vi") -> Dict[str, Any]:
    empty: Dict[str, Any] = {"rows": [], "has_gap": False, "warning": ""}
    if not isinstance(summary, Mapping):
        return empty
    logs = summary.get("scanner_logs")
    if not isinstance(logs, Mapping) or not logs:
        return empty
    rows: List[Dict[str, Any]] = []
    for tool, lg in logs.items():
        lg = lg if isinstance(lg, Mapping) else {}
        st = lg.get("status", "ok")
        st = st if st in STATUSES else "error"
        name = clean_error(tool, 60)
        rows.append({"tool": name, "label": clean_error(lg.get("label") or name, 60), "status": st,
                     "count": _count(lg.get("count")), "error": clean_error(lg.get("error"))})
    rows.sort(key=lambda r: (r["status"] not in GAP_STATUSES, r["tool"]))
    has_gap = any(r["status"] in GAP_STATUSES for r in rows)
    warning = ""
    if has_gap:
        sw = summary.get("scan_warning")
        warning = clean_error(sw, 400) if isinstance(sw, str) and sw.strip() else _GENERATED.get(lang, _GENERATED["vi"])
    return {"rows": rows, "has_gap": has_gap, "warning": warning}
