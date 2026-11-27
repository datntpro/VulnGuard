"""ReportDoc normalisation: fills defaults so every template field exists, derives counts and the
detail/low split, applies the card cap (plan D5). Pure data in, pure data out (no I/O)."""
from __future__ import annotations

from typing import Any, Mapping

from .labels import DETAIL_SEVS, RISK_WEIGHT, SEV_ORDER, get_labels

MAX_DETAIL_CARDS = 200


def _sev(v: Any) -> str:
    s = str(v or "INFO").upper()
    return s if s in SEV_ORDER else "INFO"


def risk_score(counts: Mapping[str, int]) -> int:
    return min(100, sum(RISK_WEIGHT.get(k, 0) * int(v or 0) for k, v in counts.items()))


def normalize_doc(doc: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of ``doc`` with defaults filled. Never mutates the input."""
    d: dict[str, Any] = dict(doc)
    lang = d.get("lang") if d.get("lang") in ("vi", "en") else "vi"
    d["lang"] = lang
    if not isinstance(d.get("labels"), dict):
        d["labels"] = get_labels(lang)
    meta = dict(d.get("meta") or {})
    meta.setdefault("title", str(d.get("title") or "VulnGuard"))
    for k in ("subtitle", "org", "generated"):
        meta.setdefault(k, "")
    meta.setdefault("kv", [])
    d["meta"] = meta
    findings = []
    n_detail = 0
    for i, f in enumerate(d.get("findings") or [], 1):
        g = dict(f) if isinstance(f, Mapping) else {"title": str(f)}
        g["severity"] = _sev(g.get("severity"))
        g.setdefault("id", f"VG-{i:03d}")
        want = g.get("detail")
        want = (g["severity"] in DETAIL_SEVS) if want is None else bool(want)
        if want and n_detail < MAX_DETAIL_CARDS:
            n_detail += 1
            g["detail"] = True
        else:
            g["detail"] = False
        findings.append(g)
    d["findings"] = findings
    summary = dict(d.get("summary") or {})
    counts = {s: 0 for s in SEV_ORDER}
    counts.update({k: int(v) for k, v in (summary.get("counts") or {}).items() if k in counts})
    if not summary.get("counts"):
        for g in findings:
            counts[g["severity"]] += 1
    summary["counts"] = counts
    summary.setdefault("score", risk_score(counts))
    summary.setdefault("score_text", f"{summary['score']}/100")
    for k in ("verdict", "narrative"):
        summary.setdefault(k, "")
    summary.setdefault("priorities", [])
    summary.setdefault("by_type", [])
    d["summary"] = summary
    d.setdefault("appendix", [])
    if d.get("findings_truncated_from"):
        d["truncated_note"] = str(d["labels"].get("truncated", ""))
    return d
