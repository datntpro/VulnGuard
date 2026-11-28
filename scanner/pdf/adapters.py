"""Adapters: domain objects -> ReportDoc (JSON-able dict) for the Typst templates.

Duck-typed on purpose (ORM rows or plain objects/dicts): nothing here imports the API layer, so
the module is unit-testable and cannot open a DB session. Every string produced here is DATA;
it is sanitised again by ``engine.render`` and passed to Typst as a value, never as markup.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional

from .labels import DETAIL_SEVS, SEV_ORDER, get_labels
from .model import risk_score

HIT = "▶"  # ▶ marks the hit line; the template never builds markup from it
_SEV_RANK = {s: i for i, s in enumerate(SEV_ORDER)}
_TZ = timezone(timedelta(hours=7))
STANDARDS = "OWASP Top 10 (2021) · TT 09/2020/TT-NHNN · TCVN 11930:2017 · ISO/IEC 27001:2022"
MAX_LOCATIONS = 3
MAX_FIELD = 8192            # same budget the engine applies per text field (engine.MAX_TEXT)
MAX_LOCATION = 600          # file paths / URLs / package names


def _cap(s: Any, n: int = MAX_FIELD) -> str:
    """Hard cap a (possibly hostile, 100k+ char) field BEFORE any regex/layout work touches it."""
    t = "" if s is None else str(s)
    return t if len(t) <= n else t[: max(0, n - 1)] + "…"


def _scrub(s: Any) -> str:
    """Defence in depth: mask secrets (tokens, keys, auth/cookie headers) in any free text that
    reaches the PDF, with the same redactor the pentest exports use. Fails closed."""
    t = _s(s)
    if not t:
        return t
    t = t[: 2 * MAX_FIELD]  # bound the redactor's input; the field is capped to MAX_FIELD afterwards
    try:
        from scanner.pentest.redaction import _redact_secrets

        return _redact_secrets(t)
    except Exception:  # noqa: BLE001
        return "[REDACTED]"


def _prose(s: Any, n: int = MAX_FIELD) -> str:
    """Free text (description / remediation / location): secret-scrubbed, then capped."""
    return _cap(_scrub(s), n)


def _loc(s: Any) -> str:
    return _prose(s, MAX_LOCATION)


def fmt_score(x: Any) -> str:
    """CVSS score with one decimal (7.3, never 7.300000000000001). Non-numeric text passes through."""
    if x is None or x == "":
        return ""
    try:
        f = float(x)
    except (TypeError, ValueError):
        return _s(x)
    return f"{f:.1f}" if f == f and abs(f) != float("inf") else _s(x)


def _g(o: Any, name: str, default: Any = None) -> Any:
    if isinstance(o, Mapping):
        return o.get(name, default)
    return getattr(o, name, default)


def _val(x: Any) -> str:
    return str(getattr(x, "value", x) if x is not None else "")


def _s(x: Any) -> str:
    return "" if x is None else str(x)


def fmt_dt(dt: Any, *, naive_is_utc: bool = True) -> str:
    """dd/mm/yyyy HH:MM (GMT+7). Naive datetimes are treated as UTC (how the DB stores them)."""
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
        except ValueError:
            return dt
    if not isinstance(dt, datetime):
        return "—"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc if naive_is_utc else _TZ)
    return dt.astimezone(_TZ).strftime("%d/%m/%Y %H:%M (GMT+7)")


def number_code(code: str, start: int, hit: Optional[int] = None) -> str:
    """Prefix source lines with line numbers; the hit line gets the ▶ marker."""
    out = []
    lines = (code or "").split("\n")
    width = len(str(start + len(lines)))
    for i, ln in enumerate(lines):
        n = start + i
        mark = HIT if hit is not None and n == hit else " "
        out.append(f"{mark}{n:>{width}}  {ln}")
    return "\n".join(out)


def _sev(v: Any) -> str:
    s = _val(v).upper()
    return s if s in _SEV_RANK else "INFO"


def _counts(sevs: Iterable[str]) -> Dict[str, int]:
    c = {s: 0 for s in SEV_ORDER}
    for s in sevs:
        c[_sev(s)] += 1
    return c


def _verdict(L: Mapping[str, Any], c: Mapping[str, int]) -> tuple[str, str]:
    if c.get("CRITICAL"):
        k = "critical"
    elif c.get("HIGH"):
        k = "high"
    elif c.get("MEDIUM") or c.get("LOW"):
        k = "medium"
    else:
        k = "clean"
    nar = str(L["narrative"][k]).format(c=c.get("CRITICAL", 0), h=c.get("HIGH", 0), m=c.get("MEDIUM", 0), l=c.get("LOW", 0))
    return str(L["verdict"][k]), nar


def _appendix(L: Mapping[str, Any], tools: str = "", extra: Optional[List[dict]] = None) -> List[dict]:
    ap = [
        {"title": L["ap_scoring_t"], "paras": [L["ap_scoring"]]},
        {"title": L["ap_std_t"], "paras": [L["ap_std"]]},
    ]
    if tools:
        ap.append({"title": L["ap_tools_t"], "paras": [tools]})
    ap.extend(extra or [])
    ap.append({"title": L["ap_disc_t"], "paras": [L["ap_disc"]]})
    return ap


def _status(L: Mapping[str, Any], s: Any) -> str:
    return str(L["status"].get(_val(s).upper(), _val(s) or "—"))


# ───────────────────────── scan (SAST/SCA/secrets/IaC/container) ─────────────────────────
def _scan_location(g: Mapping[str, Any]) -> str:
    if g.get("package_name"):
        return f"{g['package_name']} {g.get('package_version', '')}".strip()
    locs = []
    for it in (g.get("items") or []):
        fp = _s(it.get("file_path"))
        if fp:
            ln = it.get("line_start")
            locs.append(f"{fp}:{ln}" if ln else fp)
    shown = list(dict.fromkeys(locs))
    extra = len(shown) - MAX_LOCATIONS
    out = ", ".join(shown[:MAX_LOCATIONS])
    return out + (f" (+{extra})" if extra > 0 else "")


def _scan_catalog(g: Mapping[str, Any]) -> Dict[str, Any]:
    try:
        from scanner.knowledge import cwe_catalog

        cwe = (g.get("items") or [{}])[0].get("cwe")
        return cwe_catalog.lookup(cwe, g.get("scan_type")) or {}
    except Exception:  # noqa: BLE001 - catalog is best-effort
        return {}


def _owasp(g: Mapping[str, Any]) -> str:
    try:
        import types

        from scanner import compliance

        it = (g.get("items") or [{}])[0]
        shim = types.SimpleNamespace(cwe=it.get("cwe"), cve=(g.get("cve_list") or [None])[0], scan_type=g.get("scan_type"))
        cat = compliance.owasp_for(shim)
        return str(cat).split(" ")[0] if cat else ""
    except Exception:  # noqa: BLE001
        return ""


def _tool_status_rows(L: Mapping[str, Any], summary: Any, lang: str):
    """Per-tool run status → ([row...], warning). Empty for scans with no scanner_logs (doc unchanged)."""
    from scanner.report_tools import tool_status

    ts = tool_status(summary if isinstance(summary, Mapping) else None, lang)
    rows = []
    for r in ts["rows"]:
        st = r["status"]
        err = _cap(_scrub(r["error"]), 160)
        if st == "ok":
            detail = str(L["tool_detail_ok"]).format(n=r["count"])
        elif st == "partial":
            detail = str(L["tool_detail_partial"]).format(n=r["count"]) + (f" — {err}" if err else "")
        else:
            detail = err
        rows.append({"tool": _cap(r["label"], 60), "status": st, "status_label": L["tool_status"][st],
                     "detail": detail})
    return rows, (_cap(_scrub(ts["warning"]), 400) if ts["has_gap"] else "")


def _tool_status_line(L: Mapping[str, Any], rows: List[Mapping[str, Any]]) -> str:
    parts = []
    for st in ("ok", "error", "skipped", "partial"):
        n = sum(1 for r in rows if r["status"] == st)
        if n:
            parts.append(f"{n} {L['tool_status_count'][st]}")
    return " · ".join(parts)


def scan_doc(
    project: Any,
    scan: Any,
    grouped: Mapping[str, List[Mapping[str, Any]]],
    severity_counts: Mapping[str, int],
    *,
    branding: Optional[Mapping[str, str]] = None,
    lang: str = "vi",
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    L = get_labels(lang)
    br = branding or {}
    org = br.get("org_name") or "VulnGuard"
    flat: List[dict] = []
    for groups in grouped.values():
        flat.extend(dict(g) for g in groups)
    flat.sort(key=lambda g: (_SEV_RANK.get(_sev(g.get("severity")), 9), -int(g.get("count") or 0)))
    findings = []
    tools_all: List[str] = []
    by_type: Dict[str, dict] = {}
    for i, g in enumerate(flat, 1):
        sev = _sev(g.get("severity"))
        items = g.get("items") or [{}]
        first = items[0]
        cat = _scan_catalog(g)
        desc = g.get("ai_explanation") or first.get("description") or cat.get("mo_ta") or ""
        rem = g.get("ai_fix_suggestion") or cat.get("khac_phuc") or ""
        if g.get("fixed_version"):
            rem = (rem + "\n" if rem else "") + (f"Phiên bản vá: {g['fixed_version']}" if lang == "vi" else f"Fixed version: {g['fixed_version']}")
        code = ""
        snippet = _s(first.get("code_snippet")).strip("\n")
        if snippet:
            start = first.get("line_start")
            snippet = _scrub(snippet)
            code = number_code(snippet, int(start), int(start)) if isinstance(start, int) and start > 0 else snippet
        cvss = fmt_score(first.get("cvss_score"))
        cwe = _s(first.get("cwe"))
        owasp = _owasp(g)
        tools = ", ".join(g.get("tools") or [])
        refs = [r for r in [cat.get("cwe"), *(g.get("cve_list") or [])] if r]
        if g.get("kev"):
            refs.append("CISA KEV")
        if isinstance(g.get("epss"), (int, float)):
            refs.append(f"EPSS {g['epss'] * 100:.0f}%")
        for t in g.get("tools") or []:
            if t not in tools_all:
                tools_all.append(t)
        st = g.get("scan_type") or ""
        row = by_type.setdefault(st, {"name": L["scan_type"].get(st, st), "count": 0, "worst": "INFO", "tools": []})
        row["count"] += int(g.get("count") or 1)
        if _SEV_RANK[sev] < _SEV_RANK[row["worst"]]:
            row["worst"] = sev
        row["tools"] = list(dict.fromkeys(row["tools"] + list(g.get("tools") or [])))
        findings.append({
            "id": f"VG-{i:03d}", "severity": sev, "title": _s(g.get("title")),
            "meta": [
                [L["m_cvss"], (f"{L['cvss3']} {cvss}" if cvss else L["cvss_na"])],
                [L["m_cwe"], " · ".join(x for x in (cwe, owasp) if x) or "—"],
                [L["m_status"], _status(L, first.get("status", "OPEN"))],
                [L["m_tools"], tools or "—"],
            ],
            "cwe": cwe, "description": _prose(desc), "location": _loc(_scan_location(g)), "code": code,
            "remediation": _prose(rem), "refs": refs, "detail": sev in DETAIL_SEVS,
        })
    counts = {s: int(severity_counts.get(s, 0)) for s in SEV_ORDER}
    score = risk_score(counts)
    verdict, narrative = _verdict(L, counts)
    total = sum(counts.values())
    top = [f"{f['id']} — {f['title']}" for f in findings if f["severity"] in ("CRITICAL", "HIGH")][:3]
    scan_types = ", ".join(L["scan_type"].get(t, t) for t in (_g(scan, "scan_types") or [])) or "—"
    meta = {
        "title": str(br.get("report_title") or "").replace("\n", " ").strip() or
                 ("Báo cáo quét bảo mật mã nguồn & thành phần" if lang == "vi" else "Source code & component security scan report"),
        "subtitle": f"{_s(_g(project, 'name'))} · {L['kv_scan']} #{_s(_g(scan, 'scan_number'))}",
        "org": org, "generated": fmt_dt(now or datetime.now(timezone.utc)),
        "kv": [
            [L["kv_target"], _s(_g(project, "name"))],
            [L["kv_path"], _s(_g(scan, "scan_path"))],
            [L["kv_types"], scan_types],
            [L["kv_time"], fmt_dt(_g(scan, "started_at"))],
            [L["kv_tools"], ", ".join(tools_all) or "—"],
            [L["kv_standards"], STANDARDS],
            [L["kv_status"], _val(_g(scan, "status")) or "—"],
            [L["kv_total"], str(total)],
        ],
    }
    tool_rows, tool_warning = _tool_status_rows(L, _g(scan, "summary"), lang)
    if tool_rows:
        meta["kv"].insert(5, [L["kv_tool_status"], _tool_status_line(L, tool_rows)])
    return {
        "lang": lang, "labels": L, "meta": meta,
        "summary": {"verdict": verdict, "score": score, "score_text": f"{score}/100", "counts": counts,
                    "narrative": narrative, "priorities": top,
                    "by_type": [{**r, "tools": ", ".join(r["tools"])} for r in by_type.values()],
                    "tool_status": tool_rows, "warning": tool_warning},
        "findings": findings, "appendix": _appendix(L, ", ".join(tools_all)),
    }


# ───────────────────────── pentest ─────────────────────────
MAX_TRAFFIC_LINES = 12     # headers per side
MAX_BODY_LINES = 40


def _hdrs(h: Any) -> List[str]:
    if isinstance(h, Mapping):  # may be the string "[redaction error]" when redaction failed
        return [f"{k}: {v}" for k, v in list(h.items())[:MAX_TRAFFIC_LINES]]
    return [_s(h)] if h else []


def _cap_body(b: Any) -> str:
    lines = _s(b).split("\n")
    out = "\n".join(lines[:MAX_BODY_LINES])[:1500]
    return out + ("\n… [truncated]" if len(lines) > MAX_BODY_LINES or len(_s(b)) > len(out) else "")


def _traffic_text(t: Optional[Mapping[str, Any]]) -> str:
    if not isinstance(t, Mapping):
        return ""
    lines = [f"{_s(t.get('method'))} {_s(t.get('url'))}", *_hdrs(t.get("request_headers"))]
    if t.get("request_body"):
        lines += ["", _cap_body(t["request_body"])]
    lines += ["", f"→ HTTP {_s(t.get('status_code'))}", *_hdrs(t.get("response_headers"))]
    if t.get("response_body"):
        lines += ["", _cap_body(t["response_body"])]
    return _scrub("\n".join(lines))


def pentest_doc(model: Mapping[str, Any], *, lang: str = "vi", org: str = "VulnGuard") -> Dict[str, Any]:
    """From ``scanner.pentest.report.build_report_model`` output (already scope-filtered + redacted)."""
    L = get_labels(lang)
    run = model.get("run") or {}
    es = model.get("executive_summary") or {}
    roe = model.get("scope_and_roe") or {}
    counts = {s: int((es.get("counts") or {}).get(s.lower(), 0)) for s in SEV_ORDER}
    findings = []
    for i, f in enumerate(model.get("findings") or [], 1):
        sev = _sev(f.get("severity"))
        v4 = f.get("cvss_v4") or {}
        ver = f.get("verification") or {}
        score = v4.get("score")
        cvss = f"{L['cvss4']} {fmt_score(score)} · {_s(v4.get('severity')).upper()}" if score is not None else L["cvss_na"]
        extra: List[dict] = []
        tr = _traffic_text(f.get("evidence_traffic"))
        if tr:
            extra.append({"label": L["x_traffic"], "body": tr, "mono": True})
        poc = f.get("poc") or {}
        if poc.get("curl"):
            extra.append({"label": L["x_curl"], "body": _scrub(_cap_body(poc["curl"])), "mono": True})
        if poc.get("steps"):
            extra.append({"label": L["x_steps"], "body": _scrub("\n".join(f"{n}. {s}" for n, s in enumerate(poc["steps"][:20], 1))), "mono": False})
        if f.get("claimed_severity") and f.get("severity_cap"):
            extra.append({"label": L["x_cap"], "body": f"{_s(f['claimed_severity']).upper()} → {_s(f['severity_cap']).upper()}", "mono": False})
        refs = list(f.get("references") or [])
        for k in ("cve", "attack_technique"):
            if f.get(k):
                refs.append(_s(f[k]))
        findings.append({
            "id": f"VG-{i:03d}", "severity": sev, "title": _s(f.get("title")),
            "badge": L["badge_verified"] if ver.get("verified") else "",
            "vector": _s(v4.get("vector")),
            "meta": [
                [L["m_cvss"], cvss],
                [L["m_cwe"], " · ".join(x for x in (_s(f.get("cwe")), _s(f.get("wstg_id"))) if x) or "—"],
                [L["m_verify"], _s(ver.get("label")) or (L["badge_verified"] if ver.get("verified") else L["badge_unverified"])],
                [L["m_status"], _status(L, f.get("status", "OPEN"))],
            ],
            "cwe": _s(f.get("cwe")), "description": _prose(f.get("description")),
            "location": _loc(" ".join(x for x in (_s(f.get("target")), f"({_s(f['param'])})" if f.get("param") else "") if x)),
            "evidence": _scrub(f.get("evidence")), "extra": extra, "remediation": _prose(f.get("remediation")),
            "refs": refs, "detail": sev in DETAIL_SEVS,
        })
    worst = es.get("overall_risk")
    verdict, narrative = _verdict(L, counts)
    scope = "; ".join(f"{_s(r.get('type'))}:{_s(r.get('value'))}" for r in (roe.get("scope_rules") or []) if r.get("mode", "allow") == "allow")
    excl = "; ".join(f"{_s(r.get('type'))}:{_s(r.get('value'))}" for r in (roe.get("exclusions") or []))
    meta = {
        "title": "Báo cáo kiểm thử xâm nhập (Pentest)" if lang == "vi" else "Penetration test report",
        "subtitle": f"{_s(run.get('engagement'))} · {L['kv_run']} #{_s(run.get('number'))}",
        "org": org, "generated": fmt_dt(model.get("generated_at")),
        "kv": [
            [L["kv_engagement"], _s(run.get("engagement"))],
            [L["kv_goal"], _s(run.get("goal")) or "—"],
            [L["kv_time"], fmt_dt(run.get("started_at"))],
            [L["kv_authorized"], _s(roe.get("authorized_by")) or "—"],
            [L["kv_scope"], scope or "—"],
            [L["kv_standards"], "PTES · OWASP WSTG v4.2 · CVSS v4.0"],
            [L["kv_status"], _s(run.get("status")) or "—"],
            [L["kv_total"], str(int(es.get("total") or len(findings)))],
        ],
    }
    scope_paras = [f"{L['kv_scope']}: {scope or '—'}"]
    if excl:
        scope_paras.append(f"Exclusions: {excl}")
    if roe.get("authorization_note"):
        scope_paras.append(_s(roe["authorization_note"]))
    doc = {
        "lang": lang, "labels": L, "meta": meta,
        "summary": {"verdict": verdict if worst not in (None, "none") else L["verdict"]["clean"],
                    "score": risk_score(counts), "score_text": f"{risk_score(counts)}/100", "counts": counts,
                    "narrative": narrative if worst not in (None, "none") else L["narrative"]["clean"],
                    "priorities": [f"{x.get('id', '')[:8]} — {x.get('title', '')}" for x in (es.get("top_issues") or [])][:3],
                    "by_type": [{"name": L["scan_type"]["PENTEST"], "count": sum(counts.values()),
                                 "worst": next((s for s in SEV_ORDER if counts[s]), "INFO"), "tools": "Pentest Agent"}]},
        "findings": findings,
        "appendix": _appendix(L, extra=[
            {"title": L["ap_scope_t"], "paras": scope_paras},
            {"title": L["ap_method_t"], "paras": [L["ap_method"]]},
        ]),
    }
    return doc


# ───────────────────────── web scan ─────────────────────────
def webscan_doc(scan: Any, findings_in: Iterable[Mapping[str, Any]], *, lang: str = "vi", org: str = "VulnGuard",
                now: Optional[datetime] = None) -> Dict[str, Any]:
    """``findings_in`` are the dicts produced by ``webscans._finding_out``."""
    L = get_labels(lang)
    rows = sorted(findings_in, key=lambda f: (_SEV_RANK.get(_sev(f.get("severity")), 9), _s(f.get("name"))))
    findings = []
    for i, f in enumerate(rows, 1):
        sev = _sev(f.get("severity"))
        cvss = fmt_score(f.get("cvss_score"))
        # curl_command / nuclei `extracted` values are deliberately NOT included: they carry the
        # actual keys/tokens the templates matched, and the webscan HTML report omits them too.
        findings.append({
            "id": f"VG-{i:03d}", "severity": sev, "title": _s(f.get("name")),
            "meta": [
                [L["m_cvss"], f"{L['cvss3']} {cvss}" if cvss else L["cvss_na"]],
                [L["m_cwe"], " · ".join(x for x in (_s(f.get("cwe")), _s(f.get("cve"))) if x) or "—"],
                [L["m_template"], _s(f.get("template_id")) or "—"],
                [L["m_status"], _status(L, f.get("status", "OPEN"))],
            ],
            "cwe": _s(f.get("cwe")), "description": _prose(f.get("description")),
            "location": _loc(f.get("matched_at") or f.get("host")),
            "remediation": _prose(f.get("remediation")), "refs": [_s(r) for r in (f.get("reference") or [])[:8]],
            "detail": sev in DETAIL_SEVS,
        })
    counts = _counts(f["severity"] for f in findings)
    verdict, narrative = _verdict(L, counts)
    score = risk_score(counts)
    meta = {
        "title": "Báo cáo quét ứng dụng web" if lang == "vi" else "Web application scan report",
        "subtitle": f"{L['kv_scan']} {_s(_g(scan, 'id'))[:8]}",
        "org": org, "generated": fmt_dt(now or datetime.now(timezone.utc)),
        "kv": [
            [L["kv_time"], fmt_dt(_g(scan, "started_at"))],
            [L["kv_status"], _val(_g(scan, "status")) or "—"],
            [L["kv_authorized"], _s(_g(scan, "authorized_by")) or "—"],
            [L["kv_total"], str(len(findings))],
            [L["kv_standards"], "OWASP Top 10 (2021) · OWASP WSTG v4.2"],
        ],
    }
    return {
        "lang": lang, "labels": L, "meta": meta,
        "summary": {"verdict": verdict, "score": score, "score_text": f"{score}/100", "counts": counts, "narrative": narrative,
                    "priorities": [f"{f['id']} — {f['title']}" for f in findings if f["severity"] in ("CRITICAL", "HIGH")][:3],
                    "by_type": [{"name": L["scan_type"]["WEB"], "count": len(findings),
                                 "worst": next((s for s in SEV_ORDER if counts[s]), "INFO"), "tools": "Nuclei"}]},
        "findings": findings, "appendix": _appendix(L, "Nuclei"),
    }


# ───────────────────────── document review ─────────────────────────
_DR_SEV = {"NOT_MET": "HIGH", "PARTIAL": "MEDIUM", "MET": "INFO", "NOT_APPLICABLE": "INFO"}


def docreview_doc(document: Any, version: Any, review_findings: Iterable[Any], summary: Mapping[str, Any], *,
                  lang: str = "vi", org: str = "VulnGuard", now: Optional[datetime] = None) -> Dict[str, Any]:
    L = get_labels(lang)
    rows = list(review_findings)
    rows.sort(key=lambda r: (_SEV_RANK[_DR_SEV.get(_val(_g(r, "status")).upper(), "INFO")], _s(_g(r, "criteria_id"))))
    findings = []
    st_label = {"NOT_MET": L["dr_not_met"], "PARTIAL": L["dr_partial"], "MET": L["dr_met"], "NOT_APPLICABLE": L["dr_na"]}
    for i, r in enumerate(rows, 1):
        key = _val(_g(r, "status")).upper()
        sev = _DR_SEV.get(key, "INFO")
        findings.append({
            "id": f"VG-{i:03d}", "severity": sev, "title": f"{_s(_g(r, 'criteria_id'))} — {_scrub(_cap(_g(r, 'criteria_text'), 200))}",
            "meta": [[L["m_criteria"], _s(_g(r, "criteria_id"))], [L["m_category"], _s(_g(r, "category"))],
                     [L["m_status"], st_label.get(key, key)]],
            "description": _prose(_g(r, "criteria_text")), "evidence": _scrub(_g(r, "evidence")),
            "remediation": _prose(_g(r, "recommendation")), "location": _loc(_g(r, "category")),
            "detail": sev in DETAIL_SEVS,
        })
    counts = _counts(f["severity"] for f in findings)
    s = summary or {}
    narrative = L["dr_narrative"].format(t=s.get("total", len(rows)), met=s.get("met", 0), p=s.get("partial", 0),
                                         n=s.get("not_met", 0), na=s.get("not_applicable", 0))
    bad = bool(s.get("not_met") or s.get("partial"))
    pct = s.get("score_pct")
    meta = {
        "title": "Báo cáo rà soát tài liệu" if lang == "vi" else "Document review report",
        "subtitle": f"{_s(_g(document, 'name'))} · {L['kv_version']} {_s(_g(version, 'version_number'))}",
        "org": org, "generated": fmt_dt(now or datetime.now(timezone.utc)),
        "kv": [
            [L["kv_document"], _s(_g(document, "name"))],
            [L["kv_version"], _s(_g(version, "version_number"))],
            [L["kv_score"], f"{pct}%" if pct is not None else "—"],
            [L["kv_total"], str(len(findings))],
        ],
    }
    return {
        "lang": lang, "labels": L, "meta": meta,
        "summary": {"verdict": L["dr_verdict_bad"] if bad else L["dr_verdict_ok"],
                    "score": pct if pct is not None else 0, "score_text": f"{pct}%" if pct is not None else "—",
                    "counts": counts, "narrative": narrative, "priorities": [],
                    "by_type": [{"name": L["scan_type"]["DOCREVIEW"], "count": len(findings),
                                 "worst": next((x for x in SEV_ORDER if counts[x]), "INFO"), "tools": "AI"}]},
        "findings": findings, "appendix": [{"title": L["ap_disc_t"], "paras": [L["ap_disc"]]}],
    }
