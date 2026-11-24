"""
AI Security Report — Tạo báo cáo HTML hoàn chỉnh từ kết quả scan.

Endpoint:
  GET /api/scans/{scan_id}/report          → trả về HTML trực tiếp
  GET /api/scans/{scan_id}/report?download=true → force download file .html

Logic:
  1. Load tất cả vulns từ DB
  2. Dedup cross-tool: cùng fingerprint / (title+file+line) → gộp lại, liệt kê tất cả tools phát hiện
  3. Group theo loại:
     - SCA     → group by package_name
     - SAST    → group by rule_id / title
     - SECRETS → group by secret type (title)
     - IAC     → group by rule_id / title
  4. Dùng ai_explanation + ai_fix_suggestion đã có trong DB
  5. Render HTML template đầy đủ, tiếng Việt
"""

import json
import re
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import List, Optional

# Timezone Việt Nam (UTC+7)
VN_TZ = timezone(timedelta(hours=7))


def _now_vn() -> str:
    """Trả về giờ hiện tại theo múi giờ Việt Nam."""
    return datetime.now(VN_TZ).strftime("%d/%m/%Y %H:%M (GMT+7)")


def _fmt_vn(dt: datetime) -> str:
    """Format datetime sang giờ VN."""
    if not dt:
        return "N/A"
    if dt.tzinfo is None:
        # Assume UTC nếu không có tzinfo
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(VN_TZ).strftime("%d/%m/%Y %H:%M")

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from api.database import get_db
from api.models import Project, Scan, Vulnerability, ScanStatus, Severity, ScanType

router = APIRouter(prefix="/api/scans", tags=["report"])

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_VI = {
    "CRITICAL": "Nghiêm trọng",
    "HIGH":     "Cao",
    "MEDIUM":   "Trung bình",
    "LOW":      "Thấp",
    "INFO":     "Thông tin",
}
SEVERITY_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#16a34a",
    "INFO":     "#6b7280",
}
SEVERITY_BG = {
    "CRITICAL": "#fef2f2",
    "HIGH":     "#fff7ed",
    "MEDIUM":   "#fffbeb",
    "LOW":      "#f0fdf4",
    "INFO":     "#f9fafb",
}

SCAN_TYPE_VI = {
    "SAST":      "Phân tích mã tĩnh (SAST)",
    "SCA":       "Kiểm tra thư viện (SCA)",
    "SECRETS":   "Phát hiện bí mật (Secrets)",
    "IAC":       "Kiểm tra hạ tầng (IaC)",
    "CONTAINER": "Quét container (Container)",
}

TOOL_VI = {
    "bandit":          "Bandit",
    "semgrep":         "Semgrep",
    "trivy":           "Trivy (SCA)",
    "pip-audit":       "pip-audit",
    "trivy-container": "Trivy (Container)",
    "grype":           "Grype",
    "checkov":         "Checkov",
    "trivy-iac":       "Trivy (IaC)",
    "hadolint":        "Hadolint",
    "gitleaks":        "Gitleaks",
    "detect-secrets":  "detect-secrets",
}


def _severity_badge(sev: str) -> str:
    color = SEVERITY_COLOR.get(sev, "#6b7280")
    bg = SEVERITY_BG.get(sev, "#f9fafb")
    label = SEVERITY_VI.get(sev, sev)
    return f'<span class="badge" style="color:{color};background:{bg};border:1px solid {color}20">{label}</span>'


def _exploit_badges(g: dict) -> str:
    """Badge KEV/EPSS cho report (HTML inline, không phụ thuộc CSS class)."""
    out = ""
    if g.get("kev"):
        out += ('<span class="badge" style="color:#991b1b;background:#fee2e2;'
                'border:1px solid #991b1b20">🔥 KEV</span>')
        if g.get("kev_ransomware"):
            out += (' <span class="badge" style="color:#991b1b;background:#fee2e2;'
                    'border:1px solid #991b1b20">💀 Ransomware</span>')
    epss = g.get("epss")
    if isinstance(epss, (int, float)):
        pct = f"{epss * 100:.0f}" if epss >= 0.1 else f"{epss * 100:.1f}"
        col = "#991b1b" if epss >= 0.5 else ("#92400e" if epss >= 0.1 else "#374151")
        out += (f' <span class="badge" style="color:{col};background:#f3f4f6;'
                f'border:1px solid {col}20" title="EPSS: xác suất bị khai thác 30 ngày">EPSS {pct}%</span>')
    return out


def _esc(text: str) -> str:
    """HTML escape"""
    if not text:
        return ""
    return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def _knowledge_block(g: dict) -> str:
    """
    Khối 'Phân tích & Khắc phục (tri thức)' — LUÔN có nội dung, không phụ thuộc AI.
    Ghép từ catalog CWE (là gì / tác động / PoC / khắc phục) + tri thức lỗ hổng
    (EPSS/KEV/bản vá/summary/tham chiếu từ KB). Trả "" nếu không suy được gì.
    """
    from scanner.knowledge import cwe_catalog
    cwe_field = g["items"][0].get("cwe") if g.get("items") else None
    info = cwe_catalog.lookup(cwe_field, g.get("scan_type"))
    if not info:
        return ""

    # Tri thức lỗ hổng cho SCA: summary + references từ KB (an toàn nếu KB vắng)
    kb_summary, kb_refs = "", []
    cves = g.get("cve_list") or []
    if cves:
        try:
            from scanner.knowledge import store
            e = store.enrich(cve=cves[0])
            kb_summary = e.get("summary") or ""
            kb_refs = e.get("references") or []
        except Exception:
            pass

    head = info.get("cwe") or (f"CWE-{''.join(ch for ch in str(cwe_field) if ch.isdigit())}"
                               if cwe_field else "")
    # Tín hiệu rủi ro (badge KEV/EPSS/CVSS) để phần PoC có bối cảnh ưu tiên
    risk = _exploit_badges(g)
    cvss = g["items"][0].get("cvss_score") if g.get("items") else ""
    if cvss:
        risk += (f' <span class="badge" style="color:#374151;background:#f3f4f6;'
                 f'border:1px solid #37415120">CVSS {_esc(cvss)}</span>')

    def row(icon, label, text, color="#0369a1"):
        if not text:
            return ""
        return (f'<div style="margin-top:8px;">'
                f'<div style="font-size:11px;font-weight:700;text-transform:uppercase;'
                f'letter-spacing:.5px;color:{color};margin-bottom:3px;">{icon} {label}</div>'
                f'<div style="font-size:13px;line-height:1.55;color:#1f2937;">{text}</div></div>')

    refs_html = ""
    ref_links = []
    if head and head.startswith("CWE-"):
        n = head.split("-", 1)[1]
        ref_links.append(f'<a href="https://cwe.mitre.org/data/definitions/{n}.html" '
                         f'style="color:#2563eb;">{_esc(head)} (MITRE)</a>')
    for r in kb_refs[:5]:
        ref_links.append(f'<a href="{_esc(r)}" style="color:#2563eb;word-break:break-all;">{_esc(r)}</a>')
    if ref_links:
        refs_html = row("📎", "Tham chiếu", " · ".join(ref_links), "#6b7280")

    title = f'{_esc(head)}: {_esc(info["ten"])}' if head else _esc(info["ten"])
    desc = _esc(info["mo_ta"])
    if kb_summary:
        desc += f'<br><em style="color:#475569;">{_esc(kb_summary)}</em>'

    return f"""
    <div class="ai-block" style="border-left:4px solid #0369a1;background:#f0f9ff;">
      <div class="ai-label" style="color:#075985;">🧠 Phân tích &amp; Khắc phục (tri thức)</div>
      <div style="font-weight:700;font-size:14px;color:#0c4a6e;margin-bottom:2px;">{title}</div>
      <div style="font-size:13px;line-height:1.55;color:#1f2937;">{desc}</div>
      {row("💥", "Tác động", _esc(info.get("tac_dong")), "#b91c1c")}
      {row("🎯", "Khả năng khai thác / PoC", _esc(info.get("poc")) + (("<div style='margin-top:4px;'>" + risk + "</div>") if risk else ""), "#9a3412")}
      {row("🔧", "Khắc phục", _esc(info.get("khac_phuc")), "#15803d")}
      {refs_html}
    </div>"""


def _md_lite(text: str) -> str:
    """Markdown rút gọn → HTML an toàn: ```code```, `inline`, **bold**, bullet/number list.
    Dùng cho phần phân tích AI để dễ đọc thay vì 1 khối text phẳng."""
    import re as _re
    if not text:
        return ""
    segs = str(text).split("```")
    html = ""
    for i, seg in enumerate(segs):
        if i % 2 == 1:   # code fence
            body = _re.sub(r"^[A-Za-z0-9_+\-]*\n", "", seg).rstrip("\n")
            html += (f'<pre style="background:#0f172a;color:#e2e8f0;border-radius:6px;'
                     f'padding:10px;overflow:auto;font-size:12px;line-height:1.5;margin:8px 0;'
                     f'white-space:pre-wrap;"><code>{_esc(body)}</code></pre>')
            continue

        def _inline(s: str) -> str:
            s = _esc(s)
            s = _re.sub(r"`([^`]+)`",
                        r'<code style="background:#eef2ff;padding:1px 5px;border-radius:4px;'
                        r'font-size:12px;">\1</code>', s)
            s = _re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
            return s

        lines, para, in_list = seg.split("\n"), [], None
        def _flush_para():
            nonlocal para
            if para:
                html_parts.append(f'<p style="margin:5px 0;">{"<br>".join(para)}</p>')
                para = []
        html_parts: list = []
        for raw in lines:
            line = raw.rstrip()
            m_ul = _re.match(r"^\s*[-*]\s+(.*)", line)
            m_ol = _re.match(r"^\s*\d+[.)]\s+(.*)", line)
            if m_ul:
                _flush_para()
                if in_list != "ul":
                    if in_list:
                        html_parts.append(f"</{in_list}>")
                    html_parts.append('<ul style="margin:5px 0 5px 18px;">'); in_list = "ul"
                html_parts.append(f"<li>{_inline(m_ul.group(1))}</li>")
            elif m_ol:
                _flush_para()
                if in_list != "ol":
                    if in_list:
                        html_parts.append(f"</{in_list}>")
                    html_parts.append('<ol style="margin:5px 0 5px 18px;">'); in_list = "ol"
                html_parts.append(f"<li>{_inline(m_ol.group(1))}</li>")
            elif not line.strip():
                _flush_para()
                if in_list:
                    html_parts.append(f"</{in_list}>"); in_list = None
            else:
                if in_list:
                    html_parts.append(f"</{in_list}>"); in_list = None
                para.append(_inline(line))
        _flush_para()
        if in_list:
            html_parts.append(f"</{in_list}>")
        html += "".join(html_parts)
    return html


def _dedup_and_group(vulns: List[Vulnerability]):
    """
    Dedup cross-tool, group by (scan_type, group_key).
    Trả về dict: { scan_type: [ group_dict, ... ] }
    Mỗi group_dict:
      {
        group_key: str,
        title: str,
        severity: str (highest),
        tools: [str],
        items: [ vuln_dict ],   # đã dedup
        count: int,
        ai_explanation: str,
        ai_fix_suggestion: str,
        package_name: str,       # SCA only
        fixed_version: str,      # SCA only
        cve_list: [str],         # SCA only
      }
    """
    # Step 1: dedup by fingerprint
    seen_fps: dict = {}       # fingerprint → merged vuln dict
    no_fp_list: list = []     # vulns without fingerprint

    for v in vulns:
        fp = v.fingerprint
        if fp:
            if fp in seen_fps:
                # Merge: thêm tool nếu chưa có
                if v.tool not in seen_fps[fp]["tools"]:
                    seen_fps[fp]["tools"].append(v.tool)
                # Nếu vuln mới có AI data còn vuln cũ chưa có → dùng
                if not seen_fps[fp].get("ai_explanation") and v.ai_explanation:
                    seen_fps[fp]["ai_explanation"] = v.ai_explanation
                if not seen_fps[fp].get("ai_fix_suggestion") and v.ai_fix_suggestion:
                    seen_fps[fp]["ai_fix_suggestion"] = v.ai_fix_suggestion
            else:
                seen_fps[fp] = _vuln_to_dict(v)
        else:
            no_fp_list.append(_vuln_to_dict(v))

    deduped = list(seen_fps.values()) + no_fp_list

    # Step 2: group
    grouped: dict = defaultdict(lambda: defaultdict(list))
    for vd in deduped:
        scan_type = vd["scan_type"]
        gk = _group_key(vd)
        grouped[scan_type][gk].append(vd)

    result: dict = {}
    for scan_type, gk_map in grouped.items():
        groups = []
        for gk, items in gk_map.items():
            # Tìm severity cao nhất trong group
            highest_sev = min(items, key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))["severity"]

            # Gộp tools
            all_tools = []
            for item in items:
                for t in item["tools"]:
                    if t not in all_tools:
                        all_tools.append(t)

            # Lấy AI data từ item có data tốt nhất
            ai_expl = ""
            ai_fix = ""
            ai_fp_likelihood = ""
            ai_fp_reason = ""
            ai_exploit_public = ""
            ai_exploit_private = ""
            ai_analyzed_count = 0
            for item in items:
                if item.get("ai_explanation") and not ai_expl:
                    ai_expl = item["ai_explanation"]
                if item.get("ai_fix_suggestion") and not ai_fix:
                    ai_fix = item["ai_fix_suggestion"]
                if item.get("ai_fp_likelihood") and not ai_fp_likelihood:
                    ai_fp_likelihood = item["ai_fp_likelihood"]
                if item.get("ai_fp_reason") and not ai_fp_reason:
                    ai_fp_reason = item["ai_fp_reason"]
                if item.get("ai_exploitability_public") and not ai_exploit_public:
                    ai_exploit_public = item["ai_exploitability_public"]
                if item.get("ai_exploitability_private") and not ai_exploit_private:
                    ai_exploit_private = item["ai_exploitability_private"]
                if item.get("ai_analyzed"):
                    ai_analyzed_count += 1

            # CVE list cho SCA
            cve_list = list({
                item["cve"] for item in items
                if item.get("cve")
            })

            # fixed_version — lấy cái đầu tiên có
            fixed_version = next(
                (item["fixed_version"] for item in items if item.get("fixed_version")),
                ""
            )

            # package info
            package_name = items[0].get("package_name", "") or ""
            package_version = items[0].get("package_version", "") or ""

            # Lấy title đại diện
            title = items[0]["title"]
            if scan_type == "SCA" and package_name:
                title = f"{package_name} {package_version}".strip()

            # Tổng hợp tín hiệu khai thác (KEV/EPSS) trong group
            grp_kev = any(it.get("kev") for it in items)
            grp_ransom = any(it.get("kev_ransomware") for it in items)
            grp_epss = max((it["epss"] for it in items if isinstance(it.get("epss"), (int, float))),
                           default=None)
            groups.append({
                "group_key":             gk,
                "title":                 title,
                "severity":              highest_sev,
                "kev":                   grp_kev,
                "kev_ransomware":        grp_ransom,
                "epss":                  grp_epss,
                "tools":                 all_tools,
                "items":                 sorted(items, key=lambda x: SEVERITY_ORDER.get(x["severity"], 99)),
                "count":                 len(items),
                "ai_explanation":        ai_expl,
                "ai_fix_suggestion":     ai_fix,
                "ai_fp_likelihood":      ai_fp_likelihood,
                "ai_fp_reason":          ai_fp_reason,
                "ai_exploitability_public":  ai_exploit_public,
                "ai_exploitability_private": ai_exploit_private,
                "ai_analyzed_count":     ai_analyzed_count,
                "package_name":          package_name,
                "package_version":       package_version,
                "fixed_version":         fixed_version,
                "cve_list":              sorted(cve_list),
                "scan_type":             scan_type,
            })

        # Sort: severity cao nhất trước, sau đó count
        groups.sort(key=lambda g: (SEVERITY_ORDER.get(g["severity"], 99), -g["count"]))
        result[scan_type] = groups

    return result


def _group_key(vd: dict) -> str:
    scan_type = vd["scan_type"]
    if scan_type == "SCA":
        return vd.get("package_name") or vd["title"]
    elif scan_type in ("SAST", "IAC"):
        return vd.get("rule_id") or vd["title"]
    elif scan_type == "SECRETS":
        return vd["title"]
    else:
        return vd.get("rule_id") or vd["title"]


def _vuln_to_dict(v: Vulnerability) -> dict:
    return {
        "id":                   v.id,
        "title":               v.title or "",
        "description":         v.description or "",
        "severity":            v.severity.value if v.severity else "INFO",
        "scan_type":           v.scan_type.value if v.scan_type else "",
        "tool":                v.tool or "",
        "tools":               [v.tool] if v.tool else [],
        "rule_id":             v.rule_id or "",
        "file_path":           v.file_path or "",
        "line_start":          v.line_start,
        "line_end":            v.line_end,
        "code_snippet":        v.code_snippet or "",
        "cwe":                 v.cwe or "",
        "cve":                 v.cve or "",
        "cvss_score":          v.cvss_score or "",
        "package_name":        v.package_name or "",
        "package_version":     v.package_version or "",
        "fixed_version":       v.fixed_version or "",
        "epss":                v.epss,
        "epss_percentile":     v.epss_percentile,
        "kev":                 v.kev,
        "kev_ransomware":      v.kev_ransomware,
        "kev_due_date":        v.kev_due_date or "",
        "priority_reason":     v.priority_reason or "",
        "severity_original":   v.severity_original or "",
        "fingerprint":         v.fingerprint or "",
        "status":              v.status.value if v.status else "OPEN",
        "ai_explanation":      v.ai_explanation or "",
        "ai_fix_suggestion":   v.ai_fix_suggestion or "",
        "ai_fp_likelihood":    v.ai_false_positive_likelihood or "",
        "ai_fp_reason":        getattr(v, 'ai_false_positive_reason', None) or "",
        "ai_exploitability_public":  v.ai_exploitability_public or "",
        "ai_exploitability_private": v.ai_exploitability_private or "",
        "ai_analyzed":         v.ai_analyzed_at is not None,
    }


# ─────────────────────────────────────────────
# HTML Template
# ─────────────────────────────────────────────

def _is_fallback_text(text: str) -> bool:
    """True nếu text là fallback error message — không hiển thị trong report."""
    from scanner.ai_analyzer import _is_ai_fallback
    return _is_ai_fallback(text)


def _tools_section(scan) -> str:
    """1.5: liệt kê MỌI công cụ đã chạy kèm trạng thái (chạy/0 lỗi/bỏ qua/lỗi) — báo cáo trung thực."""
    logs = (getattr(scan, "summary", None) or {}).get("scanner_logs") or {}
    if not logs:
        return ""
    _ic = {"ok": "✅", "skipped": "⊘", "error": "❌"}
    rows = ""
    has_gap = False
    for tool, lg in sorted(logs.items()):
        st = lg.get("status", "ok")
        if st in ("skipped", "error"):
            has_gap = True
        label = _esc(lg.get("label") or tool)
        detail = (f'{lg.get("count", 0)} phát hiện' if st == "ok"
                  else ("BỎ QUA (chưa cài / thiếu PATH)" if st == "skipped" else f'LỖI: {_esc((lg.get("error") or "")[:120])}'))
        color = "#0ca30c" if st == "ok" else "#d03b3b"
        rows += (f'<tr><td>{_ic.get(st, "•")} {label}</td>'
                 f'<td style="color:{color};font-weight:600;">{detail}</td></tr>')
    warn = ('<div style="background:#fff3cd;border:1px solid #ffc107;border-radius:6px;padding:10px 14px;margin-bottom:12px;color:#856404;">'
            '⚠️ Có công cụ bị <b>bỏ qua/lỗi</b> — kết quả KHÔNG đầy đủ, "0 lỗi" không có nghĩa là sạch.</div>') if has_gap else ""
    return (f'<div class="page-section"><h2>🛠️ Công cụ đã dùng</h2>{warn}'
            f'<table style="width:100%;border-collapse:collapse;"><thead><tr>'
            f'<th style="text-align:left;border-bottom:2px solid #e2e8f0;padding:6px;">Công cụ</th>'
            f'<th style="text-align:left;border-bottom:2px solid #e2e8f0;padding:6px;">Trạng thái</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div>')


@router.get("/{scan_id}/report", response_class=HTMLResponse)
def generate_report(
    scan_id: str,
    download: bool = Query(default=False, description="True để download file .html"),
    format: str = Query(default="html", description="html | pdf (pdf cần Chromium headless)"),
    db: Session = Depends(get_db),
):
    """
    Tạo báo cáo bảo mật HTML hoàn chỉnh từ kết quả scan.
    - Dedup vulns tìm thấy bởi nhiều tools
    - Group theo package (SCA) / rule (SAST) / loại bí mật (Secrets) / IaC check
    - Tích hợp AI explanation và fix suggestion
    - Ngôn ngữ tiếng Việt
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan không tồn tại")

    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(
            status_code=400,
            detail=f"Scan chưa hoàn thành (status: {scan.status.value}). Vui lòng chờ scan hoàn tất."
        )

    project = db.query(Project).filter(Project.id == scan.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project không tồn tại")

    vulns = (
        db.query(Vulnerability)
        .filter(Vulnerability.scan_id == scan_id)
        .order_by(Vulnerability.severity)
        .all()
    )

    # Dedup + group
    grouped = _dedup_and_group(vulns)

    # Severity counts (raw, before dedup — matches summary)
    severity_counts: dict = {s.value: 0 for s in Severity}
    for v in vulns:
        severity_counts[v.severity.value] += 1

    from scanner import report_pro
    html = report_pro.render(
        project=project,
        scan=scan,
        grouped=grouped,
        severity_counts=severity_counts,
        vulns=vulns,
    )

    project_slug = project.name.replace(" ", "_")[:40]

    # Xuất PDF phía server (1-click) nếu môi trường có Chromium headless.
    if format == "pdf":
        from fastapi import Response
        from scanner.pdf_render import PdfUnavailable, html_to_pdf
        try:
            pdf = html_to_pdf(html)
        except PdfUnavailable:
            raise HTTPException(
                status_code=501,
                detail="Máy chủ chưa có Chromium headless để xuất PDF. Hãy dùng nút "
                       "'Lưu PDF / In' trong báo cáo (in ra PDF từ trình duyệt), hoặc cài "
                       "Chromium trên máy chủ.")
        return Response(
            content=pdf, media_type="application/pdf",
            headers={"Content-Disposition":
                     f'attachment; filename="vulnguard_report_{project_slug}_scan{scan.scan_number}.pdf"'})

    headers = {}
    if download:
        filename = f"vulnguard_report_{project_slug}_scan{scan.scan_number}.html"
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'

    return HTMLResponse(content=html, headers=headers)
