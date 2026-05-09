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


def _esc(text: str) -> str:
    """HTML escape"""
    if not text:
        return ""
    return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


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
            for item in items:
                if item.get("ai_explanation") and not ai_expl:
                    ai_expl = item["ai_explanation"]
                if item.get("ai_fix_suggestion") and not ai_fix:
                    ai_fix = item["ai_fix_suggestion"]

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

            groups.append({
                "group_key":       gk,
                "title":           title,
                "severity":        highest_sev,
                "tools":           all_tools,
                "items":           sorted(items, key=lambda x: SEVERITY_ORDER.get(x["severity"], 99)),
                "count":           len(items),
                "ai_explanation":  ai_expl,
                "ai_fix_suggestion": ai_fix,
                "package_name":    package_name,
                "package_version": package_version,
                "fixed_version":   fixed_version,
                "cve_list":        sorted(cve_list),
                "scan_type":       scan_type,
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
        "id":                  v.id,
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
        "fingerprint":         v.fingerprint or "",
        "status":              v.status.value if v.status else "OPEN",
        "ai_explanation":      v.ai_explanation or "",
        "ai_fix_suggestion":   v.ai_fix_suggestion or "",
        "ai_fp_likelihood":    v.ai_false_positive_likelihood or "",
    }


# ─────────────────────────────────────────────
# HTML Template
# ─────────────────────────────────────────────

def _is_fallback_text(text: str) -> bool:
    """True nếu text là fallback error message — không hiển thị trong report."""
    from scanner.ai_analyzer import _is_ai_fallback
    return _is_ai_fallback(text)


def _render_html(
    project: Project,
    scan: Scan,
    grouped: dict,
    total_vulns: int,
    severity_counts: dict,
) -> str:

    generated_at = _now_vn()
    scan_date = _fmt_vn(scan.started_at)
    completed_date = _fmt_vn(scan.completed_at)
    scan_types_str = ", ".join(scan.scan_types or [])

    # Summary numbers
    crit  = severity_counts.get("CRITICAL", 0)
    high  = severity_counts.get("HIGH", 0)
    med   = severity_counts.get("MEDIUM", 0)
    low   = severity_counts.get("LOW", 0)
    info  = severity_counts.get("INFO", 0)

    # Tools used
    tools_used = set()
    for groups in grouped.values():
        for g in groups:
            for t in g["tools"]:
                tools_used.add(t)
    tools_str = ", ".join(sorted(TOOL_VI.get(t, t) for t in tools_used)) or "N/A"

    # ── Executive Summary Table ──────────────────
    exec_summary_rows = []
    for scan_type, groups in sorted(grouped.items()):
        type_total = sum(g["count"] for g in groups)
        type_crit  = sum(g["count"] for g in groups if g["severity"] == "CRITICAL")
        type_high  = sum(g["count"] for g in groups if g["severity"] == "HIGH")
        sev_label = ""
        if type_crit:   sev_label = _severity_badge("CRITICAL")
        elif type_high: sev_label = _severity_badge("HIGH")
        else:           sev_label = _severity_badge(groups[0]["severity"] if groups else "INFO")

        top_issues = ", ".join(
            _esc(g["title"][:60] + ("…" if len(g["title"]) > 60 else ""))
            for g in groups[:3]
        )
        exec_summary_rows.append(f"""
        <tr>
          <td><strong>{_esc(SCAN_TYPE_VI.get(scan_type, scan_type))}</strong></td>
          <td class="num">{type_total}</td>
          <td>{sev_label}</td>
          <td class="issues-cell">{top_issues}</td>
        </tr>""")

    # ── Package/Component Summary (like screenshot) ──
    component_rows = []
    all_groups_flat = []
    for groups in grouped.values():
        all_groups_flat.extend(groups)
    all_groups_flat.sort(key=lambda g: (SEVERITY_ORDER.get(g["severity"], 99), -g["count"]))

    for g in all_groups_flat[:30]:  # top 30
        tools_display = " · ".join(TOOL_VI.get(t, t) for t in g["tools"])
        cve_display = ""
        if g["cve_list"]:
            cve_display = f'<br><span class="cve-list">{", ".join(g["cve_list"][:5])}</span>'

        assessment = ""
        ai_expl = g.get("ai_explanation", "")
        if ai_expl and not _is_fallback_text(ai_expl):
            sentences = ai_expl.split(". ")
            assessment = ". ".join(sentences[:2])
            if len(sentences) > 2:
                assessment += "…"
        elif g.get("description"):
            assessment = g["description"][:200]

        component_rows.append(f"""
        <tr>
          <td>
            <strong>{_esc(g["title"])}</strong>
            {f'<br><code class="pkg-ver">{_esc(g["package_version"])}</code>' if g.get("package_version") else ""}
            {cve_display}
          </td>
          <td class="num">{g["count"]}</td>
          <td>{_severity_badge(g["severity"])}</td>
          <td class="tools-cell"><span class="tool-tag">{_esc(tools_display)}</span></td>
          <td class="assessment-cell">{_esc(assessment)}</td>
        </tr>""")

    component_table = f"""
    <table class="data-table">
      <thead>
        <tr>
          <th>Package / Thành phần</th>
          <th>Số lỗi</th>
          <th>Mức độ</th>
          <th>Phát hiện bởi</th>
          <th>Nhận định</th>
        </tr>
      </thead>
      <tbody>
        {''.join(component_rows) if component_rows else '<tr><td colspan="5" class="empty">Không có vấn đề nào được phát hiện</td></tr>'}
      </tbody>
    </table>"""

    # ── Detail sections per scan type ──
    detail_sections = []
    for scan_type in ["SCA", "SAST", "SECRETS", "IAC", "CONTAINER"]:
        groups = grouped.get(scan_type, [])
        if not groups:
            continue

        section_title = SCAN_TYPE_VI.get(scan_type, scan_type)
        group_cards = []

        for g in groups:
            tools_display = " · ".join(TOOL_VI.get(t, t) for t in g["tools"])
            sev = g["severity"]
            border_color = SEVERITY_COLOR.get(sev, "#6b7280")

            # CVE / Rule ID pills
            meta_pills = []
            if g["cve_list"]:
                for cve in g["cve_list"][:8]:
                    meta_pills.append(f'<span class="pill cve-pill">{_esc(cve)}</span>')
            elif g["items"][0].get("rule_id"):
                meta_pills.append(f'<span class="pill rule-pill">{_esc(g["items"][0]["rule_id"])}</span>')
            if g["items"][0].get("cwe"):
                meta_pills.append(f'<span class="pill cwe-pill">{_esc(g["items"][0]["cwe"])}</span>')
            if g["items"][0].get("cvss_score"):
                meta_pills.append(f'<span class="pill cvss-pill">CVSS {_esc(g["items"][0]["cvss_score"])}</span>')

            pills_html = " ".join(meta_pills)

            # Fixed version (SCA)
            fix_version_html = ""
            if g.get("fixed_version"):
                fix_version_html = f'<div class="fix-version">✅ Phiên bản vá: <strong>{_esc(g["fixed_version"])}</strong></div>'

            # AI explanation — bỏ qua fallback error messages
            ai_expl_html = ""
            ai_expl = g.get("ai_explanation", "")
            if ai_expl and not _is_fallback_text(ai_expl):
                ai_expl_html = f"""
                <div class="ai-block">
                  <div class="ai-label">🤖 Phân tích AI</div>
                  <p>{_esc(ai_expl)}</p>
                </div>"""

            # AI fix suggestion — bỏ qua fallback
            ai_fix_html = ""
            ai_fix = g.get("ai_fix_suggestion", "")
            if ai_fix and not _is_fallback_text(ai_fix):
                ai_fix_html = f"""
                <div class="ai-block fix-block">
                  <div class="ai-label">🔧 Hướng dẫn khắc phục</div>
                  <p>{_esc(ai_fix)}</p>
                </div>"""

            # Locations / findings
            findings_html = ""
            if scan_type in ("SAST", "IAC", "SECRETS"):
                loc_rows = []
                for item in g["items"][:20]:
                    file_p = item.get("file_path", "")
                    line_s = item.get("line_start")
                    line_e = item.get("line_end")
                    line_str = ""
                    if line_s:
                        line_str = f"Dòng {line_s}"
                        if line_e and line_e != line_s:
                            line_str += f"–{line_e}"

                    snippet = item.get("code_snippet", "")
                    snippet_html = ""
                    if snippet:
                        snippet_html = f'<pre class="snippet">{_esc(snippet[:300])}</pre>'

                    item_sev_badge = _severity_badge(item["severity"]) if item["severity"] != g["severity"] else ""

                    loc_rows.append(f"""
                    <div class="location-item">
                      <div class="location-header">
                        <span class="file-path">📄 {_esc(file_p)}</span>
                        {f'<span class="line-num">{_esc(line_str)}</span>' if line_str else ""}
                        {item_sev_badge}
                      </div>
                      {snippet_html}
                    </div>""")

                if g["count"] > 20:
                    loc_rows.append(f'<p class="more-hint">... và {g["count"] - 20} vị trí khác</p>')

                if loc_rows:
                    findings_html = f"""
                    <div class="locations-section">
                      <div class="section-sub-title">Vị trí phát hiện ({g["count"]} chỗ)</div>
                      {''.join(loc_rows)}
                    </div>"""

            elif scan_type == "SCA":
                # Table of CVEs
                if g["items"] and (g["cve_list"] or len(g["items"]) > 1):
                    dep_rows = []
                    for item in g["items"][:15]:
                        dep_rows.append(f"""
                        <tr>
                          <td>{_esc(item.get("cve", "") or item.get("rule_id", ""))}</td>
                          <td>{_severity_badge(item["severity"])}</td>
                          <td>{_esc(item["title"][:100])}</td>
                          <td>{_esc(item.get("cvss_score", ""))}</td>
                        </tr>""")
                    findings_html = f"""
                    <div class="locations-section">
                      <table class="data-table inner-table">
                        <thead><tr><th>CVE / ID</th><th>Mức độ</th><th>Mô tả</th><th>CVSS</th></tr></thead>
                        <tbody>{''.join(dep_rows)}</tbody>
                      </table>
                    </div>"""

            group_cards.append(f"""
            <div class="vuln-card" style="border-left:4px solid {border_color}">
              <div class="card-header">
                <div class="card-title">{_esc(g["title"])}</div>
                <div class="card-meta">
                  {_severity_badge(sev)}
                  <span class="count-badge">{g["count"]} vấn đề</span>
                  <span class="tool-tag">{_esc(tools_display)}</span>
                </div>
              </div>
              {f'<div class="pills">{pills_html}</div>' if pills_html else ""}
              {fix_version_html}
              {ai_expl_html}
              {ai_fix_html}
              {findings_html}
            </div>""")

        detail_sections.append(f"""
        <section class="scan-type-section">
          <h2 class="section-title">
            <span class="section-icon">{"📦" if scan_type=="SCA" else "🔍" if scan_type=="SAST" else "🔑" if scan_type=="SECRETS" else "🏗️" if scan_type=="IAC" else "🐳"}</span>
            {_esc(section_title)}
            <span class="section-count">{sum(g["count"] for g in groups)} vấn đề</span>
          </h2>
          {''.join(group_cards)}
        </section>""")

    # ── Severity bar chart ──
    max_count = max(crit, high, med, low, info, 1)
    def bar(count, sev):
        w = round(count / max_count * 100)
        color = SEVERITY_COLOR.get(sev, "#6b7280")
        label = SEVERITY_VI.get(sev, sev)
        return f"""
        <div class="bar-row">
          <div class="bar-label">{label}</div>
          <div class="bar-track">
            <div class="bar-fill" style="width:{w}%;background:{color}"></div>
          </div>
          <div class="bar-count" style="color:{color}">{count}</div>
        </div>"""

    severity_bars = "".join([
        bar(crit, "CRITICAL"),
        bar(high, "HIGH"),
        bar(med, "MEDIUM"),
        bar(low, "LOW"),
        bar(info, "INFO"),
    ])

    # ── Assemble final HTML ──
    return f"""<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Báo cáo bảo mật — {_esc(project.name)} — Scan #{scan.scan_number}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      font-size: 14px;
      line-height: 1.6;
      color: #1a1a2e;
      background: #f8fafc;
    }}
    a {{ color: #3b82f6; text-decoration: none; }}

    /* ── Header ── */
    .report-header {{
      background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%);
      color: #fff;
      padding: 40px 48px 32px;
    }}
    .report-header .logo {{
      font-size: 12px;
      font-weight: 600;
      letter-spacing: 2px;
      text-transform: uppercase;
      color: #94a3b8;
      margin-bottom: 8px;
    }}
    .report-header h1 {{
      font-size: 28px;
      font-weight: 700;
      margin-bottom: 4px;
    }}
    .report-header .subtitle {{
      color: #94a3b8;
      font-size: 14px;
    }}
    .header-meta {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
      gap: 16px;
      margin-top: 28px;
      padding-top: 24px;
      border-top: 1px solid #ffffff20;
    }}
    .meta-item {{ }}
    .meta-label {{
      font-size: 11px;
      color: #64748b;
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 4px;
    }}
    .meta-value {{
      font-size: 13px;
      color: #e2e8f0;
      font-weight: 500;
    }}
    .meta-value code {{
      font-size: 12px;
      background: #ffffff15;
      padding: 2px 6px;
      border-radius: 4px;
    }}

    /* ── Layout ── */
    .container {{
      max-width: 1100px;
      margin: 0 auto;
      padding: 32px 24px 64px;
    }}

    /* ── Summary Cards ── */
    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 12px;
      margin-bottom: 32px;
    }}
    @media(max-width: 700px) {{ .summary-grid {{ grid-template-columns: repeat(3, 1fr); }} }}
    .summary-card {{
      background: #fff;
      border-radius: 10px;
      padding: 16px;
      text-align: center;
      box-shadow: 0 1px 3px rgba(0,0,0,.08);
      border-top: 3px solid var(--color);
    }}
    .summary-card .num {{
      font-size: 32px;
      font-weight: 800;
      color: var(--color);
      line-height: 1;
    }}
    .summary-card .label {{
      font-size: 11px;
      color: #64748b;
      margin-top: 4px;
      text-transform: uppercase;
      letter-spacing: .5px;
    }}

    /* ── Section titles ── */
    .page-section {{
      background: #fff;
      border-radius: 12px;
      padding: 28px 32px;
      margin-bottom: 24px;
      box-shadow: 0 1px 4px rgba(0,0,0,.07);
    }}
    .page-section > h2 {{
      font-size: 16px;
      font-weight: 700;
      margin-bottom: 20px;
      color: #0f172a;
      border-bottom: 2px solid #f1f5f9;
      padding-bottom: 12px;
    }}
    .section-title {{
      font-size: 20px;
      font-weight: 700;
      color: #0f172a;
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 20px;
    }}
    .section-icon {{ font-size: 22px; }}
    .section-count {{
      margin-left: auto;
      font-size: 13px;
      font-weight: 600;
      background: #f1f5f9;
      color: #475569;
      padding: 2px 10px;
      border-radius: 99px;
    }}

    /* ── Tables ── */
    .data-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }}
    .data-table th {{
      background: #f8fafc;
      font-weight: 600;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .5px;
      color: #475569;
      padding: 10px 12px;
      text-align: left;
      border-bottom: 2px solid #e2e8f0;
    }}
    .data-table td {{
      padding: 12px 12px;
      border-bottom: 1px solid #f1f5f9;
      vertical-align: top;
    }}
    .data-table tr:last-child td {{ border-bottom: none; }}
    .data-table tr:hover td {{ background: #fafbfc; }}
    .num {{ text-align: center; font-weight: 700; }}
    .issues-cell {{ color: #475569; font-size: 12px; max-width: 320px; }}
    .assessment-cell {{ color: #475569; font-size: 12px; max-width: 300px; line-height: 1.5; }}
    .tools-cell {{ font-size: 12px; }}
    .inner-table {{ margin-top: 8px; }}
    .inner-table th {{ background: #f0f4f8; font-size: 11px; }}
    .inner-table td {{ font-size: 12px; padding: 8px 10px; }}

    /* ── Badges & Pills ── */
    .badge {{
      display: inline-block;
      font-size: 11px;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 4px;
      white-space: nowrap;
    }}
    .pill {{
      display: inline-block;
      font-size: 11px;
      font-weight: 600;
      padding: 2px 8px;
      border-radius: 99px;
      margin: 2px 2px;
    }}
    .cve-pill  {{ background: #fef3c7; color: #92400e; }}
    .rule-pill {{ background: #ede9fe; color: #5b21b6; }}
    .cwe-pill  {{ background: #dbeafe; color: #1e40af; }}
    .cvss-pill {{ background: #fee2e2; color: #991b1b; }}
    .cve-list  {{ font-size: 11px; color: #64748b; }}
    .pkg-ver   {{ font-size: 11px; color: #64748b; }}

    .tool-tag {{
      display: inline-block;
      font-size: 11px;
      background: #f1f5f9;
      color: #475569;
      padding: 2px 8px;
      border-radius: 4px;
      font-weight: 500;
    }}
    .count-badge {{
      display: inline-block;
      font-size: 11px;
      font-weight: 700;
      background: #0f172a10;
      color: #0f172a;
      padding: 2px 8px;
      border-radius: 99px;
    }}

    /* ── Vuln Cards ── */
    .scan-type-section {{
      background: #fff;
      border-radius: 12px;
      padding: 28px 32px;
      margin-bottom: 24px;
      box-shadow: 0 1px 4px rgba(0,0,0,.07);
    }}
    .vuln-card {{
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      margin-bottom: 16px;
      overflow: hidden;
      background: #fff;
    }}
    .card-header {{
      padding: 14px 16px;
      background: #f8fafc;
      border-bottom: 1px solid #e2e8f0;
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
    }}
    .card-title {{
      font-weight: 700;
      font-size: 14px;
      color: #0f172a;
      flex: 1;
    }}
    .card-meta {{
      display: flex;
      align-items: center;
      gap: 6px;
      flex-wrap: wrap;
    }}
    .pills {{ padding: 8px 16px 4px; }}
    .fix-version {{
      margin: 10px 16px;
      padding: 8px 12px;
      background: #f0fdf4;
      border: 1px solid #bbf7d0;
      border-radius: 6px;
      font-size: 13px;
      color: #166534;
    }}
    .ai-block {{
      margin: 10px 16px;
      padding: 12px 14px;
      background: #f0f9ff;
      border: 1px solid #bae6fd;
      border-radius: 6px;
    }}
    .fix-block {{
      background: #fff7ed;
      border-color: #fed7aa;
    }}
    .ai-label {{
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .5px;
      color: #0369a1;
      margin-bottom: 6px;
    }}
    .fix-block .ai-label {{ color: #9a3412; }}
    .ai-block p {{
      font-size: 13px;
      color: #1e3a5f;
      line-height: 1.6;
      white-space: pre-line;
    }}
    .fix-block p {{ color: #431407; }}

    /* ── Locations ── */
    .locations-section {{
      padding: 12px 16px;
    }}
    .section-sub-title {{
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .5px;
      color: #64748b;
      margin-bottom: 10px;
    }}
    .location-item {{
      border: 1px solid #e2e8f0;
      border-radius: 6px;
      margin-bottom: 8px;
      overflow: hidden;
    }}
    .location-header {{
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 8px 12px;
      background: #f8fafc;
      flex-wrap: wrap;
    }}
    .file-path {{
      font-family: "SF Mono", "Fira Code", monospace;
      font-size: 12px;
      color: #0f172a;
      flex: 1;
      word-break: break-all;
    }}
    .line-num {{
      font-size: 11px;
      background: #e0e7ff;
      color: #3730a3;
      padding: 1px 7px;
      border-radius: 3px;
      white-space: nowrap;
    }}
    .snippet {{
      font-family: "SF Mono", "Fira Code", monospace;
      font-size: 12px;
      padding: 10px 14px;
      background: #1e293b;
      color: #e2e8f0;
      overflow-x: auto;
      border-top: 1px solid #e2e8f0;
      white-space: pre-wrap;
      word-break: break-all;
    }}
    .more-hint {{
      font-size: 12px;
      color: #94a3b8;
      padding: 6px 0;
      text-align: center;
    }}
    .empty {{ text-align: center; color: #94a3b8; padding: 24px; }}

    /* ── Severity bar chart ── */
    .bar-chart {{ margin: 8px 0; }}
    .bar-row {{
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 10px;
    }}
    .bar-label {{
      width: 80px;
      font-size: 12px;
      color: #475569;
      font-weight: 500;
      text-align: right;
    }}
    .bar-track {{
      flex: 1;
      height: 16px;
      background: #f1f5f9;
      border-radius: 99px;
      overflow: hidden;
    }}
    .bar-fill {{
      height: 100%;
      border-radius: 99px;
      transition: width .3s;
    }}
    .bar-count {{
      width: 36px;
      font-size: 13px;
      font-weight: 700;
      text-align: right;
    }}

    /* ── Footer ── */
    .report-footer {{
      text-align: center;
      padding: 32px;
      color: #94a3b8;
      font-size: 12px;
      border-top: 1px solid #e2e8f0;
      margin-top: 48px;
    }}

    /* ── Print ── */
    @media print {{
      body {{ background: #fff; font-size: 12px; }}
      .report-header {{ background: #0f172a !important; -webkit-print-color-adjust: exact; }}
      .vuln-card, .page-section, .scan-type-section {{ box-shadow: none; border: 1px solid #e2e8f0; }}
      .snippet {{ background: #1e293b !important; -webkit-print-color-adjust: exact; }}
    }}
  </style>
</head>
<body>

<!-- ═══ HEADER ═══ -->
<div class="report-header">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:12px;">
    <div>
      <div class="logo">VulnGuard · Báo cáo bảo mật</div>
      <h1>{_esc(project.name)}</h1>
      <div class="subtitle">Scan #{scan.scan_number} · {_esc(scan.scan_path)}</div>
    </div>
    <div style="display:flex;gap:10px;align-items:center;margin-top:8px;">
      <button onclick="window.print()" style="background:#ffffff20;color:#fff;border:1px solid #ffffff40;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:13px;font-weight:600;">🖨️ In / Xuất PDF</button>
      <button onclick="downloadHtml()" style="background:#7c3aed;color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:13px;font-weight:600;">⬇ Tải xuống .html</button>
    </div>
  </div>
  <div class="header-meta">
    <div class="meta-item">
      <div class="meta-label">Thời gian scan</div>
      <div class="meta-value">{_esc(scan_date)}</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Hoàn thành lúc</div>
      <div class="meta-value">{_esc(completed_date)}</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Loại scan</div>
      <div class="meta-value">{_esc(scan_types_str)}</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Công cụ đã dùng</div>
      <div class="meta-value">{_esc(tools_str)}</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Tổng vấn đề</div>
      <div class="meta-value" style="font-size:20px;font-weight:800;color:#f97316">{total_vulns}</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Báo cáo tạo lúc</div>
      <div class="meta-value">{_esc(generated_at)}</div>
    </div>
  </div>
</div>

<div class="container">

  <!-- ═══ SEVERITY SUMMARY ═══ -->
  <div class="summary-grid" style="margin-top:32px">
    <div class="summary-card" style="--color:{SEVERITY_COLOR["CRITICAL"]}">
      <div class="num">{crit}</div><div class="label">Nghiêm trọng</div>
    </div>
    <div class="summary-card" style="--color:{SEVERITY_COLOR["HIGH"]}">
      <div class="num">{high}</div><div class="label">Cao</div>
    </div>
    <div class="summary-card" style="--color:{SEVERITY_COLOR["MEDIUM"]}">
      <div class="num">{med}</div><div class="label">Trung bình</div>
    </div>
    <div class="summary-card" style="--color:{SEVERITY_COLOR["LOW"]}">
      <div class="num">{low}</div><div class="label">Thấp</div>
    </div>
    <div class="summary-card" style="--color:{SEVERITY_COLOR["INFO"]}">
      <div class="num">{info}</div><div class="label">Thông tin</div>
    </div>
  </div>

  <!-- ═══ EXECUTIVE SUMMARY ═══ -->
  <div class="page-section">
    <h2>📊 Tóm tắt điều hành</h2>
    <div style="display:grid;grid-template-columns:1fr 2fr;gap:32px;align-items:start">
      <div>
        <div style="font-size:12px;font-weight:700;color:#64748b;text-transform:uppercase;margin-bottom:12px">Phân bổ theo mức độ</div>
        <div class="bar-chart">{severity_bars}</div>
      </div>
      <div>
        <div style="font-size:12px;font-weight:700;color:#64748b;text-transform:uppercase;margin-bottom:12px">Theo loại scan</div>
        <table class="data-table">
          <thead>
            <tr><th>Loại scan</th><th>Số vấn đề</th><th>Mức cao nhất</th><th>Vấn đề chính</th></tr>
          </thead>
          <tbody>
            {''.join(exec_summary_rows) if exec_summary_rows else '<tr><td colspan="4" class="empty">Không có vấn đề nào</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- ═══ COMPONENT / PACKAGE TABLE ═══ -->
  <div class="page-section">
    <h2>🗂️ Tổng hợp vấn đề theo thành phần</h2>
    {component_table}
  </div>

  <!-- ═══ DETAIL SECTIONS ═══ -->
  {''.join(detail_sections)}

</div>

<div class="report-footer">
  <strong>VulnGuard</strong> · Powered by AST Team - Tạo lúc {_esc(generated_at)}
  <br>Báo cáo được tạo tự động bởi AI và công cụ scan. Vui lòng xem xét kỹ trước khi hành động.
</div>

<script>
function downloadHtml() {{
  const html = document.documentElement.outerHTML;
  const blob = new Blob([html], {{ type: 'text/html;charset=utf-8' }});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'vulnguard_report_{_esc(project.name.replace(" ", "_")[:30])}_scan{scan.scan_number}.html';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}}
</script>
</body>
</html>"""


# ─────────────────────────────────────────────
# Endpoint
# ─────────────────────────────────────────────

@router.get("/{scan_id}/report", response_class=HTMLResponse)
def generate_report(
    scan_id: str,
    download: bool = Query(default=False, description="True để download file .html"),
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

    html = _render_html(
        project=project,
        scan=scan,
        grouped=grouped,
        total_vulns=len(vulns),
        severity_counts=severity_counts,
    )

    headers = {}
    if download:
        project_slug = project.name.replace(" ", "_")[:40]
        filename = f"vulnguard_report_{project_slug}_scan{scan.scan_number}.html"
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'

    return HTMLResponse(content=html, headers=headers)
