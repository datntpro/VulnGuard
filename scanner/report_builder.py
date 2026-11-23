"""
Trình xuất báo cáo scan: PDF (server-side), Markdown & AI-JSON (cho LLM đọc).

- PDF: fpdf2 + font DejaVu bundled (scanner/assets/fonts) → render tiếng Việt mọi OS/Docker,
  không cần font hệ thống.
- Markdown: gọn, token-efficient, lý tưởng để dán cho AI hoặc commit vào repo.
- AI-JSON: cấu trúc tối giản, chỉ field cần thiết, để agent/LLM nạp tự động.
"""
import json
import os
from datetime import datetime
from typing import Any, Dict, List

from scanner import compliance

_FONT_DIR = os.path.join(os.path.dirname(__file__), "assets", "fonts")
_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# ── Branding báo cáo (logo + header/footer) — chỉnh trong Settings → Báo cáo ──
# Lưu cùng chỗ với scanner_config.json; ghi đè bằng env REPORT_BRANDING_FILE.
_BRANDING_FILE = os.environ.get(
    "REPORT_BRANDING_FILE",
    os.path.join(os.path.dirname(os.environ.get(
        "SCANNER_CONFIG_FILE", "/app/storage/scanner_config.json")), "report_branding.json"),
)
_BRANDING_DEFAULT = {
    "org_name": "VulnGuard",
    "org_tagline": "DevSecOps Security Platform",
    "report_title": "BÁO CÁO QUÉT BẢO MẬT\nMÃ NGUỒN & THÀNH PHẦN",
    "footer_text": "VulnGuard · Báo cáo quét bảo mật",
    "confidential_label": "BẢO MẬT / CONFIDENTIAL",
    "logo_path": "",  # rỗng → dùng logo bundled scanner/assets/logo.png
}


def load_branding() -> Dict[str, str]:
    """Đọc branding từ file (nếu có), trộn với mặc định."""
    b = dict(_BRANDING_DEFAULT)
    try:
        with open(_BRANDING_FILE) as f:
            data = json.load(f) or {}
        for k in _BRANDING_DEFAULT:
            if isinstance(data.get(k), str) and data[k].strip():
                b[k] = data[k]
    except Exception:
        pass
    return b


def save_branding(data: Dict[str, str]) -> Dict[str, str]:
    """Lưu branding (chỉ các field hợp lệ), trả về bản đã lưu."""
    cur = load_branding()
    for k in _BRANDING_DEFAULT:
        if k in data and isinstance(data[k], str):
            cur[k] = data[k]
    os.makedirs(os.path.dirname(_BRANDING_FILE), exist_ok=True)
    with open(_BRANDING_FILE, "w") as f:
        json.dump(cur, f, ensure_ascii=False, indent=2)
    return cur


def branding_dir() -> str:
    d = os.path.dirname(_BRANDING_FILE)
    os.makedirs(d, exist_ok=True)
    return d


def _logo_path(branding) -> str:
    """Logo tùy chỉnh nếu có & tồn tại, ngược lại dùng logo bundled."""
    p = (branding or {}).get("logo_path") or ""
    if p and os.path.exists(p):
        return p
    return _LOGO
_SEV_RGB = {
    "CRITICAL": (244, 63, 94), "HIGH": (251, 138, 60), "MEDIUM": (245, 196, 67),
    "LOW": (52, 211, 153), "INFO": (96, 165, 250),
}


def _sev(v) -> str:
    s = (v.severity.value if hasattr(v.severity, "value") else str(v.severity)).upper()
    return s if s in _SEV_ORDER else "INFO"


def _stype(v) -> str:
    return v.scan_type.value if hasattr(v.scan_type, "value") else str(v.scan_type or "")


def _counts(vulns) -> Dict[str, int]:
    c = {s: 0 for s in _SEV_ORDER}
    for v in vulns:
        c[_sev(v)] += 1
    return c


def _clip(s, n=600) -> str:
    s = (s or "").strip()
    return s if len(s) <= n else s[:n] + "…"


# ─────────────────────────────────────────────
# Markdown — cho AI/người đọc
# ─────────────────────────────────────────────
def build_markdown(scan, vulns: List[Any], project_name: str) -> str:
    c = _counts(vulns)
    out = [
        f"# VulnGuard — Báo cáo quét bảo mật / Security Scan Report",
        "",
        f"- **Project:** {project_name}",
        f"- **Scan #:** {scan.scan_number}  ·  **Path:** `{scan.scan_path}`",
        f"- **Loại quét / Scan types:** {', '.join(scan.scan_types or [])}",
        f"- **Thời điểm / Generated:** {datetime.utcnow().isoformat()}Z",
        f"- **Tổng số phát hiện / Total findings:** {len(vulns)}",
        "",
        "## Tổng hợp theo mức độ / Severity summary",
        "",
        "| Mức | Số lượng |", "|---|---|",
    ]
    out += [f"| {s} | {c[s]} |" for s in _SEV_ORDER]
    out += ["", "## Chi tiết phát hiện / Findings", ""]
    for s in _SEV_ORDER:
        group = [v for v in vulns if _sev(v) == s]
        if not group:
            continue
        out.append(f"### {s} ({len(group)})")
        out.append("")
        for v in group:
            loc = f"`{v.file_path}`" + (f":{v.line_start}" if v.line_start else "") if v.file_path else "—"
            ids = " · ".join(filter(None, [
                f"CVE {v.cve}" if v.cve else "", f"CWE {v.cwe}" if v.cwe else "",
                f"CVSS {v.cvss_score}" if v.cvss_score else "", f"rule {v.rule_id}" if v.rule_id else ""]))
            out.append(f"#### [{s}] {v.title}")
            out.append(f"- **Tool:** {v.tool} ({_stype(v)})  ·  **Vị trí:** {loc}")
            if ids:
                out.append(f"- **ID:** {ids}")
            if v.status and str(getattr(v.status, 'value', v.status)) != "OPEN":
                out.append(f"- **Trạng thái:** {getattr(v.status,'value',v.status)}")
            if v.description:
                out.append(f"- **Mô tả:** {_clip(v.description, 500)}")
            if getattr(v, "ai_false_positive_likelihood", None):
                out.append(f"- **AI — khả năng false positive:** {v.ai_false_positive_likelihood}"
                           + (f" ({v.ai_provider})" if getattr(v, 'ai_provider', None) else ""))
            if getattr(v, "ai_explanation", None):
                out.append(f"- **AI — giải thích:** {_clip(v.ai_explanation, 500)}")
            if getattr(v, "ai_fix_suggestion", None):
                out.append(f"- **AI — hướng dẫn fix:** {_clip(v.ai_fix_suggestion, 600)}")
            out.append("")
    return "\n".join(out)


# ─────────────────────────────────────────────
# AI-JSON — tối giản cho LLM/agent nạp
# ─────────────────────────────────────────────
def build_ai_json(scan, vulns: List[Any], project_name: str) -> str:
    data = {
        "report_type": "vulnguard_scan",
        "project": project_name,
        "scan_number": scan.scan_number,
        "scan_path": scan.scan_path,
        "scan_types": scan.scan_types or [],
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": _counts(vulns),
        "total": len(vulns),
        "findings": [{
            "severity": _sev(v), "title": v.title, "tool": v.tool, "type": _stype(v),
            "file": v.file_path, "line": v.line_start, "rule_id": v.rule_id,
            "cve": v.cve, "cwe": v.cwe, "cvss": v.cvss_score,
            "status": getattr(v.status, "value", str(v.status)) if v.status else "OPEN",
            "description": _clip(v.description, 800),
            "ai": {
                "false_positive_likelihood": getattr(v, "ai_false_positive_likelihood", None),
                "explanation": _clip(getattr(v, "ai_explanation", None), 800),
                "fix_suggestion": _clip(getattr(v, "ai_fix_suggestion", None), 800),
                "provider": getattr(v, "ai_provider", None),
            },
        } for v in vulns],
    }
    return json.dumps(data, ensure_ascii=False, indent=2)


# ─────────────────────────────────────────────
# PDF — fpdf2, thiết kế doanh nghiệp (bìa + bảng navy + header/footer)
# ─────────────────────────────────────────────
_NAVY = (31, 56, 100)
_ACCENT = (37, 99, 175)
_GREY = (110, 110, 110)
_LIGHT = (238, 241, 248)
_SEV_VN = {"CRITICAL": "NGHIÊM TRỌNG", "HIGH": "CAO", "MEDIUM": "TRUNG BÌNH",
           "LOW": "THẤP", "INFO": "THÔNG TIN"}
_FONT_REG = os.path.join(_FONT_DIR, "DejaVuSans.ttf")
_FONT_BOLD = os.path.join(_FONT_DIR, "DejaVuSans-Bold.ttf")
_FONT_MONO = os.path.join(_FONT_DIR, "DejaVuSansMono.ttf")
_LOGO = os.path.join(os.path.dirname(__file__), "assets", "logo.png")


def _risk(counts):
    w = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 0.5, "INFO": 0}
    raw = sum(w[s] * counts.get(s, 0) for s in w)
    score = round(100 * (1 - 1 / (1 + raw / 50.0)), 0) if raw > 0 else 0
    if counts.get("CRITICAL"):
        verdict = "CÓ lỗ hổng NGHIÊM TRỌNG — KHÔNG nên triển khai production"
    elif counts.get("HIGH"):
        verdict = "CÓ lỗ hổng mức CAO — cần xử lý trước khi triển khai"
    elif counts.get("MEDIUM") or counts.get("LOW"):
        verdict = "Có lỗ hổng mức Trung bình/Thấp — nên khắc phục"
    else:
        verdict = "Không phát hiện lỗ hổng — ĐẠT"
    return int(score), verdict


class _Report:
    """Bọc FPDF với header/footer chạy + số trang (fpdf2.FPDF subclass)."""


def _make_pdf(project_name, scan, branding):
    from fpdf import FPDF

    code = f"VulnGuard_{project_name}_{scan.scan_number}".replace(" ", "")
    foot = f"{branding['footer_text']} · {branding['confidential_label']}".strip(" ·")

    class VGReport(FPDF):
        def header(self):
            if self.page_no() == 1:
                return
            self.set_font("DejaVu", "", 8)
            self.set_text_color(*_GREY)
            self.cell(0, 6, f"{project_name} · Scan #{scan.scan_number}", align="L")
            self.cell(0, 6, code, align="R", new_x="LMARGIN", new_y="NEXT")
            self.set_draw_color(200, 200, 200)
            self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
            self.ln(3)
            self.set_text_color(0, 0, 0)

        def footer(self):
            self.set_y(-14)
            self.set_draw_color(200, 200, 200)
            self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
            self.ln(1)
            self.set_font("DejaVu", "", 7.5)
            self.set_text_color(*_GREY)
            self.cell(0, 6, foot, align="L")
            self.cell(0, 6, f"Trang {self.page_no()}", align="R")
            self.set_text_color(0, 0, 0)

    pdf = VGReport(format="A4")
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.add_font("DejaVu", "", _FONT_REG)
    pdf.add_font("DejaVu", "B", _FONT_BOLD)
    pdf.add_font("Mono", "", _FONT_MONO)
    return pdf


def _h(pdf, num, title):
    pdf.ln(2)
    pdf.set_font("DejaVu", "B", 13)
    pdf.set_text_color(*_ACCENT)
    pdf.cell(0, 9, f"{num}. {title}" if num else title, new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(1)


def _navy_heading():
    from fpdf.fonts import FontFace
    return FontFace(emphasis="BOLD", color=(255, 255, 255), fill_color=_NAVY)


def build_pdf(scan, vulns, project_name):
    from fpdf.fonts import FontFace

    counts = _counts(vulns)
    score, verdict = _risk(counts)
    branding = load_branding()
    pdf = _make_pdf(project_name, scan, branding)
    pdf.add_page()

    # ── Bìa: logo + tổ chức ──
    try:
        pdf.image(_logo_path(branding), x=pdf.l_margin, y=12, h=16)
    except Exception:
        pass
    pdf.set_xy(pdf.l_margin, 12)
    pdf.set_font("DejaVu", "B", 9)
    pdf.set_text_color(*_NAVY)
    pdf.cell(0, 5, branding["org_name"], align="R", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("DejaVu", "", 8)
    pdf.set_text_color(*_GREY)
    pdf.cell(0, 5, branding["org_tagline"], align="R", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.set_y(32)
    pdf.set_draw_color(*_NAVY)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.ln(8)

    # ── Tiêu đề ──
    pdf.set_font("DejaVu", "B", 20)
    pdf.set_text_color(*_NAVY)
    pdf.multi_cell(0, 10, branding["report_title"], align="C")
    pdf.ln(1)
    pdf.set_font("DejaVu", "", 10)
    pdf.set_text_color(*_GREY)
    pdf.multi_cell(0, 6, f"Project: {project_name}  ·  Scan #{scan.scan_number}  ·  {', '.join(scan.scan_types or [])}", align="C")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(6)

    # ── Bảng thông tin ──
    info = [
        ("Đối tượng", project_name),
        ("Đường dẫn quét", scan.scan_path or "—"),
        ("Loại quét", ", ".join(scan.scan_types or [])),
        ("Công cụ", "VulnGuard (SAST/SCA/IaC/Container/Secrets + AI triage)"),
        ("Thời điểm", datetime.utcnow().strftime("%Y-%m-%d %H:%M") + " UTC"),
        ("Tổng phát hiện", str(len(vulns))),
        ("Tiêu chuẩn tham chiếu", "OWASP Top 10; CWE; EPSS/CISA KEV"),
    ]
    label_face = FontFace(emphasis="BOLD", fill_color=_LIGHT)
    pdf.set_font("DejaVu", "", 9.5)
    pdf.set_draw_color(205, 205, 205)
    with pdf.table(col_widths=(32, 68), first_row_as_headings=False,
                   borders_layout="ALL", line_height=6) as table:
        for k, v in info:
            row = table.row()
            row.cell(k, style=label_face)
            row.cell(v)

    # ── Hộp kết luận ──
    pdf.ln(4)
    pdf.set_fill_color(*_LIGHT)
    pdf.set_draw_color(*_NAVY)
    y0 = pdf.get_y()
    pdf.rect(pdf.l_margin, y0, pdf.w - pdf.l_margin - pdf.r_margin, 26, style="DF")
    pdf.set_xy(pdf.l_margin, y0 + 3)
    pdf.set_font("DejaVu", "B", 10)
    pdf.set_text_color(*_NAVY)
    pdf.cell(0, 6, "KẾT LUẬN ĐÁNH GIÁ", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(pdf.l_margin)
    pdf.set_font("DejaVu", "B", 12)
    pdf.set_text_color(218, 54, 51)
    pdf.cell(0, 8, verdict, align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(pdf.l_margin)
    pdf.set_font("DejaVu", "", 10)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 6, f"Điểm rủi ro tổng hợp: {score}/100", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_y(y0 + 30)
    pdf.set_font("DejaVu", "", 8)
    pdf.set_text_color(*_GREY)
    pdf.multi_cell(0, 4.5, "Lưu ý: Báo cáo sinh tự động bởi VulnGuard (kết quả scanner + AI triage). "
                   "Không thay thế kiểm thử thâm nhập thủ công chuyên sâu. Quyết định phê duyệt thuộc thẩm quyền người duyệt.")
    pdf.set_text_color(0, 0, 0)

    # ── Trang nội dung: tổng hợp ──
    pdf.add_page()
    _h(pdf, "1", "Tổng hợp theo mức độ")
    pdf.set_font("DejaVu", "", 9.5)
    with pdf.table(text_align="CENTER", headings_style=_navy_heading(), line_height=6) as table:
        table.row(["Nghiêm trọng", "Cao", "Trung bình", "Thấp", "Thông tin", "Tổng"])
        table.row([str(counts["CRITICAL"]), str(counts["HIGH"]), str(counts["MEDIUM"]),
                   str(counts["LOW"]), str(counts["INFO"]), str(len(vulns))])

    # Phân bố theo loại quét
    by_type = {}
    for v in vulns:
        by_type[_stype(v)] = by_type.get(_stype(v), 0) + 1
    if by_type:
        pdf.ln(3)
        _h(pdf, None, "Phân bố theo loại quét")
        pdf.set_font("DejaVu", "", 9.5)
        with pdf.table(col_widths=(60, 40), text_align=("LEFT", "CENTER"),
                       headings_style=_navy_heading(), line_height=6) as table:
            table.row(["Loại", "Số phát hiện"])
            for t, n in sorted(by_type.items(), key=lambda x: -x[1]):
                table.row([t or "—", str(n)])

    # ── Danh sách phát hiện ──
    _h(pdf, "2", "Danh sách phát hiện (theo mức độ)")
    pdf.set_font("DejaVu", "", 8.5)
    with pdf.table(col_widths=(16, 16, 44, 16, 8), text_align=("LEFT",) * 5,
                   headings_style=_navy_heading(), line_height=5) as table:
        table.row(["Mức", "Tool", "Phát hiện", "Vị trí", "CWE"])
        for s in _SEV_ORDER:
            for v in [x for x in vulns if _sev(x) == s]:
                loc = ((v.file_path or "") + (f":{v.line_start}" if v.line_start else "")) or "—"
                table.row([_SEV_VN[s], v.tool, v.title, loc[-40:], (v.cwe or v.cve or "")])

    # ── Chi tiết ──
    _h(pdf, "3", "Chi tiết phát hiện")
    for s in _SEV_ORDER:
        group = [v for v in vulns if _sev(v) == s]
        for v in group:
            if pdf.will_page_break(26):
                pdf.add_page()
            pdf.set_fill_color(*_NAVY)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("DejaVu", "B", 9.5)
            pdf.multi_cell(0, 6, f"  [{_SEV_VN[s]}] {v.title}", fill=True, new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(*_GREY)
            pdf.set_font("DejaVu", "", 8.5)
            loc = ((v.file_path or "") + (f":{v.line_start}" if v.line_start else "")) or "—"
            ids = " · ".join(filter(None, [f"CVE {v.cve}" if v.cve else "", f"CWE {v.cwe}" if v.cwe else "",
                                           f"CVSS {v.cvss_score}" if v.cvss_score else ""]))
            tagline = "  ·  ".join(compliance.owasp_tags(v))
            pdf.multi_cell(0, 5, f"{v.tool} ({_stype(v)})  |  {loc}" + (f"  |  {ids}" if ids else "")
                           + (f"\n{tagline}" if tagline else ""),
                           new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("DejaVu", "", 9)
            if v.description:
                pdf.multi_cell(0, 5, _clip(v.description, 600), new_x="LMARGIN", new_y="NEXT")
            if getattr(v, "ai_explanation", None):
                pdf.set_text_color(*_ACCENT)
                pdf.set_font("DejaVu", "B", 8.5)
                pdf.cell(0, 5, "Phân tích AI:", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("DejaVu", "", 9)
                pdf.multi_cell(0, 5, _clip(v.ai_explanation, 500), new_x="LMARGIN", new_y="NEXT")
                pdf.set_text_color(0, 0, 0)
            if getattr(v, "ai_fix_suggestion", None):
                pdf.set_text_color(34, 139, 90)
                pdf.set_font("DejaVu", "B", 8.5)
                pdf.cell(0, 5, "Khuyến nghị khắc phục:", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("DejaVu", "", 9)
                pdf.multi_cell(0, 5, _clip(v.ai_fix_suggestion, 500), new_x="LMARGIN", new_y="NEXT")
                pdf.set_text_color(0, 0, 0)
            pdf.ln(3)

    # ── Ánh xạ tuân thủ ──
    if vulns:
        summ = compliance.compliance_summary(vulns)
        pdf.add_page()
        _h(pdf, "4", "Ánh xạ tuân thủ (Compliance mapping)")
        pdf.set_font("DejaVu", "", 9)
        pdf.set_text_color(*_GREY)
        pdf.multi_cell(0, 5, "Mỗi phát hiện được ánh xạ sang OWASP Top 10 2021, ISO/IEC 27001:2022, "
                       "TCVN 11930:2017 / NĐ 85/2016 và PCI-DSS v4.0. Điểm = % nhóm kiểm soát ĐẠT "
                       "trên số nhóm bị chạm tới. KHÔNG ĐẠT = có lỗ hổng Cao/Nghiêm trọng.",
                       new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)
        pdf.ln(2)
        for fw in compliance.FRAMEWORKS:
            d = summ[fw]
            pdf.set_font("DejaVu", "B", 10.5)
            pdf.set_text_color(*_NAVY)
            pdf.cell(0, 7, f"{d['label']}  —  {d['score']}/100"
                     + (f"  ({d['failed']} nhóm KHÔNG ĐẠT)" if d['failed'] else "  (không vi phạm)"),
                     new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(0, 0, 0)
            if not d["controls"]:
                pdf.set_font("DejaVu", "", 9)
                pdf.set_text_color(*_GREY)
                pdf.cell(0, 6, "Không có phát hiện chạm tới khung này.", new_x="LMARGIN", new_y="NEXT")
                pdf.set_text_color(0, 0, 0)
                pdf.ln(2)
                continue
            pdf.set_font("DejaVu", "", 8.5)
            with pdf.table(col_widths=(20, 48, 14, 18), text_align=("LEFT", "LEFT", "CENTER", "CENTER"),
                           headings_style=_navy_heading(), line_height=5) as table:
                table.row(["Mã", "Nhóm kiểm soát", "Số PH", "Trạng thái"])
                for c in d["controls"]:
                    table.row([c["control_id"], c["control_name"], str(c["findings"]), c["status"]])
            pdf.ln(3)

    return bytes(pdf.output())


# ─────────────────────────────────────────────
# SARIF 2.1.0 — cho GitHub Code Scanning / GitLab / Azure DevOps
# ─────────────────────────────────────────────
_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                "LOW": "note", "INFO": "note"}
_SARIF_SECSEV = {"CRITICAL": "9.5", "HIGH": "7.5", "MEDIUM": "5.0", "LOW": "3.0", "INFO": "1.0"}


def build_sarif(scan, vulns: List[Any], project_name: str) -> str:
    """Xuất SARIF 2.1.0 — cắm thẳng vào GitHub Code Scanning / GitLab / Azure DevOps."""
    rules: Dict[str, Dict[str, Any]] = {}
    results = []
    for v in vulns:
        sev = _sev(v)
        rid = (getattr(v, "rule_id", None) or f"{v.tool}:{getattr(v, 'cwe', '') or v.title[:40]}")
        tags = ["security"] + compliance.owasp_tags(v)
        if getattr(v, "cwe", None):
            tags.append(f"external/cwe/cwe-{compliance._cwe_int(v.cwe)}")
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": (v.tool or "VulnGuard").title().replace(" ", ""),
                "shortDescription": {"text": _clip(v.title, 120)},
                "fullDescription": {"text": _clip(getattr(v, "description", "") or v.title, 1000)},
                "helpUri": "https://owasp.org/Top10/",
                "properties": {"tags": tags, "security-severity": _SARIF_SECSEV.get(sev, "1.0")},
            }
        loc = (v.file_path or "").lstrip("/") or "UNKNOWN"
        line = int(getattr(v, "line_start", 0) or 1) or 1
        msg = _clip(getattr(v, "ai_explanation", None) or getattr(v, "description", "") or v.title, 800)
        results.append({
            "ruleId": rid,
            "level": _SARIF_LEVEL.get(sev, "note"),
            "message": {"text": msg},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": loc},
                "region": {"startLine": line},
            }}],
            "properties": {
                "severity": sev,
                "security-severity": _SARIF_SECSEV.get(sev, "1.0"),
                "cwe": str(getattr(v, "cwe", "") or ""),
                "cve": str(getattr(v, "cve", "") or ""),
                "owasp": compliance.owasp_for(v),
                "tool": v.tool,
            },
        })
    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "VulnGuard",
                "informationUri": "https://github.com/datntpro/VulnGuard",
                "version": "1.0",
                "rules": list(rules.values()),
            }},
            "automationDetails": {"id": f"{project_name}/scan-{scan.scan_number}"},
            "results": results,
        }],
    }
    return json.dumps(doc, ensure_ascii=False, indent=2)
