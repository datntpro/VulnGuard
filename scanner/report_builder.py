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

_FONT_DIR = os.path.join(os.path.dirname(__file__), "assets", "fonts")
_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
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
# PDF — fpdf2 + font bundled
# ─────────────────────────────────────────────
def build_pdf(scan, vulns: List[Any], project_name: str) -> bytes:
    from fpdf import FPDF

    reg = os.path.join(_FONT_DIR, "DejaVuSans.ttf")
    bold = os.path.join(_FONT_DIR, "DejaVuSans-Bold.ttf")
    pdf = FPDF(format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_font("DejaVu", "", reg)
    pdf.add_font("DejaVu", "B", bold if os.path.exists(bold) else reg)
    pdf.set_font("DejaVu", "", 11)
    pdf.add_page()

    # Cover / header
    pdf.set_font("DejaVu", "B", 20)
    pdf.set_text_color(91, 91, 247)
    pdf.cell(0, 12, "VulnGuard — Báo cáo quét bảo mật", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("DejaVu", "", 10)
    meta = [f"Project: {project_name}", f"Scan #{scan.scan_number}  ·  {scan.scan_path}",
            f"Loại quét: {', '.join(scan.scan_types or [])}",
            f"Thời điểm: {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC",
            f"Tổng phát hiện: {len(vulns)}"]
    for m in meta:
        pdf.cell(0, 6, m, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    # Severity summary bar
    c = _counts(vulns)
    pdf.set_font("DejaVu", "B", 12)
    pdf.cell(0, 8, "Tổng hợp theo mức độ", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("DejaVu", "", 10)
    for s in _SEV_ORDER:
        r, g, b = _SEV_RGB[s]
        pdf.set_fill_color(r, g, b)
        pdf.set_text_color(255 if s != "MEDIUM" else 0, 255 if s != "MEDIUM" else 0, 255 if s != "MEDIUM" else 0)
        pdf.cell(38, 7, f"{s}: {c[s]}", border=0, fill=True, align="C")
        pdf.cell(3, 7, "", border=0)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(12)

    # Findings
    for s in _SEV_ORDER:
        group = [v for v in vulns if _sev(v) == s]
        if not group:
            continue
        r, g, b = _SEV_RGB[s]
        pdf.set_font("DejaVu", "B", 13)
        pdf.set_text_color(r, g, b)
        pdf.cell(0, 9, f"{s} ({len(group)})", new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)
        for v in group:
            pdf.set_font("DejaVu", "B", 10)
            pdf.multi_cell(0, 5.5, f"• {v.title}", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("DejaVu", "", 9)
            loc = (v.file_path + (f":{v.line_start}" if v.line_start else "")) if v.file_path else "—"
            ids = " · ".join(filter(None, [f"CVE {v.cve}" if v.cve else "", f"CWE {v.cwe}" if v.cwe else "",
                                           f"CVSS {v.cvss_score}" if v.cvss_score else ""]))
            line = f"{v.tool} ({_stype(v)})  |  {loc}" + (f"  |  {ids}" if ids else "")
            pdf.set_text_color(90, 90, 90)
            pdf.multi_cell(0, 5, line, new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(0, 0, 0)
            if v.description:
                pdf.multi_cell(0, 5, _clip(v.description, 500), new_x="LMARGIN", new_y="NEXT")
            if getattr(v, "ai_explanation", None):
                pdf.set_text_color(31, 111, 235)
                pdf.multi_cell(0, 5, "AI: " + _clip(v.ai_explanation, 400), new_x="LMARGIN", new_y="NEXT")
                pdf.set_text_color(0, 0, 0)
            if getattr(v, "ai_fix_suggestion", None):
                pdf.set_text_color(52, 150, 90)
                pdf.multi_cell(0, 5, "Fix: " + _clip(v.ai_fix_suggestion, 400), new_x="LMARGIN", new_y="NEXT")
                pdf.set_text_color(0, 0, 0)
            pdf.ln(2)
        pdf.ln(2)

    out = pdf.output()
    return bytes(out)
