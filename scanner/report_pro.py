"""
Trình dựng BÁO CÁO BẢO MẬT chuyên nghiệp (HTML, in ra PDF đẹp) — bố cục theo mẫu
AppSec ngân hàng: trang bìa + bảng metadata + kết luận & điểm rủi ro, 1) Tóm tắt
điều hành, Danh sách phát hiện theo mức độ, 2) Chi tiết phát hiện (card + bảng),
3) Phụ lục (OWASP/chuẩn VN/công cụ/chấm điểm/miễn trừ).

LUÔN có nội dung kể cả khi không bật AI: diễn giải/tác động/PoC/khắc phục lấy từ
catalog CWE (scanner.knowledge.cwe_catalog); nếu có AI thì ưu tiên nội dung AI.
"""
import base64
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

SEV_VI = {"CRITICAL": "Nghiêm trọng", "HIGH": "Cao", "MEDIUM": "Trung bình",
          "LOW": "Thấp", "INFO": "Thông tin"}
SEV_COLOR = {"CRITICAL": "#b91c1c", "HIGH": "#ea580c", "MEDIUM": "#b45309",
             "LOW": "#2563eb", "INFO": "#64748b"}
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
RISK_WEIGHT = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 4, "LOW": 1, "INFO": 0}

SCAN_TYPE_VI = {"SAST": "Phân tích mã tĩnh (SAST)", "SCA": "Thành phần phụ thuộc (SCA)",
                "SECRETS": "Lộ bí mật (Secrets)", "IAC": "Hạ tầng as code (IaC)",
                "CONTAINER": "Container/Image", "DAST": "Quét động (DAST)"}
TOOL_VI = {"bandit": "Bandit", "semgrep": "Semgrep", "trivy": "Trivy", "pip-audit": "pip-audit",
           "gitleaks": "Gitleaks", "detect-secrets": "detect-secrets", "checkov": "Checkov",
           "hadolint": "Hadolint", "grype": "Grype", "sonar-scanner": "SonarQube", "nuclei": "Nuclei"}


def _esc(t) -> str:
    if not t:
        return ""
    return (str(t).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _fmt(dt) -> str:
    try:
        return dt.strftime("%d/%m/%Y %H:%M")
    except Exception:
        return "—"


def _logo_data_uri() -> str:
    """Logo branding → data URI để nhúng thẳng vào HTML (báo cáo tự chứa)."""
    try:
        from scanner import report_builder as rb
        path = rb._logo_path(rb.load_branding())
        if path and os.path.exists(path) and os.path.getsize(path) < 2_000_000:
            ext = os.path.splitext(path)[1].lower()
            mime = "image/jpeg" if ext in (".jpg", ".jpeg") else "image/png"
            with open(path, "rb") as f:
                return f"data:{mime};base64," + base64.b64encode(f.read()).decode()
    except Exception:
        pass
    return ""


def _risk_score(sev_counts: Dict[str, int]) -> int:
    s = sum(RISK_WEIGHT.get(k, 0) * v for k, v in sev_counts.items())
    return min(100, s)


def _conclusion(sev_counts: Dict[str, int], score: int) -> str:
    c, h = sev_counts.get("CRITICAL", 0), sev_counts.get("HIGH", 0)
    if c:
        return "CÓ LỖ HỔNG NGHIÊM TRỌNG — cần khắc phục trước khi đưa lên production"
    if h:
        return "CÒN LỖI MỨC CAO — chưa đủ căn cứ cho production, cần xử lý trước"
    if sev_counts.get("MEDIUM", 0) or sev_counts.get("LOW", 0):
        return "KHÔNG CÓ LỖI CAO — còn một số lỗi mức trung bình/thấp nên khắc phục"
    return "KHÔNG PHÁT HIỆN LỖI ĐÁNG KỂ trong phạm vi quét"


def _confidence(g: dict) -> str:
    reason = (g.get("ai_fp_reason") or "").lower()
    if reason.startswith("[lỗi thật"):
        return "Cao"
    if "false positive" in reason:
        return "Thấp (nghi false positive)"
    if "review" in reason:
        return "Cần review"
    return {"CRITICAL": "Cao", "HIGH": "Cao", "MEDIUM": "Trung bình"}.get(g.get("severity"), "Theo công cụ")


def _cwe_of(g: dict) -> Optional[str]:
    return g["items"][0].get("cwe") if g.get("items") else None


def _owasp_label(g: dict) -> str:
    from scanner import compliance
    import types
    shim = types.SimpleNamespace(cwe=_cwe_of(g), cve=(g.get("cve_list") or [None])[0],
                                 scan_type=g.get("scan_type"))
    cat = compliance.owasp_for(shim)
    return compliance.OWASP_2021.get(cat, cat)


def _sev_ribbon(sev: str) -> str:
    col = SEV_COLOR.get(sev, "#64748b")
    return (f'<span style="display:inline-block;background:{col};color:#fff;font-size:11px;'
            f'font-weight:700;letter-spacing:.5px;padding:3px 12px;border-radius:3px;'
            f'text-transform:uppercase;">{_esc(SEV_VI.get(sev, sev))}</span>')


def _location(g: dict) -> str:
    if g.get("package_name"):
        return _esc(f"{g['package_name']} {g.get('package_version','')}".strip())
    files = []
    for it in (g.get("items") or [])[:6]:
        fp = it.get("file_path") or ""
        ln = it.get("line_start")
        files.append(_esc(fp + (f":{ln}" if ln else "")))
    extra = len(g.get("items") or []) - 6
    out = "<br>".join(f'<code>{f}</code>' for f in files if f)
    if extra > 0:
        out += f'<br><span style="color:#64748b;">… và {extra} vị trí khác</span>'
    return out or "—"


def render(project, scan, grouped: Dict[str, List[dict]], severity_counts: Dict[str, int],
           vulns: list) -> str:
    from api.routes.report import _md_lite          # tái dùng markdown-lite
    from scanner.knowledge import cwe_catalog
    from scanner import report_builder as rb

    branding = rb.load_branding()
    logo = _logo_data_uri()
    org = branding.get("org_name") or "VulnGuard"
    tagline = branding.get("org_tagline") or ""
    rpt_title = (branding.get("report_title") or "BÁO CÁO ĐÁNH GIÁ BẢO MẬT\nMÃ NGUỒN & THÀNH PHẦN")
    footer_text = branding.get("footer_text") or "VulnGuard · Báo cáo quét bảo mật"
    confidential = branding.get("confidential_label") or "BẢO MẬT / CONFIDENTIAL"

    total = len(vulns)
    score = _risk_score(severity_counts)
    conclusion = _conclusion(severity_counts, score)
    crit = severity_counts.get("CRITICAL", 0); high = severity_counts.get("HIGH", 0)
    med = severity_counts.get("MEDIUM", 0); low = severity_counts.get("LOW", 0)
    info = severity_counts.get("INFO", 0)

    tools_used = sorted({t for groups in grouped.values() for g in groups for t in g["tools"]})
    tools_str = ", ".join(TOOL_VI.get(t, t) for t in tools_used) or "—"
    status_txt = ("ĐÃ HOÀN THÀNH" if getattr(scan, "status", None) and scan.status.value == "COMPLETED"
                  else getattr(getattr(scan, "status", None), "value", "—"))

    # Flatten + sort findings, gán mã VG-01…
    flat = []
    for groups in grouped.values():
        flat.extend(groups)
    flat.sort(key=lambda g: (SEV_ORDER.get(g["severity"], 9), -g.get("count", 0)))
    for i, g in enumerate(flat, 1):
        g["_code"] = f"VG-{i:02d}"

    # ── Trang bìa: bảng metadata ──
    def meta_row(k, v):
        return f'<tr><th>{_esc(k)}</th><td>{v}</td></tr>'
    standards = "OWASP Top 10 (2021); TT 09/2020/TT-NHNN; TCVN 11930:2017; ISO/IEC 27001:2022"
    meta_table = "".join([
        meta_row("Đối tượng kiểm thử", _esc(project.name)),
        meta_row("Nguồn mã / phạm vi", f'<code>{_esc(scan.scan_path)}</code>'),
        meta_row("Loại đánh giá", _esc(", ".join(scan.scan_types or []) or "—")),
        meta_row("Tổ chức", _esc(org)),
        meta_row("Thời điểm quét", _fmt(getattr(scan, "started_at", None))),
        meta_row("Công cụ sử dụng", _esc(tools_str)),
        meta_row("Tiêu chuẩn tham chiếu", _esc(standards)),
        meta_row("Trạng thái", _esc(status_txt)),
        meta_row("Tổng số phát hiện", str(total)),
    ])

    # ── 1. Severity table + phân bố loại quét ──
    sev_cells = "".join(
        f'<td style="text-align:center;"><div style="font-size:11px;color:#475569;">{SEV_VI[s]}</div>'
        f'<div style="font-size:22px;font-weight:800;color:{SEV_COLOR[s]};">{severity_counts.get(s,0)}</div></td>'
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
    dist_rows = ""
    for st, groups in sorted(grouped.items()):
        n = sum(g.get("count", 0) for g in groups)
        if not n:
            continue
        worst = min((g["severity"] for g in groups), key=lambda s: SEV_ORDER.get(s, 9))
        dist_rows += (f'<tr><td>{_esc(SCAN_TYPE_VI.get(st, st))}</td>'
                      f'<td style="text-align:center;">{n}</td>'
                      f'<td>{_sev_ribbon(worst)}</td></tr>')

    # ── Danh sách phát hiện theo mức độ ──
    list_rows = ""
    for g in flat:
        list_rows += (
            f'<tr><td>{_sev_ribbon(g["severity"])}</td>'
            f'<td><strong>{g["_code"]}</strong></td>'
            f'<td>{_esc(g["title"][:120])}</td>'
            f'<td>{_esc(SCAN_TYPE_VI.get(g.get("scan_type"), g.get("scan_type")))}</td>'
            f'<td style="font-size:12px;">{_esc(_owasp_label(g).split(" – ")[0])}</td></tr>')

    # ── 2. Chi tiết phát hiện ──
    detail_html = ""
    for g in flat:
        info_cwe = cwe_catalog.lookup(_cwe_of(g), g.get("scan_type")) or {}
        # Mô tả: AI > tool description > catalog
        ai_expl = g.get("ai_explanation", "")
        has_ai = bool(ai_expl and "AI " not in ai_expl[:6] and len(ai_expl) > 20)
        mota = (_md_lite(ai_expl) if has_ai
                else _esc(info_cwe.get("mo_ta") or (g.get("items") or [{}])[0].get("description") or "—"))
        # Tác động
        ai_pub = g.get("ai_exploitability_public", "")
        tacdong = _esc(info_cwe.get("tac_dong") or "—")
        if ai_pub and len(ai_pub) > 15:
            tacdong += f'<div style="margin-top:4px;">{_md_lite(ai_pub)}</div>'
        # PoC / khả năng khai thác
        poc = _esc(info_cwe.get("poc") or "")
        # Khắc phục: AI fix > catalog
        ai_fix = g.get("ai_fix_suggestion", "")
        if ai_fix and len(ai_fix) > 15:
            khacphuc = _md_lite(ai_fix)
        else:
            khacphuc = _esc(info_cwe.get("khac_phuc") or "—")
        if g.get("fixed_version"):
            khacphuc += (f'<div style="margin-top:4px;color:#15803d;">✅ Phiên bản vá: '
                         f'<strong>{_esc(g["fixed_version"])}</strong></div>')
        # tín hiệu rủi ro
        risk_line = ""
        if g.get("kev"):
            risk_line += '<span style="color:#991b1b;font-weight:700;">🔥 CISA KEV (đang bị khai thác)</span> '
        if isinstance(g.get("epss"), (int, float)):
            risk_line += f'<span style="color:#9a3412;">EPSS {g["epss"]*100:.0f}%</span> '
        cvss = (g.get("items") or [{}])[0].get("cvss_score")
        if cvss:
            risk_line += f'<span style="color:#374151;">CVSS {_esc(cvss)}</span>'

        cwe_disp = _esc(info_cwe.get("cwe") or _cwe_of(g) or "—")
        if info_cwe.get("ten"):
            cwe_disp += f' — {_esc(info_cwe["ten"])}'
        refs = []
        if info_cwe.get("cwe"):
            nnum = info_cwe["cwe"].split("-")[-1]
            refs.append(f'<a href="https://cwe.mitre.org/data/definitions/{nnum}.html">{_esc(info_cwe["cwe"])}</a>')
        refs.append("TT 09/2020/TT-NHNN · TCVN 11930:2017")

        def drow(k, v):
            return (f'<tr><th style="width:170px;">{_esc(k)}</th>'
                    f'<td>{v}</td></tr>') if v and v != "—" else ""

        detail_html += f"""
        <div class="finding">
          <div class="finding-head">{_sev_ribbon(g["severity"])}
            <span class="finding-title">{g["_code"]} · {_esc(g["title"][:110])}</span></div>
          <table class="dtable">
            {drow("Mã / Công cụ", f'{g["_code"]} · Độ tin cậy: {_confidence(g)} · {_esc(" · ".join(TOOL_VI.get(t,t) for t in g["tools"]))}')}
            {drow("Vị trí", _location(g))}
            {drow("Mô tả", mota)}
            {drow("Tác động", tacdong)}
            {drow("🎯 Khả năng khai thác / PoC", (poc + (f'<div style="margin-top:4px;">{risk_line}</div>' if risk_line else '')) if poc else risk_line)}
            {drow("Khuyến nghị khắc phục", khacphuc)}
            {drow("OWASP Top 10", _esc(_owasp_label(g)))}
            {drow("CWE", cwe_disp)}
            {drow("Tham chiếu chuẩn", " · ".join(refs))}
          </table>
        </div>"""

    # ── 3. Phụ lục ──
    from scanner import compliance
    owasp_list = "".join(f"<li>{_esc(v)}</li>" for v in compliance.OWASP_2021.values())
    tools_table = "".join(
        f'<tr><td>{_esc(TOOL_VI.get(t,t))}</td><td>{_esc(t)}</td></tr>' for t in tools_used)

    css = _CSS.replace("__ACCENT__", "#1e3a5f")
    return f"""<!DOCTYPE html>
<html lang="vi"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Báo cáo bảo mật — {_esc(project.name)} — Scan #{getattr(scan,'scan_number','')}</title>
<style>{css}</style></head><body>
<div class="print-footer">{_esc(footer_text)} · {_esc(confidential)}</div>

<!-- TRANG BÌA -->
<section class="cover page">
  <div class="cover-top">
    {f'<img class="cover-logo" src="{logo}" alt="logo">' if logo else f'<div class="cover-logo-txt">{_esc(org)}</div>'}
    <div class="cover-org"><div class="org-name">{_esc(org)}</div><div class="org-tag">{_esc(tagline)}</div></div>
  </div>
  <div class="cover-rule"></div>
  <h1 class="cover-title">{_esc(rpt_title).replace(chr(10), '<br>')}</h1>
  <table class="meta-table">{meta_table}</table>
  <div class="conclusion">
    <div class="conclusion-label">KẾT LUẬN ĐÁNH GIÁ</div>
    <div class="conclusion-text">{_esc(conclusion)}</div>
    <div class="risk-score">Điểm rủi ro tổng hợp: <strong>{score}/100</strong></div>
  </div>
  <p class="disclaimer">Lưu ý: Báo cáo tạo tự động từ kết quả quét. Một số kết luận có thể cần kiểm chứng thủ công;
  đánh giá này KHÔNG thay thế kiểm thử thâm nhập chuyên sâu. Quyết định phê duyệt thuộc thẩm quyền người phê duyệt.</p>
</section>

<!-- 1. TÓM TẮT ĐIỀU HÀNH -->
<section class="page">
  <h2>1. Tóm tắt điều hành</h2>
  <p class="lead">Phát hiện <strong>{total}</strong> vấn đề: {crit} nghiêm trọng, {high} cao, {med} trung bình,
  {low} thấp, {info} thông tin. Điểm rủi ro tổng hợp <strong>{score}/100</strong>. {_esc(conclusion)}.</p>
  <table class="sev-table"><tr>{sev_cells}</tr></table>
  <h3>Phân bố theo loại quét</h3>
  <table class="data-table"><thead><tr><th>Loại quét</th><th>Số phát hiện</th><th>Mức nặng nhất</th></tr></thead>
  <tbody>{dist_rows or '<tr><td colspan=3>Không có phát hiện</td></tr>'}</tbody></table>

  <h3 style="margin-top:22px;">Danh sách phát hiện (theo mức độ)</h3>
  <table class="data-table"><thead><tr><th>Mức</th><th>Mã</th><th>Phát hiện</th><th>Loại</th><th>OWASP</th></tr></thead>
  <tbody>{list_rows or '<tr><td colspan=5>Không có phát hiện</td></tr>'}</tbody></table>
</section>

<!-- 2. CHI TIẾT PHÁT HIỆN -->
<section class="page">
  <h2>2. Chi tiết phát hiện</h2>
  {detail_html or '<p>Không có phát hiện trong phạm vi quét.</p>'}
</section>

<!-- 3. PHỤ LỤC -->
<section class="page">
  <h2>3. Phụ lục — Tham chiếu &amp; Công cụ</h2>
  <h3>3.1 OWASP Top 10 (2021)</h3><ul class="ref-list">{owasp_list}</ul>
  <h3>3.2 Văn bản/tiêu chuẩn ngành ngân hàng Việt Nam</h3>
  <ul class="ref-list">
    <li>Thông tư 09/2020/TT-NHNN — An toàn hệ thống thông tin trong hoạt động ngân hàng.</li>
    <li>TCVN 11930:2017 — Yêu cầu cơ bản về an toàn hệ thống thông tin theo cấp độ.</li>
    <li>Nghị định 85/2016/NĐ-CP — Bảo đảm an toàn hệ thống thông tin theo cấp độ.</li>
    <li>Nghị định 13/2023/NĐ-CP — Bảo vệ dữ liệu cá nhân.</li>
    <li>PCI DSS — áp dụng khi hệ thống xử lý dữ liệu thẻ thanh toán.</li>
  </ul>
  <h3>3.3 Công cụ sử dụng</h3>
  <table class="data-table"><thead><tr><th>Công cụ</th><th>Định danh</th></tr></thead>
  <tbody>{tools_table or '<tr><td colspan=2>—</td></tr>'}</tbody></table>
  <h3>3.4 Phương pháp chấm điểm</h3>
  <p>Điểm rủi ro = tổng trọng số các phát hiện (Nghiêm trọng 25, Cao 10, Trung bình 4, Thấp 1, Thông tin 0), tối đa 100.</p>
  <h3>3.5 Tuyên bố miễn trừ &amp; sử dụng hợp pháp</h3>
  <p>Báo cáo chỉ dùng cho kiểm thử được uỷ quyền trên hệ thống thuộc quyền quản lý của tổ chức. Kết quả có thể có
  dương/âm tính giả. Tài liệu thuộc loại {_esc(confidential)}.</p>
</section>

<div class="actions no-print">
  <button onclick="window.print()">🖨️ Lưu PDF / In</button>
</div>
</body></html>"""


_CSS = """
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;font-size:13px;line-height:1.6;color:#1f2937;background:#f1f5f9}
a{color:#2563eb;text-decoration:none;word-break:break-all}
code{font-family:"SFMono-Regular",Consolas,monospace;font-size:12px;background:#f1f5f9;padding:1px 5px;border-radius:4px}
.page{max-width:900px;margin:18px auto;background:#fff;padding:40px 48px;box-shadow:0 2px 14px rgba(0,0,0,.08);border-radius:4px}
h2{color:__ACCENT__;font-size:21px;border-bottom:2px solid __ACCENT__;padding-bottom:6px;margin-bottom:16px}
h3{color:__ACCENT__;font-size:15px;margin:18px 0 8px}
.lead{font-weight:600;margin-bottom:16px}
/* cover */
.cover-top{display:flex;justify-content:space-between;align-items:center}
.cover-logo{max-height:52px;max-width:200px;object-fit:contain}
.cover-logo-txt{font-size:22px;font-weight:800;color:__ACCENT__}
.cover-org{text-align:right}.org-name{font-weight:700;font-size:14px;color:#334155}.org-tag{font-size:11px;color:#64748b}
.cover-rule{height:3px;background:linear-gradient(90deg,#d97706,#1e3a5f);margin:14px 0 28px}
.cover-title{text-align:center;font-size:30px;font-weight:800;color:__ACCENT__;letter-spacing:.5px;margin:30px 0}
.meta-table{width:100%;border-collapse:collapse;margin:26px 0}
.meta-table th{text-align:left;background:#f8fafc;color:#334155;font-weight:700;width:190px;vertical-align:top;font-size:12px}
.meta-table th,.meta-table td{border:1px solid #e2e8f0;padding:8px 12px;font-size:13px;vertical-align:top}
.conclusion{border:2px solid #d97706;border-radius:6px;padding:16px;text-align:center;margin:24px 0}
.conclusion-label{font-size:11px;letter-spacing:2px;color:#92400e;font-weight:700}
.conclusion-text{font-size:18px;font-weight:800;color:#1e3a5f;margin:8px 0}
.risk-score{font-size:14px;color:#334155}
.disclaimer{font-size:11px;color:#64748b;line-height:1.5}
/* tables */
.sev-table{width:100%;border-collapse:collapse;margin:8px 0 6px}
.sev-table td{border:1px solid #e2e8f0;padding:10px}
.data-table{width:100%;border-collapse:collapse;margin:6px 0;font-size:12.5px}
.data-table thead th{background:__ACCENT__;color:#fff;text-align:left;padding:7px 10px;font-size:12px}
.data-table td{border:1px solid #e2e8f0;padding:7px 10px;vertical-align:top}
.data-table tbody tr:nth-child(even){background:#f8fafc}
.ref-list{margin:6px 0 6px 20px}.ref-list li{margin:3px 0}
/* finding card */
.finding{border:1px solid #e2e8f0;border-radius:6px;margin:16px 0;overflow:hidden}
.finding-head{background:#f8fafc;padding:10px 14px;border-bottom:1px solid #e2e8f0;display:flex;align-items:center;gap:10px}
.finding-title{font-weight:700;color:#1e3a5f;font-size:14px}
.dtable{width:100%;border-collapse:collapse}
.dtable th{text-align:left;background:#fcfdfe;color:#475569;font-weight:700;vertical-align:top;font-size:12px}
.dtable th,.dtable td{border-bottom:1px solid #eef2f7;padding:8px 14px;vertical-align:top;font-size:13px}
.dtable tr:last-child th,.dtable tr:last-child td{border-bottom:none}
.actions{max-width:900px;margin:0 auto 30px;text-align:right}
.actions button{background:__ACCENT__;color:#fff;border:none;padding:9px 18px;border-radius:6px;cursor:pointer;font-size:13px;font-weight:600}
.print-footer{display:none}
@media print{
  body{background:#fff}
  .page{box-shadow:none;margin:0;max-width:none;padding:26px 30px;border-radius:0;page-break-after:always}
  .page:last-of-type{page-break-after:auto}
  .no-print{display:none!important}
  .finding{break-inside:avoid}
  .conclusion,.finding-head,.data-table thead th,.sev-table td{-webkit-print-color-adjust:exact;print-color-adjust:exact}
  .print-footer{display:block;position:fixed;bottom:6px;left:0;right:0;text-align:center;font-size:9px;color:#94a3b8}
  @page{margin:16mm 12mm 14mm}
}
"""
