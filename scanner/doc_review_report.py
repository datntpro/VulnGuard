"""
Báo cáo HTML cho kết quả Document Review — dùng để gửi lại bên viết tài liệu kèm
danh sách điểm đã đáp ứng / chưa đáp ứng về an toàn thông tin.
"""
from datetime import datetime, timezone, timedelta
from collections import defaultdict

VN_TZ = timezone(timedelta(hours=7))

STATUS_LABEL = {
    "MET": ("Đã đáp ứng", "#1f9d55", "✅"),
    "PARTIAL": ("Đáp ứng một phần", "#d97706", "⚠️"),
    "NOT_MET": ("Chưa đáp ứng", "#dc2626", "❌"),
    "NOT_APPLICABLE": ("Không áp dụng", "#6b7280", "➖"),
}


def _now_vn() -> str:
    return datetime.now(VN_TZ).strftime("%d/%m/%Y %H:%M (GMT+7)")


def _esc(s: str) -> str:
    if not s:
        return ""
    return (
        s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )


def build_report_html(doc, version, findings) -> str:
    summary = version.summary or {}
    by_category = defaultdict(list)
    for f in findings:
        by_category[f.category].append(f)

    rows = []
    for category, items in by_category.items():
        rows.append(f'<tr class="cat-row"><td colspan="3"><strong>{_esc(category)}</strong></td></tr>')
        for f in items:
            label, color, icon = STATUS_LABEL.get(f.status.value, ("?", "#999", ""))
            rows.append(f"""
            <tr>
              <td style="white-space:nowrap;color:#888;">{_esc(f.criteria_id)}</td>
              <td>
                <div>{_esc(f.criteria_text)}</div>
                <div style="margin-top:6px;font-size:13px;color:#444;"><b>Đánh giá AI:</b> {_esc(f.evidence or '')}</div>
                {f'<div style="margin-top:4px;font-size:13px;color:#0a5;"><b>Gợi ý bổ sung:</b> {_esc(f.recommendation)}</div>' if f.recommendation else ''}
              </td>
              <td><span style="display:inline-block;padding:3px 10px;border-radius:12px;background:{color}20;color:{color};font-weight:600;font-size:12px;white-space:nowrap;">{icon} {label}</span></td>
            </tr>
            """)

    revision_block = ""
    if version.revision_note:
        revision_block = f"""
        <div style="margin-top:20px;padding:14px;background:#fff7e6;border:1px solid #f0c36d;border-radius:8px;">
          <b>📝 Ghi chú gửi lại bên viết tài liệu:</b><br>{_esc(version.revision_note)}
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="utf-8">
<title>Document Review — {_esc(doc.name if doc else '')} v{version.version_number}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 32px; background: #f5f6f8; color: #1a1a1a; }}
  .container {{ max-width: 980px; margin: 0 auto; background: #fff; border-radius: 10px; padding: 32px; box-shadow: 0 1px 4px rgba(0,0,0,.08); }}
  h1 {{ font-size: 22px; margin-bottom: 4px; }}
  .meta {{ color: #666; font-size: 13px; margin-bottom: 20px; }}
  .score {{ font-size: 32px; font-weight: 700; }}
  .summary-grid {{ display: flex; gap: 16px; margin: 20px 0; flex-wrap: wrap; }}
  .summary-card {{ flex: 1; min-width: 120px; padding: 14px; border-radius: 8px; background: #f8f9fb; text-align: center; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
  td {{ padding: 10px 8px; border-bottom: 1px solid #eee; vertical-align: top; font-size: 14px; }}
  .cat-row td {{ background: #f0f2f5; padding-top: 14px; padding-bottom: 6px; }}
  .footer {{ margin-top: 28px; font-size: 12px; color: #999; text-align: center; }}
</style>
</head>
<body>
<div class="container">
  <h1>📑 Báo cáo Review An toàn thông tin Tài liệu</h1>
  <div class="meta">
    Tài liệu: <b>{_esc(doc.name if doc else '')}</b> &nbsp;·&nbsp;
    Version: <b>v{version.version_number}</b> ({_esc(version.original_filename)}) &nbsp;·&nbsp;
    Xuất báo cáo: {_now_vn()}
  </div>

  <div class="summary-grid">
    <div class="summary-card"><div class="score" style="color:#1f9d55;">{summary.get('met', 0)}</div>Đã đáp ứng</div>
    <div class="summary-card"><div class="score" style="color:#d97706;">{summary.get('partial', 0)}</div>Một phần</div>
    <div class="summary-card"><div class="score" style="color:#dc2626;">{summary.get('not_met', 0)}</div>Chưa đáp ứng</div>
    <div class="summary-card"><div class="score" style="color:#6b7280;">{summary.get('not_applicable', 0)}</div>Không áp dụng</div>
    <div class="summary-card"><div class="score">{summary.get('score_pct', 'N/A')}{'%' if summary.get('score_pct') is not None else ''}</div>Điểm tổng</div>
  </div>

  <table>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>

  {revision_block}

  <div class="footer">Tạo bởi VulnGuard — Document Review (AI chạy local qua Ollama, không gửi dữ liệu ra ngoài)</div>
</div>
</body>
</html>"""
