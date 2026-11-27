"""
Gửi email báo cáo scan cho owner (SMTP). Đính kèm PDF báo cáo + tóm tắt mức độ.
Cấu hình SMTP lưu ở runtime_settings (mật khẩu mã hoá Fernet).
"""
import logging
import smtplib
import ssl
import time
from email.message import EmailMessage
from typing import Dict, List

from sqlalchemy.orm import Session

from api.services import runtime_settings as rt

logger = logging.getLogger(__name__)

_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _counts(vulns) -> Dict[str, int]:
    c = {s: 0 for s in _SEV_ORDER}
    for v in vulns:
        s = (v.severity.value if hasattr(v.severity, "value") else str(v.severity)).upper()
        c[s if s in c else "INFO"] += 1
    return c


def send_email(to_addr: str, subject: str, body: str,
               attachments: List[Dict] = None) -> None:
    """Gửi 1 email. attachments: [{filename, content(bytes), mime:'application/pdf'}]."""
    cfg = rt.smtp_config()
    if not cfg["host"] or not cfg["from_addr"]:
        raise RuntimeError("Chưa cấu hình SMTP (Settings → Thông báo/SMTP)")
    msg = EmailMessage()
    msg["From"] = cfg["from_addr"]
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)
    for a in attachments or []:
        maintype, _, subtype = (a.get("mime") or "application/octet-stream").partition("/")
        msg.add_attachment(a["content"], maintype=maintype, subtype=subtype or "octet-stream",
                           filename=a["filename"])

    port = cfg["port"]
    if port == 465:
        with smtplib.SMTP_SSL(cfg["host"], port, timeout=30, context=ssl.create_default_context()) as s:
            if cfg["username"]:
                s.login(cfg["username"], cfg["password"])
            s.send_message(msg)
    else:
        with smtplib.SMTP(cfg["host"], port, timeout=30) as s:
            if cfg["use_tls"]:
                s.starttls(context=ssl.create_default_context())
            if cfg["username"]:
                s.login(cfg["username"], cfg["password"])
            s.send_message(msg)


def _scan_pdf(db: Session, scan_id: str):
    """Typst PDF for a scan via the SAME engine/builder as the download endpoint (PDF PR-5).

    Returns ``(bytes, ascii_stem)`` or ``None`` when the engine is unavailable/fails: the mail is then
    sent WITHOUT an attachment (and says so) rather than falling back to any other renderer.
    """
    from api.services import pdf_export
    from scanner.pdf.errors import PdfBusy, PdfEngineError
    try:
        pre = pdf_export.prepare("scan", scan_id, db, None, {})
        for attempt in range(6):          # all render slots busy -> wait our turn
            try:
                data, stem, _ = pdf_export.render_pdf("scan", pre)
                return bytes(data), stem
            except PdfBusy:
                time.sleep(2)
        logger.warning("[mailer] PDF engine busy, gửi không kèm PDF (scan %s)", scan_id)
    except PdfEngineError as e:
        logger.warning("[mailer] không tạo được PDF (scan %s): %s", scan_id, getattr(e, "code", type(e).__name__))
    except Exception as e:  # noqa: BLE001 - mail must still go out
        logger.warning("[mailer] lỗi tạo PDF (scan %s): %s", scan_id, type(e).__name__)
    return None


def send_scan_report(db: Session, scan_id: str, to_addr: str, project_name: str) -> None:
    """Dựng PDF báo cáo (Typst) + tóm tắt rồi gửi cho owner."""
    from api.models import Scan, Vulnerability, ACTIVE_VULN_STATUS_VALUES

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return
    vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
    active = [v for v in vulns if (v.status.value if hasattr(v.status, "value") else v.status) in ACTIVE_VULN_STATUS_VALUES]
    c = _counts(active)
    pdf = _scan_pdf(db, scan_id)

    verdict = ("CÓ lỗ hổng NGHIÊM TRỌNG — cần xử lý ngay" if c["CRITICAL"] else
               "Có lỗ hổng mức CAO — cần xử lý" if c["HIGH"] else
               "Có lỗ hổng mức trung bình/thấp" if (c["MEDIUM"] or c["LOW"]) else
               "Không phát hiện lỗ hổng mở")
    attach_note = ("Báo cáo chi tiết (PDF) được đính kèm." if pdf else
                   "Không tạo được PDF đính kèm (engine PDF không khả dụng) — hãy tải báo cáo từ VulnGuard.")
    body = (
        f"Xin chào,\n\n"
        f"Báo cáo quét bảo mật tự động cho repository: {project_name} (scan #{scan.scan_number}).\n\n"
        f"Kết luận: {verdict}\n"
        f"Tổng lỗ hổng còn mở: {len(active)}\n"
        f"  - Nghiêm trọng: {c['CRITICAL']}\n"
        f"  - Cao:          {c['HIGH']}\n"
        f"  - Trung bình:   {c['MEDIUM']}\n"
        f"  - Thấp:         {c['LOW']}\n"
        f"  - Thông tin:    {c['INFO']}\n\n"
        f"{attach_note} Vui lòng xử lý các lỗ hổng theo thứ tự ưu tiên.\n\n"
        f"— VulnGuard DevSecOps Platform"
    )
    attachments = ([{"filename": f"{pdf[1]}.pdf", "content": pdf[0], "mime": "application/pdf"}] if pdf else [])
    send_email(to_addr, f"[VulnGuard] Báo cáo bảo mật: {project_name} (#{scan.scan_number})", body, attachments)
    logger.info(f"[mailer] đã gửi report scan {scan_id} tới {to_addr} (pdf={'có' if pdf else 'không'})")
