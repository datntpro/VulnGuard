"""
Gửi email báo cáo scan cho owner (SMTP). Đính kèm PDF báo cáo + tóm tắt mức độ.
Cấu hình SMTP lưu ở runtime_settings (mật khẩu mã hoá Fernet).
"""
import logging
import smtplib
import ssl
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


def send_scan_report(db: Session, scan_id: str, to_addr: str, project_name: str) -> None:
    """Dựng PDF báo cáo + tóm tắt rồi gửi cho owner."""
    from api.models import Scan, Vulnerability, ACTIVE_VULN_STATUS_VALUES
    from scanner import report_builder as rb

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return
    vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
    active = [v for v in vulns if (v.status.value if hasattr(v.status, "value") else v.status) in ACTIVE_VULN_STATUS_VALUES]
    c = _counts(active)
    pdf = rb.build_pdf(scan, vulns, project_name)

    verdict = ("CÓ lỗ hổng NGHIÊM TRỌNG — cần xử lý ngay" if c["CRITICAL"] else
               "Có lỗ hổng mức CAO — cần xử lý" if c["HIGH"] else
               "Có lỗ hổng mức trung bình/thấp" if (c["MEDIUM"] or c["LOW"]) else
               "Không phát hiện lỗ hổng mở")
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
        f"Báo cáo chi tiết (PDF) được đính kèm. Vui lòng xử lý các lỗ hổng theo thứ tự ưu tiên.\n\n"
        f"— VulnGuard DevSecOps Platform"
    )
    send_email(to_addr, f"[VulnGuard] Báo cáo bảo mật: {project_name} (#{scan.scan_number})",
               body, [{"filename": f"vulnguard_{project_name}_{scan.scan_number}.pdf",
                       "content": bytes(pdf), "mime": "application/pdf"}])
    logger.info(f"[mailer] đã gửi report scan {scan_id} tới {to_addr}")
