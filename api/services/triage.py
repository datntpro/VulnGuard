"""
Triage service (GĐ1 — kiểu Checkmarx):
  - inherit_triage: khi scan mới ingest xong, KẾ THỪA trạng thái triage + note từ
    lần scan trước (match theo fingerprint cùng project) → không phải triage lại
    những finding đã đánh "Không khai thác được / Đã xác nhận / Chấp nhận".
  - apply_triage: đổi trạng thái 1 finding có kiểm tra quyền + note bắt buộc +
    ghi audit (TriageEvent).
  - Đánh dấu first_seen_at để UI phân biệt "Mới" vs "Tái xuất hiện".
"""
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from api.models import (Scan, Vulnerability, TriageEvent, VulnStatus,
                        NOTE_REQUIRED_STATUSES, ADMIN_ONLY_STATUSES)

# Trạng thái coi là "đã triage" (đáng để kế thừa sang scan sau)
_TRIAGED = {VulnStatus.CONFIRMED, VulnStatus.URGENT, VulnStatus.PROPOSED_NE,
            VulnStatus.NOT_EXPLOITABLE, VulnStatus.ACCEPTED, VulnStatus.FALSE_POSITIVE}


def inherit_triage(db: Session, scan: Scan) -> int:
    """Kế thừa triage từ các lần scan trước của cùng project. Trả số finding được kế thừa."""
    project_id = scan.project_id
    cur = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
    if not cur:
        return 0

    # Gom finding đã triage của các scan TRƯỚC trong cùng project, lấy bản mới nhất theo fingerprint
    prior_scan_ids = [s.id for s in db.query(Scan.id).filter(
        Scan.project_id == project_id, Scan.id != scan.id).all()]
    latest_by_fp = {}
    first_seen_by_fp = {}          # fp -> (first_seen_at, first_seen_scan_id)
    if prior_scan_ids:
        prior = (db.query(Vulnerability)
                 .filter(Vulnerability.scan_id.in_(prior_scan_ids),
                         Vulnerability.fingerprint.isnot(None))
                 .order_by(Vulnerability.created_at.asc()).all())
        for v in prior:
            fp = v.fingerprint
            if fp not in first_seen_by_fp:
                first_seen_by_fp[fp] = (v.first_seen_at or v.created_at,
                                        v.first_seen_scan_id or v.scan_id)
            # giữ bản triaged mới nhất
            if v.status in _TRIAGED:
                latest_by_fp[fp] = v  # order asc → bản sau ghi đè = mới nhất

    now = datetime.utcnow()
    inherited = 0
    for v in cur:
        fp = v.fingerprint
        if fp in first_seen_by_fp:
            v.first_seen_at, v.first_seen_scan_id = first_seen_by_fp[fp]   # tái xuất hiện
        else:
            v.first_seen_at, v.first_seen_scan_id = now, scan.id           # finding mới
        src = latest_by_fp.get(fp) if fp else None
        if src is not None and v.status == VulnStatus.OPEN:
            v.status = src.status
            v.triage_note = src.triage_note
            v.triage_by = src.triage_by
            v.triage_at = src.triage_at
            inherited += 1
    db.commit()
    return inherited


def is_new_finding(v: Vulnerability, scan: Optional[Scan] = None) -> bool:
    """True nếu finding lần đầu xuất hiện ở chính scan này (không có ở scan trước)."""
    if not v.first_seen_scan_id:
        return True
    return v.first_seen_scan_id == v.scan_id


class TriageError(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


def apply_triage(db: Session, vuln: Vulnerability, to_status: VulnStatus,
                 note: Optional[str], actor: Optional[str], is_admin: bool) -> Vulnerability:
    """Đổi trạng thái triage có kiểm tra quyền + note + ghi audit."""
    note = (note or "").strip()
    if to_status in ADMIN_ONLY_STATUSES and not is_admin:
        raise TriageError(403, "Chỉ ADMIN mới được chốt trạng thái 'Không khai thác được'. "
                               "Hãy chọn 'Đề xuất: không khai thác được' để chuyển cho reviewer.")
    if to_status in NOTE_REQUIRED_STATUSES and not note:
        raise TriageError(422, "Trạng thái này bắt buộc nhập ghi chú (lý do).")

    from_status = vuln.status.value if vuln.status else None
    vuln.status = to_status
    vuln.triage_note = note or vuln.triage_note
    vuln.triage_by = actor
    vuln.triage_at = datetime.utcnow()

    db.add(TriageEvent(
        vulnerability_id=vuln.id,
        project_id=_project_id_of(db, vuln),
        fingerprint=vuln.fingerprint,
        from_status=from_status,
        to_status=to_status.value,
        note=note or None,
        actor=actor,
    ))
    db.commit()
    db.refresh(vuln)
    return vuln


def _project_id_of(db: Session, vuln: Vulnerability) -> Optional[str]:
    s = db.query(Scan.project_id).filter(Scan.id == vuln.scan_id).first()
    return s[0] if s else None
