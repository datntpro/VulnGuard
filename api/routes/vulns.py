from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime

from api.database import get_db
from api.models import Vulnerability, Waiver, VulnStatus
from api.schemas import VulnOut, VulnStatusUpdate, WaiverCreate, WaiverOut
from api.config import settings

router = APIRouter(prefix="/api/vulns", tags=["vulnerabilities"])

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _check_block_threshold(vuln: Vulnerability):
    """Kiểm tra xem vuln có vượt ngưỡng block không."""
    threshold = SEVERITY_ORDER.get(settings.block_severity_threshold, 1)
    vuln_level = SEVERITY_ORDER.get(vuln.severity.value, 99)
    return vuln_level <= threshold


@router.get("/{vuln_id}", response_model=VulnOut)
def get_vuln(vuln_id: str, db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability không tồn tại")
    return vuln


@router.patch("/{vuln_id}/status", response_model=VulnOut)
def update_vuln_status(vuln_id: str, payload: VulnStatusUpdate, db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability không tồn tại")

    vuln.status = payload.status
    db.commit()
    db.refresh(vuln)
    return vuln


@router.post("/{vuln_id}/waiver", response_model=WaiverOut, status_code=201)
def create_waiver(vuln_id: str, payload: WaiverCreate, db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability không tồn tại")

    if vuln.waiver:
        raise HTTPException(status_code=409, detail="Vulnerability này đã có waiver")

    waiver = Waiver(
        vulnerability_id=vuln_id,
        approver_name=payload.approver_name,
        approver_email=payload.approver_email,
        reason=payload.reason,
        expiry_date=payload.expiry_date,
        is_false_positive=payload.is_false_positive,
    )
    db.add(waiver)

    # Cập nhật status vuln
    if payload.is_false_positive:
        vuln.status = VulnStatus.FALSE_POSITIVE
    else:
        vuln.status = VulnStatus.ACCEPTED

    db.commit()
    db.refresh(waiver)
    return waiver


@router.delete("/{vuln_id}/waiver", status_code=204)
def delete_waiver(vuln_id: str, db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln or not vuln.waiver:
        raise HTTPException(status_code=404, detail="Waiver không tồn tại")

    db.delete(vuln.waiver)
    vuln.status = VulnStatus.OPEN
    db.commit()


@router.get("/{vuln_id}/block-status")
def check_block_status(vuln_id: str, db: Session = Depends(get_db)):
    """Kiểm tra vuln này có block approve không."""
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability không tồn tại")

    is_blocked = _check_block_threshold(vuln) and vuln.status == VulnStatus.OPEN
    return {
        "vuln_id": vuln_id,
        "severity": vuln.severity.value,
        "status": vuln.status.value,
        "is_blocked": is_blocked,
        "threshold": settings.block_severity_threshold,
        "message": f"BLOCKED: Severity {vuln.severity.value} vượt ngưỡng {settings.block_severity_threshold}" if is_blocked
                   else "OK: Không bị block",
    }
