from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from api.database import get_db
from api.models import Scan, Vulnerability, VulnStatus
from api.schemas import CompareResult, VulnDiff, VulnOut, ScanOut
from api.config import settings

router = APIRouter(prefix="/api/projects", tags=["compare"])

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@router.get("/{project_id}/compare", response_model=CompareResult)
def compare_scans(
    project_id: str,
    scan_old_id: str,
    scan_new_id: str,
    db: Session = Depends(get_db)
):
    """So sánh hai lần scan để xác định vulns mới, đã fix, và tồn tại."""
    scan_old = db.query(Scan).filter(Scan.id == scan_old_id, Scan.project_id == project_id).first()
    scan_new = db.query(Scan).filter(Scan.id == scan_new_id, Scan.project_id == project_id).first()

    if not scan_old or not scan_new:
        raise HTTPException(status_code=404, detail="Scan không tồn tại hoặc không thuộc project này")

    old_vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_old_id).all()
    new_vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_new_id).all()

    # Dùng fingerprint để match vulns across scans
    old_fps = {v.fingerprint: v for v in old_vulns if v.fingerprint}
    new_fps = {v.fingerprint: v for v in new_vulns if v.fingerprint}

    new_findings = []       # Trong new nhưng không có trong old
    fixed_findings = []     # Trong old nhưng không có trong new
    persisted_findings = [] # Trong cả hai

    for fp, vuln in new_fps.items():
        if fp in old_fps:
            persisted_findings.append(vuln)
        else:
            new_findings.append(vuln)

    for fp, vuln in old_fps.items():
        if fp not in new_fps:
            fixed_findings.append(vuln)

    # Vulns không có fingerprint — so sánh theo title + file_path
    old_no_fp = [v for v in old_vulns if not v.fingerprint]
    new_no_fp = [v for v in new_vulns if not v.fingerprint]

    old_keys = {(v.title, v.file_path, v.line_start): v for v in old_no_fp}
    new_keys = {(v.title, v.file_path, v.line_start): v for v in new_no_fp}

    for key, vuln in new_keys.items():
        if key in old_keys:
            persisted_findings.append(vuln)
        else:
            new_findings.append(vuln)

    for key, vuln in old_keys.items():
        if key not in new_keys:
            fixed_findings.append(vuln)

    # Sắp xếp theo severity
    def sort_key(v):
        return SEVERITY_ORDER.get(v.severity.value, 99)

    new_findings.sort(key=sort_key)
    fixed_findings.sort(key=sort_key)
    persisted_findings.sort(key=sort_key)

    # Check scan có bị block không
    threshold = settings.block_severity_threshold
    threshold_level = SEVERITY_ORDER.get(threshold, 1)
    blocked_vulns = [
        v for v in new_vulns
        if SEVERITY_ORDER.get(v.severity.value, 99) <= threshold_level
        and v.status.value == "OPEN"
    ]

    summary = {
        "new_count": len(new_findings),
        "fixed_count": len(fixed_findings),
        "persisted_count": len(persisted_findings),
        "blocked_count": len(blocked_vulns),
        "approve_status": "BLOCKED" if blocked_vulns else "APPROVED",
        "approve_message": (
            f"⛔ BLOCKED: {len(blocked_vulns)} vulnerability chưa được xử lý có severity >= {threshold}"
            if blocked_vulns
            else "✅ APPROVED: Không có vulnerability nào vượt ngưỡng block"
        ),
    }

    return CompareResult(
        project_id=project_id,
        scan_old=ScanOut.model_validate(scan_old),
        scan_new=ScanOut.model_validate(scan_new),
        diff=VulnDiff(
            new=[VulnOut.model_validate(v) for v in new_findings],
            fixed=[VulnOut.model_validate(v) for v in fixed_findings],
            persisted=[VulnOut.model_validate(v) for v in persisted_findings],
        ),
        summary=summary,
    )


@router.get("/{project_id}/approve-check")
def approve_check(project_id: str, scan_id: str, db: Session = Depends(get_db)):
    """Kiểm tra một scan có đủ điều kiện approve deploy không."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.project_id == project_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan không tồn tại")

    threshold = settings.block_severity_threshold
    threshold_level = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(threshold, 1)

    blocked_vulns = db.query(Vulnerability).filter(
        Vulnerability.scan_id == scan_id,
        Vulnerability.status == "OPEN"
    ).all()

    blocked_vulns = [
        v for v in blocked_vulns
        if {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(v.severity.value, 99) <= threshold_level
    ]

    return {
        "scan_id": scan_id,
        "project_id": project_id,
        "scan_number": scan.scan_number,
        "threshold": threshold,
        "blocked_count": len(blocked_vulns),
        "approve_status": "BLOCKED" if blocked_vulns else "APPROVED",
        "blocked_vulns": [
            {
                "id": v.id,
                "title": v.title,
                "severity": v.severity.value,
                "file_path": v.file_path,
                "cve": v.cve,
            }
            for v in blocked_vulns
        ],
        "message": (
            f"⛔ BLOCKED: Còn {len(blocked_vulns)} vulnerability OPEN có severity >= {threshold}. "
            f"Hãy fix hoặc tạo waiver trước khi approve."
            if blocked_vulns
            else "✅ APPROVED: Scan đủ điều kiện để approve deploy."
        ),
    }
