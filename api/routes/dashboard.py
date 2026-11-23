"""
Dashboard tổng hợp rủi ro toàn hệ thống — gom mọi nguồn:
  - Code scan (SAST/SCA/IaC/Secrets): Vulnerability
  - Web scan (Nuclei/DAST): WebFinding
  - Pentest Agent: PentestFinding
  - Asset inventory (XDR/EDR/NAC): Asset + AssetVuln + AssetAlert
Cho cái nhìn một màn hình: tư thế rủi ro, top rủi ro, độ phủ, việc đang chờ.
"""
from collections import Counter
from datetime import datetime, timedelta
from typing import Dict, List

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.database import get_db

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

_SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_OPENISH = {"OPEN", "open", None, ""}


def _empty_sev() -> Dict[str, int]:
    return {s: 0 for s in _SEVS}


def _norm(sev) -> str:
    s = (sev.value if hasattr(sev, "value") else str(sev or "")).upper()
    return s if s in _SEVS else "INFO"


@router.get("/overview")
def overview(db: Session = Depends(get_db)):
    from api.models import Project, Scan, Vulnerability, VulnStatus, ACTIVE_VULN_STATUSES
    from api.webscan_models import WebFinding, WebScan
    from api.domain_models import Domain
    from api.pentest_models import (Engagement, PentestFinding, PentestRun, RunStatus,
                                    ApprovalRequest, ApprovalStatus)
    from api.asset_models import Asset, AssetAlert
    from api.connector_models import ConnectorConfig
    from scanner.assets.scoring import band

    # ── Findings theo nguồn (chỉ tính OPEN để phản ánh rủi ro còn tồn) ──
    by_source: Dict[str, Dict[str, int]] = {}

    code = _empty_sev()
    for v in db.query(Vulnerability).filter(Vulnerability.status == VulnStatus.OPEN).all():
        code[_norm(v.severity)] += 1
    by_source["code"] = code

    web = _empty_sev()
    for f in db.query(WebFinding).filter(WebFinding.status == "OPEN").all():
        web[_norm(f.severity)] += 1
    by_source["web"] = web

    pentest = _empty_sev()
    for f in db.query(PentestFinding).filter(PentestFinding.status == "OPEN").all():
        pentest[_norm(f.severity)] += 1
    by_source["pentest"] = pentest

    asset_v = _empty_sev()
    from api.asset_models import AssetVuln
    for av in db.query(AssetVuln).filter(AssetVuln.status == "OPEN").all():
        asset_v[_norm(av.severity)] += 1
    by_source["asset"] = asset_v

    totals = _empty_sev()
    for src in by_source.values():
        for s in _SEVS:
            totals[s] += src[s]

    # ── Asset risk ──
    assets = db.query(Asset).all()
    asset_bands = {b: 0 for b in _SEVS}
    for a in assets:
        asset_bands[band(a.risk_score or 0)] += 1
    top_assets = sorted(assets, key=lambda a: a.risk_score or 0, reverse=True)[:8]
    active_alert_assets = [a for a in assets if (a.active_alert_count or 0) > 0]

    # ── Việc đang chờ / đang chạy ──
    active_runs = db.query(PentestRun).filter(PentestRun.status.in_(
        [RunStatus.RUNNING, RunStatus.WAITING_APPROVAL, RunStatus.PENDING, RunStatus.PAUSED])).count()
    pending_approvals = db.query(ApprovalRequest).filter(
        ApprovalRequest.status == ApprovalStatus.PENDING).count()
    running_scans = db.query(Scan).filter(Scan.status.in_(["RUNNING", "PENDING"])).count()

    # ── Độ phủ ──
    connectors = db.query(ConnectorConfig).all()
    coverage = {
        "projects": db.query(Project).count(),
        "domains": db.query(Domain).count(),
        "assets": len(assets),
        "connectors": len(connectors),
        "connectors_ok": sum(1 for c in connectors if c.last_sync_status == "ok"),
        "engagements": db.query(Engagement).count(),
        "edr_monitored": sum(1 for a in assets if a.edr_agent_present),
    }

    # ── Top rủi ro hợp nhất (asset + finding critical) ──
    top_risks: List[Dict] = []
    for a in top_assets[:6]:
        if (a.risk_score or 0) > 0:
            top_risks.append({"type": "asset", "name": a.hostname or a.ip,
                              "risk_score": a.risk_score, "band": band(a.risk_score or 0),
                              "detail": f"{a.active_alert_count or 0} cảnh báo EDR · {len(a.vulns)} CVE",
                              "id": a.id})

    # ── Xu hướng: scan 14 ngày gần nhất ──
    since = datetime.utcnow() - timedelta(days=14)
    recent_scans = db.query(Scan).filter(Scan.started_at >= since).all()
    trend: Dict[str, int] = {}
    for s in recent_scans:
        d = (s.started_at or datetime.utcnow()).strftime("%Y-%m-%d")
        trend[d] = trend.get(d, 0) + 1
    trend_series = [{"date": k, "scans": trend[k]} for k in sorted(trend.keys())]

    # ── Risk posture score (0..100) toàn hệ thống ──
    posture = _posture_score(totals, asset_bands, active_alert_assets)

    return {
        "posture": posture,
        "findings_by_source": by_source,
        "findings_total": totals,
        "findings_open_total": sum(totals.values()),
        "asset_bands": asset_bands,
        "assets_with_active_alerts": len(active_alert_assets),
        "top_risks": top_risks,
        "top_assets": [{"id": a.id, "hostname": a.hostname, "ip": a.ip,
                        "risk_score": a.risk_score, "band": band(a.risk_score or 0),
                        "active_alerts": a.active_alert_count, "sources": a.sources or []}
                       for a in top_assets],
        "queue": {"active_pentest_runs": active_runs, "pending_approvals": pending_approvals,
                  "running_scans": running_scans},
        "coverage": coverage,
        "scan_trend": trend_series,
        "generated_at": datetime.utcnow(),
    }


@router.get("/compliance")
def compliance(project_id: str = None, db: Session = Depends(get_db)):
    """Tổng hợp tuân thủ toàn hệ thống (hoặc 1 project) từ các lỗ hổng code OPEN.

    Ánh xạ sang OWASP Top 10, ISO 27001, TCVN 11930/NĐ 85, PCI-DSS.
    """
    from api.models import Scan, Vulnerability, VulnStatus, ACTIVE_VULN_STATUSES
    from scanner import compliance as C

    q = db.query(Vulnerability).filter(Vulnerability.status.in_(ACTIVE_VULN_STATUSES))
    if project_id:
        scan_ids = [s.id for s in db.query(Scan).filter(Scan.project_id == project_id).all()]
        q = q.filter(Vulnerability.scan_id.in_(scan_ids or ["__none__"]))
    vulns = q.all()
    summary = C.compliance_summary(vulns)
    return {
        "total_findings": len(vulns),
        "frameworks": [summary[fw] for fw in C.FRAMEWORKS],
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }


def _posture_score(findings_totals, asset_bands, active_alert_assets) -> Dict:
    """Điểm tư thế rủi ro 0..100 (càng cao càng xấu) + nhãn. Có trọng số theo severity."""
    w = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 0.5, "INFO": 0}
    f = sum(w[s] * findings_totals.get(s, 0) for s in w)
    a = asset_bands.get("CRITICAL", 0) * 10 + asset_bands.get("HIGH", 0) * 4
    alert = len(active_alert_assets) * 8
    raw = f + a + alert
    # Chuẩn hoá log để không vọt 100 ngay: score = 100*(1 - 1/(1+raw/50))
    score = round(100 * (1 - 1 / (1 + raw / 50.0)), 1) if raw > 0 else 0.0
    if score >= 75:
        label = "NGHIÊM TRỌNG"
    elif score >= 50:
        label = "CAO"
    elif score >= 25:
        label = "TRUNG BÌNH"
    elif score > 0:
        label = "THẤP"
    else:
        label = "TỐT"
    return {"score": score, "label": label,
            "drivers": {"weighted_findings": round(f, 1), "critical_high_assets": a,
                        "active_alerts": alert}}
