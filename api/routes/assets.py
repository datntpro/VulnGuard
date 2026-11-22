"""
Asset inventory + risk scoring API.
"""
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.asset_models import Asset, AssetAlert, AssetSoftware, AssetVuln, Criticality, Exposure
from api.database import get_db
from scanner.assets.scoring import band
from scanner.assets.service import recompute_all, recompute_asset_risk

router = APIRouter(prefix="/api/assets", tags=["assets"])


class AssetPatch(BaseModel):
    criticality: Optional[Criticality] = None
    exposure: Optional[Exposure] = None
    owner: Optional[str] = None
    tags: Optional[List[str]] = None


def _asset_out(a: Asset, detail: bool = False) -> dict:
    d = {
        "id": a.id, "hostname": a.hostname, "ip": a.ip, "mac": a.mac,
        "asset_type": a.asset_type.value if a.asset_type else None,
        "os": a.os, "os_version": a.os_version,
        "criticality": a.criticality.value if a.criticality else None,
        "exposure": a.exposure.value if a.exposure else None,
        "owner": a.owner, "tags": a.tags or [], "vlan": a.vlan, "nac_status": a.nac_status,
        "edr_agent_present": a.edr_agent_present, "edr_health": a.edr_health,
        "active_alert_count": a.active_alert_count, "sources": a.sources or [],
        "risk_score": a.risk_score, "risk_band": band(a.risk_score or 0),
        "last_seen": a.last_seen, "first_seen": a.first_seen,
    }
    if detail:
        d["risk_factors"] = a.risk_factors or {}
        d["software"] = [{"name": s.name, "version": s.version, "vendor": s.vendor, "source": s.source}
                         for s in a.software]
        d["vulns"] = [{"cve": v.cve, "title": v.title, "cvss_score": v.cvss_score, "epss": v.epss,
                       "kev": v.kev, "risk_score": v.risk_score, "severity": v.severity,
                       "source": v.source, "status": v.status}
                      for v in sorted(a.vulns, key=lambda x: x.risk_score or 0, reverse=True)]
        d["alerts"] = [{"source": al.source, "title": al.title, "severity": al.severity,
                        "status": al.status, "technique": al.technique, "detected_at": al.detected_at}
                       for al in a.alerts]
    return d


@router.get("")
def list_assets(sort: str = "risk", min_risk: float = 0, source: Optional[str] = None,
                db: Session = Depends(get_db)):
    q = db.query(Asset)
    rows = q.all()
    if source:
        rows = [a for a in rows if source in (a.sources or [])]
    if min_risk:
        rows = [a for a in rows if (a.risk_score or 0) >= min_risk]
    if sort == "risk":
        rows.sort(key=lambda a: a.risk_score or 0, reverse=True)
    elif sort == "hostname":
        rows.sort(key=lambda a: (a.hostname or a.ip or ""))
    return [_asset_out(a) for a in rows]


@router.get("/summary")
def assets_summary(db: Session = Depends(get_db)):
    rows = db.query(Asset).all()
    bands = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for a in rows:
        bands[band(a.risk_score or 0)] += 1
    top = sorted(rows, key=lambda a: a.risk_score or 0, reverse=True)[:10]
    return {"total": len(rows), "by_band": bands,
            "with_active_alerts": sum(1 for a in rows if (a.active_alert_count or 0) > 0),
            "top_risk": [_asset_out(a) for a in top]}


@router.get("/{asset_id}")
def get_asset(asset_id: str, db: Session = Depends(get_db)):
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Asset không tồn tại")
    return _asset_out(a, detail=True)


@router.patch("/{asset_id}")
def patch_asset(asset_id: str, payload: AssetPatch, db: Session = Depends(get_db)):
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Asset không tồn tại")
    data = payload.model_dump(exclude_unset=True)
    if "criticality" in data and data["criticality"]:
        a.criticality = data["criticality"]
    if "exposure" in data and data["exposure"]:
        a.exposure = data["exposure"]
    if "owner" in data:
        a.owner = data["owner"]
    if "tags" in data and data["tags"] is not None:
        a.tags = sorted(set(data["tags"]))
    recompute_asset_risk(db, a)   # criticality/exposure đổi → risk đổi
    db.commit()
    return _asset_out(a, detail=True)


@router.delete("/{asset_id}", status_code=204)
def delete_asset(asset_id: str, db: Session = Depends(get_db)):
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Asset không tồn tại")
    db.delete(a)
    db.commit()
    return None


@router.post("/recompute")
def recompute(db: Session = Depends(get_db)):
    n = recompute_all(db)
    return {"recomputed": n}
