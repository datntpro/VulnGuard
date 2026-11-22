"""
Asset service — upsert/dedup/merge tài sản + tính lại risk score.

dedup_key: ưu tiên mac → hostname(lower) → ip. Nhờ vậy cùng 1 máy đổi IP vẫn gộp
đúng (nếu có mac/hostname). Observation thô từ connector được normalize rồi upsert.
"""
import logging
from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from api.asset_models import (
    Asset, AssetAlert, AssetSoftware, AssetVuln, AssetType, Criticality, Exposure,
)
from scanner.assets.scoring import asset_risk, band, score_vuln_row
from scanner.intel.feeds import epss_for, is_kev

logger = logging.getLogger(__name__)


def compute_dedup_key(mac: Optional[str], hostname: Optional[str], ip: Optional[str]) -> str:
    if mac:
        return "mac:" + mac.lower().replace("-", ":")
    if hostname:
        return "host:" + hostname.lower()
    if ip:
        return "ip:" + ip
    return "unknown:" + (hostname or ip or mac or "?")


def _enum_val(enum_cls, v, default):
    if v is None:
        return default
    try:
        return enum_cls(str(v).upper())
    except ValueError:
        return default


def _find_existing(db: Session, mac, hostname, ip) -> Optional[Asset]:
    """Match linh hoạt: mac → hostname → ip (nhiều nguồn cho định danh khác nhau về
    cùng 1 máy vẫn gộp đúng, vd NAC cho mac+hostname còn alert chỉ có hostname)."""
    if mac:
        m = "mac:" + mac.lower().replace("-", ":")
        a = db.query(Asset).filter((Asset.dedup_key == m) |
                                   (Asset.mac.isnot(None) & (func.lower(Asset.mac) == mac.lower()))).first()
        if a:
            return a
    if hostname:
        a = db.query(Asset).filter((Asset.dedup_key == "host:" + hostname.lower()) |
                                   (func.lower(Asset.hostname) == hostname.lower())).first()
        if a:
            return a
    if ip:
        a = db.query(Asset).filter((Asset.dedup_key == "ip:" + ip) | (Asset.ip == ip)).first()
        if a:
            return a
    return None


def upsert_asset(db: Session, norm: Dict, source: str) -> Asset:
    """norm: dict chuẩn hoá {hostname, ip, mac, asset_type, os, os_version, criticality,
    exposure, vlan, switch_port, nac_status, edr_agent_present, edr_health, owner, tags}."""
    asset = _find_existing(db, norm.get("mac"), norm.get("hostname"), norm.get("ip"))
    if not asset:
        asset = Asset(dedup_key=compute_dedup_key(norm.get("mac"), norm.get("hostname"), norm.get("ip")))
        db.add(asset)
    else:
        # Nâng cấp dedup_key nếu nguồn mới cho định danh ổn định hơn (mac > hostname > ip)
        best = compute_dedup_key(norm.get("mac") or asset.mac, norm.get("hostname") or asset.hostname,
                                 norm.get("ip") or asset.ip)
        if best.startswith("mac:") or (best.startswith("host:") and (asset.dedup_key or "").startswith("ip:")):
            # tránh đụng unique nếu đã có asset khác giữ key này
            if not db.query(Asset).filter(Asset.dedup_key == best, Asset.id != asset.id).first():
                asset.dedup_key = best
    # Merge — chỉ ghi đè khi có giá trị mới (không xoá dữ liệu cũ bằng None)
    for f in ("hostname", "ip", "mac", "os", "os_version", "vlan", "switch_port", "nac_status",
              "edr_health", "owner"):
        if norm.get(f):
            setattr(asset, f, norm[f])
    if norm.get("asset_type"):
        asset.asset_type = _enum_val(AssetType, norm["asset_type"], AssetType.UNKNOWN)
    if norm.get("criticality"):
        asset.criticality = _enum_val(Criticality, norm["criticality"], asset.criticality or Criticality.MEDIUM)
    if norm.get("exposure"):
        asset.exposure = _enum_val(Exposure, norm["exposure"], asset.exposure or Exposure.UNKNOWN)
    if "edr_agent_present" in norm and norm["edr_agent_present"] is not None:
        asset.edr_agent_present = bool(norm["edr_agent_present"])
    if norm.get("tags"):
        asset.tags = sorted(set((asset.tags or []) + list(norm["tags"])))
    asset.sources = sorted(set((asset.sources or []) + [source]))
    asset.last_seen = datetime.utcnow()
    db.flush()
    return asset


def replace_software(db: Session, asset: Asset, items: List[Dict], source: str):
    db.query(AssetSoftware).filter(AssetSoftware.asset_id == asset.id,
                                   AssetSoftware.source == source).delete()
    for it in items:
        db.add(AssetSoftware(asset_id=asset.id, name=(it.get("name") or "")[:300],
                             version=it.get("version"), vendor=it.get("vendor"),
                             cpe=it.get("cpe"), source=source))
    db.flush()


def upsert_alert(db: Session, asset: Asset, norm: Dict, source: str):
    existing = None
    if norm.get("external_id"):
        existing = db.query(AssetAlert).filter(AssetAlert.asset_id == asset.id,
                                               AssetAlert.external_id == norm["external_id"]).first()
    a = existing or AssetAlert(asset_id=asset.id)
    a.source = source
    a.external_id = norm.get("external_id")
    a.title = (norm.get("title") or "")[:500]
    a.severity = norm.get("severity")
    a.status = norm.get("status")
    a.technique = norm.get("technique")
    a.detected_at = norm.get("detected_at")
    a.raw = norm.get("raw")
    if not existing:
        db.add(a)
    db.flush()


def upsert_vuln(db: Session, asset: Asset, cve: str, cvss: Optional[float], title: str,
                source: str, severity: Optional[str] = None) -> AssetVuln:
    cve = cve.upper()
    v = db.query(AssetVuln).filter(AssetVuln.asset_id == asset.id, AssetVuln.cve == cve).first()
    if not v:
        v = AssetVuln(asset_id=asset.id, cve=cve)
        db.add(v)
    v.cvss_score = cvss if cvss is not None else v.cvss_score
    v.title = (title or v.title or cve)[:500]
    v.source = source
    v.severity = severity or v.severity
    v.epss = epss_for(cve)
    v.kev = is_kev(cve)
    db.flush()
    return v


def recompute_asset_risk(db: Session, asset: Asset) -> float:
    """Enrich + chấm điểm từng vuln, rồi tổng hợp điểm asset. Trả risk_score."""
    active_alerts = db.query(AssetAlert).filter(
        AssetAlert.asset_id == asset.id,
        AssetAlert.status.notin_(["closed", "resolved", "CLOSED", "RESOLVED"]),
    ).count()
    asset.active_alert_count = active_alerts
    scores = []
    top = None   # factors của vuln rủi ro cao nhất — để giải thích threat/context trên asset
    for v in asset.vulns:
        if v.epss is None:
            v.epss = epss_for(v.cve)
        if not v.kev:
            v.kev = is_kev(v.cve)
        r = score_vuln_row(v, asset)
        v.risk_score = r["score"]
        scores.append(r["score"])
        if top is None or r["score"] > top[0]:
            top = (r["score"], v.cve, r["factors"])
    agg = asset_risk(scores, active_alerts)
    asset.risk_score = agg["score"]
    factors = {**agg["factors"], "band": band(agg["score"]), "vuln_count": len(scores)}
    if top:
        factors["top_cve"] = top[1]
        factors["threat_mult"] = top[2].get("threat_mult")
        factors["context_mult"] = top[2].get("context_mult")
        factors["top_cvss"] = top[2].get("cvss")
        factors["top_epss"] = top[2].get("epss")
        factors["top_kev"] = top[2].get("kev")
    asset.risk_factors = factors
    db.flush()
    return asset.risk_score


def recompute_all(db: Session) -> int:
    assets = db.query(Asset).all()
    for a in assets:
        recompute_asset_risk(db, a)
    db.commit()
    return len(assets)
