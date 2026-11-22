"""
Sync engine — kéo asset + alert từ 1 connector vào Asset inventory, rồi tính lại risk.

Alert được match về asset theo hostname/ip/mac; nếu chưa có asset thì tạo mới từ
thông tin host của alert. Sau sync, recompute risk cho các asset bị chạm.
"""
import logging
from dataclasses import asdict
from datetime import datetime
from typing import Dict, List

from sqlalchemy.orm import Session

from api.connector_models import ConnectorConfig
from scanner.assets.service import (
    compute_dedup_key, recompute_asset_risk, replace_software, upsert_alert, upsert_asset,
)
from scanner.connectors.base import NormAlert, NormAsset
from scanner.connectors.registry import build_connector

logger = logging.getLogger(__name__)


def _norm_asset_dict(na: NormAsset) -> Dict:
    d = asdict(na)
    d["software"] = [{"name": s["name"], "version": s.get("version"), "vendor": s.get("vendor"),
                      "cpe": s.get("cpe")} for s in d.get("software", [])]
    return d


def connector_from_config(cfg: ConnectorConfig):
    from api.security import decrypt_secret
    secrets = {k: decrypt_secret(v) for k, v in (cfg.secrets_enc or {}).items()}
    return build_connector(cfg.kind.value if hasattr(cfg.kind, "value") else cfg.kind,
                           cfg.base_url, cfg.config or {}, secrets)


async def run_sync(db: Session, cfg: ConnectorConfig) -> Dict:
    source = (cfg.kind.value if hasattr(cfg.kind, "value") else cfg.kind).lower()
    connector = connector_from_config(cfg)
    touched = set()
    stats = {"assets": 0, "alerts": 0, "software": 0, "errors": []}

    # Assets
    try:
        assets: List[NormAsset] = await connector.fetch_assets()
    except Exception as e:
        assets = []
        stats["errors"].append(f"fetch_assets: {e}")
    for na in assets:
        try:
            a = upsert_asset(db, _norm_asset_dict(na), source)
            if na.software:
                replace_software(db, a, [{"name": s.name, "version": s.version, "vendor": s.vendor,
                                          "cpe": s.cpe} for s in na.software], source)
                stats["software"] += len(na.software)
            touched.add(a.id)
            stats["assets"] += 1
        except Exception as e:
            stats["errors"].append(f"upsert asset {na.hostname}: {e}")
    db.commit()

    # Alerts — match/tạo asset theo host keys
    try:
        alerts: List[NormAlert] = await connector.fetch_alerts()
    except Exception as e:
        alerts = []
        stats["errors"].append(f"fetch_alerts: {e}")
    for al in alerts:
        try:
            a = upsert_asset(db, {"hostname": al.hostname, "ip": al.ip, "mac": al.mac}, source)
            upsert_alert(db, a, {"external_id": al.external_id, "title": al.title, "severity": al.severity,
                                 "status": al.status or "open", "technique": al.technique,
                                 "detected_at": _parse_dt(al.detected_at), "raw": al.raw}, source)
            if al.detected_at:
                a.last_edr_alert_at = _parse_dt(al.detected_at)
            touched.add(a.id)
            stats["alerts"] += 1
        except Exception as e:
            stats["errors"].append(f"alert {al.external_id}: {e}")
    db.commit()

    # Recompute risk cho asset bị chạm
    from api.asset_models import Asset
    for aid in touched:
        a = db.query(Asset).filter(Asset.id == aid).first()
        if a:
            recompute_asset_risk(db, a)
    db.commit()

    cfg.last_sync_at = datetime.utcnow()
    cfg.last_sync_status = "error" if stats["errors"] and not touched else "ok"
    cfg.last_sync_message = ("; ".join(stats["errors"])[:1000] if stats["errors"]
                             else f"Đồng bộ {stats['assets']} asset, {stats['alerts']} alert")
    cfg.last_sync_stats = {k: v for k, v in stats.items() if k != "errors"} | {"touched": len(touched)}
    db.commit()
    return stats


def _parse_dt(v):
    if v is None or isinstance(v, datetime):
        return v
    s = str(v).replace("Z", "+00:00")
    for parse in (datetime.fromisoformat,):
        try:
            return parse(s).replace(tzinfo=None)
        except (ValueError, TypeError):
            pass
    return None
