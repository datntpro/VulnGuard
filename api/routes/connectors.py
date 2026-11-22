"""
Connector API — cấu hình & đồng bộ XDR/EDR/NAC. Secret mã hoá, không bao giờ trả raw.
"""
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.connector_models import ConnectorConfig, ConnectorKind
from api.database import SessionLocal, get_db
from api.routes.auth import require_admin
from api.security import decrypt_secret, encrypt_secret, mask_secret
from scanner.connectors.registry import REGISTRY, describe

router = APIRouter(prefix="/api/connectors", tags=["connectors"])


class ConnectorIn(BaseModel):
    name: str
    kind: ConnectorKind
    base_url: Optional[str] = None
    enabled: bool = True
    config: Dict[str, Any] = {}
    secrets: Dict[str, str] = {}         # write-only; chỉ gửi field muốn đặt/đổi


class ConnectorPatch(BaseModel):
    name: Optional[str] = None
    base_url: Optional[str] = None
    enabled: Optional[bool] = None
    config: Optional[Dict[str, Any]] = None
    secrets: Optional[Dict[str, str]] = None
    clear_secrets: Optional[List[str]] = None


def _out(c: ConnectorConfig) -> dict:
    enc = c.secrets_enc or {}
    hints = {}
    for k, v in enc.items():
        val = decrypt_secret(v)
        hints[k] = mask_secret(val) if val else ""
    return {"id": c.id, "name": c.name, "kind": c.kind.value if c.kind else None,
            "enabled": c.enabled, "base_url": c.base_url, "config": c.config or {},
            "secret_hints": hints, "secret_fields_set": list(enc.keys()),
            "last_sync_at": c.last_sync_at, "last_sync_status": c.last_sync_status,
            "last_sync_message": c.last_sync_message, "last_sync_stats": c.last_sync_stats,
            "created_at": c.created_at}


@router.get("/kinds")
def list_kinds():
    labels = {"TRELLIX_XDR": "Trellix XDR (EDR)", "TRENDMICRO_VISION_ONE": "Trend Micro Vision One (XDR)",
              "FORTINAC": "FortiNAC"}
    return [{**d, "label": labels.get(d["kind"], d["kind"])} for d in describe()]


@router.get("")
def list_connectors(_=Depends(require_admin), db: Session = Depends(get_db)):
    return [_out(c) for c in db.query(ConnectorConfig).order_by(ConnectorConfig.created_at).all()]


def _apply_secrets(c: ConnectorConfig, secrets: Dict[str, str]):
    enc = dict(c.secrets_enc or {})
    for k, v in (secrets or {}).items():
        if v:   # chỉ set khi có giá trị mới (rỗng = giữ nguyên)
            enc[k] = encrypt_secret(v)
    c.secrets_enc = enc


@router.post("", status_code=201)
def create_connector(payload: ConnectorIn, _=Depends(require_admin), db: Session = Depends(get_db)):
    c = ConnectorConfig(name=payload.name, kind=payload.kind, base_url=payload.base_url,
                        enabled=payload.enabled, config=payload.config, secrets_enc={})
    _apply_secrets(c, payload.secrets)
    db.add(c)
    db.commit()
    db.refresh(c)
    return _out(c)


@router.patch("/{cid}")
def update_connector(cid: str, payload: ConnectorPatch, _=Depends(require_admin), db: Session = Depends(get_db)):
    c = db.query(ConnectorConfig).filter(ConnectorConfig.id == cid).first()
    if not c:
        raise HTTPException(status_code=404, detail="Connector không tồn tại")
    data = payload.model_dump(exclude_unset=True)
    for f in ("name", "base_url", "enabled", "config"):
        if f in data and data[f] is not None:
            setattr(c, f, data[f])
    if payload.secrets:
        _apply_secrets(c, payload.secrets)
    if payload.clear_secrets:
        enc = dict(c.secrets_enc or {})
        for k in payload.clear_secrets:
            enc.pop(k, None)
        c.secrets_enc = enc
    db.commit()
    db.refresh(c)
    return _out(c)


@router.delete("/{cid}", status_code=204)
def delete_connector(cid: str, _=Depends(require_admin), db: Session = Depends(get_db)):
    c = db.query(ConnectorConfig).filter(ConnectorConfig.id == cid).first()
    if not c:
        raise HTTPException(status_code=404, detail="Connector không tồn tại")
    db.delete(c)
    db.commit()
    return None


@router.post("/{cid}/test")
async def test_connector(cid: str, _=Depends(require_admin), db: Session = Depends(get_db)):
    c = db.query(ConnectorConfig).filter(ConnectorConfig.id == cid).first()
    if not c:
        raise HTTPException(status_code=404, detail="Connector không tồn tại")
    from scanner.connectors.sync import connector_from_config
    try:
        return await connector_from_config(c).test_connection()
    except Exception as e:
        return {"ok": False, "message": str(e)[:300], "detail": ""}


_running: set = set()


async def _sync_bg(cid: str):
    db = SessionLocal()
    try:
        c = db.query(ConnectorConfig).filter(ConnectorConfig.id == cid).first()
        if not c:
            return
        c.last_sync_status = "running"
        db.commit()
        from scanner.connectors.sync import run_sync
        await run_sync(db, c)
    except Exception as e:
        c = db.query(ConnectorConfig).filter(ConnectorConfig.id == cid).first()
        if c:
            c.last_sync_status = "error"
            c.last_sync_message = str(e)[:500]
            db.commit()
    finally:
        _running.discard(cid)
        db.close()


@router.post("/{cid}/sync")
def sync_connector(cid: str, background: BackgroundTasks, _=Depends(require_admin), db: Session = Depends(get_db)):
    c = db.query(ConnectorConfig).filter(ConnectorConfig.id == cid).first()
    if not c:
        raise HTTPException(status_code=404, detail="Connector không tồn tại")
    if not c.enabled:
        raise HTTPException(status_code=400, detail="Connector đang tắt")
    if cid in _running:
        raise HTTPException(status_code=409, detail="Đang đồng bộ")
    _running.add(cid)
    background.add_task(_sync_bg, cid)
    return {"started": True}
