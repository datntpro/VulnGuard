"""
Knowledge Base API — trạng thái KB, cập nhật ngay, import offline, tra cứu enrich.
Chỉ admin được cập nhật/import. KB là file sqlite riêng, swap atomically (updater.py).
"""
import os
import tempfile
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel

from api.config import settings
from api.routes.auth import require_admin
from scanner.knowledge import store, updater

router = APIRouter(prefix="/api/knowledge", tags=["knowledge"])


class EnrichQuery(BaseModel):
    cve: Optional[str] = None
    ecosystem: Optional[str] = None
    package: Optional[str] = None


@router.get("/status")
def status():
    """Phiên bản KB hiện tại + cấu hình auto-update (public để UI hiển thị badge)."""
    meta = store.get_meta()
    return {
        "available": meta.get("available", False),
        "version": meta.get("version"),
        "built_at": meta.get("built_at"),
        "advisory_count": meta.get("advisory_count", 0),
        "epss_count": meta.get("epss_count", 0),
        "kev_count": meta.get("kev_count", 0),
        "sources": meta.get("sources", []),
        "ecosystems": meta.get("ecosystems", {}),
        "auto_update": settings.kb_auto_update,
        "manifest_url": settings.kb_manifest_url,
        "update_interval_hours": settings.kb_update_interval_hours,
    }


@router.post("/update")
def update_now(force: bool = False, _: object = Depends(require_admin)):
    """Kiểm tra manifest vendor và tải bản mới nếu có (đồng bộ, trả kết quả)."""
    if not settings.kb_manifest_url:
        raise HTTPException(400, "Chưa cấu hình kb_manifest_url")
    return updater.check_and_update(force=force)


@router.post("/import")
async def import_offline(file: UploadFile = File(...), sha256: Optional[str] = None,
                         _: object = Depends(require_admin)):
    """Import KB offline/air-gap: upload kb.sqlite hoặc kb.sqlite.gz."""
    name = (file.filename or "").lower()
    if not (name.endswith(".sqlite") or name.endswith(".gz") or name.endswith(".db")):
        raise HTTPException(400, "Chỉ chấp nhận .sqlite / .db / .gz")
    suffix = ".gz" if name.endswith(".gz") else ".sqlite"
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    try:
        tmp.write(await file.read())
        tmp.close()
        meta = updater.import_file(tmp.name, store.kb_path(), expected_sha256=sha256)
        return {"ok": True, "version": meta.get("version"),
                "advisory_count": meta.get("advisory_count", 0)}
    except ValueError as e:
        raise HTTPException(400, str(e))
    finally:
        if os.path.exists(tmp.name):
            os.unlink(tmp.name)


@router.get("/cwe")
def cwe_knowledge(cwe: str = "", scan_type: str = ""):
    """Tri thức CWE (là gì/tác động/PoC/khắc phục) cho modal chi tiết lỗ hổng."""
    from scanner.knowledge import cwe_catalog
    info = cwe_catalog.lookup(cwe or None, scan_type or None)
    return {"found": bool(info), "info": info or {}}


@router.post("/enrich")
def enrich(q: EnrichQuery):
    """Tra cứu làm giàu 1 lỗ hổng/package (fix version, CVSS, CWE, refs)."""
    data = store.enrich(cve=q.cve, ecosystem=q.ecosystem, package=q.package)
    return {"found": bool(data), "enrichment": data}
