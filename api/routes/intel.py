"""Threat intel (EPSS/KEV) feed status + refresh."""
from fastapi import APIRouter, Depends

from api.routes.auth import require_admin
from scanner.intel.feeds import feed_status, refresh_epss, refresh_kev

router = APIRouter(prefix="/api/intel", tags=["intel"])


@router.get("/status")
def status():
    return feed_status()


@router.post("/refresh")
def refresh(_=Depends(require_admin)):
    ok_e, msg_e = refresh_epss()
    ok_k, msg_k = refresh_kev()
    return {"epss": {"ok": ok_e, "message": msg_e}, "kev": {"ok": ok_k, "message": msg_k},
            "status": feed_status()}
