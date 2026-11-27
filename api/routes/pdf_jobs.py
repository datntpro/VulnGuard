"""PDF PR-3: async PDF jobs. The API takes ids + options only, never report content."""
from typing import Any, Dict, Literal

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.database import get_db
from api.services import pdf_export as px

router = APIRouter(prefix="/api/reports", tags=["report"])


class PdfJobIn(BaseModel):
    kind: Literal["scan", "pentest", "webscan", "docreview"]
    id: str = Field(min_length=1, max_length=64)
    options: Dict[str, Any] = Field(default_factory=dict)


@router.post("/pdf-jobs", status_code=202)
def create_pdf_job(body: PdfJobIn, request: Request, db: Session = Depends(get_db)):
    user = px._current_user(request)
    px.rate_limit(px.user_key(user))
    try:
        pre = px.prepare(body.kind, body.id, db, user, body.options)   # same 404/403 checks as the direct export
    except Exception as e:
        px.audit(user, body.kind, body.id, "denied", status=getattr(e, "status_code", 500))
        raise
    job = px.create_job(body.kind, body.id, user, body.options)
    px.audit(user, body.kind, body.id, "queued", job=job.id, findings=pre.count)
    return JSONResponse(px.job_public(job), status_code=202,
                        headers={**px._SAFE_HEADERS, "Location": f"/api/reports/pdf-jobs/{job.id}"})


@router.get("/pdf-jobs/{job_id}")
def pdf_job_status(job_id: str, request: Request):
    return JSONResponse(px.job_public(px.get_job(job_id, px._current_user(request))), headers=px._SAFE_HEADERS)


@router.get("/pdf-jobs/{job_id}/file")
def pdf_job_file(job_id: str, request: Request):
    return px.job_file_response(px.get_job(job_id, px._current_user(request)))
