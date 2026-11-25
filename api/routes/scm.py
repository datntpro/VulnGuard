"""
API tích hợp SCM: kết nối GitHub/GitLab (cloud & onprem), chọn repo, scan tay,
và lịch quét định kỳ. Token mã hoá, không bao giờ trả raw.
"""
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.database import get_db
from api.security import encrypt_secret, decrypt_secret, mask_secret
from api.scm_models import ScmConnection, ScmRepo, ScanSchedule, ScmProvider
from scanner.scm import providers

router = APIRouter(prefix="/api/scm", tags=["scm"])


# ─────────────── Connections ───────────────
class ConnCreate(BaseModel):
    name: str
    provider: ScmProvider
    base_url: Optional[str] = ""
    token: str


def _conn_public(c: ScmConnection) -> dict:
    tok = decrypt_secret(c.token_enc)
    return {"id": c.id, "name": c.name, "provider": c.provider.value,
            "base_url": c.base_url or "", "token_set": bool(tok),
            "token_hint": mask_secret(tok) if tok else "",
            "cloud": not bool(c.base_url)}


@router.get("/connections")
def list_connections(db: Session = Depends(get_db)):
    return [_conn_public(c) for c in db.query(ScmConnection).order_by(ScmConnection.created_at).all()]


@router.post("/connections", status_code=201)
def create_connection(body: ConnCreate, db: Session = Depends(get_db)):
    try:
        providers.check_base_url(body.base_url)
    except ValueError as e:
        raise HTTPException(400, str(e))
    c = ScmConnection(name=body.name.strip(), provider=body.provider,
                      base_url=(body.base_url or "").strip().rstrip("/") or None,
                      token_enc=encrypt_secret(body.token.strip()) if body.token else None)
    db.add(c); db.commit(); db.refresh(c)
    return _conn_public(c)


@router.delete("/connections/{conn_id}", status_code=204)
def delete_connection(conn_id: str, db: Session = Depends(get_db)):
    c = db.query(ScmConnection).filter(ScmConnection.id == conn_id).first()
    if not c:
        raise HTTPException(404, "Kết nối không tồn tại")
    # xoá repo + schedule liên quan
    repos = db.query(ScmRepo).filter(ScmRepo.connection_id == conn_id).all()
    for r in repos:
        db.query(ScanSchedule).filter(ScanSchedule.repo_id == r.id).delete()
        db.delete(r)
    db.delete(c); db.commit()


@router.post("/connections/{conn_id}/test")
async def test_connection(conn_id: str, db: Session = Depends(get_db)):
    c = db.query(ScmConnection).filter(ScmConnection.id == conn_id).first()
    if not c:
        raise HTTPException(404, "Kết nối không tồn tại")
    token = decrypt_secret(c.token_enc) or ""
    try:
        info = await providers.validate(c.provider.value, c.base_url, token)
        return {"ok": True, **info}
    except Exception as e:
        raise HTTPException(502, f"Token/kết nối không hợp lệ: {str(e)[:200]}")


@router.get("/connections/{conn_id}/remote-repos")
async def remote_repos(conn_id: str, db: Session = Depends(get_db)):
    c = db.query(ScmConnection).filter(ScmConnection.id == conn_id).first()
    if not c:
        raise HTTPException(404, "Kết nối không tồn tại")
    token = decrypt_secret(c.token_enc) or ""
    try:
        return await providers.list_repos(c.provider.value, c.base_url, token)
    except Exception as e:
        raise HTTPException(502, f"Không lấy được danh sách repo: {str(e)[:200]}")


# ─────────────── Repos (targets) ───────────────
class RepoCreate(BaseModel):
    connection_id: str
    repo_full_name: str
    default_branch: Optional[str] = "main"
    owner_email: Optional[str] = ""
    scan_types: List[str] = []
    run_ai: bool = False


def _repo_public(r: ScmRepo) -> dict:
    return {"id": r.id, "connection_id": r.connection_id, "repo_full_name": r.repo_full_name,
            "default_branch": r.default_branch, "owner_email": r.owner_email or "",
            "project_id": r.project_id, "scan_types": r.scan_types or [],
            "run_ai": r.run_ai, "enabled": r.enabled}


@router.get("/repos")
def list_repos_cfg(db: Session = Depends(get_db)):
    return [_repo_public(r) for r in db.query(ScmRepo).order_by(ScmRepo.created_at).all()]


@router.post("/repos", status_code=201)
def add_repo(body: RepoCreate, db: Session = Depends(get_db)):
    if not db.query(ScmConnection).filter(ScmConnection.id == body.connection_id).first():
        raise HTTPException(400, "connection_id không hợp lệ")
    r = ScmRepo(connection_id=body.connection_id, repo_full_name=body.repo_full_name.strip("/"),
                default_branch=(body.default_branch or "main").strip(),
                owner_email=(body.owner_email or "").strip() or None,
                scan_types=body.scan_types or [], run_ai=body.run_ai, enabled=True)
    db.add(r); db.commit(); db.refresh(r)
    return _repo_public(r)


@router.delete("/repos/{repo_id}", status_code=204)
def delete_repo(repo_id: str, db: Session = Depends(get_db)):
    r = db.query(ScmRepo).filter(ScmRepo.id == repo_id).first()
    if not r:
        raise HTTPException(404, "Repo không tồn tại")
    db.query(ScanSchedule).filter(ScanSchedule.repo_id == repo_id).delete()
    db.delete(r); db.commit()


@router.post("/repos/{repo_id}/scan-now")
async def scan_now(repo_id: str, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    r = db.query(ScmRepo).filter(ScmRepo.id == repo_id).first()
    if not r:
        raise HTTPException(404, "Repo không tồn tại")
    from api.services.scm_service import run_repo_scan
    background_tasks.add_task(run_repo_scan, repo_id, False, None)
    return {"ok": True, "message": "Đã kích hoạt scan — xem tiến trình trong Projects/Scans."}


# ─────────────── Schedules ───────────────
class ScheduleUpsert(BaseModel):
    repo_id: str
    interval_minutes: int = 1440
    email_report: bool = True
    enabled: bool = True


def _sch_public(s: ScanSchedule) -> dict:
    return {"id": s.id, "repo_id": s.repo_id, "interval_minutes": s.interval_minutes,
            "enabled": s.enabled, "email_report": s.email_report,
            "last_run_at": s.last_run_at.isoformat() + "Z" if s.last_run_at else None,
            "last_status": s.last_status, "last_error": s.last_error,
            "next_run_at": s.next_run_at.isoformat() + "Z" if s.next_run_at else None}


@router.get("/schedules")
def list_schedules(db: Session = Depends(get_db)):
    return [_sch_public(s) for s in db.query(ScanSchedule).order_by(ScanSchedule.created_at).all()]


@router.post("/schedules", status_code=201)
def create_schedule(body: ScheduleUpsert, db: Session = Depends(get_db)):
    if not db.query(ScmRepo).filter(ScmRepo.id == body.repo_id).first():
        raise HTTPException(400, "repo_id không hợp lệ")
    if body.interval_minutes < 5:
        raise HTTPException(422, "interval_minutes tối thiểu 5 phút")
    s = ScanSchedule(repo_id=body.repo_id, interval_minutes=body.interval_minutes,
                     email_report=body.email_report, enabled=body.enabled)
    s.next_run_at = s.compute_next()
    db.add(s); db.commit(); db.refresh(s)
    return _sch_public(s)


@router.put("/schedules/{sch_id}")
def update_schedule(sch_id: str, body: ScheduleUpsert, db: Session = Depends(get_db)):
    s = db.query(ScanSchedule).filter(ScanSchedule.id == sch_id).first()
    if not s:
        raise HTTPException(404, "Lịch không tồn tại")
    if body.interval_minutes < 5:
        raise HTTPException(422, "interval_minutes tối thiểu 5 phút")
    s.interval_minutes = body.interval_minutes
    s.email_report = body.email_report
    s.enabled = body.enabled
    s.next_run_at = s.compute_next()
    db.commit()
    return _sch_public(s)


@router.delete("/schedules/{sch_id}", status_code=204)
def delete_schedule(sch_id: str, db: Session = Depends(get_db)):
    s = db.query(ScanSchedule).filter(ScanSchedule.id == sch_id).first()
    if not s:
        raise HTTPException(404, "Lịch không tồn tại")
    db.delete(s); db.commit()
