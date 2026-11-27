"""
API tích hợp SCM: kết nối GitHub/GitLab (cloud & onprem), chọn repo, scan tay,
và lịch quét định kỳ. Token mã hoá, không bao giờ trả raw.
"""
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request
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
async def scan_now(repo_id: str, background_tasks: BackgroundTasks, request: Request, db: Session = Depends(get_db)):
    r = db.query(ScmRepo).filter(ScmRepo.id == repo_id).first()
    if not r:
        raise HTTPException(404, "Repo không tồn tại")
    from api.services.scm_service import run_repo_scan
    uid = getattr(getattr(request.state, "user", None), "id", None)   # [AI PR-3] scan thủ công = job của người bấm
    background_tasks.add_task(run_repo_scan, repo_id, False, None, uid)
    return {"ok": True, "message": "Đã kích hoạt scan — xem tiến trình trong Projects/Scans."}


# ─────────────── Schedules ───────────────
class ScheduleUpsert(BaseModel):
    repo_id: str
    interval_minutes: int = 1440
    email_report: bool = True
    enabled: bool = True
    ai_credential_policy: str = "inherit"     # [AI PR-3] org | owner | local_only | inherit


def _sch_public(s: ScanSchedule) -> dict:
    return {"id": s.id, "repo_id": s.repo_id, "interval_minutes": s.interval_minutes,
            "enabled": s.enabled, "email_report": s.email_report,
            "ai_credential_policy": s.ai_credential_policy or "inherit",
            "last_run_at": s.last_run_at.isoformat() + "Z" if s.last_run_at else None,
            "last_status": s.last_status, "last_error": s.last_error,
            "next_run_at": s.next_run_at.isoformat() + "Z" if s.next_run_at else None}


def _check_sched_policy(v: str) -> None:
    from api.services.ai_policy import SCHEDULE_POLICIES
    if v not in SCHEDULE_POLICIES:
        raise HTTPException(422, "ai_credential_policy phải là org | owner | local_only | inherit")


@router.get("/schedules")
def list_schedules(db: Session = Depends(get_db)):
    return [_sch_public(s) for s in db.query(ScanSchedule).order_by(ScanSchedule.created_at).all()]


@router.post("/schedules", status_code=201)
def create_schedule(body: ScheduleUpsert, request: Request, db: Session = Depends(get_db)):
    if not db.query(ScmRepo).filter(ScmRepo.id == body.repo_id).first():
        raise HTTPException(400, "repo_id không hợp lệ")
    if body.interval_minutes < 5:
        raise HTTPException(422, "interval_minutes tối thiểu 5 phút")
    _check_sched_policy(body.ai_credential_policy)
    _uid = getattr(getattr(request.state, "user", None), "id", None)
    if body.ai_credential_policy == "owner" and not _uid:
        raise HTTPException(403, "Cần tài khoản thật để dùng khoá AI cá nhân")
    s = ScanSchedule(repo_id=body.repo_id, interval_minutes=body.interval_minutes,
                     email_report=body.email_report, enabled=body.enabled,
                     created_by_user_id=getattr(getattr(request.state, "user", None), "id", None),
                     ai_credential_policy=body.ai_credential_policy, ai_owner_consent=True)
    s.next_run_at = s.compute_next()
    db.add(s); db.commit(); db.refresh(s)
    return _sch_public(s)


def _is_owner_key_policy(policy: Optional[str]) -> bool:
    """Policy này (đã resolve 'inherit' theo policy toàn cục) sẽ chạy bằng key CÁ NHÂN của chủ lịch?"""
    from api.services import ai_policy
    p = policy or "inherit"
    return p == "owner" or (p == "inherit" and ai_policy.get_policy()["scheduled_jobs_credential"] == "owner")


def _effective_owner_policy(s: ScanSchedule) -> bool:
    return _is_owner_key_policy(s.ai_credential_policy)


@router.put("/schedules/{sch_id}")
def update_schedule(sch_id: str, body: ScheduleUpsert, request: Request, db: Session = Depends(get_db)):
    s = db.query(ScanSchedule).filter(ScanSchedule.id == sch_id).first()
    if not s:
        raise HTTPException(404, "Lịch không tồn tại")
    if body.interval_minutes < 5:
        raise HTTPException(422, "interval_minutes tối thiểu 5 phút")
    _check_sched_policy(body.ai_credential_policy)
    uid = getattr(getattr(request.state, "user", None), "id", None)
    is_creator = bool(uid) and s.created_by_user_id == uid
    # [AI PR-3 / verify B1] chỉ CHỦ lịch được đặt/giữ policy 'owner' (key cá nhân của họ) — kể cả ADMIN không thể đặt cho người khác
    if body.ai_credential_policy == "owner" and not is_creator:
        raise HTTPException(403, "Chỉ người tạo lịch mới được dùng khoá AI cá nhân cho lịch này")
    # [re-verify] kiểm policy MỚI sau resolve 'inherit': org/local_only → inherit khi policy toàn cục là 'owner' cũng là key cá nhân
    if _is_owner_key_policy(body.ai_credential_policy) and not is_creator:
        raise HTTPException(403, "Policy này sẽ chạy bằng khoá AI cá nhân của chủ lịch — chỉ chủ lịch được đặt")
    if _effective_owner_policy(s) and not is_creator:
        # lịch đang chạy bằng key cá nhân của người khác: chỉ được TẮT, hoặc chuyển sang org/local_only — không đổi tần suất/bật lại
        switching_away = body.ai_credential_policy in ("org", "local_only")
        only_disable = (not body.enabled) and body.interval_minutes == s.interval_minutes
        if not (switching_away or only_disable):
            raise HTTPException(403, "Lịch này chạy bằng khoá AI cá nhân của người khác — chỉ chủ lịch được sửa")
    s.ai_credential_policy = body.ai_credential_policy
    # đồng ý dùng key cá nhân: chỉ chủ lịch lưu mới "đồng ý"; người khác sửa → thu hồi (chạy lúc run-time sẽ không dùng key chủ)
    s.ai_owner_consent = bool(is_creator)
    s.interval_minutes = body.interval_minutes
    s.email_report = body.email_report
    s.enabled = body.enabled
    s.next_run_at = s.compute_next()
    db.commit()
    return _sch_public(s)


@router.delete("/schedules/{sch_id}", status_code=204)
def delete_schedule(sch_id: str, request: Request, db: Session = Depends(get_db)):
    from api.auth_models import UserRole
    s = db.query(ScanSchedule).filter(ScanSchedule.id == sch_id).first()
    if not s:
        raise HTTPException(404, "Lịch không tồn tại")
    u = getattr(request.state, "user", None)
    # Lịch là hạ tầng của tổ chức: chủ lịch hoặc ADMIN được xoá (lịch cũ không có chủ: như trước)
    if s.created_by_user_id and getattr(u, "id", None) != s.created_by_user_id and getattr(u, "role", None) != UserRole.ADMIN:
        raise HTTPException(403, "Chỉ chủ lịch hoặc ADMIN được xoá lịch")
    db.delete(s); db.commit()
