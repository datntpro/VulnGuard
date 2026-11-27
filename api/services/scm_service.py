"""
Clone repo từ SCM rồi chạy scan (tái dùng orchestrator qua _run_scan_background),
sau đó tuỳ chọn gửi báo cáo cho owner.

Dùng cho: scan tay ("scan now") và scan theo lịch (scheduler).
"""
import asyncio
import logging
import os
import shutil
import subprocess  # nosec B404 — git clone có kiểm soát tham số
import tempfile
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from api.config import settings
from api.database import SessionLocal
from api.models import Project, Scan, ScanStatus
from api.security import decrypt_secret
from api.scm_models import ScmConnection, ScmRepo
from scanner.scm import providers
from scanner.scanners.base import scrubbed_env

logger = logging.getLogger(__name__)

DEFAULT_SCAN_TYPES = ["SAST", "SCA", "SECRETS", "IAC"]


def _clone(conn: ScmConnection, repo: ScmRepo, dest: str) -> None:
    """git clone shallow nhánh mặc định. Token được redact trong mọi log/lỗi."""
    providers.check_base_url(conn.base_url)   # L-1: kiểm tra lại lúc dùng (thu hẹp DNS rebinding)
    token = decrypt_secret(conn.token_enc) or ""
    url = providers.clone_url(conn.provider.value, conn.base_url, token, repo.repo_full_name)
    branch = (repo.default_branch or "main").strip()
    # C2: không theo redirect (SSRF qua 30x từ host SCM), chỉ cho giao thức https (http khi SCM_ALLOW_HTTP)
    hard = ["git", "-c", "http.followRedirects=false", "-c", "protocol.allow=never",
            "-c", "protocol.https.allow=always"]
    if settings.scm_allow_http:
        hard += ["-c", "protocol.http.allow=always"]
    cmd = hard + ["clone", "--depth", "1", "--single-branch", "--branch", branch, url, dest]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=600, env=scrubbed_env())  # nosec B603
    except subprocess.CalledProcessError as e:
        # thử lại không chỉ định branch (repo có thể dùng master/khác)
        err = providers.redact((e.stderr or e.stdout or ""), token)
        logger.warning(f"[scm] clone branch '{branch}' lỗi, thử nhánh mặc định: {err[-200:]}")
        cmd2 = hard + ["clone", "--depth", "1", url, dest]
        try:
            subprocess.run(cmd2, check=True, capture_output=True, text=True, timeout=600, env=scrubbed_env())  # nosec B603
        except subprocess.CalledProcessError as e2:
            raise RuntimeError("Clone thất bại: " + providers.redact((e2.stderr or e2.stdout or "")[-300:], token))


def _ensure_project(db: Session, repo: ScmRepo) -> Project:
    if repo.project_id:
        p = db.query(Project).filter(Project.id == repo.project_id).first()
        if p:
            return p
    p = Project(name=repo.repo_full_name)
    db.add(p)
    db.commit()
    db.refresh(p)
    repo.project_id = p.id
    db.commit()
    return p


async def run_repo_scan(repo_id: str, email_report: bool = False,
                        schedule_id: Optional[str] = None, user_id: Optional[str] = None) -> Optional[str]:
    """Pipeline đầy đủ: clone → tạo scan → chạy → (tuỳ chọn) gửi report. Trả scan_id."""
    from api.config import settings as _settings
    from api.routes.scans import _run_scan_background

    db = SessionLocal()
    workdir = None
    try:
        repo = db.query(ScmRepo).filter(ScmRepo.id == repo_id).first()
        if not repo:
            return None
        conn = db.query(ScmConnection).filter(ScmConnection.id == repo.connection_id).first()
        if not conn:
            raise RuntimeError("Kết nối SCM không tồn tại")

        project = _ensure_project(db, repo)

        # Clone vào workspace tạm
        base_ws = os.environ.get("SCAN_WORKSPACE", tempfile.gettempdir())
        os.makedirs(base_ws, exist_ok=True)
        workdir = tempfile.mkdtemp(prefix="vgscm_", dir=base_ws)
        clone_dest = os.path.join(workdir, "repo")
        _clone(conn, repo, clone_dest)

        scan_types = list(repo.scan_types or []) or DEFAULT_SCAN_TYPES

        # Tạo scan (rolling, giữ lịch sử tối đa max_scans_per_project)
        scans = db.query(Scan).filter(Scan.project_id == project.id).order_by(Scan.scan_number).all()
        if len(scans) >= _settings.max_scans_per_project:
            db.delete(scans[0]); db.commit()
            scans = scans[1:]
        next_number = (scans[-1].scan_number + 1) if scans else 1
        # [AI PR-3] credential AI: người bấm "scan now" → job của họ (ghim default); lịch/hệ thống → policy lịch
        from api.scm_models import ScanSchedule as _Sch
        from api.services.llm_resolver import pin_for_user, schedule_pin
        pin, sp, so = None, None, None
        if user_id:
            pin = pin_for_user(user_id)
        else:
            sch = db.query(_Sch).filter(_Sch.id == schedule_id).first() if schedule_id else None
            sp, so, pin = schedule_pin(getattr(sch, "created_by_user_id", None), getattr(sch, "ai_credential_policy", None),
                                     getattr(sch, "ai_owner_consent", True))
        scan = Scan(project_id=project.id, scan_number=next_number, scan_path=clone_dest,
                    scan_types=scan_types, status=ScanStatus.PENDING, triggered_by_user_id=user_id,
                    ai_credential_id=pin, ai_sched_policy=sp, ai_sched_owner_id=so)
        db.add(scan); db.commit(); db.refresh(scan)
        scan_id = scan.id

        # Chạy scan (đồng bộ trong task này)
        await _run_scan_background(scan_id, clone_dest, scan_types, repo.run_ai)

        # Gửi report
        if email_report and repo.owner_email:
            try:
                from api.services.mailer import send_scan_report
                await asyncio.to_thread(send_scan_report, db, scan_id, repo.owner_email, project.name)  # PDF render blocks
            except Exception as e:
                logger.warning(f"[scm] gửi report lỗi: {e}")

        if schedule_id:
            _mark_schedule(db, schedule_id, "OK", None)
        return scan_id
    except Exception as e:
        logger.exception("[scm] run_repo_scan lỗi")
        if schedule_id:
            _mark_schedule(db, schedule_id, "ERROR", str(e)[:1000])
        return None
    finally:
        db.close()
        if workdir and os.path.isdir(workdir):
            shutil.rmtree(workdir, ignore_errors=True)


def _mark_schedule(db: Session, schedule_id: str, status: str, error: Optional[str]):
    from api.scm_models import ScanSchedule
    sch = db.query(ScanSchedule).filter(ScanSchedule.id == schedule_id).first()
    if sch:
        sch.last_run_at = datetime.utcnow()
        sch.last_status = status
        sch.last_error = error
        sch.next_run_at = sch.compute_next()
        db.commit()
