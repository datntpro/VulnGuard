"""
Scheduler nhẹ (asyncio) cho scan theo lịch — kiểm tra mỗi 60s các ScanSchedule
đến hạn rồi chạy run_repo_scan. Không cần dependency ngoài (APScheduler…).

Chống chạy trùng: khi nhận lịch, set next_run_at ngay trước khi chạy.
Bật/tắt bằng env VULNGUARD_SCHEDULER (mặc định bật ở production).
"""
import asyncio
import logging
import os
from datetime import datetime

logger = logging.getLogger(__name__)

_task = None
_TICK_SECONDS = 60
_last_kb_check = None   # datetime lần cuối kiểm tra KB


def enabled() -> bool:
    v = os.environ.get("VULNGUARD_SCHEDULER", "").lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    # mặc định: bật khi APP_ENV=production
    return (os.environ.get("APP_ENV", "production").lower() == "production")


async def _tick():
    from api.database import SessionLocal
    from api.scm_models import ScanSchedule, ScmRepo
    from api.services.scm_service import run_repo_scan

    db = SessionLocal()
    due_ids = []
    try:
        now = datetime.utcnow()
        schedules = db.query(ScanSchedule).filter(ScanSchedule.enabled.is_(True)).all()
        for sch in schedules:
            if sch.last_status == "RUNNING":
                continue
            if sch.next_run_at is not None and sch.next_run_at > now:
                continue
            repo = db.query(ScmRepo).filter(ScmRepo.id == sch.repo_id).first()
            if not repo or not repo.enabled:
                continue
            # đánh dấu chạy ngay để tick sau không nhặt lại
            sch.last_status = "RUNNING"
            sch.next_run_at = sch.compute_next(now)
            db.commit()
            due_ids.append((sch.id, repo.id, bool(sch.email_report)))
    finally:
        db.close()

    for sch_id, repo_id, email_report in due_ids:
        logger.info(f"[scheduler] chạy lịch {sch_id} cho repo {repo_id}")
        asyncio.create_task(run_repo_scan(repo_id, email_report=email_report, schedule_id=sch_id))


async def _kb_tick():
    """Kiểm tra + tải bản KB mới theo chu kỳ kb_update_interval_hours."""
    global _last_kb_check
    from datetime import timedelta

    from api.config import settings
    if not (settings.kb_auto_update and settings.kb_manifest_url):
        return
    now = datetime.utcnow()
    interval = timedelta(hours=max(1, settings.kb_update_interval_hours))
    if _last_kb_check is not None and (now - _last_kb_check) < interval:
        return
    _last_kb_check = now
    from scanner.knowledge import updater
    res = await asyncio.to_thread(updater.check_and_update)
    if res.get("updated"):
        logger.info("[scheduler] KB cập nhật %s → %s", res.get("from"), res.get("to"))
    else:
        logger.debug("[scheduler] KB: %s", res.get("reason"))


async def _loop():
    logger.info("[scheduler] khởi động — kiểm tra lịch mỗi %ss", _TICK_SECONDS)
    while True:
        try:
            await _tick()
        except Exception as e:
            logger.warning(f"[scheduler] tick lỗi: {e}")
        try:
            await _kb_tick()
        except Exception as e:
            logger.warning(f"[scheduler] KB tick lỗi: {e}")
        await asyncio.sleep(_TICK_SECONDS)


def start():
    global _task
    if not enabled():
        logger.info("[scheduler] tắt (VULNGUARD_SCHEDULER)")
        return
    if _task is None:
        _task = asyncio.create_task(_loop())
