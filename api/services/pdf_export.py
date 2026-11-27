"""PDF export for the API (PDF PR-3): direct download, async jobs, safe headers, audit, rate limit.

Every report kind goes through the same path::

    authorize/preflight (404/403, finding count) -> build ReportDoc (adapters) -> engine.render -> bytes

Above ``VG_PDF_ASYNC_THRESHOLD`` findings (default 300) or with ``?async=1`` the request becomes a
background job. The job API takes ids only (never report content) and jobs are bound to the
requesting user. Error responses never contain temp paths or report content.
"""
from __future__ import annotations

import logging
import os
import queue
import re
import threading
import time
import unicodedata
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import quote

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse, Response

from scanner.pdf.errors import (
    PdfBusy,
    PdfCompileError,
    PdfEngineError,
    PdfInputTooLarge,
    PdfInvalidInput,
    PdfOutputTooLarge,
    PdfTimeout,
    PdfWorkerKilled,
)

_log = logging.getLogger("vulnguard.pdf")
_audit = logging.getLogger("vulnguard.audit")

KINDS = ("scan", "pentest", "webscan", "docreview")
ASYNC_THRESHOLD = int(os.environ.get("VG_PDF_ASYNC_THRESHOLD", "300"))
JOB_TTL_S = int(os.environ.get("VG_PDF_JOB_TTL_S", "3600"))
MAX_JOBS_PER_USER = 3
RATE_PER_MIN = int(os.environ.get("VG_PDF_RATE_PER_MIN", "10"))
RETRY_AFTER_S = "10"

_SAFE_HEADERS = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}

# ───────────────────────── filenames / headers ─────────────────────────
_VN_MAP = str.maketrans({"đ": "d", "Đ": "D"})
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏ -‮⁦-⁩﻿]")


def slugify(s: Any, max_len: int = 60) -> str:
    """NFKD -> ASCII ``[A-Za-z0-9_-]``, collapsed, at most ``max_len`` chars."""
    t = unicodedata.normalize("NFKD", str(s or "").translate(_VN_MAP))
    t = t.encode("ascii", "ignore").decode("ascii")
    t = re.sub(r"[^A-Za-z0-9_-]+", "-", t).strip("-_")
    return (t[:max_len].strip("-_")) or "report"


def _utf8_stem(s: Any, max_len: int = 80) -> str:
    """Display name for ``filename*``: keep Unicode letters, drop controls/quotes/path separators."""
    t = unicodedata.normalize("NFC", str(s or ""))
    t = _CTRL.sub("", t)
    t = re.sub(r'[\\/:*?"<>|;,%\']+', "_", t).strip(" ._")
    return t[:max_len] or "report"


def content_disposition(ascii_stem: str, utf8_stem: Optional[str] = None) -> str:
    """``attachment; filename="<ascii>.pdf"; filename*=UTF-8''<pct>.pdf`` (RFC 6266 / 5987).

    ``ascii_stem`` is re-slugged defensively, so no header value can carry CR/LF/quotes.
    """
    a = slugify(ascii_stem, 100)
    out = f'attachment; filename="{a}.pdf"'
    if utf8_stem:
        out += f"; filename*=UTF-8''{quote(_utf8_stem(utf8_stem) + '.pdf', safe='')}"
    return out


def _date() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d")


# ───────────────────────── errors ─────────────────────────
_ERR_MSG = {
    "pdf_compile_error": "Không tạo được PDF từ dữ liệu báo cáo này.",
    "pdf_timeout": "Tạo PDF quá thời gian cho phép. Hãy thử lại với ít phát hiện hơn hoặc dùng JSON/SARIF.",
    "pdf_worker_killed": "Tạo PDF vượt giới hạn bộ nhớ. Hãy lọc bớt phát hiện hoặc dùng JSON/SARIF.",
    "pdf_input_too_large": "Báo cáo quá lớn để xuất PDF. Hãy lọc bớt phát hiện hoặc dùng JSON/SARIF.",
    "pdf_output_too_large": "File PDF vượt giới hạn kích thước. Hãy lọc bớt phát hiện hoặc dùng JSON/SARIF.",
    "pdf_invalid_input": "Dữ liệu báo cáo không hợp lệ để xuất PDF.",
    "pdf_render_failed": "Tạo PDF thất bại. Vui lòng thử lại; nếu lỗi lặp lại hãy liên hệ quản trị viên.",
}
_ERR_STATUS = {"pdf_input_too_large": 413, "pdf_output_too_large": 413, "pdf_invalid_input": 422}


def error_payload(e: BaseException) -> Dict[str, str]:
    """Stable ``{code, message}`` for an engine error. Never echoes ``str(e)`` (may carry paths)."""
    code = getattr(e, "code", "pdf_render_failed")
    if code not in _ERR_MSG:
        code = "pdf_render_failed"
    return {"code": code, "message": _ERR_MSG[code]}


def busy_exception() -> HTTPException:
    return HTTPException(
        status_code=503,
        detail={"code": "pdf_busy", "message": "Máy chủ đang tạo nhiều PDF. Vui lòng thử lại sau vài giây."},
        headers={"Retry-After": RETRY_AFTER_S},
    )


def engine_http_error(e: BaseException, ref: str = "") -> HTTPException:
    if isinstance(e, PdfBusy):
        return busy_exception()
    p = error_payload(e)
    _log.error("pdf render failed code=%s ref=%s type=%s", p["code"], ref, type(e).__name__)
    return HTTPException(status_code=_ERR_STATUS.get(p["code"], 500), detail=p)


# ───────────────────────── rate limit + audit ─────────────────────────
_HITS: Dict[str, list] = {}
_HITS_LOCK = threading.Lock()


def rate_limit(user_key: str, per_min: Optional[int] = None) -> None:
    limit = RATE_PER_MIN if per_min is None else per_min
    now = time.monotonic()
    with _HITS_LOCK:
        hits = [t for t in _HITS.get(user_key, []) if now - t < 60]
        if len(hits) >= limit:
            _HITS[user_key] = hits
            raise HTTPException(
                status_code=429,
                detail={"code": "pdf_rate_limited", "message": "Xuất PDF quá nhanh, thử lại sau ít phút."},
                headers={"Retry-After": "30"},
            )
        hits.append(now)
        _HITS[user_key] = hits
        if len(_HITS) > 2000:
            for k in [k for k, v in _HITS.items() if not v or now - v[-1] > 60]:
                _HITS.pop(k, None)


def audit(user: Any, kind: str, rid: str, outcome: str, **extra: Any) -> None:
    """One structured line per export attempt (who, what, result). No report content."""
    who = getattr(user, "email", None) or getattr(user, "id", None) or "anon"
    kv = " ".join(f"{k}={v}" for k, v in extra.items())
    _audit.info("pdf_export user=%s kind=%s id=%s outcome=%s %s", slugify(who, 80) if "@" not in str(who) else who,
                kind, slugify(rid, 64), outcome, kv)


def user_key(user: Any) -> str:
    return str(getattr(user, "id", None) or getattr(user, "email", None) or "anon")


# ───────────────────────── authorisation / doc builders ─────────────────────────
@dataclass
class Prepared:
    count: int
    build: Callable[[], Tuple[dict, str, str, str]]  # () -> (doc, ascii_stem, utf8_stem, kind)


def _is_admin(user: Any) -> bool:
    from api.auth_models import UserRole
    return user is not None and getattr(user, "role", None) == UserRole.ADMIN


def _branding_org() -> str:
    try:
        from scanner import report_builder as rb
        return rb.load_branding().get("org_name") or "VulnGuard"
    except Exception:  # noqa: BLE001
        return "VulnGuard"


def prepare(kind: str, rid: str, db, user: Any, options: Dict[str, Any]) -> Prepared:
    """Same existence/permission checks as the matching HTML/JSON export, plus a finding count.

    Raises HTTPException (404/400/403). ``build()`` is only invoked after this succeeded.
    """
    from scanner.pdf import adapters

    if kind == "scan":
        from api.routes.report import load_report_data
        project, scan, vulns, grouped, counts = load_report_data(db, rid)
        branding = None
        try:
            from scanner import report_builder as rb
            branding = rb.load_branding()
        except Exception:  # noqa: BLE001
            pass

        def build_scan():
            doc = adapters.scan_doc(project, scan, grouped, counts, branding=branding)
            stem = f"VulnGuard_{slugify(project.name)}_Scan{int(getattr(scan, 'scan_number', 0) or 0)}_{_date()}"
            return doc, stem, f"VulnGuard_{project.name}_Scan{getattr(scan, 'scan_number', '')}_{_date()}", "scan"

        return Prepared(len(vulns), build_scan)

    if kind == "pentest":
        from api.pentest_models import Engagement, PentestFinding, PentestRun
        from scanner.pentest import report as rp
        run = db.query(PentestRun).filter(PentestRun.id == rid).first()
        if not run:
            raise HTTPException(status_code=404, detail="Run không tồn tại")
        eng = db.query(Engagement).filter(Engagement.id == run.engagement_id).first()
        if not eng or (eng.deleted_at is not None and not _is_admin(user)):
            raise HTTPException(status_code=404, detail="Engagement không tồn tại")
        include = options.get("include") or "confirmed"
        if include not in ("confirmed", "likely", "all"):
            raise HTTPException(status_code=422, detail="include không hợp lệ")
        cap = rp.MAX_FINDINGS["json"]
        lim = options.get("limit")
        lim = cap if lim is None else max(1, min(int(lim), cap))
        off = max(0, int(options.get("offset") or 0))
        n = db.query(PentestFinding).filter(PentestFinding.run_id == rid).count()

        def build_pentest():
            model = rp.build_report_model(db, rid, include=include, limit=lim, offset=off)
            doc = adapters.pentest_doc(model, org=_branding_org())
            stem = f"VulnGuard_Pentest_{slugify(eng.name)}_{str(rid)[:8]}_{_date()}"
            return doc, stem, f"VulnGuard_Pentest_{eng.name}_{str(rid)[:8]}_{_date()}", "pentest"

        return Prepared(min(n, lim), build_pentest)

    if kind == "webscan":
        from api.routes import webscans as ws
        from api.webscan_models import WebFinding, WebScan
        scan = db.query(WebScan).filter(WebScan.id == rid).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Web scan không tồn tại")
        rows = db.query(WebFinding).filter(WebFinding.scan_id == rid).all()

        def build_web():
            doc = adapters.webscan_doc(scan, [ws._finding_out(f) for f in rows], org=_branding_org())
            num = getattr(scan, "scan_number", None) or str(rid)[:8]
            stem = f"VulnGuard_WebScan_{slugify(num)}_{_date()}"
            return doc, stem, stem, "webscan"

        return Prepared(len(rows), build_web)

    if kind == "docreview":
        from api.docreview_models import Document, DocumentVersion, ReviewFinding
        from api.routes.docreview import _compute_summary
        version = db.query(DocumentVersion).filter(DocumentVersion.id == rid).first()
        if not version:
            raise HTTPException(status_code=404, detail="Version không tồn tại")
        document = db.query(Document).filter(Document.id == version.document_id).first()
        findings = db.query(ReviewFinding).filter(ReviewFinding.version_id == rid).all()

        def build_dr():
            doc = adapters.docreview_doc(document, version, findings, _compute_summary(findings), org=_branding_org())
            name = getattr(document, "name", "document")
            vn = getattr(version, "version_number", "")
            return (doc, f"VulnGuard_DocReview_{slugify(name)}_v{slugify(vn)}_{_date()}",
                    f"VulnGuard_DocReview_{name}_v{vn}_{_date()}", "docreview")

        return Prepared(len(findings), build_dr)

    raise HTTPException(status_code=404, detail="Loại báo cáo không hợp lệ")


def render_pdf(kind: str, prepared: Prepared) -> Tuple[bytes, str, str]:
    """Build + render. Returns (pdf_bytes, ascii_stem, utf8_stem). Raises PdfEngineError."""
    from scanner.pdf import engine
    doc, ascii_stem, utf8_stem, ekind = prepared.build()
    return engine.render(ekind, doc), ascii_stem, utf8_stem


# ───────────────────────── async jobs ─────────────────────────
@dataclass
class Job:
    id: str
    user: str
    kind: str
    rid: str
    options: Dict[str, Any]
    status: str = "queued"          # queued | running | done | failed
    pages: Optional[int] = None
    error: Optional[Dict[str, str]] = None
    path: Optional[Path] = None
    ascii_stem: str = "report"
    utf8_stem: str = "report"
    created: float = field(default_factory=time.time)
    finished: Optional[float] = None


_JOBS: Dict[str, Job] = {}
_JOBS_LOCK = threading.Lock()
_Q: "queue.Queue[str]" = queue.Queue()
_WORKER: Optional[threading.Thread] = None


def jobs_dir() -> Path:
    from api.config import settings
    d = Path(settings.storage_dir) / "reports" / "pdf-jobs"
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    return d


def _sweep(now: Optional[float] = None) -> None:
    now = now or time.time()
    with _JOBS_LOCK:
        old = [j for j in _JOBS.values() if j.status in ("done", "failed") and now - (j.finished or j.created) > JOB_TTL_S]
        for j in old:
            _JOBS.pop(j.id, None)
    for j in old:
        if j.path:
            try:
                j.path.unlink()
            except OSError:
                pass


def _ensure_worker() -> None:
    global _WORKER
    with _JOBS_LOCK:
        if _WORKER is None or not _WORKER.is_alive():
            _WORKER = threading.Thread(target=_work_loop, name="pdf-jobs", daemon=True)
            _WORKER.start()


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _run_job(job: Job) -> None:
    from api.database import SessionLocal
    from scanner.pdf import engine
    job.status = "running"
    db = SessionLocal()
    try:
        # Re-run the checks: the object may have changed/vanished since the request was accepted.
        pre = prepare(job.kind, job.rid, db, _JobUser(job), job.options)
        last: Optional[BaseException] = None
        for attempt in range(6):  # all render slots busy -> wait our turn instead of failing
            try:
                data, job.ascii_stem, job.utf8_stem = render_pdf(job.kind, pre)
                last = None
                break
            except PdfBusy as e:
                last = e
                time.sleep(2)
        if last:
            raise last
        job.pages = engine.check_pdf(data)
        job.path = jobs_dir() / f"{job.id}.pdf"
        _write_private(job.path, data)
        job.status = "done"
        audit(_JobUser(job), job.kind, job.rid, "ok", job=job.id, pages=job.pages, bytes=len(data), mode="async")
    except HTTPException as e:
        d = e.detail
        job.error = d if isinstance(d, dict) else {"code": "pdf_not_available", "message": str(d)}
        job.status = "failed"
        audit(_JobUser(job), job.kind, job.rid, "denied", job=job.id, status=e.status_code)
    except PdfEngineError as e:
        job.error = error_payload(e) if not isinstance(e, PdfBusy) else busy_exception().detail
        job.status = "failed"
        _log.error("pdf job failed job=%s code=%s", job.id, job.error["code"])
        audit(_JobUser(job), job.kind, job.rid, "error", job=job.id, code=job.error["code"])
    except Exception as e:  # noqa: BLE001
        _log.error("pdf job crashed job=%s type=%s", job.id, type(e).__name__)
        job.error = error_payload(e)
        job.status = "failed"
        audit(_JobUser(job), job.kind, job.rid, "error", job=job.id, code=job.error["code"])
    finally:
        job.finished = time.time()
        db.close()


class _JobUser:
    """Minimal stand-in for the requesting user inside the worker thread (role is re-resolved)."""

    def __init__(self, job: Job):
        self.id = job.user
        self.email = job.options.get("_email")
        from api.auth_models import UserRole
        role = job.options.get("_role")
        self.role = UserRole(role) if role else None


def _work_loop() -> None:
    while True:
        jid = _Q.get()
        with _JOBS_LOCK:
            job = _JOBS.get(jid)
        if job is None:
            continue
        try:
            _run_job(job)
        except Exception:  # noqa: BLE001 - never let the worker die
            job.status, job.error = "failed", error_payload(RuntimeError())
        _sweep()


def create_job(kind: str, rid: str, user: Any, options: Dict[str, Any]) -> Job:
    _sweep()
    uk = user_key(user)
    with _JOBS_LOCK:
        active = sum(1 for j in _JOBS.values() if j.user == uk and j.status in ("queued", "running"))
        if active >= MAX_JOBS_PER_USER:
            raise HTTPException(
                status_code=429,
                detail={"code": "pdf_too_many_jobs", "message": "Bạn đang có quá nhiều PDF đang tạo, hãy chờ chúng hoàn tất."},
                headers={"Retry-After": "15"},
            )
        opts = {k: v for k, v in (options or {}).items() if k in ("include", "limit", "offset")}
        role = getattr(getattr(user, "role", None), "value", None)
        opts["_email"], opts["_role"] = getattr(user, "email", None), role
        job = Job(id=uuid.uuid4().hex, user=uk, kind=kind, rid=rid, options=opts)
        _JOBS[job.id] = job
    _ensure_worker()
    _Q.put(job.id)
    return job


def get_job(job_id: str, user: Any) -> Job:
    """Jobs are private to the requesting user; anyone else gets 404 (no existence oracle)."""
    _sweep()
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
    if job is None or job.user != user_key(user):
        raise HTTPException(status_code=404, detail="Job không tồn tại hoặc đã hết hạn")
    return job


def job_public(job: Job) -> Dict[str, Any]:
    out: Dict[str, Any] = {"job_id": job.id, "status": job.status, "kind": job.kind}
    if job.pages is not None:
        out["pages"] = job.pages
    if job.error:
        out["error"] = job.error
    if job.status == "done":
        out["file_url"] = f"/api/reports/pdf-jobs/{job.id}/file"
    return out


def job_file_response(job: Job) -> Response:
    if job.status != "done" or not job.path or not job.path.is_file():
        raise HTTPException(status_code=409, detail={"code": "pdf_not_ready", "message": "PDF chưa sẵn sàng."})
    return Response(
        content=job.path.read_bytes(), media_type="application/pdf",
        headers={**_SAFE_HEADERS, "Content-Disposition": content_disposition(job.ascii_stem, job.utf8_stem)},
    )


# ───────────────────────── entry point used by the routes ─────────────────────────
def _current_user(request: Request):
    from api.routes.auth import current_user
    return current_user(request)


def pdf_response(kind: str, rid: str, request: Request, db, options: Optional[Dict[str, Any]] = None,
                 *, want_async: bool = False) -> Response:
    """Authorise, rate-limit, then return the PDF (200) or a job handle (202)."""
    options = options or {}
    user = _current_user(request)
    rate_limit(user_key(user))
    try:
        pre = prepare(kind, rid, db, user, options)
    except HTTPException as e:
        audit(user, kind, rid, "denied", status=e.status_code)
        raise
    if want_async or pre.count > ASYNC_THRESHOLD:
        job = create_job(kind, rid, user, options)
        audit(user, kind, rid, "queued", job=job.id, findings=pre.count)
        return JSONResponse(job_public(job), status_code=202, headers={
            **_SAFE_HEADERS, "Location": f"/api/reports/pdf-jobs/{job.id}"})
    try:
        data, a, u = render_pdf(kind, pre)
    except PdfBusy:
        audit(user, kind, rid, "busy")
        raise busy_exception()
    except PdfEngineError as e:
        audit(user, kind, rid, "error", code=error_payload(e)["code"])
        raise engine_http_error(e, ref=slugify(rid, 16))
    audit(user, kind, rid, "ok", bytes=len(data), findings=pre.count, mode="sync")
    return Response(content=data, media_type="application/pdf",
                    headers={**_SAFE_HEADERS, "Content-Disposition": content_disposition(a, u)})
