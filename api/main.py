from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
import os

from api.config import settings as app_settings
from api.database import Base, engine
from api.routes import projects, scans, vulns, compare, ollama, settings, report, domains, coworker, coworker_agent, docreview, file_assistant
from api.routes import ai_credentials as ai_credentials_routes, ai_settings
from api.services.llm_resolver import RouteRefused
from api.routes import auth, ai, webscans, pentest, assets, intel, connectors, dashboard, scm, knowledge
# domain_models / docreview_models phải được import trước create_all() để SQLAlchemy
# đăng ký các bảng tương ứng (module riêng, tách khỏi models.py)
from api import domain_models  # noqa: F401
from api import docreview_models  # noqa: F401
from api import file_assistant_models  # noqa: F401
from api import agent_conversation_models  # noqa: F401
from api import auth_models  # noqa: F401
from api import webscan_models  # noqa: F401
from api import pentest_models  # noqa: F401
from api import asset_models  # noqa: F401
from api import connector_models  # noqa: F401
from api import scm_models  # noqa: F401
from api import ai_cred_models  # noqa: F401  [AI PR-2]

# Tạo DB tables
Base.metadata.create_all(bind=engine)

# Startup migration: thêm các columns mới vào existing DB (SQLite safe)
def _run_migrations():
    from sqlalchemy import text
    with engine.connect() as conn:
        # Thêm scanner_progress nếu chưa có
        try:
            conn.execute(text("ALTER TABLE scans ADD COLUMN scanner_progress TEXT"))
            conn.commit()
        except Exception:
            pass  # Column đã tồn tại — bình thường

        # Thêm ai_false_positive_reason nếu chưa có
        try:
            conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN ai_false_positive_reason TEXT"))
            conn.commit()
        except Exception:
            pass  # Column đã tồn tại — bình thường

        # Thêm các cột AI analysis cho domain_crawls nếu chưa có (feature mới)
        for ddl in (
            "ALTER TABLE domain_crawls ADD COLUMN ai_status TEXT DEFAULT 'NOT_REQUESTED'",
            "ALTER TABLE domain_crawls ADD COLUMN ai_summary TEXT",
            "ALTER TABLE domain_crawls ADD COLUMN ai_sensitive_endpoints TEXT",
            "ALTER TABLE domain_crawls ADD COLUMN ai_waf_suggestions TEXT",
            "ALTER TABLE domain_crawls ADD COLUMN ai_error TEXT",
            "ALTER TABLE vulnerabilities ADD COLUMN ai_provider VARCHAR(120)",
            "ALTER TABLE pentest_findings ADD COLUMN evidence_traffic_id VARCHAR",
            "ALTER TABLE pentest_runs ADD COLUMN todolist TEXT",
            "ALTER TABLE pentest_engagements ADD COLUMN max_parallel INTEGER DEFAULT 3",
            # GĐ1 triage (Checkmarx-style) — cột mới trên vulnerabilities
            "ALTER TABLE vulnerabilities ADD COLUMN triage_note TEXT",
            "ALTER TABLE vulnerabilities ADD COLUMN triage_by VARCHAR(200)",
            "ALTER TABLE vulnerabilities ADD COLUMN triage_at DATETIME",
            "ALTER TABLE vulnerabilities ADD COLUMN first_seen_at DATETIME",
            "ALTER TABLE vulnerabilities ADD COLUMN first_seen_scan_id VARCHAR",
            # P0 (an toàn/trung thực)
            "ALTER TABLE users ADD COLUMN must_change_password BOOLEAN DEFAULT 0",  # P0.3
            "ALTER TABLE domains ADD COLUMN ownership_verified BOOLEAN DEFAULT 0",  # P0.4
            "ALTER TABLE domains ADD COLUMN ownership_token VARCHAR(80)",
            "ALTER TABLE domains ADD COLUMN ownership_method VARCHAR(20)",
            "ALTER TABLE domains ADD COLUMN ownership_verified_at DATETIME",
            "ALTER TABLE pentest_runs ADD COLUMN scope_snapshot TEXT",  # 1.7 audit
            "ALTER TABLE scans ADD COLUMN triggered_by_user_id VARCHAR(64)",  # [AI PR-1]
            "ALTER TABLE agent_conversations ADD COLUMN owner_user_id VARCHAR(64)",  # [AI PR-1]
            "ALTER TABLE agent_conversations ADD COLUMN route_kind VARCHAR(8)",  # [AI PR-3b]
            "ALTER TABLE agent_conversations ADD COLUMN provider VARCHAR(32)",
            "ALTER TABLE agent_conversations ADD COLUMN model VARCHAR(120)",
            "ALTER TABLE agent_conversations ADD COLUMN ai_credential_id VARCHAR(36)",
            "ALTER TABLE agent_conversations ADD COLUMN transcript JSON",
            "ALTER TABLE agent_conversations ADD COLUMN cloud_state JSON",
            "ALTER TABLE scans ADD COLUMN ai_credential_id VARCHAR(36)",  # [AI PR-3]
            "ALTER TABLE scans ADD COLUMN ai_sched_policy VARCHAR(16)",
            "ALTER TABLE scans ADD COLUMN ai_sched_owner_id VARCHAR(64)",
            "ALTER TABLE pentest_runs ADD COLUMN ai_credential_id VARCHAR(36)",
            "ALTER TABLE scan_schedules ADD COLUMN created_by_user_id VARCHAR(64)",
            "ALTER TABLE scan_schedules ADD COLUMN ai_credential_policy VARCHAR(16)",
            "ALTER TABLE scan_schedules ADD COLUMN ai_owner_consent BOOLEAN",
        ):
            try:
                conn.execute(text(ddl))
                conn.commit()
            except Exception:
                pass  # Column đã tồn tại hoặc bảng chưa tồn tại lần đầu — bình thường

_run_migrations()
from api.pentest_migrations import run as _pentest_migrate  # P1-0: api/pentest_migrations/
_pentest_migrate(engine)

# [AI PR-2] che secret trong log + chặn debug SDK ở production + migrate cấu hình AI org → ai_credentials
from api.services import ai_credentials as _ai_creds
_ai_creds.startup()


def _cleanup_stale_scans():
    """Reset các scan PENDING/RUNNING về FAILED khi app restart.

    Lý do: khi container bị stop/restart, tất cả background tasks đang chạy
    sẽ bị kill đột ngột. Nếu không cleanup, các scan này sẽ mãi ở trạng
    thái RUNNING/PENDING dù không có gì đang chạy cả.
    """
    from api.database import SessionLocal
    from api.models import Scan, ScanStatus
    from sqlalchemy import text
    from datetime import datetime

    db = SessionLocal()
    try:
        stale = db.query(Scan).filter(
            Scan.status.in_([ScanStatus.RUNNING, ScanStatus.PENDING])
        ).all()

        if stale:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"[Startup] Tìm thấy {len(stale)} scan bị treo — reset về FAILED")
            for scan in stale:
                scan.status = ScanStatus.FAILED
                scan.error_message = (
                    "Scan bị gián đoạn do container restart. "
                    "Vui lòng chạy lại scan."
                )
                scan.completed_at = datetime.utcnow()
            db.commit()
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"[Startup] Cleanup lỗi: {e}")
    finally:
        db.close()


import os as _os
if not _os.environ.get('VULNGUARD_DEMO'):
    _cleanup_stale_scans()


def _cleanup_stale_doc_reviews():
    """Giống _cleanup_stale_scans — reset các Document Review đang RUNNING/PENDING
    về FAILED khi app restart (background task bị kill đột ngột)."""
    from api.database import SessionLocal
    from api.docreview_models import DocumentVersion, ReviewStatus
    from datetime import datetime

    db = SessionLocal()
    try:
        stale = db.query(DocumentVersion).filter(
            DocumentVersion.review_status.in_([ReviewStatus.RUNNING, ReviewStatus.PENDING])
        ).all()
        if stale:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"[Startup] Tìm thấy {len(stale)} document review bị treo — reset về FAILED")
            for v in stale:
                v.review_status = ReviewStatus.FAILED
                v.review_error = "Review bị gián đoạn do container restart. Vui lòng review lại."
                v.review_completed_at = datetime.utcnow()
            db.commit()
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"[Startup] Cleanup doc review lỗi: {e}")
    finally:
        db.close()


if not _os.environ.get('VULNGUARD_DEMO'):
    _cleanup_stale_doc_reviews()


from scanner.pentest.lifecycle import cleanup_on_api_start as _cleanup_stale_pentest_runs  # P2-6


if not _os.environ.get('VULNGUARD_DEMO'):
    _cleanup_stale_pentest_runs()

app = FastAPI(
    title="VulnGuard API",
    description="Local DevSecOps Security Scanner với AI Analysis",
    version="1.0.0",
    docs_url="/docs" if app_settings.expose_api_docs else None,
    redoc_url="/redoc" if app_settings.expose_api_docs else None,
    openapi_url="/openapi.json" if app_settings.expose_api_docs else None,
)

@app.exception_handler(RequestValidationError)
async def _validation_error_handler(request, exc: RequestValidationError):
    """422 không được echo lại giá trị đầu vào (`input`/`ctx`): body có thể chứa mật khẩu/token."""
    errors = [{"type": e.get("type"), "loc": list(e.get("loc", [])),
               "msg": str(e.get("msg", "")).removeprefix("Value error, ")}
              for e in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": errors})


# M-2/D-5: mặc định SAME-ORIGIN (không CORS). Chỉ bật khi liệt kê origin trong CORS_ALLOW_ORIGINS.
_cors_origins = [o.strip() for o in app_settings.cors_allow_origins.split(",") if o.strip()]
if _cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )

# Auth: gắn user vào request.state + chặn /api/* chưa đăng nhập (xem api/routes/auth.py)
app.middleware("http")(auth.auth_middleware)
from api.upload_limit import UploadSizeLimitMiddleware  # noqa: E402
app.add_middleware(UploadSizeLimitMiddleware)  # M-5: chặn body quá lớn trước khi spool

# Baseline CSP (D-12: CSP nghiêm ngặt không inline hoãn lại). Font Google được brand.css @import.
_CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "img-src 'self' data: blob:; font-src 'self' data: https://fonts.gstatic.com; "
        "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")


async def _security_headers(request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Frame-Options"] = "DENY"
    # Swagger (/docs, /redoc) tải JS từ cdn.jsdelivr.net → bỏ qua CSP cho 2 trang đó
    if (resp.headers.get("content-type", "").startswith("text/html")
            and request.url.path not in ("/docs", "/redoc")):
        resp.headers["Content-Security-Policy"] = _CSP
    return resp


from api.deprecation import deprecation_middleware  # noqa: E402  [AI PR-7]
app.middleware("http")(deprecation_middleware)   # chỉ thêm header Deprecation/Sunset/Link — không đổi hành vi

# Đăng ký SAU auth_middleware → ngoài cùng, bọc cả response 401/403/421 của auth
app.middleware("http")(_security_headers)

# API Routes
app.include_router(auth.router)


@app.exception_handler(RouteRefused)
async def _route_refused_handler(request, exc):     # [AI PR-3] mã chuẩn hoá, không bao giờ văn bản provider
    from fastapi.responses import JSONResponse
    return JSONResponse({"detail": {"code": exc.code, "message_key": exc.message_key}, "code": exc.code}, status_code=409)

app.include_router(ai.router)
app.include_router(ai_settings.router)
app.include_router(ai_credentials_routes.router)
app.include_router(webscans.router)
app.include_router(pentest.router)
from api.routes import pentest_accounts  # noqa: E402  P2-11
app.include_router(pentest_accounts.router)
app.include_router(assets.router)
app.include_router(intel.router)
app.include_router(connectors.router)
app.include_router(dashboard.router)
app.include_router(projects.router)
app.include_router(scans.router)
app.include_router(vulns.router)
app.include_router(compare.router)
app.include_router(ollama.router)
app.include_router(settings.router)
app.include_router(report.router)
from api.routes import pdf_jobs  # noqa: E402  PDF PR-3
app.include_router(pdf_jobs.router)
app.include_router(domains.router)
app.include_router(coworker.router)
app.include_router(coworker_agent.router)
app.include_router(docreview.router)
app.include_router(file_assistant.router)
app.include_router(scm.router)
app.include_router(knowledge.router)


@app.on_event("startup")
async def _check_bind():
    """Từ chối khởi động khi auth tắt mà bind non-loopback (compose/run.sh truyền VULNGUARD_BIND vào env)."""
    from api import bind_policy
    _, deprecated = bind_policy.resolve_bind()
    bind = bind_policy.detect_runtime_bind()
    if deprecated:
        import logging
        logging.getLogger(__name__).warning("[bind] VULNGUARD_HOST đã deprecated — dùng VULNGUARD_BIND.")
    bind_policy.check_startup(bind, app_settings.auth_enabled, app_settings.allowed_hosts, app_settings.cookie_secure)


@app.on_event("startup")
async def _init_setup_token():
    try:
        from api.routes.auth import init_setup_token
        init_setup_token()
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"[setup-token] không khởi tạo được: {e}")


@app.on_event("startup")
async def _start_scheduler():
    try:
        from api.services import scheduler
        scheduler.start()
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"[scheduler] không khởi động được: {e}")


@app.on_event("startup")
async def _start_pdf_maintenance():
    try:
        from api.services import pdf_export
        pdf_export.start_maintenance()
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"[pdf] maintenance không khởi động được: {e}")


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "VulnGuard", "deploy_mode": app_settings.deploy_mode}


@app.get("/api/features")
def features():
    """1.9: cờ bật/tắt module (để ẩn khỏi bản bán theo ICP)."""
    return {
        "coworker": app_settings.feature_coworker,
        "docreview": app_settings.feature_docreview,
        "file_assistant": app_settings.feature_file_assistant,
    }


# Serve Web UI
web_dir = os.path.join(os.path.dirname(__file__), "..", "web")
if os.path.exists(web_dir):
    app.mount("/static", StaticFiles(directory=web_dir), name="static")

    @app.get("/login", include_in_schema=False)
    def serve_login():
        return FileResponse(os.path.join(web_dir, "login.html"))

    @app.get("/", include_in_schema=False)
    def serve_ui():
        return FileResponse(os.path.join(web_dir, "index.html"))
