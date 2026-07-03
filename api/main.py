from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
import os

from api.config import settings as app_settings
from api.database import Base, engine
from api.routes import projects, scans, vulns, compare, ollama, settings, report, domains, coworker, coworker_agent, docreview, file_assistant
# domain_models / docreview_models phải được import trước create_all() để SQLAlchemy
# đăng ký các bảng tương ứng (module riêng, tách khỏi models.py)
from api import domain_models  # noqa: F401
from api import docreview_models  # noqa: F401
from api import file_assistant_models  # noqa: F401
from api import agent_conversation_models  # noqa: F401

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
        ):
            try:
                conn.execute(text(ddl))
                conn.commit()
            except Exception:
                pass  # Column đã tồn tại hoặc bảng chưa tồn tại lần đầu — bình thường

_run_migrations()


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


_cleanup_stale_doc_reviews()

app = FastAPI(
    title="VulnGuard API",
    description="Local DevSecOps Security Scanner với AI Analysis",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    # Không dùng allow_credentials=True cùng allow_origins=["*"] — tổ hợp này bị
    # browser từ chối với credentialed requests, và app không dùng cookie nên
    # không cần credentials xuyên origin.
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Routes
app.include_router(projects.router)
app.include_router(scans.router)
app.include_router(vulns.router)
app.include_router(compare.router)
app.include_router(ollama.router)
app.include_router(settings.router)
app.include_router(report.router)
app.include_router(domains.router)
app.include_router(coworker.router)
app.include_router(coworker_agent.router)
app.include_router(docreview.router)
app.include_router(file_assistant.router)


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "VulnGuard", "deploy_mode": app_settings.deploy_mode}


# Serve Web UI
web_dir = os.path.join(os.path.dirname(__file__), "..", "web")
if os.path.exists(web_dir):
    app.mount("/static", StaticFiles(directory=web_dir), name="static")

    @app.get("/", include_in_schema=False)
    def serve_ui():
        return FileResponse(os.path.join(web_dir, "index.html"))
