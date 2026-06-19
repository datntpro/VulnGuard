import asyncio
import io
import json
from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from api.database import get_db, SessionLocal
from api.domain_models import Domain, DomainCrawl, CrawlEndpoint, CrawlStatus, AIAnalysisStatus
from api.domain_schemas import DomainCreate, DomainOut, CrawlCreate, CrawlOut, EndpointOut
from api.config import settings

router = APIRouter(prefix="/api/domains", tags=["domains"])


# ─────────────────────────────────────────────
# Domain CRUD
# ─────────────────────────────────────────────
@router.post("", response_model=DomainOut, status_code=201)
def create_domain(payload: DomainCreate, db: Session = Depends(get_db)):
    url = payload.url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url

    existing = db.query(Domain).filter(Domain.url == url).first()
    if existing:
        raise HTTPException(status_code=400, detail="Domain này đã được khai báo")

    domain = Domain(name=payload.name, url=url, description=payload.description)
    db.add(domain)
    db.commit()
    db.refresh(domain)
    return domain


@router.get("", response_model=List[DomainOut])
def list_domains(db: Session = Depends(get_db)):
    return db.query(Domain).order_by(Domain.created_at.desc()).all()


@router.get("/{domain_id}", response_model=DomainOut)
def get_domain(domain_id: str, db: Session = Depends(get_db)):
    domain = db.query(Domain).filter(Domain.id == domain_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain không tồn tại")
    return domain


@router.delete("/{domain_id}", status_code=204)
def delete_domain(domain_id: str, db: Session = Depends(get_db)):
    domain = db.query(Domain).filter(Domain.id == domain_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain không tồn tại")
    db.delete(domain)
    db.commit()
    return None


# ─────────────────────────────────────────────
# Crawl trigger + lifecycle (giống pattern scans.py)
# ─────────────────────────────────────────────
_domain_crawl_locks: dict[str, asyncio.Lock] = {}


def _get_domain_lock(domain_id: str) -> asyncio.Lock:
    lock = _domain_crawl_locks.get(domain_id)
    if lock is None:
        lock = asyncio.Lock()
        _domain_crawl_locks[domain_id] = lock
    return lock


async def _run_crawl_background(crawl_id: str, url: str, params: dict):
    from scanner.crawler.katana_runner import run_katana

    db = SessionLocal()
    try:
        crawl = db.query(DomainCrawl).filter(DomainCrawl.id == crawl_id).first()
        if not crawl:
            return

        crawl.status = CrawlStatus.RUNNING
        crawl.started_at = datetime.utcnow()
        crawl.progress = {"phase": "crawling", "message": "Đang khởi động katana..."}
        db.commit()

        endpoints, meta = await run_katana(
            url=url,
            depth=params["depth"],
            js_crawl=params["js_crawl"],
            include_subdomains=params["include_subdomains"],
            exclude_patterns=params["exclude_patterns"],
            max_urls=params["max_urls"],
            timeout=params["timeout"],
        )

        crawl = db.query(DomainCrawl).filter(DomainCrawl.id == crawl_id).first()
        if not crawl:
            return

        if meta.get("error") and not endpoints:
            crawl.status = CrawlStatus.FAILED
            crawl.error_message = meta["error"]
            crawl.completed_at = datetime.utcnow()
            db.commit()
            return

        for ep in endpoints:
            db.add(CrawlEndpoint(
                crawl_id=crawl_id,
                url=ep["url"],
                path=ep["path"],
                method=ep["method"],
                status_code=ep["status_code"],
                content_type=ep["content_type"],
                source_tag=ep["source_tag"],
                query_params=ep["query_params"],
                body_params=ep["body_params"],
                forms=ep["forms"],
            ))

        methods_count: dict[str, int] = {}
        total_params = 0
        total_forms = 0
        for ep in endpoints:
            methods_count[ep["method"]] = methods_count.get(ep["method"], 0) + 1
            total_params += len(ep["query_params"]) + len(ep["body_params"])
            total_forms += len(ep["forms"])

        crawl.summary = {
            "total_urls": len(endpoints),
            "methods": methods_count,
            "total_params_seen": total_params,
            "total_forms": total_forms,
            "raw_lines": meta.get("raw_lines", 0),
            "truncated": meta.get("truncated", False),
            "warning": meta.get("error"),
        }
        crawl.status = CrawlStatus.COMPLETED
        crawl.completed_at = datetime.utcnow()
        crawl.progress = {"phase": "done"}
        db.commit()

        run_ai = params.get("run_ai_analysis", False)

    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Crawl {crawl_id} failed: {e}", exc_info=True)
        crawl = db.query(DomainCrawl).filter(DomainCrawl.id == crawl_id).first()
        if crawl:
            crawl.status = CrawlStatus.FAILED
            crawl.error_message = str(e)
            crawl.completed_at = datetime.utcnow()
            db.commit()
        return
    finally:
        db.close()

    # Phase 2: AI analysis (chạy sau khi crawl đã COMPLETED, không chặn crawl chính
    # nếu AI lỗi — crawl vẫn giữ kết quả, chỉ ai_status = FAILED)
    if run_ai:
        await _run_ai_crawl_analysis(crawl_id, url)


def _group_endpoints_for_ai(db: Session, crawl_id: str) -> list:
    """Gom endpoint theo path — giảm kích thước input gửi cho AI (1 path có thể
    có nhiều method/param thay vì lặp lại từng URL riêng)."""
    rows = db.query(CrawlEndpoint).filter(CrawlEndpoint.crawl_id == crawl_id).all()
    grouped: dict[str, dict] = {}
    for ep in rows:
        path = ep.path or "/"
        g = grouped.setdefault(path, {
            "path": path, "methods": set(), "query_params": set(),
            "body_params": set(), "has_form": False,
        })
        g["methods"].add(ep.method or "GET")
        g["query_params"].update(ep.query_params or [])
        g["body_params"].update(ep.body_params or [])
        if ep.forms:
            g["has_form"] = True

    result = []
    for g in grouped.values():
        result.append({
            "path": g["path"],
            "methods": sorted(g["methods"]),
            "query_params": sorted(g["query_params"]),
            "body_params": sorted(g["body_params"]),
            "has_form": g["has_form"],
        })
    result.sort(key=lambda x: x["path"])
    return result


async def _run_ai_crawl_analysis(crawl_id: str, domain_url: str):
    """Chạy AI (Ollama) phân loại endpoint nhạy cảm + gợi ý WAF + tóm tắt crawl.

    Tách session riêng (giống pattern _run_ai_analysis trong scans.py) — chạy
    sau khi crawl đã commit COMPLETED, lỗi ở đây không ảnh hưởng kết quả crawl.
    """
    import logging
    from scanner.ai_analyzer import AIAnalyzer

    logger = logging.getLogger(__name__)
    db = SessionLocal()
    try:
        crawl = db.query(DomainCrawl).filter(DomainCrawl.id == crawl_id).first()
        if not crawl:
            return

        crawl.ai_status = AIAnalysisStatus.RUNNING
        db.commit()

        grouped = _group_endpoints_for_ai(db, crawl_id)
        analyzer = AIAnalyzer()
        result = await analyzer.analyze_crawl(domain_url, grouped)

        crawl = db.query(DomainCrawl).filter(DomainCrawl.id == crawl_id).first()
        if not crawl:
            return

        if result.get("error") and not result.get("summary"):
            crawl.ai_status = AIAnalysisStatus.FAILED
            crawl.ai_error = result["error"]
        else:
            crawl.ai_status = AIAnalysisStatus.DONE
            crawl.ai_summary = result.get("summary") or ""
            crawl.ai_sensitive_endpoints = result.get("sensitive_endpoints") or []
            crawl.ai_waf_suggestions = result.get("waf_suggestions") or []
            crawl.ai_error = result.get("error")  # có thể có warning nhẹ kèm summary thô
        db.commit()

    except Exception as e:
        logger.error(f"AI crawl analysis {crawl_id} failed: {e}", exc_info=True)
        crawl = db.query(DomainCrawl).filter(DomainCrawl.id == crawl_id).first()
        if crawl:
            crawl.ai_status = AIAnalysisStatus.FAILED
            crawl.ai_error = str(e)[:500]
            db.commit()
    finally:
        db.close()


@router.post("/{domain_id}/crawls", response_model=CrawlOut, status_code=202)
async def trigger_crawl(
    domain_id: str,
    payload: CrawlCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    domain = db.query(Domain).filter(Domain.id == domain_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain không tồn tại")

    async with _get_domain_lock(domain_id):
        crawls = db.query(DomainCrawl).filter(DomainCrawl.domain_id == domain_id).order_by(DomainCrawl.crawl_number).all()
        if len(crawls) >= settings.max_crawls_per_domain:
            oldest = crawls[0]
            db.delete(oldest)
            db.commit()
            crawls = crawls[1:]

        next_number = (crawls[-1].crawl_number + 1) if crawls else 1

        crawl = DomainCrawl(
            domain_id=domain_id,
            crawl_number=next_number,
            depth=payload.depth,
            max_urls=payload.max_urls,
            js_crawl=1 if payload.js_crawl else 0,
            include_subdomains=1 if payload.include_subdomains else 0,
            exclude_patterns=payload.exclude_patterns,
            status=CrawlStatus.PENDING,
        )
        db.add(crawl)
        db.commit()
        db.refresh(crawl)

    background_tasks.add_task(
        _run_crawl_background,
        crawl.id,
        domain.url,
        {
            "depth": payload.depth,
            "js_crawl": payload.js_crawl,
            "include_subdomains": payload.include_subdomains,
            "exclude_patterns": payload.exclude_patterns,
            "max_urls": payload.max_urls,
            "timeout": payload.timeout,
            "run_ai_analysis": payload.run_ai_analysis,
        },
    )

    return crawl


@router.get("/{domain_id}/crawls", response_model=List[CrawlOut])
def list_crawls(domain_id: str, db: Session = Depends(get_db)):
    domain = db.query(Domain).filter(Domain.id == domain_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain không tồn tại")
    return db.query(DomainCrawl).filter(DomainCrawl.domain_id == domain_id).order_by(DomainCrawl.crawl_number.desc()).all()


@router.get("/crawls/{crawl_id}", response_model=CrawlOut, tags=["domains"])
def get_crawl(crawl_id: str, db: Session = Depends(get_db)):
    crawl = db.query(DomainCrawl).filter(DomainCrawl.id == crawl_id).first()
    if not crawl:
        raise HTTPException(status_code=404, detail="Crawl không tồn tại")
    return crawl


@router.get("/crawls/{crawl_id}/progress", tags=["domains"])
def get_crawl_progress(crawl_id: str, db: Session = Depends(get_db)):
    crawl = db.query(DomainCrawl).filter(DomainCrawl.id == crawl_id).first()
    if not crawl:
        raise HTTPException(status_code=404, detail="Crawl không tồn tại")

    return {
        "crawl_id": crawl_id,
        "status": crawl.status.value,
        "progress": crawl.progress or {},
        "summary": crawl.summary if crawl.status == CrawlStatus.COMPLETED else None,
        "error_message": crawl.error_message,
        "started_at": crawl.started_at.isoformat() if crawl.started_at else None,
        "completed_at": crawl.completed_at.isoformat() if crawl.completed_at else None,
    }


@router.post("/crawls/{crawl_id}/analyze", response_model=CrawlOut, status_code=202, tags=["domains"])
async def analyze_crawl_ai(
    crawl_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Chạy AI (Ollama) phân loại endpoint nhạy cảm + gợi ý WAF + tóm tắt — on-demand,
    dùng cho crawl đã xong nhưng lúc tạo không tick 'Phân tích AI', hoặc muốn chạy lại."""
    crawl = db.query(DomainCrawl).filter(DomainCrawl.id == crawl_id).first()
    if not crawl:
        raise HTTPException(status_code=404, detail="Crawl không tồn tại")
    if crawl.status != CrawlStatus.COMPLETED:
        raise HTTPException(status_code=400, detail=f"Crawl chưa hoàn thành (status: {crawl.status.value})")
    if crawl.ai_status == AIAnalysisStatus.RUNNING:
        raise HTTPException(status_code=409, detail="AI đang phân tích crawl này, vui lòng đợi")

    domain = db.query(Domain).filter(Domain.id == crawl.domain_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain không tồn tại")

    crawl.ai_status = AIAnalysisStatus.PENDING
    crawl.ai_error = None
    db.commit()
    db.refresh(crawl)

    background_tasks.add_task(_run_ai_crawl_analysis, crawl_id, domain.url)
    return crawl


@router.get("/crawls/{crawl_id}/endpoints", response_model=List[EndpointOut], tags=["domains"])
def get_crawl_endpoints(
    crawl_id: str,
    method: str = None,
    search: str = None,
    db: Session = Depends(get_db),
):
    crawl = db.query(DomainCrawl).filter(DomainCrawl.id == crawl_id).first()
    if not crawl:
        raise HTTPException(status_code=404, detail="Crawl không tồn tại")

    query = db.query(CrawlEndpoint).filter(CrawlEndpoint.crawl_id == crawl_id)
    if method:
        query = query.filter(CrawlEndpoint.method == method.upper())
    if search:
        query = query.filter(CrawlEndpoint.url.contains(search))
    return query.order_by(CrawlEndpoint.path).all()


# ─────────────────────────────────────────────
# Export
# ─────────────────────────────────────────────
@router.get("/crawls/{crawl_id}/export", tags=["domains"])
def export_crawl(
    crawl_id: str,
    format: str = Query(default="json", pattern="^(json|sitemap_xml|waf_baseline|modsecurity)$"),
    db: Session = Depends(get_db),
):
    from scanner.crawler.waf_export import (
        build_sitemap_xml, build_endpoints_export, build_waf_baseline, build_modsecurity_rules,
    )

    crawl = db.query(DomainCrawl).filter(DomainCrawl.id == crawl_id).first()
    if not crawl:
        raise HTTPException(status_code=404, detail="Crawl không tồn tại")
    if crawl.status != CrawlStatus.COMPLETED:
        raise HTTPException(status_code=400, detail=f"Crawl chưa hoàn thành (status: {crawl.status.value})")

    domain = db.query(Domain).filter(Domain.id == crawl.domain_id).first()
    domain_url = domain.url if domain else ""
    domain_name = (domain.name if domain else crawl.domain_id).replace(" ", "_")
    endpoints = [
        {
            "url": e.url, "path": e.path, "method": e.method,
            "status_code": e.status_code, "content_type": e.content_type,
            "source_tag": e.source_tag,
            "query_params": e.query_params or [], "body_params": e.body_params or [],
            "forms": e.forms or [],
        }
        for e in db.query(CrawlEndpoint).filter(CrawlEndpoint.crawl_id == crawl_id).all()
    ]

    filename_base = f"vulnguard_sitemap_{domain_name}_{crawl.crawl_number}"

    if format == "sitemap_xml":
        content = build_sitemap_xml(domain_url, endpoints)
        return StreamingResponse(
            io.BytesIO(content.encode("utf-8")),
            media_type="application/xml",
            headers={"Content-Disposition": f'attachment; filename="{filename_base}.xml"'},
        )
    elif format == "waf_baseline":
        baseline = build_waf_baseline(domain_url, endpoints)
        content = json.dumps(baseline, ensure_ascii=False, indent=2)
        return StreamingResponse(
            io.BytesIO(content.encode("utf-8")),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename_base}_waf_baseline.json"'},
        )
    elif format == "modsecurity":
        baseline = build_waf_baseline(domain_url, endpoints)
        content = build_modsecurity_rules(domain_url, baseline)
        return StreamingResponse(
            io.BytesIO(content.encode("utf-8")),
            media_type="text/plain",
            headers={"Content-Disposition": f'attachment; filename="{filename_base}_modsecurity.conf"'},
        )
    else:
        crawl_meta = {
            "crawl_number": crawl.crawl_number,
            "depth": crawl.depth,
            "started_at": crawl.started_at.isoformat() if crawl.started_at else None,
            "completed_at": crawl.completed_at.isoformat() if crawl.completed_at else None,
            "summary": crawl.summary or {},
        }
        data = build_endpoints_export(domain_url, crawl_meta, endpoints)
        content = json.dumps(data, ensure_ascii=False, indent=2)
        return StreamingResponse(
            io.BytesIO(content.encode("utf-8")),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename_base}.json"'},
        )
