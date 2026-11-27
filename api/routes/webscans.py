"""
Web Scan API (Nuclei) — quét lỗ hổng web cho Domain đã khai báo.

  POST   /api/domains/{domain_id}/webscans      — trigger (yêu cầu authorized=true)
  GET    /api/domains/{domain_id}/webscans      — danh sách
  GET    /api/webscans/{id}                     — chi tiết + progress
  GET    /api/webscans/{id}/findings            — findings
  PATCH  /api/webscans/findings/{id}/status     — đổi trạng thái finding
  DELETE /api/webscans/{id}
"""
import asyncio
import hashlib
import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.config import settings
from api.database import SessionLocal, get_db
from api.domain_models import CrawlEndpoint, CrawlStatus, Domain, DomainCrawl
from api.webscan_models import WebFinding, WebFindingStatus, WebScan, WebScanStatus

logger = logging.getLogger(__name__)
router = APIRouter(tags=["webscans"])

MAX_TARGETS = 5000
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_running: set[str] = set()   # domain_id đang có web scan chạy


class WebScanCreate(BaseModel):
    crawl_id: Optional[str] = None
    severities: List[str] = Field(default_factory=lambda: ["critical", "high", "medium", "low"])
    tags: List[str] = Field(default_factory=list)
    exclude_tags: List[str] = Field(default_factory=list)   # P0.9: loại nhóm template
    fuzz: bool = False
    rate_limit: int = Field(default=10, ge=1, le=500)        # P0.9: mặc định 10 req/s (an toàn hơn)
    authorized: bool = False


class FindingStatusUpdate(BaseModel):
    status: WebFindingStatus


def _scan_out(s: WebScan) -> dict:
    return {
        "id": s.id, "domain_id": s.domain_id, "crawl_id": s.crawl_id,
        "status": s.status.value if s.status else None,
        "severities": s.severities or [], "tags": s.tags or [], "fuzz": bool(s.fuzz),
        "rate_limit": s.rate_limit, "authorized_by": s.authorized_by,
        "target_count": s.target_count or 0,
        "started_at": s.started_at, "completed_at": s.completed_at,
        "error_message": s.error_message, "summary": s.summary or {}, "progress": s.progress or {},
    }


def _finding_out(f: WebFinding) -> dict:
    return {
        "id": f.id, "scan_id": f.scan_id, "template_id": f.template_id, "name": f.name,
        "severity": f.severity, "matched_at": f.matched_at, "host": f.host, "type": f.type,
        "matcher_name": f.matcher_name, "description": f.description, "remediation": f.remediation,
        "reference": f.reference or [], "tags": f.tags or [], "cve": f.cve, "cwe": f.cwe,
        "cvss_score": f.cvss_score, "extracted": f.extracted or [], "curl_command": f.curl_command,
        "status": f.status.value if f.status else "OPEN", "created_at": f.created_at,
    }


def _collect_targets(db: Session, domain: Domain, crawl_id: Optional[str]) -> List[str]:
    if not crawl_id:
        return [domain.url]
    rows = db.query(CrawlEndpoint.url).filter(CrawlEndpoint.crawl_id == crawl_id).all()
    seen, out = set(), []
    for (url,) in rows:
        if url and url not in seen:
            seen.add(url)
            out.append(url)
    if domain.url not in seen:
        out.insert(0, domain.url)
    return out[:MAX_TARGETS]


def _fingerprint(item: dict) -> str:
    raw = f"{item['template_id']}|{item.get('matcher_name','')}|{item.get('matched_at','')}"
    return hashlib.sha256(raw.encode()).hexdigest()


async def _run_webscan(scan_id: str, domain_id: str, targets: List[str], params: dict):
    from scanner.crawler.nuclei_runner import run_nuclei

    db = SessionLocal()
    counts = {s: 0 for s in _SEV_ORDER}
    seen_fp: set[str] = set()
    lock = asyncio.Lock()

    def _set_progress(message: str, phase: str = "scanning"):
        scan = db.query(WebScan).filter(WebScan.id == scan_id).first()
        if scan:
            scan.progress = {"phase": phase, "message": message, "findings": sum(counts.values())}
            db.commit()

    async def _on_finding(item: dict):
        async with lock:
            fp = _fingerprint(item)
            if fp in seen_fp:
                return
            seen_fp.add(fp)
            counts[item["severity"]] = counts.get(item["severity"], 0) + 1
            cols = {k: v for k, v in item.items() if k not in ('request', 'response')}
            db.add(WebFinding(scan_id=scan_id, fingerprint=fp, **cols))
            db.commit()
            _set_progress(f"Đã phát hiện {sum(counts.values())} finding…")

    try:
        scan = db.query(WebScan).filter(WebScan.id == scan_id).first()
        scan.status = WebScanStatus.RUNNING
        scan.started_at = datetime.utcnow()
        db.commit()
        _set_progress(f"Đang quét {len(targets)} URL bằng nuclei…")

        # 1.2: kiểm security header thiếu (native) — chạy trước, luôn có dù nuclei thiếu template
        try:
            from scanner.crawler.headers_check import check_targets as _hdr_check
            await _hdr_check(targets, _on_finding)
        except Exception as _e:
            import logging as _lg
            _lg.getLogger(__name__).warning(f"[webscan] header check lỗi: {_e}")

        _, meta = await run_nuclei(
            targets=targets, severities=params["severities"], tags=params["tags"],
            fuzz=params["fuzz"], rate_limit=params["rate_limit"],
            timeout=settings.nuclei_timeout_minutes * 60, on_finding=_on_finding,
            exclude_tags=params.get("exclude_tags"),
        )
        scan = db.query(WebScan).filter(WebScan.id == scan_id).first()
        scan.summary = {**counts, "total": sum(counts.values()), "timed_out": meta.get("timed_out", False)}
        scan.completed_at = datetime.utcnow()
        if meta.get("error") and not sum(counts.values()) and not meta.get("timed_out"):
            scan.status = WebScanStatus.FAILED
            scan.error_message = meta["error"]
            scan.progress = {"phase": "failed", "message": meta["error"][:300], "findings": 0}
        else:
            scan.status = WebScanStatus.COMPLETED
            scan.error_message = meta.get("error")
            scan.progress = {"phase": "done", "message": "Hoàn tất", "findings": sum(counts.values())}
        db.commit()
    except Exception as e:
        logger.exception(f"Web scan {scan_id} lỗi")
        db.rollback()
        scan = db.query(WebScan).filter(WebScan.id == scan_id).first()
        if scan:
            scan.status = WebScanStatus.FAILED
            scan.error_message = str(e)[:1000]
            scan.completed_at = datetime.utcnow()
            db.commit()
    finally:
        _running.discard(domain_id)
        db.close()


def _enforce_rolling(db: Session, domain_id: str):
    scans = (db.query(WebScan).filter(WebScan.domain_id == domain_id)
             .order_by(WebScan.started_at.desc()).all())
    for old in scans[max(1, settings.max_webscans_per_domain) - 1:]:
        if old.status not in (WebScanStatus.RUNNING, WebScanStatus.PENDING):
            db.delete(old)
    db.commit()


@router.post("/api/domains/{domain_id}/webscans", status_code=201)
def trigger_webscan(domain_id: str, payload: WebScanCreate, background: BackgroundTasks,
                    request: Request, db: Session = Depends(get_db)):
    from scanner.crawler.nuclei_runner import is_nuclei_available, VALID_SEVERITIES

    domain = db.query(Domain).filter(Domain.id == domain_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain không tồn tại")
    # P0.4: phải xác minh quyền sở hữu domain (DNS TXT / .well-known) trước khi quét
    if not getattr(domain, "ownership_verified", False):
        raise HTTPException(status_code=403, detail="Domain chưa xác minh quyền sở hữu — "
                            "xác minh (DNS TXT / .well-known) trước khi web scan.")
    if not payload.authorized:
        raise HTTPException(status_code=400, detail="Cần xác nhận bạn có quyền quét domain này (authorized=true)")
    # P0.9: fuzz là quét xâm nhập mạnh → chỉ ADMIN được bật (duyệt như Pentest Agent)
    if payload.fuzz:
        _u = getattr(request.state, "user", None)
        from api.auth_models import UserRole as _R
        if _u is not None and getattr(_u, "role", None) != _R.ADMIN:
            raise HTTPException(status_code=403, detail="Chỉ ADMIN mới được bật fuzz (quét xâm nhập mạnh)")
    if not is_nuclei_available():
        raise HTTPException(status_code=400, detail="Nuclei chưa được cài trên máy chủ VulnGuard")
    if domain_id in _running:
        raise HTTPException(status_code=409, detail="Domain này đang có web scan chạy")
    severities = [s.lower() for s in payload.severities if s.lower() in VALID_SEVERITIES]
    if not severities:
        raise HTTPException(status_code=422, detail="Chọn ít nhất 1 mức severity hợp lệ")
    if payload.crawl_id:
        crawl = db.query(DomainCrawl).filter(DomainCrawl.id == payload.crawl_id,
                                             DomainCrawl.domain_id == domain_id).first()
        if not crawl:
            raise HTTPException(status_code=404, detail="Crawl không thuộc domain này")
        if crawl.status != CrawlStatus.COMPLETED:
            raise HTTPException(status_code=400, detail="Crawl chưa hoàn tất")

    _enforce_rolling(db, domain_id)
    targets = _collect_targets(db, domain, payload.crawl_id)
    user = getattr(request.state, "user", None)
    scan = WebScan(
        domain_id=domain_id, crawl_id=payload.crawl_id, severities=severities,
        tags=[t.strip()[:60] for t in payload.tags if t.strip()][:20],
        fuzz=int(payload.fuzz), rate_limit=payload.rate_limit,
        authorized_by=getattr(user, "email", None) or "auth-disabled",
        status=WebScanStatus.PENDING, target_count=len(targets),
        progress={"phase": "pending", "message": "Đang chờ chạy…", "findings": 0},
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    _running.add(domain_id)
    background.add_task(_run_webscan, scan.id, domain_id, targets, {
        "severities": severities, "tags": scan.tags, "fuzz": payload.fuzz, "rate_limit": payload.rate_limit,
        "exclude_tags": [t.strip()[:60] for t in payload.exclude_tags if t.strip()][:20],
    })
    return _scan_out(scan)


@router.get("/api/domains/{domain_id}/webscans")
def list_webscans(domain_id: str, db: Session = Depends(get_db)):
    rows = (db.query(WebScan).filter(WebScan.domain_id == domain_id)
            .order_by(WebScan.started_at.desc()).all())
    return [_scan_out(s) for s in rows]


@router.get("/api/webscans/{scan_id}")
def get_webscan(scan_id: str, db: Session = Depends(get_db)):
    s = db.query(WebScan).filter(WebScan.id == scan_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Web scan không tồn tại")
    return _scan_out(s)


@router.get("/api/webscans/{scan_id}/findings")
def list_findings(scan_id: str, severity: Optional[str] = None, db: Session = Depends(get_db)):
    q = db.query(WebFinding).filter(WebFinding.scan_id == scan_id)
    if severity:
        q = q.filter(WebFinding.severity == severity.lower())
    rows = q.all()
    rows.sort(key=lambda f: (_SEV_ORDER.index(f.severity) if f.severity in _SEV_ORDER else 9, f.name))
    return [_finding_out(f) for f in rows]


@router.get("/api/webscans/{scan_id}/export")
def export_webscan(scan_id: str, format: str = Query(default="json", pattern="^(json|csv|html|pdf)$"),
                   request: Request = None, async_: bool = Query(default=False, alias="async"),
                   db: Session = Depends(get_db)):
    """1.1: xuất báo cáo web scan — JSON / CSV / HTML / PDF (Typst, tải trực tiếp)."""
    if format == "pdf":
        from api.services import pdf_export
        return pdf_export.pdf_response("webscan", scan_id, request, db, {}, want_async=async_)
    import csv as _csv
    import html as _html
    import io as _io
    import json as _json
    from fastapi.responses import StreamingResponse

    scan = db.query(WebScan).filter(WebScan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Web scan không tồn tại")
    rows = db.query(WebFinding).filter(WebFinding.scan_id == scan_id).all()
    rows.sort(key=lambda f: (_SEV_ORDER.index(f.severity) if f.severity in _SEV_ORDER else 9, f.name))
    findings = [_finding_out(f) for f in rows]
    counts = {s: 0 for s in _SEV_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    base = f"vulnguard_webscan_{scan.scan_number if hasattr(scan,'scan_number') else scan_id[:8]}"

    if format == "json":
        doc = {"scan_id": scan_id, "domain_id": scan.domain_id, "generated_at": datetime.utcnow().isoformat() + "Z",
               "summary": {**counts, "total": len(findings)}, "findings": findings}
        data = _json.dumps(doc, ensure_ascii=False, indent=2, default=str)
        return StreamingResponse(iter([data.encode()]), media_type="application/json; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{base}.json"'})
    if format == "csv":
        buf = _io.StringIO(); w = _csv.writer(buf)
        w.writerow(["severity", "name", "host", "matched_at", "template_id", "cve", "cwe", "status", "remediation"])
        for f in findings:
            w.writerow([f["severity"], f["name"], f["host"], f["matched_at"], f["template_id"],
                        f["cve"] or "", f["cwe"] or "", f["status"], (f["remediation"] or "")[:300]])
        return StreamingResponse(iter([buf.getvalue().encode()]), media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{base}.csv"'})

    # HTML (self-contained)
    e = _html.escape
    sev_color = {"critical": "#d03b3b", "high": "#ec835a", "medium": "#fab219", "low": "#0ca30c", "info": "#3987e5"}
    bars = "".join(f'<span style="background:{sev_color[s]};color:#fff;padding:2px 8px;border-radius:4px;margin-right:6px;">{s}: {counts[s]}</span>'
                   for s in _SEV_ORDER if counts[s])
    rows_html = "".join(
        f'<tr><td style="color:{sev_color.get(f["severity"],"#333")};font-weight:600;">{e(f["severity"].upper())}</td>'
        f'<td>{e(f["name"])}</td><td style="font-family:monospace;font-size:12px;">{e(f["matched_at"] or f["host"] or "")}</td>'
        f'<td>{e(f["cve"] or f["cwe"] or "")}</td><td>{e((f["remediation"] or "")[:200])}</td></tr>'
        for f in findings)
    html_doc = f"""<!doctype html><html lang="vi"><head><meta charset="utf-8"><title>{e(base)}</title>
<style>body{{font-family:system-ui,Arial;margin:32px;color:#1a1a1a;}}h1{{color:#1F3864;}}
table{{border-collapse:collapse;width:100%;margin-top:16px;}}th,td{{border:1px solid #ddd;padding:8px;text-align:left;vertical-align:top;}}
th{{background:#1F3864;color:#fff;}}</style></head><body>
<h1>Báo cáo quét web — VulnGuard</h1>
<p>Scan: {e(scan_id)} · Thời điểm: {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC · Tổng: {len(findings)} finding</p>
<div style="margin:12px 0;">{bars or '<em>Không có lỗ hổng</em>'}</div>
<table><thead><tr><th>Mức</th><th>Tên</th><th>Vị trí</th><th>CVE/CWE</th><th>Khuyến nghị</th></tr></thead>
<tbody>{rows_html}</tbody></table>
<p style="margin-top:24px;font-size:12px;"><a href="/api/webscans/{e(scan_id)}/export?format=pdf">⬇ Tải PDF</a></p>
</body></html>"""
    return StreamingResponse(iter([html_doc.encode()]), media_type="text/html; charset=utf-8",
        headers={"Content-Disposition": f'inline; filename="{base}.html"'})


@router.patch("/api/webscans/findings/{finding_id}/status")
def update_finding_status(finding_id: str, payload: FindingStatusUpdate, db: Session = Depends(get_db)):
    f = db.query(WebFinding).filter(WebFinding.id == finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding không tồn tại")
    f.status = payload.status
    db.commit()
    return _finding_out(f)


@router.delete("/api/webscans/{scan_id}", status_code=204)
def delete_webscan(scan_id: str, db: Session = Depends(get_db)):
    s = db.query(WebScan).filter(WebScan.id == scan_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Web scan không tồn tại")
    if s.status in (WebScanStatus.RUNNING, WebScanStatus.PENDING):
        raise HTTPException(status_code=409, detail="Không thể xoá scan đang chạy")
    db.delete(s)
    db.commit()
    return None
