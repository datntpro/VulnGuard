import asyncio
import csv
import io
import json
import os
from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from fastapi.responses import StreamingResponse, JSONResponse
from sqlalchemy.orm import Session

from api.database import get_db, SessionLocal
from api.models import Project, Scan, Vulnerability, ScanStatus, Severity
from api.schemas import ScanCreate, ScanOut, VulnOut
from api.config import settings

router = APIRouter(prefix="/api/projects", tags=["scans"])


def _compute_summary(vulns: List[Vulnerability]) -> dict:
    summary = {s.value: 0 for s in Severity}
    summary["total"] = 0
    summary["open"] = 0
    summary["accepted"] = 0
    summary["false_positive"] = 0

    for v in vulns:
        summary[v.severity.value] += 1
        summary["total"] += 1
        if v.status.value == "OPEN":
            summary["open"] += 1
        elif v.status.value == "ACCEPTED":
            summary["accepted"] += 1
        elif v.status.value == "FALSE_POSITIVE":
            summary["false_positive"] += 1

    return summary


async def _run_scan_background(scan_id: str, scan_path: str, scan_types: list, run_ai: bool):
    """Chạy scan trong background với live progress updates."""
    from scanner.orchestrator import Orchestrator, TOOL_LABELS
    from scanner.ai_analyzer import AIAnalyzer

    db = SessionLocal()
    completed_tools = {}  # tool_name -> log dict

    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        # ── Validate scan path ────────────────────────────────────────────
        if not os.path.exists(scan_path):
            scan.status = ScanStatus.FAILED
            scan.error_message = (
                f"Scan path không tồn tại: '{scan_path}'\n"
                f"Hãy đảm bảo path đã được mount vào Docker container.\n"
                f"Ví dụ: thêm volume '-v /your/project:/scan' và dùng path '/scan'"
            )
            scan.completed_at = datetime.utcnow()
            db.commit()
            return

        # ── Initialize progress ───────────────────────────────────────────
        orchestrator = Orchestrator(scan_path=scan_path, scan_types=scan_types)
        tool_list = orchestrator.get_scanner_list()
        total_tools = len(tool_list)

        initial_progress = {
            "total_tools": total_tools,
            "completed_tools": 0,
            "tools": {
                t["tool"]: {
                    "status": "pending",
                    "label": t["label"],
                    "scan_type": t["scan_type"],
                }
                for t in tool_list
            },
        }

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.utcnow()
        scan.scanner_progress = initial_progress
        db.commit()

        # ── Progress callback — gọi sau mỗi tool hoàn thành ─────────────
        async def on_tool_done(tool_name: str, count: int, error: str, duration: float):
            nonlocal completed_tools
            completed_tools[tool_name] = {
                "status": "error" if error else "ok",
                "count": count,
                "duration_s": round(duration, 1),
                "error": error or None,
                "label": TOOL_LABELS.get(tool_name, tool_name),
            }

            # Lấy scan từ DB mới để tránh stale state
            _db = SessionLocal()
            try:
                _scan = _db.query(Scan).filter(Scan.id == scan_id).first()
                if not _scan:
                    return
                progress = _scan.scanner_progress or {}
                tools_state = progress.get("tools", {})

                # Cập nhật trạng thái tool này
                if tool_name in tools_state:
                    tools_state[tool_name].update({
                        "status": "error" if error else "done",
                        "count": count,
                        "duration_s": round(duration, 1),
                        "error": error or None,
                    })
                else:
                    tools_state[tool_name] = {
                        "status": "error" if error else "done",
                        "count": count,
                        "duration_s": round(duration, 1),
                        "label": TOOL_LABELS.get(tool_name, tool_name),
                    }

                done_count = sum(
                    1 for t in tools_state.values()
                    if t.get("status") in ("done", "error")
                )
                _scan.scanner_progress = {
                    "total_tools": total_tools,
                    "completed_tools": done_count,
                    "tools": tools_state,
                }
                _db.commit()
            finally:
                _db.close()

        # ── Run all scanners ──────────────────────────────────────────────
        findings, scanner_logs = await orchestrator.run(on_tool_done=on_tool_done)

        # Persist findings
        for finding in findings:
            vuln = Vulnerability(
                scan_id=scan_id,
                tool=finding.get("tool", "unknown"),
                scan_type=finding.get("scan_type"),
                rule_id=finding.get("rule_id"),
                title=finding.get("title", "Unknown"),
                description=finding.get("description"),
                severity=finding.get("severity", Severity.INFO),
                file_path=finding.get("file_path"),
                line_start=finding.get("line_start"),
                line_end=finding.get("line_end"),
                code_snippet=finding.get("code_snippet"),
                cwe=finding.get("cwe"),
                cve=finding.get("cve"),
                cvss_score=finding.get("cvss_score"),
                package_name=finding.get("package_name"),
                package_version=finding.get("package_version"),
                fixed_version=finding.get("fixed_version"),
                raw_output=finding.get("raw"),
                fingerprint=finding.get("fingerprint"),
            )
            db.add(vuln)

        db.commit()
        db.refresh(scan)

        # ── Phase 1 DONE: Đánh dấu scan COMPLETED ngay (không đợi AI) ────
        # UI sẽ thấy kết quả scan ngay lập tức
        vulns_for_summary = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
        summary = _compute_summary(vulns_for_summary)
        summary["scanner_logs"] = scanner_logs
        summary["ai_status"] = "pending" if (run_ai and findings) else "skipped"
        summary["ai_total"] = len(vulns_for_summary) if (run_ai and findings) else 0
        summary["ai_done"] = 0
        scan.summary = summary
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()
        db.commit()

        # ── Phase 2: AI Analysis (chạy tiếp sau khi scan đã COMPLETED) ───
        if run_ai and findings:
            await _run_ai_analysis(scan_id, scanner_logs)

    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Scan {scan_id} failed: {e}", exc_info=True)
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)
            scan.completed_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()


async def _run_ai_analysis(scan_id: str, scanner_logs: dict):
    """Chạy AI analysis cho từng vuln — có concurrency limit, timeout, progress tracking."""
    import logging
    import asyncio as _asyncio
    from scanner.ai_analyzer import AIAnalyzer

    logger = logging.getLogger(__name__)
    db = SessionLocal()

    try:
        vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
        total = len(vulns)
        if not total:
            return

        logger.info(f"[AI] Bắt đầu phân tích {total} vulnerabilities cho scan {scan_id}")

        analyzer = AIAnalyzer()
        done_count = 0
        semaphore = _asyncio.Semaphore(3)  # Tối đa 3 vuln song song

        # Cập nhật progress ban đầu
        def _update_ai_progress(done: int, status: str = "analyzing"):
            _db = SessionLocal()
            try:
                _scan = _db.query(Scan).filter(Scan.id == scan_id).first()
                if _scan and _scan.summary:
                    s = dict(_scan.summary)
                    s["ai_status"] = status
                    s["ai_done"] = done
                    s["ai_total"] = total
                    s["scanner_logs"] = scanner_logs
                    _scan.summary = s
                    _db.commit()
            except Exception as _e:
                logger.warning(f"[AI] Không cập nhật được progress: {_e}")
            finally:
                _db.close()

        _update_ai_progress(0, "analyzing")

        async def _analyze_one(vuln_id: str, vuln_data: dict):
            nonlocal done_count
            async with semaphore:
                try:
                    # Per-vuln timeout = OLLAMA_TIMEOUT (default 120s)
                    analysis = await _asyncio.wait_for(
                        analyzer.analyze_raw(vuln_data),
                        timeout=analyzer.timeout,
                    )
                    # Persist kết quả cho vuln này
                    _db = SessionLocal()
                    try:
                        _v = _db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
                        if _v:
                            _v.ai_false_positive_likelihood = analysis.get("false_positive_likelihood")
                            _v.ai_exploitability_public = analysis.get("exploitability_public")
                            _v.ai_exploitability_private = analysis.get("exploitability_private")
                            _v.ai_explanation = analysis.get("explanation")
                            _v.ai_fix_suggestion = analysis.get("fix_suggestion")
                            _v.ai_analyzed_at = datetime.utcnow()
                            _db.commit()
                    finally:
                        _db.close()

                    logger.debug(f"[AI] ✓ Vuln {vuln_id[:8]}...")
                except _asyncio.TimeoutError:
                    logger.warning(f"[AI] ⏱ Timeout vuln {vuln_id[:8]}... (>{analyzer.timeout}s)")
                except Exception as _e:
                    logger.error(f"[AI] ✗ Lỗi vuln {vuln_id[:8]}...: {_e}")
                finally:
                    done_count += 1
                    # Cập nhật progress mỗi 5 vuln hoặc lần cuối
                    if done_count % 5 == 0 or done_count == total:
                        _update_ai_progress(done_count, "analyzing")

        # Serialize vuln data trước (tránh SQLAlchemy session issues khi dùng async)
        vuln_snapshots = [
            (v.id, {
                "id": v.id,
                "tool": v.tool,
                "scan_type": v.scan_type.value if hasattr(v.scan_type, "value") else str(v.scan_type),
                "rule_id": v.rule_id or "",
                "title": v.title,
                "severity": v.severity.value if hasattr(v.severity, "value") else str(v.severity),
                "file_path": v.file_path or "",
                "line_start": v.line_start or 0,
                "description": (v.description or "")[:500],
                "code_snippet": (v.code_snippet or "")[:300],
                "cwe": v.cwe or "",
                "cve": v.cve or "",
                "package_name": v.package_name or "",
                "package_version": v.package_version or "",
                "fixed_version": v.fixed_version or "",
            })
            for v in vulns
        ]

        # Chạy tất cả concurrently (với semaphore limit = 3)
        tasks = [_analyze_one(vid, vdata) for vid, vdata in vuln_snapshots]
        await _asyncio.gather(*tasks, return_exceptions=True)

        # Đánh dấu AI done
        _update_ai_progress(total, "done")
        logger.info(f"[AI] ✔ Hoàn thành {done_count}/{total} vulns cho scan {scan_id}")

    except Exception as e:
        logger.error(f"[AI] Fatal error scan {scan_id}: {e}", exc_info=True)
        # Cập nhật status AI failed nhưng scan vẫn COMPLETED
        try:
            _db2 = SessionLocal()
            _scan2 = _db2.query(Scan).filter(Scan.id == scan_id).first()
            if _scan2 and _scan2.summary:
                s = dict(_scan2.summary)
                s["ai_status"] = "error"
                s["ai_error"] = str(e)[:200]
                _scan2.summary = s
                _db2.commit()
            _db2.close()
        except Exception:
            pass
    finally:
        db.close()



# ─────────────────────────────────────────────
# Scan Endpoints
# ─────────────────────────────────────────────

@router.post("/{project_id}/scans", response_model=ScanOut, status_code=202)
async def trigger_scan(
    project_id: str,
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project không tồn tại")

    # Rolling scan (max 5)
    scans = db.query(Scan).filter(Scan.project_id == project_id).order_by(Scan.scan_number).all()
    if len(scans) >= settings.max_scans_per_project:
        oldest = scans[0]
        db.delete(oldest)
        db.commit()
        scans = scans[1:]

    next_number = (scans[-1].scan_number + 1) if scans else 1

    scan = Scan(
        project_id=project_id,
        scan_number=next_number,
        scan_path=payload.scan_path,
        scan_types=[t.value for t in payload.scan_types],
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(
        _run_scan_background,
        scan.id,
        payload.scan_path,
        [t.value for t in payload.scan_types],
        payload.run_ai_analysis,
    )

    return scan


@router.get("/{project_id}/scans", response_model=List[ScanOut])
def list_scans(project_id: str, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project không tồn tại")
    return db.query(Scan).filter(Scan.project_id == project_id).order_by(Scan.scan_number.desc()).all()


@router.get("/scans/{scan_id}", response_model=ScanOut, tags=["scans"])
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan không tồn tại")
    return scan


@router.get("/scans/{scan_id}/progress", tags=["scans"])
def get_scan_progress(scan_id: str, db: Session = Depends(get_db)):
    """Live progress endpoint — poll mỗi 2s khi scan đang chạy.

    Response:
    {
      "scan_id": "...",
      "status": "RUNNING",
      "scan_path": "/app/myproject",
      "path_exists": true,
      "total_tools": 8,
      "completed_tools": 3,
      "percent": 37,
      "tools": {
        "bandit": {"status": "done", "count": 8, "duration_s": 1.2, "label": "Bandit (Python SAST)"},
        "semgrep": {"status": "running"},
        "pip-audit": {"status": "pending"},
        ...
      },
      "total_findings_so_far": 8,
      "error_message": null
    }
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan không tồn tại")

    progress = scan.scanner_progress or {}
    tools = progress.get("tools", {})
    total_tools = progress.get("total_tools", 0)
    completed_tools = progress.get("completed_tools", 0)

    # Tính tổng findings đã tìm được (chỉ các tools đã done)
    findings_so_far = sum(
        t.get("count", 0)
        for t in tools.values()
        if t.get("status") in ("done", "error")
    )

    percent = round((completed_tools / total_tools * 100) if total_tools > 0 else 0)
    if scan.status == ScanStatus.COMPLETED:
        percent = 100
    elif scan.status == ScanStatus.FAILED:
        percent = 0

    return {
        "scan_id": scan_id,
        "status": scan.status.value,
        "scan_path": scan.scan_path,
        "path_exists": os.path.exists(scan.scan_path),
        "total_tools": total_tools,
        "completed_tools": completed_tools,
        "percent": percent,
        "tools": tools,
        "total_findings_so_far": findings_so_far,
        "final_summary": scan.summary if scan.status == ScanStatus.COMPLETED else None,
        "error_message": scan.error_message,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
    }


@router.get("/scans/{scan_id}/vulns", response_model=List[VulnOut], tags=["scans"])
def get_scan_vulns(
    scan_id: str,
    severity: str = None,
    status: str = None,
    scan_type: str = None,
    db: Session = Depends(get_db)
):
    query = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id)
    if severity:
        query = query.filter(Vulnerability.severity == severity.upper())
    if status:
        query = query.filter(Vulnerability.status == status.upper())
    if scan_type:
        query = query.filter(Vulnerability.scan_type == scan_type.upper())
    return query.order_by(Vulnerability.severity).all()


# ─────────────────────────────────────────────
# Export Endpoints
# ─────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@router.get("/scans/{scan_id}/export", tags=["scans"])
def export_scan(
    scan_id: str,
    format: str = Query(default="json", pattern="^(json|csv)$"),
    severity: str = None,
    status: str = None,
    scan_type: str = None,
    db: Session = Depends(get_db)
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan không tồn tại")

    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail=f"Scan chưa hoàn thành (status: {scan.status.value})")

    query = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id)
    if severity:
        query = query.filter(Vulnerability.severity == severity.upper())
    if status:
        query = query.filter(Vulnerability.status == status.upper())
    if scan_type:
        query = query.filter(Vulnerability.scan_type == scan_type.upper())
    vulns = query.order_by(Vulnerability.severity).all()

    project = db.query(Project).filter(Project.id == scan.project_id).first()
    project_name = project.name if project else scan.project_id
    filename_base = f"vulnguard_{project_name}_{scan.scan_number}".replace(" ", "_")

    if format == "json":
        return _export_json(scan, vulns, project_name, filename_base)
    else:
        return _export_csv(scan, vulns, filename_base)


def _export_json(scan: Scan, vulns: list, project_name: str, filename_base: str) -> StreamingResponse:
    data = {
        "export_info": {
            "tool": "VulnGuard",
            "version": "1.0.0",
            "exported_at": datetime.utcnow().isoformat() + "Z",
        },
        "scan": {
            "id": scan.id,
            "project": project_name,
            "scan_number": scan.scan_number,
            "scan_path": scan.scan_path,
            "scan_types": scan.scan_types,
            "status": scan.status.value,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "summary": scan.summary or {},
        },
        "vulnerabilities": [
            {
                "id": v.id,
                "tool": v.tool,
                "scan_type": v.scan_type.value,
                "rule_id": v.rule_id,
                "title": v.title,
                "description": v.description,
                "severity": v.severity.value,
                "status": v.status.value,
                "file_path": v.file_path,
                "line_start": v.line_start,
                "line_end": v.line_end,
                "code_snippet": v.code_snippet,
                "cwe": v.cwe,
                "cve": v.cve,
                "cvss_score": v.cvss_score,
                "package_name": v.package_name,
                "package_version": v.package_version,
                "fixed_version": v.fixed_version,
                "fingerprint": v.fingerprint,
                "ai_false_positive_likelihood": v.ai_false_positive_likelihood,
                "ai_explanation": v.ai_explanation,
                "ai_fix_suggestion": v.ai_fix_suggestion,
                "waiver": {
                    "approver_name": v.waiver.approver_name,
                    "approver_email": v.waiver.approver_email,
                    "reason": v.waiver.reason,
                    "expiry_date": v.waiver.expiry_date.isoformat() if v.waiver.expiry_date else None,
                    "is_false_positive": v.waiver.is_false_positive,
                } if v.waiver else None,
                "created_at": v.created_at.isoformat() if v.created_at else None,
            }
            for v in vulns
        ],
    }
    content = json.dumps(data, ensure_ascii=False, indent=2)
    return StreamingResponse(
        io.BytesIO(content.encode("utf-8")),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename_base}.json"'},
    )


def _export_csv(scan: Scan, vulns: list, filename_base: str) -> StreamingResponse:
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_ALL)
    writer.writerow([
        "Severity", "Status", "Scan Type", "Tool",
        "Title", "CVE/Rule ID", "CWE", "CVSS Score",
        "File Path", "Line Start",
        "Package", "Package Version", "Fixed Version",
        "Description",
        "AI FP Likelihood", "AI Fix Suggestion",
        "Waiver Approver", "Waiver Reason",
        "Fingerprint",
    ])
    sorted_vulns = sorted(vulns, key=lambda v: SEVERITY_ORDER.get(v.severity.value, 99))
    for v in sorted_vulns:
        writer.writerow([
            v.severity.value, v.status.value, v.scan_type.value, v.tool,
            v.title, v.cve or v.rule_id or "", v.cwe or "", v.cvss_score or "",
            v.file_path or "", v.line_start or "",
            v.package_name or "", v.package_version or "", v.fixed_version or "",
            (v.description or "")[:500],
            v.ai_false_positive_likelihood or "",
            (v.ai_fix_suggestion or "")[:300],
            v.waiver.approver_name if v.waiver else "",
            v.waiver.reason if v.waiver else "",
            v.fingerprint or "",
        ])
    content = output.getvalue()
    return StreamingResponse(
        io.BytesIO(content.encode("utf-8-sig")),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename_base}.csv"'},
    )
