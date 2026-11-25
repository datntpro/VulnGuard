import asyncio
import csv
import io
import json
import os
import shutil
from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query, UploadFile, File, Form
from fastapi.responses import StreamingResponse, JSONResponse
from sqlalchemy.orm import Session

from api.database import get_db, SessionLocal
from api.models import Project, Scan, Vulnerability, ScanStatus, Severity, ACTIVE_VULN_STATUS_VALUES
from api.schemas import ScanCreate, ScanOut, VulnOut
from api.config import settings

router = APIRouter(prefix="/api/projects", tags=["scans"])

# Thứ tự ưu tiên hiển thị severity (CRITICAL trước, INFO sau cùng).
# Dùng để sort trong Python vì order_by(Vulnerability.severity) ở SQL chỉ
# sort theo thứ tự Enum khai báo trong DB, không phải theo mức độ nghiêm trọng.
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _compute_summary(vulns: List[Vulnerability]) -> dict:
    summary = {s.value: 0 for s in Severity}
    summary["total"] = 0
    summary["open"] = 0
    summary["accepted"] = 0
    summary["false_positive"] = 0

    for v in vulns:
        summary[v.severity.value] += 1
        summary["total"] += 1
        if v.status.value in ACTIVE_VULN_STATUS_VALUES:
            summary["open"] += 1
        elif v.status.value == "ACCEPTED":
            summary["accepted"] += 1
        elif v.status.value == "FALSE_POSITIVE":
            summary["false_positive"] += 1

    return summary


async def _run_scan_background(scan_id: str, scan_path: str, scan_types: list, run_ai: bool):
    """Chạy scan trong background với live progress updates."""
    from scanner.orchestrator import Orchestrator, TOOL_LABELS

    db = SessionLocal()
    completed_tools = {}  # tool_name -> log dict

    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        # ── Validate scan path ────────────────────────────────────────────
        if not os.path.exists(scan_path):
            from api.config import settings as _st
            if (_st.deploy_mode or "docker").lower() == "native":
                hint = (
                    "Đang chạy chế độ NATIVE — path phải tồn tại trên chính máy chạy VulnGuard "
                    "và tiến trình phải có quyền đọc. Kiểm tra lại đường dẫn tuyệt đối.\n"
                    "Mẹo: dùng tính năng upload .zip để quét mà không cần khai báo path."
                )
            else:
                hint = (
                    "Đang chạy chế độ DOCKER — path phải được mount vào container.\n"
                    "Ví dụ: thêm volume '-v /your/project:/scan' rồi dùng path '/scan'.\n"
                    "Mẹo: dùng tính năng upload .zip để quét mà không cần mount."
                )
            scan.status = ScanStatus.FAILED
            scan.error_message = f"Scan path không tồn tại trong môi trường chạy: '{scan_path}'\n{hint}"
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
            # Gói tri thức khai thác (EPSS/KEV) + nâng ưu tiên vào raw_output
            # (không cần cột DB mới) để VulnOut expose qua property.
            kb_meta = {k: finding[k] for k in (
                "epss", "epss_percentile", "kev", "kev_ransomware",
                "priority_reason", "severity_original") if finding.get(k) is not None}
            if isinstance(finding.get("kb"), dict):
                kb_meta.setdefault("kev_due_date", finding["kb"].get("kev_due_date"))
            raw = finding.get("raw")
            if kb_meta:
                raw = ({**raw, "_vulnguard_kb": kb_meta} if isinstance(raw, dict)
                       else {"_raw": raw, "_vulnguard_kb": kb_meta})
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
                raw_output=raw,
                fingerprint=finding.get("fingerprint"),
            )
            db.add(vuln)

        db.commit()
        db.refresh(scan)

        # ── Kế thừa triage từ scan trước (Checkmarx-style): finding đã đánh
        #    "Không khai thác được / Đã xác nhận / Chấp nhận" không phải triage lại ──
        try:
            import logging as _lg
            from api.services.triage import inherit_triage
            n_inherited = inherit_triage(db, scan)
            if n_inherited:
                _lg.getLogger(__name__).info(f"[triage] kế thừa {n_inherited} finding từ scan trước")
        except Exception as e:
            import logging as _lg
            _lg.getLogger(__name__).warning(f"[triage] kế thừa lỗi (bỏ qua): {e}")

        # ── Phase 1 DONE: Đánh dấu scan COMPLETED ngay (không đợi AI) ────
        # UI sẽ thấy kết quả scan ngay lập tức
        vulns_for_summary = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
        summary = _compute_summary(vulns_for_summary)
        summary["scanner_logs"] = scanner_logs
        # P0.1: đánh dấu cảnh báo nếu có công cụ BỊ BỎ QUA/LỖI — kết quả KHÔNG đầy đủ,
        # không được hiểu "0 lỗi = sạch".
        skipped = [t for t, l in scanner_logs.items() if l.get("status") == "skipped"]
        errored = [t for t, l in scanner_logs.items() if l.get("status") == "error"]
        summary["tools_skipped"] = skipped
        summary["tools_errored"] = errored
        if skipped or errored:
            summary["scan_warning"] = (
                "Kết quả KHÔNG đầy đủ — công cụ bị bỏ qua: "
                + (", ".join(skipped) or "—")
                + (("; lỗi: " + ", ".join(errored)) if errored else "")
            )
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
        _scan_row = db.query(Scan).filter(Scan.id == scan_id).first()
        scan_path = _scan_row.scan_path if _scan_row else ""   # cho cloud AI đọc ngữ cảnh code
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
                            _v.ai_false_positive_reason     = analysis.get("false_positive_reason")
                            _v.ai_exploitability_public     = analysis.get("exploitability_public")
                            _v.ai_exploitability_private    = analysis.get("exploitability_private")
                            _v.ai_explanation               = analysis.get("explanation")
                            _v.ai_fix_suggestion            = analysis.get("fix_suggestion")
                            _v.ai_analyzed_at               = datetime.utcnow()
                            _v.ai_provider                  = analysis.get("provider")
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
                "scan_path": scan_path,
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

# Lock per-project để tránh race condition (TOCTOU) khi 2 request tạo scan
# cho cùng 1 project chạy đồng thời: cả 2 có thể đọc cùng danh sách scans
# trước khi commit, tính trùng next_number, hoặc xóa nhầm 2 lần "scan cũ nhất".
# Lock này chỉ bảo vệ trong cùng 1 process (đủ cho local single-user tool;
# không cần thiết phải chống concurrency multi-worker/multi-instance).
_project_scan_locks: dict[str, asyncio.Lock] = {}


def _get_project_lock(project_id: str) -> asyncio.Lock:
    lock = _project_scan_locks.get(project_id)
    if lock is None:
        lock = asyncio.Lock()
        _project_scan_locks[project_id] = lock
    return lock


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

    from api.services.path_policy import PathNotAllowed, allowed_scan_roots, resolve_under_roots
    roots = allowed_scan_roots()
    try:
        real = resolve_under_roots(payload.scan_path, roots, "dir")
    except PathNotAllowed:
        raise HTTPException(status_code=400,
                            detail=f"scan_path phải nằm trong: {', '.join(roots)}")

    scan = await _create_and_run_scan(
        db, project_id, real,
        [t.value for t in payload.scan_types], payload.run_ai_analysis, background_tasks)
    return scan


async def _create_and_run_scan(db, project_id, scan_path, scan_types, run_ai, background_tasks):
    """Tạo Scan (rolling) + chạy nền. Dùng chung cho scan theo path và scan file upload."""
    async with _get_project_lock(project_id):
        scans = db.query(Scan).filter(Scan.project_id == project_id).order_by(Scan.scan_number).all()
        if len(scans) >= settings.max_scans_per_project:
            _remove_upload_dir(db, scans[0])
            db.delete(scans[0]); db.commit(); scans = scans[1:]
        next_number = (scans[-1].scan_number + 1) if scans else 1
        scan = Scan(project_id=project_id, scan_number=next_number, scan_path=scan_path,
                    scan_types=scan_types, status=ScanStatus.PENDING)
        db.add(scan); db.commit(); db.refresh(scan)
    background_tasks.add_task(_run_scan_background, scan.id, scan_path, scan_types, run_ai)
    return scan


def _remove_upload_dir(db, scan) -> None:
    """Xóa thư mục upload của scan bị xoay vòng. Chỉ xóa đúng
    scan_uploads/<project_id của scan>/<hex>, không khi scan còn đang chạy, và không khi
    scan khác vẫn tham chiếu thư mục đó."""
    try:
        uploads = os.path.realpath(os.path.join(settings.storage_dir, "scan_uploads"))
        real = os.path.realpath(scan.scan_path or "")
        if scan.status == ScanStatus.RUNNING:
            return
        if os.path.dirname(os.path.dirname(real)) != uploads or \
                os.path.basename(os.path.dirname(real)) != str(scan.project_id):
            return
        if db.query(Scan).filter(Scan.scan_path == scan.scan_path, Scan.id != scan.id).first():
            return
        shutil.rmtree(real, ignore_errors=True)
    except Exception:
        pass


class ZipLimitExceeded(ValueError):
    """Zip vượt giới hạn (số file, dung lượng giải nén, tỉ lệ nén)."""


def _precheck_central_directory(src, max_files: int) -> None:
    """Đếm record trong central directory MÀ KHÔNG dựng ZipInfo, bằng đúng cách CPython xác
    định vị trí CD (luôn dò Zip64 locator ngay trước EOCD). Không tin số entry khai báo.
    Vượt max_files → ZipLimitExceeded, TRƯỚC khi zipfile.ZipFile() ăn RAM."""
    import struct
    import zipfile
    opened = None
    f = src
    if isinstance(src, (str, os.PathLike)):
        opened = f = open(src, "rb")
    try:
        pos0 = f.tell()
        f.seek(0, os.SEEK_END)
        end = f.tell()
        tail_len = min(end, 22 + 0xFFFF)
        f.seek(end - tail_len)
        tail = f.read(tail_len)
        i = tail.rfind(b"PK\x05\x06")
        if i < 0 or len(tail) - i < 22:
            return  # để zipfile báo BadZipFile
        eocd_pos = end - tail_len + i
        cd_size = struct.unpack("<I", tail[i + 12:i + 16])[0]
        cd_end = eocd_pos
        if eocd_pos >= 76:  # luôn dò Zip64 như CPython (không phụ thuộc giá trị 0xFFFF)
            f.seek(eocd_pos - 20)
            if f.read(4) == b"PK\x06\x07":
                f.seek(eocd_pos - 76)
                rec = f.read(56)
                if len(rec) == 56 and rec[:4] == b"PK\x06\x06":
                    cd_size = struct.unpack("<Q", rec[40:48])[0]
                    cd_end = eocd_pos - 76
        start = cd_end - cd_size
        if start < 0:
            raise zipfile.BadZipFile("Bad offset for central directory")
        pos, count = start, 0
        while pos < cd_end:
            f.seek(pos)
            h = f.read(46)
            if len(h) < 46 or h[:4] != b"PK\x01\x02":
                raise zipfile.BadZipFile("Bad magic number for central directory")
            n, m, k = struct.unpack("<HHH", h[28:34])
            pos += 46 + n + m + k
            count += 1
            if count > max_files:
                raise ZipLimitExceeded(f"Zip có quá nhiều file (tối đa {max_files})")
        f.seek(pos0)
    finally:
        if opened:
            opened.close()


def _safe_extract_zip(src, dest_dir: str) -> int:
    """Giải nén zip vào dest_dir, CHỐNG zip-slip và zip bomb.
    `src`: bytes, đường dẫn hoặc file object. Trả số file đã giải nén.
    Vượt giới hạn → ZipLimitExceeded (caller xóa dest_dir)."""
    import zipfile
    max_files = settings.upload_max_files
    max_total = settings.upload_max_uncompressed_bytes
    max_ratio = settings.upload_max_ratio
    if isinstance(src, (bytes, bytearray)):
        src = io.BytesIO(src)
    _precheck_central_directory(src, max_files)
    os.makedirs(dest_dir, exist_ok=True)
    root = os.path.realpath(dest_dir)
    n = 0
    total = 0
    with zipfile.ZipFile(src) as zf:
        members = [i for i in zf.infolist() if not i.filename.endswith("/")]
        if len(members) > max_files:
            raise ZipLimitExceeded(f"Zip có quá nhiều file (tối đa {max_files})")
        declared = sum(i.file_size for i in members)
        if declared > max_total:
            raise ZipLimitExceeded("Dung lượng sau giải nén vượt giới hạn")
        for i in members:
            if i.file_size > (1 << 20) and i.compress_size > 0 \
                    and i.file_size / i.compress_size > max_ratio:
                raise ZipLimitExceeded("Tỉ lệ nén bất thường (nghi zip bomb)")
        os.makedirs(settings.storage_dir, exist_ok=True)
        if declared * 1.1 > shutil.disk_usage(settings.storage_dir).free:
            raise ZipLimitExceeded("Không đủ dung lượng đĩa để giải nén")
        for info in members:
            target = os.path.realpath(os.path.join(dest_dir, info.filename))
            if not (target == root or target.startswith(root + os.sep)):
                continue   # zip-slip: bỏ qua
            os.makedirs(os.path.dirname(target), exist_ok=True)
            written = 0
            with zf.open(info) as s, open(target, "wb") as out:
                while True:
                    chunk = s.read(1 << 20)
                    if not chunk:
                        break
                    written += len(chunk)
                    total += len(chunk)
                    if written > info.file_size or total > max_total:
                        raise ZipLimitExceeded("Dữ liệu giải nén vượt khai báo/giới hạn")
                    out.write(chunk)
            n += 1
    return n


@router.post("/{project_id}/scan-upload", response_model=ScanOut, status_code=202)
async def scan_upload(
    project_id: str,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    scan_types: str = Form("SAST,SCA,IAC,SECRETS"),
    run_ai_analysis: bool = Form(True),
    db: Session = Depends(get_db),
):
    """Upload 1 file .zip mã nguồn → giải nén an toàn → tạo scan trên đó."""
    from api.models import ScanType
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project không tồn tại")
    if not (file.filename or "").lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Chỉ chấp nhận file .zip")
    # validate scan_types
    valid = {t.value for t in ScanType}
    types = [t.strip().upper() for t in scan_types.split(",") if t.strip().upper() in valid] or ["SAST"]

    import tempfile
    import uuid as _uuid
    tmp_root = os.path.join(settings.storage_dir, "tmp")
    os.makedirs(tmp_root, exist_ok=True)
    dest = os.path.join(settings.storage_dir, "scan_uploads", project_id, _uuid.uuid4().hex)
    fd, tmp_path = tempfile.mkstemp(prefix="upload_", suffix=".zip", dir=tmp_root)
    try:
        size = 0
        with os.fdopen(fd, "wb") as tmp:
            while True:
                chunk = await file.read(1 << 20)
                if not chunk:
                    break
                size += len(chunk)
                if size > settings.upload_max_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail=f"File quá lớn (tối đa {settings.upload_max_bytes // (1024 * 1024)}MB)")
                tmp.write(chunk)
        try:
            count = _safe_extract_zip(tmp_path, dest)
        except ZipLimitExceeded as e:
            shutil.rmtree(dest, ignore_errors=True)
            raise HTTPException(status_code=413, detail=f"Zip vượt giới hạn: {e}")
        except Exception as e:
            shutil.rmtree(dest, ignore_errors=True)
            raise HTTPException(status_code=400, detail=f"Không giải nén được zip: {str(e)[:200]}")
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
    if count == 0:
        shutil.rmtree(dest, ignore_errors=True)
        raise HTTPException(status_code=400, detail="Zip rỗng hoặc mọi file bị chặn (zip-slip)")

    scan = await _create_and_run_scan(db, project_id, dest, types, run_ai_analysis, background_tasks)
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


def _validate_vuln_filters(severity: str = None, status: str = None, scan_type: str = None):
    """Validate filter query params against các Enum hợp lệ.

    Trước đây giá trị không hợp lệ (vd ?status=bogus) bị âm thầm filter ra
    danh sách rỗng thay vì báo lỗi rõ ràng cho client — gây khó debug ở UI.
    """
    from api.models import Severity, VulnStatus, ScanType

    if severity and severity.upper() not in {s.value for s in Severity}:
        raise HTTPException(status_code=400, detail=f"severity không hợp lệ: '{severity}'")
    if status and status.upper() not in {s.value for s in VulnStatus}:
        raise HTTPException(status_code=400, detail=f"status không hợp lệ: '{status}'")
    if scan_type and scan_type.upper() not in {s.value for s in ScanType}:
        raise HTTPException(status_code=400, detail=f"scan_type không hợp lệ: '{scan_type}'")


@router.get("/scans/{scan_id}/vulns", response_model=List[VulnOut], tags=["scans"])
def get_scan_vulns(
    scan_id: str,
    severity: str = None,
    status: str = None,
    scan_type: str = None,
    db: Session = Depends(get_db)
):
    _validate_vuln_filters(severity, status, scan_type)

    query = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id)
    if severity:
        query = query.filter(Vulnerability.severity == severity.upper())
    if status:
        query = query.filter(Vulnerability.status == status.upper())
    if scan_type:
        query = query.filter(Vulnerability.scan_type == scan_type.upper())
    # Sort theo mức độ nghiêm trọng thật (CRITICAL → INFO), không phải theo
    # thứ tự Enum trong DB — order_by(Vulnerability.severity) ở SQL không
    # đảm bảo đúng thứ tự này.
    vulns = query.all()
    vulns.sort(key=lambda v: SEVERITY_ORDER.get(v.severity.value, 99))
    return vulns


# ─────────────────────────────────────────────
# Export Endpoints
# ─────────────────────────────────────────────


@router.get("/scans/{scan_id}/export", tags=["scans"])
def export_scan(
    scan_id: str,
    format: str = Query(default="json", pattern="^(json|csv|pdf|md|ai|sarif)$"),
    severity: str = None,
    status: str = None,
    scan_type: str = None,
    diff: str = Query(default="all", pattern="^(all|new|recurrent)$"),
    scope: str = Query(default="all", pattern="^(all|active)$"),
    db: Session = Depends(get_db)
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan không tồn tại")

    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail=f"Scan chưa hoàn thành (status: {scan.status.value})")

    _validate_vuln_filters(severity, status, scan_type)

    query = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id)
    if severity:
        query = query.filter(Vulnerability.severity == severity.upper())
    if status:
        query = query.filter(Vulnerability.status == status.upper())
    if scan_type:
        query = query.filter(Vulnerability.scan_type == scan_type.upper())
    # Sort theo severity rank thật (CRITICAL → INFO) — giống _export_csv,
    # tránh JSON export trả vulns theo thứ tự Enum DB không liên quan tới mức độ nghiêm trọng.
    vulns = sorted(query.all(), key=lambda v: SEVERITY_ORDER.get(v.severity.value, 99))

    # Lọc theo phạm vi báo cáo (Checkmarx-style): New/Recurrent + chỉ còn mở
    if scope == "active":
        vulns = [v for v in vulns if v.status.value in ACTIVE_VULN_STATUS_VALUES]
    if diff == "new":
        vulns = [v for v in vulns if (not v.first_seen_scan_id) or v.first_seen_scan_id == scan_id]
    elif diff == "recurrent":
        vulns = [v for v in vulns if v.first_seen_scan_id and v.first_seen_scan_id != scan_id]

    project = db.query(Project).filter(Project.id == scan.project_id).first()
    project_name = project.name if project else scan.project_id
    filename_base = f"vulnguard_{project_name}_{scan.scan_number}".replace(" ", "_")

    if format == "json":
        return _export_json(scan, vulns, project_name, filename_base)
    if format == "csv":
        return _export_csv(scan, vulns, filename_base)
    # Nhãn phạm vi báo cáo (Checkmarx-style)
    _diff_lbl = {"all": "Tất cả", "new": "Chỉ lỗ hổng MỚI", "recurrent": "Chỉ lỗ hổng TÁI XUẤT HIỆN"}
    scope_note = None
    if diff != "all" or scope != "all":
        scope_note = _diff_lbl[diff] + ("; chỉ còn mở (active)" if scope == "active" else "")

    # PDF / Markdown / AI-JSON — dùng scanner/report_builder
    from scanner import report_builder as rb
    if format == "pdf":
        data = rb.build_pdf(scan, vulns, project_name, scope_note=scope_note)
        return StreamingResponse(iter([data]), media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename_base}.pdf"'})
    if format == "md":
        text = rb.build_markdown(scan, vulns, project_name)
        return StreamingResponse(iter([text.encode("utf-8")]), media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename_base}.md"'})
    if format == "sarif":
        text = rb.build_sarif(scan, vulns, project_name)
        return StreamingResponse(iter([text.encode("utf-8")]), media_type="application/sarif+json; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename_base}.sarif"'})
    # ai — JSON tối giản cho LLM (mở xem được trên trình duyệt, không ép tải)
    text = rb.build_ai_json(scan, vulns, project_name)
    return StreamingResponse(iter([text.encode("utf-8")]), media_type="application/json; charset=utf-8",
        headers={"Content-Disposition": f'inline; filename="{filename_base}.ai.json"'})


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
                "ai_provider": v.ai_provider,
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
