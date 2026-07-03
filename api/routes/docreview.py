"""
Document Review API — review tài liệu phát triển hệ thống (SRS/FRS/BRD, HLD/LLD,
đặc tả API/DB schema) theo checklist an toàn thông tin (OWASP ASVS-based), dùng AI
local (Ollama). Hỗ trợ versioning: mỗi lần bên viết tài liệu cập nhật, upload version
mới gắn vào cùng Document để theo dõi tiến triển qua các lần review.

Luồng chính:
  1. POST /documents                       — tạo Document mới + upload version 1
  2. POST /documents/{id}/versions         — upload version mới (sau khi đã gửi-lại-sửa)
  3. POST /versions/{id}/review             — trigger AI review (background)
  4. GET  /versions/{id}                    — xem kết quả review (kèm findings)
  5. PATCH /versions/{id}/send-back         — gửi lại bên viết tài liệu kèm ghi chú
  6. PATCH /versions/{id}/accept            — chấp nhận tài liệu (đủ an toàn thông tin)
  7. GET  /documents/{id}/compare           — so sánh 2 version để xem cải thiện/regression
  8. GET  /versions/{id}/export             — xuất báo cáo HTML
"""
import os
from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, UploadFile, File, Form, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
import io

from api.database import get_db, SessionLocal
from api.docreview_models import (
    Document, DocumentVersion, ReviewFinding,
    DocType, ReviewStatus, VersionStatus, FindingStatus,
)
from api.docreview_schemas import (
    DocumentCreate, DocumentOut, DocumentVersionOut, DocumentVersionDetail,
    SendBackRequest, AcceptRequest, VersionCompareResult, CompareFindingDiff,
)
from scanner.doc_checklist import get_checklist, list_doc_types, DOC_TYPE_LABELS

router = APIRouter(prefix="/api/docreview", tags=["docreview"])

STORAGE_DIR = os.environ.get("DOCREVIEW_STORAGE_DIR", "/app/storage/documents")
MAX_FILE_SIZE = 25 * 1024 * 1024  # 25MB — đủ cho hầu hết SRS/HLD dạng pdf/docx


def _ensure_storage():
    os.makedirs(STORAGE_DIR, exist_ok=True)


def _compute_summary(findings: List[ReviewFinding]) -> dict:
    summary = {"met": 0, "partial": 0, "not_met": 0, "not_applicable": 0, "total": 0}
    for f in findings:
        key = f.status.value.lower()
        if key in summary:
            summary[key] += 1
        summary["total"] += 1

    applicable = summary["total"] - summary["not_applicable"]
    if applicable > 0:
        # Điểm: MET = 1 điểm, PARTIAL = 0.5 điểm, NOT_MET = 0 điểm — trên tổng tiêu chí áp dụng
        score = (summary["met"] + 0.5 * summary["partial"]) / applicable * 100
        summary["score_pct"] = round(score, 1)
    else:
        summary["score_pct"] = None

    return summary


# ─────────────────────────────────────────────
# Doc types / checklist metadata
# ─────────────────────────────────────────────
@router.get("/doc-types")
def get_doc_types():
    return {"doc_types": list_doc_types()}


# ─────────────────────────────────────────────
# Document CRUD
# ─────────────────────────────────────────────
@router.get("/documents", response_model=List[DocumentOut])
def list_documents(db: Session = Depends(get_db)):
    return db.query(Document).order_by(Document.updated_at.desc()).all()


@router.get("/documents/{document_id}", response_model=DocumentOut)
def get_document(document_id: str, db: Session = Depends(get_db)):
    doc = db.query(Document).filter(Document.id == document_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Tài liệu không tồn tại")
    return doc


@router.delete("/documents/{document_id}", status_code=204)
def delete_document(document_id: str, db: Session = Depends(get_db)):
    doc = db.query(Document).filter(Document.id == document_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Tài liệu không tồn tại")

    # Xóa file vật lý của tất cả version trước khi xóa record
    for v in doc.versions:
        try:
            if v.stored_path and os.path.exists(v.stored_path):
                os.remove(v.stored_path)
        except Exception:
            pass

    db.delete(doc)
    db.commit()
    return None


@router.get("/documents/{document_id}/versions", response_model=List[DocumentVersionOut])
def list_versions(document_id: str, db: Session = Depends(get_db)):
    doc = db.query(Document).filter(Document.id == document_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Tài liệu không tồn tại")
    return db.query(DocumentVersion).filter(
        DocumentVersion.document_id == document_id
    ).order_by(DocumentVersion.version_number.desc()).all()


# ─────────────────────────────────────────────
# Upload — tạo Document mới (version 1) hoặc thêm version mới vào Document có sẵn
# ─────────────────────────────────────────────
def _save_upload(document_id: str, version_number: int, file: UploadFile, content: bytes) -> tuple[str, str]:
    _ensure_storage()
    doc_dir = os.path.join(STORAGE_DIR, document_id)
    os.makedirs(doc_dir, exist_ok=True)

    _, ext = os.path.splitext(file.filename or "")
    ext = ext.lower()
    safe_name = f"v{version_number}{ext}"
    stored_path = os.path.join(doc_dir, safe_name)

    with open(stored_path, "wb") as f:
        f.write(content)

    return stored_path, ext


async def _read_and_validate_upload(file: UploadFile) -> bytes:
    from scanner.doc_extractor import is_supported

    if not is_supported(file.filename or ""):
        raise HTTPException(
            status_code=400,
            detail="Định dạng file không được hỗ trợ — chỉ hỗ trợ .pdf, .docx, .md, .txt",
        )

    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail=f"File quá lớn — giới hạn {MAX_FILE_SIZE // (1024*1024)}MB")
    if not content:
        raise HTTPException(status_code=400, detail="File rỗng")

    return content


def _create_version_record(db: Session, document_id: str, version_number: int, file: UploadFile, content: bytes) -> DocumentVersion:
    stored_path, ext = _save_upload(document_id, version_number, file, content)

    from scanner.doc_extractor import extract_text
    text, extract_error = extract_text(stored_path, ext)

    version = DocumentVersion(
        document_id=document_id,
        version_number=version_number,
        original_filename=file.filename or f"version_{version_number}{ext}",
        stored_path=stored_path,
        file_ext=ext,
        file_size=len(content),
        extracted_text_length=len(text) if text else 0,
        extract_error=extract_error,
        status=VersionStatus.UPLOADED,
        review_status=ReviewStatus.NOT_REVIEWED,
    )
    db.add(version)
    return version


@router.post("/documents", response_model=DocumentVersionDetail, status_code=201)
async def create_document(
    background_tasks: BackgroundTasks,
    name: str = Form(...),
    doc_type: DocType = Form(...),
    description: str = Form(None),
    auto_review: bool = Form(True),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """Tạo tài liệu mới + upload version 1. auto_review=True sẽ tự trigger AI review."""
    content = await _read_and_validate_upload(file)

    doc = Document(name=name, doc_type=doc_type, description=description)
    db.add(doc)
    db.flush()  # cần doc.id trước khi tạo version

    version = _create_version_record(db, doc.id, 1, file, content)
    db.commit()
    db.refresh(version)

    if auto_review and not version.extract_error:
        version.review_status = ReviewStatus.PENDING
        db.commit()
        db.refresh(version)
        background_tasks.add_task(_run_review_background, version.id)

    return DocumentVersionDetail(**DocumentVersionOut.model_validate(version).model_dump(), findings=[])


@router.post("/documents/{document_id}/versions", response_model=DocumentVersionDetail, status_code=201)
async def upload_new_version(
    document_id: str,
    background_tasks: BackgroundTasks,
    auto_review: bool = Form(True),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """Upload version mới cho tài liệu đã có — dùng khi bên viết tài liệu đã cập nhật
    sau khi nhận lại ghi chú revision (send-back)."""
    doc = db.query(Document).filter(Document.id == document_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Tài liệu không tồn tại")

    content = await _read_and_validate_upload(file)

    existing = db.query(DocumentVersion).filter(DocumentVersion.document_id == document_id).order_by(
        DocumentVersion.version_number.desc()
    ).first()
    next_number = (existing.version_number + 1) if existing else 1

    version = _create_version_record(db, document_id, next_number, file, content)
    doc.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(version)

    if auto_review and not version.extract_error:
        version.review_status = ReviewStatus.PENDING
        db.commit()
        db.refresh(version)
        background_tasks.add_task(_run_review_background, version.id)

    return DocumentVersionDetail(**DocumentVersionOut.model_validate(version).model_dump(), findings=[])


# ─────────────────────────────────────────────
# Version detail + trigger review
# ─────────────────────────────────────────────
@router.get("/versions/{version_id}", response_model=DocumentVersionDetail)
def get_version(version_id: str, db: Session = Depends(get_db)):
    version = db.query(DocumentVersion).filter(DocumentVersion.id == version_id).first()
    if not version:
        raise HTTPException(status_code=404, detail="Version không tồn tại")

    findings = db.query(ReviewFinding).filter(ReviewFinding.version_id == version_id).all()
    return DocumentVersionDetail(
        **DocumentVersionOut.model_validate(version).model_dump(),
        findings=findings,
    )


async def _run_review_background(version_id: str):
    """Chạy AI review trong background — tách session riêng (giống pattern
    _run_ai_analysis trong scans.py / domains.py)."""
    import logging
    from scanner.doc_reviewer import DocReviewer
    from scanner.doc_checklist import get_checklist, DOC_TYPE_LABELS
    from scanner.doc_extractor import extract_text

    logger = logging.getLogger(__name__)
    db = SessionLocal()
    try:
        version = db.query(DocumentVersion).filter(DocumentVersion.id == version_id).first()
        if not version:
            return

        version.review_status = ReviewStatus.RUNNING
        version.review_started_at = datetime.utcnow()
        version.status = VersionStatus.UNDER_REVIEW
        db.commit()

        doc = db.query(Document).filter(Document.id == version.document_id).first()
        doc_type = doc.doc_type if doc else DocType.OTHER

        text, extract_error = extract_text(version.stored_path, version.file_ext)
        if extract_error or not text:
            version = db.query(DocumentVersion).filter(DocumentVersion.id == version_id).first()
            version.review_status = ReviewStatus.FAILED
            version.review_error = extract_error or "Không trích xuất được nội dung tài liệu"
            version.review_completed_at = datetime.utcnow()
            db.commit()
            return

        checklist = get_checklist(doc_type)
        reviewer = DocReviewer()
        findings_data = await reviewer.review(text, DOC_TYPE_LABELS.get(doc_type, "Tài liệu"), checklist)

        version = db.query(DocumentVersion).filter(DocumentVersion.id == version_id).first()
        if not version:
            return

        # Xóa findings cũ (nếu review lại) rồi ghi findings mới
        db.query(ReviewFinding).filter(ReviewFinding.version_id == version_id).delete()

        findings_orm = []
        for f in findings_data:
            finding = ReviewFinding(
                version_id=version_id,
                category=f["category"],
                criteria_id=f["criteria_id"],
                criteria_text=f["criteria_text"],
                status=FindingStatus(f["status"]),
                evidence=f.get("evidence"),
                recommendation=f.get("recommendation"),
            )
            db.add(finding)
            findings_orm.append(finding)

        version.summary = _compute_summary(findings_orm)
        version.review_status = ReviewStatus.DONE
        version.review_completed_at = datetime.utcnow()
        version.review_error = None
        db.commit()

    except Exception as e:
        logger.error(f"Doc review {version_id} failed: {e}", exc_info=True)
        version = db.query(DocumentVersion).filter(DocumentVersion.id == version_id).first()
        if version:
            version.review_status = ReviewStatus.FAILED
            version.review_error = str(e)[:500]
            version.review_completed_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()


@router.post("/versions/{version_id}/review", response_model=DocumentVersionOut, status_code=202)
async def trigger_review(
    version_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Trigger (hoặc re-trigger) AI review cho 1 version — dùng khi upload không tự
    review, hoặc muốn review lại."""
    version = db.query(DocumentVersion).filter(DocumentVersion.id == version_id).first()
    if not version:
        raise HTTPException(status_code=404, detail="Version không tồn tại")
    if version.review_status == ReviewStatus.RUNNING:
        raise HTTPException(status_code=409, detail="Đang review version này, vui lòng đợi")
    if version.extract_error:
        raise HTTPException(status_code=400, detail=f"Không thể review — lỗi đọc file: {version.extract_error}")

    version.review_status = ReviewStatus.PENDING
    version.review_error = None
    db.commit()
    db.refresh(version)

    background_tasks.add_task(_run_review_background, version_id)
    return version


@router.get("/versions/{version_id}/progress")
def get_review_progress(version_id: str, db: Session = Depends(get_db)):
    version = db.query(DocumentVersion).filter(DocumentVersion.id == version_id).first()
    if not version:
        raise HTTPException(status_code=404, detail="Version không tồn tại")
    return {
        "version_id": version_id,
        "review_status": version.review_status.value,
        "review_error": version.review_error,
        "summary": version.summary,
    }


# ─────────────────────────────────────────────
# Send-back / Accept workflow
# ─────────────────────────────────────────────
@router.patch("/versions/{version_id}/send-back", response_model=DocumentVersionOut)
def send_back(version_id: str, payload: SendBackRequest, db: Session = Depends(get_db)):
    """Gửi lại tài liệu cho bên viết tài liệu cập nhật, kèm ghi chú yêu cầu bổ sung.
    Bên viết tài liệu cập nhật xong sẽ upload version mới qua
    POST /documents/{id}/versions."""
    version = db.query(DocumentVersion).filter(DocumentVersion.id == version_id).first()
    if not version:
        raise HTTPException(status_code=404, detail="Version không tồn tại")

    version.status = VersionStatus.SENT_FOR_REVISION
    version.revision_note = payload.note
    version.sent_back_at = datetime.utcnow()
    db.commit()
    db.refresh(version)
    return version


@router.patch("/versions/{version_id}/accept", response_model=DocumentVersionOut)
def accept_version(version_id: str, payload: AcceptRequest, db: Session = Depends(get_db)):
    """Chấp nhận tài liệu — đã đáp ứng đủ yêu cầu an toàn thông tin cần thiết."""
    version = db.query(DocumentVersion).filter(DocumentVersion.id == version_id).first()
    if not version:
        raise HTTPException(status_code=404, detail="Version không tồn tại")

    version.status = VersionStatus.ACCEPTED
    if payload.note:
        version.revision_note = payload.note
    db.commit()
    db.refresh(version)
    return version


# ─────────────────────────────────────────────
# Compare 2 versions — xem tiến triển sau khi bên viết tài liệu cập nhật
# ─────────────────────────────────────────────
@router.get("/documents/{document_id}/compare", response_model=VersionCompareResult)
def compare_versions(
    document_id: str,
    old_version: int = Query(..., description="Số version cũ"),
    new_version: int = Query(..., description="Số version mới"),
    db: Session = Depends(get_db),
):
    doc = db.query(Document).filter(Document.id == document_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Tài liệu không tồn tại")

    v_old = db.query(DocumentVersion).filter(
        DocumentVersion.document_id == document_id, DocumentVersion.version_number == old_version
    ).first()
    v_new = db.query(DocumentVersion).filter(
        DocumentVersion.document_id == document_id, DocumentVersion.version_number == new_version
    ).first()
    if not v_old or not v_new:
        raise HTTPException(status_code=404, detail="Version không tồn tại")

    old_findings = {f.criteria_id: f for f in db.query(ReviewFinding).filter(ReviewFinding.version_id == v_old.id)}
    new_findings = {f.criteria_id: f for f in db.query(ReviewFinding).filter(ReviewFinding.version_id == v_new.id)}

    rank = {"NOT_MET": 0, "PARTIAL": 1, "NOT_APPLICABLE": 1, "MET": 2}

    improved, regressed, unchanged_not_met = [], [], []
    for cid, nf in new_findings.items():
        of = old_findings.get(cid)
        diff = CompareFindingDiff(
            criteria_id=cid, category=nf.category, criteria_text=nf.criteria_text,
            old_status=of.status if of else None, new_status=nf.status,
        )
        if not of:
            continue
        old_rank, new_rank = rank.get(of.status.value, 0), rank.get(nf.status.value, 0)
        if new_rank > old_rank:
            improved.append(diff)
        elif new_rank < old_rank:
            regressed.append(diff)
        elif nf.status in (FindingStatus.NOT_MET, FindingStatus.PARTIAL):
            unchanged_not_met.append(diff)

    return VersionCompareResult(
        document_id=document_id,
        old_version=v_old, new_version=v_new,
        improved=improved, regressed=regressed, unchanged_not_met=unchanged_not_met,
    )


# ─────────────────────────────────────────────
# Export báo cáo HTML
# ─────────────────────────────────────────────
@router.get("/versions/{version_id}/export")
def export_version_report(version_id: str, download: bool = False, db: Session = Depends(get_db)):
    from scanner.doc_review_report import build_report_html

    version = db.query(DocumentVersion).filter(DocumentVersion.id == version_id).first()
    if not version:
        raise HTTPException(status_code=404, detail="Version không tồn tại")
    doc = db.query(Document).filter(Document.id == version.document_id).first()
    findings = db.query(ReviewFinding).filter(ReviewFinding.version_id == version_id).order_by(ReviewFinding.category).all()

    html = build_report_html(doc, version, findings)

    if download:
        filename = f"docreview_{(doc.name if doc else 'document').replace(' ', '_')}_v{version.version_number}.html"
        return StreamingResponse(
            io.BytesIO(html.encode("utf-8")),
            media_type="text/html",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=html)
