"""
Module riêng cho tính năng "Document Review" — review tài liệu phát triển hệ thống
(SRS/FRS/BRD, thiết kế kiến trúc HLD/LLD, đặc tả API/DB schema...) theo tiêu chí
an toàn thông tin (OWASP ASVS-based checklist), có versioning để theo dõi tài liệu
đã được bên viết tài liệu cập nhật/bổ sung qua các lần review.

Tách riêng khỏi api/models.py (Project/Scan/Vulnerability) — dùng chung Base/engine,
theo đúng pattern của api/domain_models.py (tính năng Domain Sitemap).

Quan hệ:
  Document (1) ──< DocumentVersion (N, rolling theo lần upload)
  DocumentVersion (1) ──< ReviewFinding (N, mỗi finding = 1 tiêu chí ASVS được AI đánh giá)
"""
from sqlalchemy import (
    Column, String, Integer, DateTime, Text, Enum, ForeignKey, JSON
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
import enum

from api.database import Base


def gen_id():
    return str(uuid.uuid4())


class DocType(str, enum.Enum):
    SRS_FRS_BRD = "SRS_FRS_BRD"          # Đặc tả yêu cầu (SRS/FRS/BRD)
    ARCHITECTURE = "ARCHITECTURE"         # Thiết kế kiến trúc (HLD/LLD)
    API_DB_SCHEMA = "API_DB_SCHEMA"       # Đặc tả API / DB schema
    OTHER = "OTHER"                       # Loại khác — dùng checklist chung


class ReviewStatus(str, enum.Enum):
    NOT_REVIEWED = "NOT_REVIEWED"
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    DONE = "DONE"
    FAILED = "FAILED"


class VersionStatus(str, enum.Enum):
    """Trạng thái xử lý của 1 version tài liệu trong vòng đời review."""
    UPLOADED = "UPLOADED"                 # Mới upload, chưa review
    UNDER_REVIEW = "UNDER_REVIEW"         # Đang/đã review, đang chờ quyết định
    SENT_FOR_REVISION = "SENT_FOR_REVISION"  # Đã gửi lại bên viết tài liệu để cập nhật
    ACCEPTED = "ACCEPTED"                 # Đã đáp ứng đủ an toàn thông tin, chấp nhận


class FindingStatus(str, enum.Enum):
    MET = "MET"                     # Đã đáp ứng
    PARTIAL = "PARTIAL"             # Đáp ứng một phần
    NOT_MET = "NOT_MET"             # Chưa đáp ứng
    NOT_APPLICABLE = "NOT_APPLICABLE"  # Không áp dụng cho tài liệu này


# ─────────────────────────────────────────────
class Document(Base):
    __tablename__ = "review_documents"

    id = Column(String, primary_key=True, default=gen_id)
    name = Column(String(300), nullable=False)             # Tên gợi nhớ, vd "SRS - Hệ thống thanh toán"
    doc_type = Column(Enum(DocType), nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    versions = relationship(
        "DocumentVersion", back_populates="document",
        cascade="all, delete-orphan", order_by="DocumentVersion.version_number",
    )


# ─────────────────────────────────────────────
class DocumentVersion(Base):
    __tablename__ = "review_document_versions"

    id = Column(String, primary_key=True, default=gen_id)
    document_id = Column(String, ForeignKey("review_documents.id"), nullable=False)
    version_number = Column(Integer, nullable=False)        # 1, 2, 3... tăng dần, không rolling-xóa (cần giữ lịch sử)

    original_filename = Column(String(500), nullable=False)
    stored_path = Column(String(1000), nullable=False)      # path thật trong storage/documents/...
    file_ext = Column(String(20), nullable=True)             # pdf/docx/md/txt
    file_size = Column(Integer, nullable=True)               # bytes
    extracted_text_length = Column(Integer, nullable=True)
    extract_error = Column(Text, nullable=True)               # lỗi extract text (nếu có)

    status = Column(Enum(VersionStatus), default=VersionStatus.UPLOADED)
    review_status = Column(Enum(ReviewStatus), default=ReviewStatus.NOT_REVIEWED)
    review_error = Column(Text, nullable=True)
    review_started_at = Column(DateTime, nullable=True)
    review_completed_at = Column(DateTime, nullable=True)

    # Tổng hợp kết quả review — tính lại mỗi khi review xong, tránh phải
    # COUNT() lại findings mỗi lần hiển thị danh sách version.
    summary = Column(JSON, nullable=True)   # {met, partial, not_met, not_applicable, total, score_pct}

    # Ghi chú khi gửi lại cho bên viết tài liệu cập nhật (versioning workflow)
    revision_note = Column(Text, nullable=True)
    sent_back_at = Column(DateTime, nullable=True)

    uploaded_at = Column(DateTime, server_default=func.now())

    document = relationship("Document", back_populates="versions")
    findings = relationship(
        "ReviewFinding", back_populates="version", cascade="all, delete-orphan",
    )


# ─────────────────────────────────────────────
class ReviewFinding(Base):
    __tablename__ = "review_findings"

    id = Column(String, primary_key=True, default=gen_id)
    version_id = Column(String, ForeignKey("review_document_versions.id"), nullable=False)

    category = Column(String(200), nullable=False)          # vd "Xác thực & Quản lý phiên (ASVS V2/V3)"
    criteria_id = Column(String(50), nullable=False)         # vd "ASVS-2.1.1"
    criteria_text = Column(Text, nullable=False)             # Nội dung tiêu chí (tiếng Việt)

    status = Column(Enum(FindingStatus), nullable=False, default=FindingStatus.NOT_MET)
    evidence = Column(Text, nullable=True)                   # Trích đoạn/lý do AI tìm thấy trong tài liệu
    recommendation = Column(Text, nullable=True)             # Gợi ý bổ sung/sửa cho bên viết tài liệu

    created_at = Column(DateTime, server_default=func.now())

    version = relationship("DocumentVersion", back_populates="findings")
