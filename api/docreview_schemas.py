from pydantic import BaseModel, Field, ConfigDict, model_validator
from typing import Optional, List, Any
from datetime import datetime

from api.docreview_models import DocType, ReviewStatus, VersionStatus, FindingStatus


# ─────────────────────────────────────────────
# Document Schemas
# ─────────────────────────────────────────────
class DocumentCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=300)
    doc_type: DocType
    description: Optional[str] = None


class DocumentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    doc_type: DocType
    description: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    version_count: int = 0
    latest_version: Optional["DocumentVersionOut"] = None

    @model_validator(mode="before")
    @classmethod
    def extract(cls, data: Any) -> Any:
        if isinstance(data, dict):
            return data
        if hasattr(data, "__tablename__"):
            versions = data.versions or []
            return {
                "id": data.id,
                "name": data.name,
                "doc_type": data.doc_type,
                "description": data.description,
                "created_at": data.created_at,
                "updated_at": data.updated_at,
                "version_count": len(versions),
                "latest_version": versions[-1] if versions else None,
            }
        return data


# ─────────────────────────────────────────────
# ReviewFinding Schemas
# ─────────────────────────────────────────────
class ReviewFindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    category: str
    criteria_id: str
    criteria_text: str
    status: FindingStatus
    evidence: Optional[str] = None
    recommendation: Optional[str] = None


# ─────────────────────────────────────────────
# DocumentVersion Schemas
# ─────────────────────────────────────────────
class DocumentVersionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    document_id: str
    version_number: int
    original_filename: str
    file_ext: Optional[str] = None
    file_size: Optional[int] = None
    extracted_text_length: Optional[int] = None
    extract_error: Optional[str] = None

    status: VersionStatus
    review_status: ReviewStatus
    review_error: Optional[str] = None
    review_started_at: Optional[datetime] = None
    review_completed_at: Optional[datetime] = None

    summary: Optional[dict] = None
    revision_note: Optional[str] = None
    sent_back_at: Optional[datetime] = None

    uploaded_at: datetime


class DocumentVersionDetail(DocumentVersionOut):
    findings: List[ReviewFindingOut] = []


class SendBackRequest(BaseModel):
    note: str = Field(..., min_length=5, description="Ghi chú gửi lại cho bên viết tài liệu — nêu rõ cần bổ sung gì")


class AcceptRequest(BaseModel):
    note: Optional[str] = None


class CompareFindingDiff(BaseModel):
    criteria_id: str
    category: str
    criteria_text: str
    old_status: Optional[FindingStatus] = None
    new_status: Optional[FindingStatus] = None


class VersionCompareResult(BaseModel):
    document_id: str
    old_version: DocumentVersionOut
    new_version: DocumentVersionOut
    improved: List[CompareFindingDiff] = []     # NOT_MET/PARTIAL -> MET hoặc cải thiện
    regressed: List[CompareFindingDiff] = []    # MET -> NOT_MET/PARTIAL (xấu đi)
    unchanged_not_met: List[CompareFindingDiff] = []  # vẫn NOT_MET/PARTIAL ở cả 2 lần


DocumentOut.model_rebuild()
