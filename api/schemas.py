from pydantic import BaseModel, Field, model_validator, ConfigDict
from typing import Optional, List, Any
from datetime import datetime
from api.models import ScanStatus, Severity, VulnStatus, ScanType


# ─────────────────────────────────────────────
# Project Schemas
# ─────────────────────────────────────────────
class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    language_stacks: List[str] = []


class ProjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: Optional[str]
    language_stacks: List[str]
    created_at: datetime
    scan_count: int = 0

    @model_validator(mode="before")
    @classmethod
    def extract_scan_count(cls, data: Any) -> Any:
        """Tự động tính scan_count từ SQLAlchemy relationship khi validate ORM object."""
        if isinstance(data, dict):
            return data  # Đã là dict, dùng nguyên

        # SQLAlchemy ORM object — trích xuất thủ công
        if hasattr(data, "__tablename__"):
            return {
                "id": data.id,
                "name": data.name,
                "description": data.description,
                "language_stacks": data.language_stacks or [],
                "created_at": data.created_at,
                "scan_count": len(data.scans) if data.scans is not None else 0,
            }
        return data


# ─────────────────────────────────────────────
# Scan Schemas
# ─────────────────────────────────────────────
class ScanCreate(BaseModel):
    scan_path: str = Field(..., description="Đường dẫn thư mục cần scan (trong container)")
    scan_types: List[ScanType] = Field(
        default=[ScanType.SAST, ScanType.SCA, ScanType.SECRETS, ScanType.IAC],
        description="Loại scan cần thực hiện"
    )
    run_ai_analysis: bool = True


class ScanSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0
    open: int = 0
    accepted: int = 0
    false_positive: int = 0


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    scan_number: int
    scan_path: str
    scan_types: List[str]
    status: ScanStatus
    started_at: datetime
    completed_at: Optional[datetime]
    error_message: Optional[str]
    summary: Optional[dict]
    scanner_progress: Optional[dict] = None


# ─────────────────────────────────────────────
# Vulnerability Schemas
# ─────────────────────────────────────────────
class WaiverOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    approver_name: str
    approver_email: Optional[str]
    reason: str
    expiry_date: Optional[datetime]
    is_false_positive: bool
    created_at: datetime


class VulnOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    tool: str
    scan_type: ScanType
    rule_id: Optional[str]
    title: str
    description: Optional[str]
    severity: Severity
    file_path: Optional[str]
    line_start: Optional[int]
    line_end: Optional[int]
    code_snippet: Optional[str]
    cwe: Optional[str]
    cve: Optional[str]
    cvss_score: Optional[str]
    package_name: Optional[str]
    package_version: Optional[str]
    fixed_version: Optional[str]
    status: VulnStatus
    ai_false_positive_likelihood: Optional[str]
    ai_exploitability_public: Optional[str]
    ai_exploitability_private: Optional[str]
    ai_explanation: Optional[str]
    ai_fix_suggestion: Optional[str]
    ai_analyzed_at: Optional[datetime]
    fingerprint: Optional[str]
    created_at: datetime
    waiver: Optional[WaiverOut]


class VulnStatusUpdate(BaseModel):
    status: VulnStatus


class WaiverCreate(BaseModel):
    approver_name: str = Field(..., min_length=1)
    approver_email: Optional[str] = None
    reason: str = Field(..., min_length=10, description="Lý do chấp nhận rủi ro (tối thiểu 10 ký tự)")
    expiry_date: Optional[datetime] = None
    is_false_positive: bool = False


# ─────────────────────────────────────────────
# Compare Schemas
# ─────────────────────────────────────────────
class VulnDiff(BaseModel):
    new: List[VulnOut] = []        # Xuất hiện lần đầu trong scan mới
    fixed: List[VulnOut] = []      # Có trong scan cũ, không còn trong scan mới
    persisted: List[VulnOut] = []  # Vẫn còn trong cả hai


class CompareResult(BaseModel):
    project_id: str
    scan_old: ScanOut
    scan_new: ScanOut
    diff: VulnDiff
    summary: dict
