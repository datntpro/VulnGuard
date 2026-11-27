from sqlalchemy import (
    Column, String, Integer, DateTime, Text, Enum, ForeignKey, JSON, Boolean
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
import enum

from api.database import Base


def gen_id():
    return str(uuid.uuid4())


class ScanStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnStatus(str, enum.Enum):
    # Trạng thái triage kiểu Checkmarx. OPEN = "Cần xác minh (To Verify)" — mặc định,
    # giữ tên OPEN để tương thích dữ liệu/quyền cũ.
    OPEN = "OPEN"                       # To Verify — chưa triage
    CONFIRMED = "CONFIRMED"             # Đã xác nhận là lỗi thật, cần sửa
    URGENT = "URGENT"                   # Đã xác nhận + khẩn cấp
    PROPOSED_NE = "PROPOSED_NE"         # Đề xuất: không khai thác được (chờ reviewer chốt)
    NOT_EXPLOITABLE = "NOT_EXPLOITABLE" # Chốt: không khai thác được (final)
    ACCEPTED = "ACCEPTED"              # Chấp nhận rủi ro
    FALSE_POSITIVE = "FALSE_POSITIVE"  # (legacy, coi như NOT_EXPLOITABLE)
    FIXED = "FIXED"                    # Đã sửa


# Trạng thái còn "mở" (tính vào rủi ro / chặn approve / hiện trong summary)
ACTIVE_VULN_STATUSES = (
    VulnStatus.OPEN, VulnStatus.CONFIRMED, VulnStatus.URGENT, VulnStatus.PROPOSED_NE,
)
ACTIVE_VULN_STATUS_VALUES = tuple(s.value for s in ACTIVE_VULN_STATUSES)
# Chuyển sang các trạng thái này BẮT BUỘC ghi chú (note)
NOTE_REQUIRED_STATUSES = (VulnStatus.NOT_EXPLOITABLE, VulnStatus.ACCEPTED)
# Chỉ ADMIN mới được chốt các trạng thái này
ADMIN_ONLY_STATUSES = (VulnStatus.NOT_EXPLOITABLE,)


class ScanType(str, enum.Enum):
    SAST = "SAST"
    SCA = "SCA"
    CONTAINER = "CONTAINER"
    IAC = "IAC"
    SECRETS = "SECRETS"


# ─────────────────────────────────────────────
class Project(Base):
    __tablename__ = "projects"

    id = Column(String, primary_key=True, default=gen_id)
    name = Column(String(200), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    language_stacks = Column(JSON, default=list)   # ["java", "python", "terraform"]
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")


# ─────────────────────────────────────────────
class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, default=gen_id)
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    scan_number = Column(Integer, nullable=False)          # 1..5 (rolling)
    scan_path = Column(String(500), nullable=False)         # Path đã scan
    scan_types = Column(JSON, default=list)                 # ["SAST","SCA",...]
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    started_at = Column(DateTime, server_default=func.now())
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    summary = Column(JSON, nullable=True)                  # {critical: 2, high: 5, ...}
    scanner_progress = Column(JSON, nullable=True)         # live progress: {tools: {...}, pct: 60}
    triggered_by_user_id = Column(String(64), nullable=True)   # [AI PR-1] người kích hoạt (None = lịch/hệ thống)

    project = relationship("Project", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")


# ─────────────────────────────────────────────
class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(String, primary_key=True, default=gen_id)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)

    # Thông tin từ scanner
    tool = Column(String(100), nullable=False)             # "semgrep", "trivy", ...
    scan_type = Column(Enum(ScanType), nullable=False)
    rule_id = Column(String(200), nullable=True)           # CVE, CWE, rule name
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(Enum(Severity), nullable=False)
    file_path = Column(String(1000), nullable=True)
    line_start = Column(Integer, nullable=True)
    line_end = Column(Integer, nullable=True)
    code_snippet = Column(Text, nullable=True)
    cwe = Column(String(50), nullable=True)
    cve = Column(String(50), nullable=True)
    cvss_score = Column(String(10), nullable=True)
    package_name = Column(String(200), nullable=True)      # cho SCA
    package_version = Column(String(100), nullable=True)
    fixed_version = Column(String(100), nullable=True)
    raw_output = Column(JSON, nullable=True)               # Raw JSON từ tool

    # Trạng thái xử lý
    status = Column(Enum(VulnStatus), default=VulnStatus.OPEN)

    # AI Analysis
    ai_false_positive_likelihood = Column(String(10), nullable=True)  # "85%"
    ai_false_positive_reason = Column(Text, nullable=True)            # Lý do đánh giá FP
    ai_exploitability_public = Column(Text, nullable=True)
    ai_exploitability_private = Column(Text, nullable=True)
    ai_explanation = Column(Text, nullable=True)           # Tiếng Việt
    ai_fix_suggestion = Column(Text, nullable=True)
    ai_analyzed_at = Column(DateTime, nullable=True)
    ai_provider = Column(String(120), nullable=True)       # "ollama:llama3.2" | "claude-api:claude-opus-5-5" | "bedrock:…"

    # Fingerprint cho tracking across scans
    fingerprint = Column(String(64), nullable=True, index=True)

    # Triage (kiểu Checkmarx) — kế thừa qua các lần scan theo fingerprint
    triage_note = Column(Text, nullable=True)
    triage_by = Column(String(200), nullable=True)
    triage_at = Column(DateTime, nullable=True)
    first_seen_at = Column(DateTime, nullable=True)       # lần đầu finding này xuất hiện (xuyên scan)
    first_seen_scan_id = Column(String, nullable=True)    # scan đầu tiên thấy finding (để đánh dấu "Mới")

    created_at = Column(DateTime, server_default=func.now())

    scan = relationship("Scan", back_populates="vulnerabilities")
    waiver = relationship("Waiver", back_populates="vulnerability", uselist=False, cascade="all, delete-orphan")

    # ── Tri thức khai thác (EPSS/KEV) + nâng ưu tiên — lưu trong raw_output
    #    dưới khoá _vulnguard_kb (không cần cột mới). Expose qua property để VulnOut đọc.
    @property
    def _kb(self) -> dict:
        ro = self.raw_output
        return ro.get("_vulnguard_kb", {}) if isinstance(ro, dict) else {}

    @property
    def epss(self):
        v = self._kb.get("epss")
        return float(v) if isinstance(v, (int, float)) else None

    @property
    def epss_percentile(self):
        v = self._kb.get("epss_percentile")
        return float(v) if isinstance(v, (int, float)) else None

    @property
    def kev(self) -> bool:
        return bool(self._kb.get("kev"))

    @property
    def kev_ransomware(self) -> bool:
        return bool(self._kb.get("kev_ransomware"))

    @property
    def kev_due_date(self):
        return self._kb.get("kev_due_date")

    @property
    def priority_reason(self):
        return self._kb.get("priority_reason")

    @property
    def severity_original(self):
        return self._kb.get("severity_original")


# ─────────────────────────────────────────────
class Waiver(Base):
    __tablename__ = "waivers"

    id = Column(String, primary_key=True, default=gen_id)
    vulnerability_id = Column(String, ForeignKey("vulnerabilities.id"), nullable=False, unique=True)
    approver_name = Column(String(200), nullable=False)
    approver_email = Column(String(200), nullable=True)
    reason = Column(Text, nullable=False)
    expiry_date = Column(DateTime, nullable=True)           # Null = không hết hạn
    is_false_positive = Column(Boolean, default=False)
    created_at = Column(DateTime, server_default=func.now())

    vulnerability = relationship("Vulnerability", back_populates="waiver")


# ─────────────────────────────────────────────
# Audit trail đổi trạng thái triage (change log kiểu Checkmarx)
class TriageEvent(Base):
    __tablename__ = "triage_events"

    id = Column(String, primary_key=True, default=gen_id)
    vulnerability_id = Column(String, ForeignKey("vulnerabilities.id"), nullable=True, index=True)
    project_id = Column(String, nullable=True, index=True)
    fingerprint = Column(String(64), nullable=True, index=True)   # để truy vết xuyên scan
    from_status = Column(String(40), nullable=True)
    to_status = Column(String(40), nullable=False)
    note = Column(Text, nullable=True)
    actor = Column(String(200), nullable=True)                    # email/tên người triage
    created_at = Column(DateTime, server_default=func.now())
