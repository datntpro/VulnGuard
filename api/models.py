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
    OPEN = "OPEN"
    ACCEPTED = "ACCEPTED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    FIXED = "FIXED"


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
    ai_exploitability_public = Column(Text, nullable=True)
    ai_exploitability_private = Column(Text, nullable=True)
    ai_explanation = Column(Text, nullable=True)           # Tiếng Việt
    ai_fix_suggestion = Column(Text, nullable=True)
    ai_analyzed_at = Column(DateTime, nullable=True)

    # Fingerprint cho tracking across scans
    fingerprint = Column(String(64), nullable=True, index=True)

    created_at = Column(DateTime, server_default=func.now())

    scan = relationship("Scan", back_populates="vulnerabilities")
    waiver = relationship("Waiver", back_populates="vulnerability", uselist=False, cascade="all, delete-orphan")


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
