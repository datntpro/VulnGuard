"""
Web Scan (Nuclei / DAST) — gắn với Domain (api/domain_models.py).
  WebScan     — 1 lần quét nuclei (có thể dựa trên 1 DomainCrawl)
  WebFinding  — 1 kết quả template match
"""
import enum
import uuid

from sqlalchemy import Column, String, Integer, DateTime, Text, Enum, ForeignKey, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from api.database import Base


def gen_id():
    return str(uuid.uuid4())


class WebScanStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class WebFindingStatus(str, enum.Enum):
    OPEN = "OPEN"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED = "ACCEPTED"
    FIXED = "FIXED"


class WebScan(Base):
    __tablename__ = "web_scans"

    id = Column(String, primary_key=True, default=gen_id)
    domain_id = Column(String, ForeignKey("domains.id", ondelete="CASCADE"), nullable=False, index=True)
    crawl_id = Column(String, ForeignKey("domain_crawls.id", ondelete="SET NULL"), nullable=True)

    severities = Column(JSON, default=list)
    tags = Column(JSON, default=list)
    fuzz = Column(Integer, default=0)
    rate_limit = Column(Integer, default=50)
    authorized_by = Column(String(255), nullable=True)   # email user đã xác nhận có quyền quét

    status = Column(Enum(WebScanStatus), default=WebScanStatus.PENDING)
    target_count = Column(Integer, default=0)
    started_at = Column(DateTime, server_default=func.now())
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    summary = Column(JSON, nullable=True)
    progress = Column(JSON, nullable=True)

    findings = relationship("WebFinding", back_populates="scan", cascade="all, delete-orphan")


class WebFinding(Base):
    __tablename__ = "web_findings"

    id = Column(String, primary_key=True, default=gen_id)
    scan_id = Column(String, ForeignKey("web_scans.id", ondelete="CASCADE"), nullable=False, index=True)

    template_id = Column(String(300), nullable=False)
    name = Column(String(500), nullable=False)
    severity = Column(String(10), nullable=False)       # critical|high|medium|low|info
    matched_at = Column(String(2000), nullable=True)
    host = Column(String(500), nullable=True)
    type = Column(String(30), nullable=True)
    matcher_name = Column(String(200), nullable=True)
    description = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    reference = Column(JSON, default=list)
    tags = Column(JSON, default=list)
    cve = Column(String(50), nullable=True)
    cwe = Column(String(50), nullable=True)
    cvss_score = Column(String(10), nullable=True)
    extracted = Column(JSON, default=list)
    curl_command = Column(Text, nullable=True)
    fingerprint = Column(String(64), nullable=True, index=True)

    status = Column(Enum(WebFindingStatus), default=WebFindingStatus.OPEN)
    created_at = Column(DateTime, server_default=func.now())

    scan = relationship("WebScan", back_populates="findings")
