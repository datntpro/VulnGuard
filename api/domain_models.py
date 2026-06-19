"""
Module riêng cho tính năng "Domain Sitemap / WAF Baseline":
- Domain: khai báo 1 domain/website cần crawl
- DomainCrawl: 1 lần crawl (rolling, giữ tối đa N lần giống Scan của Project)
- CrawlEndpoint: 1 URL/endpoint phát hiện được trong lần crawl đó

Tách riêng khỏi api/models.py (Project/Scan/Vulnerability) theo yêu cầu —
không đụng vào schema scan source code hiện tại, dùng chung Base/engine.
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


class CrawlStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class AIAnalysisStatus(str, enum.Enum):
    NOT_REQUESTED = "NOT_REQUESTED"
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    DONE = "DONE"
    FAILED = "FAILED"


# ─────────────────────────────────────────────
class Domain(Base):
    __tablename__ = "domains"

    id = Column(String, primary_key=True, default=gen_id)
    name = Column(String(200), nullable=False)               # Tên gợi nhớ, vd "Website chính"
    url = Column(String(500), nullable=False, unique=True)    # Root URL, vd https://example.com
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    crawls = relationship("DomainCrawl", back_populates="domain", cascade="all, delete-orphan")


# ─────────────────────────────────────────────
class DomainCrawl(Base):
    __tablename__ = "domain_crawls"

    id = Column(String, primary_key=True, default=gen_id)
    domain_id = Column(String, ForeignKey("domains.id"), nullable=False)
    crawl_number = Column(Integer, nullable=False)             # 1..5 (rolling, giống Scan)

    # Tham số crawl
    depth = Column(Integer, default=3)
    max_urls = Column(Integer, default=2000)
    js_crawl = Column(Integer, default=1)                      # bool lưu dạng int cho SQLite an toàn
    include_subdomains = Column(Integer, default=0)
    exclude_patterns = Column(JSON, default=list)               # ["\\.png$", "/logout"]

    status = Column(Enum(CrawlStatus), default=CrawlStatus.PENDING)
    started_at = Column(DateTime, server_default=func.now())
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)

    summary = Column(JSON, nullable=True)        # {total_urls, total_get, total_post, total_params, total_forms, methods:{...}}
    progress = Column(JSON, nullable=True)        # {phase, urls_found, current_url}

    # ── AI Analysis (Ollama) — tùy chọn, chạy sau khi crawl xong ──
    # Phân loại endpoint nhạy cảm + gợi ý siết WAF + tóm tắt crawl bằng ngôn ngữ tự nhiên.
    # Tách riêng status để không ảnh hưởng status crawl chính (crawl có thể COMPLETED
    # dù AI analysis chưa chạy/đang chạy/lỗi).
    ai_status = Column(Enum(AIAnalysisStatus), default=AIAnalysisStatus.NOT_REQUESTED)
    ai_summary = Column(Text, nullable=True)                 # Tóm tắt tiếng Việt
    ai_sensitive_endpoints = Column(JSON, nullable=True)      # [{path, method, category, reason}]
    ai_waf_suggestions = Column(JSON, nullable=True)          # [{path, param, suggested_regex, suggested_action, reason}]
    ai_error = Column(Text, nullable=True)

    domain = relationship("Domain", back_populates="crawls")
    endpoints = relationship("CrawlEndpoint", back_populates="crawl", cascade="all, delete-orphan")


# ─────────────────────────────────────────────
class CrawlEndpoint(Base):
    __tablename__ = "crawl_endpoints"

    id = Column(String, primary_key=True, default=gen_id)
    crawl_id = Column(String, ForeignKey("domain_crawls.id"), nullable=False)

    url = Column(String(2000), nullable=False)
    path = Column(String(1000), nullable=True)        # path không kèm query, dùng để gom nhóm cho WAF baseline
    method = Column(String(10), default="GET")
    status_code = Column(Integer, nullable=True)
    content_type = Column(String(200), nullable=True)
    source_tag = Column(String(50), nullable=True)    # a / form / script / fetch ... (từ katana)

    query_params = Column(JSON, default=list)         # ["id", "page"]
    body_params = Column(JSON, default=list)          # tham số form (POST)
    forms = Column(JSON, default=list)                 # [{method, action, fields:[...]}]

    discovered_at = Column(DateTime, server_default=func.now())

    crawl = relationship("DomainCrawl", back_populates="endpoints")
