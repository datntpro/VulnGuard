from pydantic import BaseModel, Field, ConfigDict, model_validator
from typing import Optional, List, Any
from datetime import datetime

from api.domain_models import CrawlStatus, AIAnalysisStatus


# ─────────────────────────────────────────────
# Domain Schemas
# ─────────────────────────────────────────────
class DomainCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    url: str = Field(..., min_length=4, max_length=500, description="vd: https://example.com")
    description: Optional[str] = None


class DomainOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    url: str
    description: Optional[str] = None
    created_at: datetime
    crawl_count: int = 0

    @model_validator(mode="before")
    @classmethod
    def extract_crawl_count(cls, data: Any) -> Any:
        if isinstance(data, dict):
            return data
        if hasattr(data, "__tablename__"):
            return {
                "id": data.id,
                "name": data.name,
                "url": data.url,
                "description": data.description,
                "created_at": data.created_at,
                "crawl_count": len(data.crawls) if data.crawls is not None else 0,
            }
        return data


# ─────────────────────────────────────────────
# Crawl Schemas
# ─────────────────────────────────────────────
class CrawlCreate(BaseModel):
    depth: int = Field(default=3, ge=1, le=10)
    max_urls: int = Field(default=2000, ge=10, le=20000)
    js_crawl: bool = True
    include_subdomains: bool = False
    exclude_patterns: List[str] = Field(default_factory=list)
    timeout: int = Field(default=600, ge=30, le=3600)
    run_ai_analysis: bool = Field(
        default=False,
        description="Sau khi crawl xong, dùng Ollama phân loại endpoint nhạy cảm + gợi ý WAF + tóm tắt",
    )


class CrawlOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    domain_id: str
    crawl_number: int
    depth: int
    max_urls: int
    js_crawl: bool
    include_subdomains: bool
    exclude_patterns: List[str]
    status: CrawlStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    summary: Optional[dict] = None
    progress: Optional[dict] = None

    ai_status: AIAnalysisStatus = AIAnalysisStatus.NOT_REQUESTED
    ai_summary: Optional[str] = None
    ai_sensitive_endpoints: Optional[List[dict]] = None
    ai_waf_suggestions: Optional[List[dict]] = None
    ai_error: Optional[str] = None


class EndpointOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    url: str
    path: Optional[str]
    method: str
    status_code: Optional[int]
    content_type: Optional[str]
    source_tag: Optional[str]
    query_params: List[str]
    body_params: List[str]
    forms: List[dict]
