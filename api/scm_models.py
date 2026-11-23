"""
Tích hợp SCM (GitHub, GitLab cloud & self-managed/onprem) để scan theo lịch
và gửi báo cáo tự động cho owner.

- ScmConnection: 1 kết nối tới 1 server SCM (token mã hoá Fernet).
- ScmRepo: 1 repository được chọn để quét (gắn owner_email để gửi report).
- ScanSchedule: lịch quét định kỳ cho 1 repo (interval phút, hoặc tắt = quét tay).

Token KHÔNG bao giờ trả raw qua API (chỉ hint).
"""
import enum
import uuid
from datetime import datetime

from sqlalchemy import Column, String, DateTime, Enum, Boolean, Integer, ForeignKey, JSON
from sqlalchemy.sql import func

from api.database import Base


def gen_id():
    return str(uuid.uuid4())


class ScmProvider(str, enum.Enum):
    GITHUB = "GITHUB"            # github.com hoặc GitHub Enterprise (base_url)
    GITLAB = "GITLAB"           # gitlab.com hoặc self-managed/onprem (base_url)


class ScmConnection(Base):
    __tablename__ = "scm_connections"

    id = Column(String, primary_key=True, default=gen_id)
    name = Column(String(200), nullable=False)
    provider = Column(Enum(ScmProvider), nullable=False)
    # base_url: để trống = dịch vụ cloud mặc định (github.com / gitlab.com).
    # onprem: https://gitlab.corp.vn hoặc https://github.corp.vn
    base_url = Column(String(500), nullable=True)
    token_enc = Column(String, nullable=True)         # Fernet
    created_at = Column(DateTime, server_default=func.now())


class ScmRepo(Base):
    __tablename__ = "scm_repos"

    id = Column(String, primary_key=True, default=gen_id)
    connection_id = Column(String, ForeignKey("scm_connections.id"), nullable=False, index=True)
    repo_full_name = Column(String(400), nullable=False)   # owner/repo (GitHub) · group/sub/proj (GitLab)
    default_branch = Column(String(200), nullable=True, default="main")
    owner_email = Column(String(200), nullable=True)       # nhận báo cáo tự động
    project_id = Column(String, nullable=True)             # Project VulnGuard tương ứng (sau lần scan đầu)
    scan_types = Column(JSON, default=list)                # [] = auto theo tool có sẵn
    run_ai = Column(Boolean, default=False)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, server_default=func.now())


class ScanSchedule(Base):
    __tablename__ = "scan_schedules"

    id = Column(String, primary_key=True, default=gen_id)
    repo_id = Column(String, ForeignKey("scm_repos.id"), nullable=False, index=True)
    interval_minutes = Column(Integer, nullable=False, default=1440)   # mặc định 1 ngày
    enabled = Column(Boolean, default=True)
    email_report = Column(Boolean, default=True)           # gửi report cho owner sau khi scan
    last_run_at = Column(DateTime, nullable=True)
    last_status = Column(String(40), nullable=True)        # OK / ERROR / RUNNING
    last_error = Column(String(1000), nullable=True)
    next_run_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    def compute_next(self, base: datetime = None) -> datetime:
        from datetime import timedelta
        base = base or datetime.utcnow()
        return base + timedelta(minutes=max(1, self.interval_minutes or 1440))
