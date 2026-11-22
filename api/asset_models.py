"""
Asset inventory — "nguồn sự thật" về tài sản, làm giàu từ connector (XDR/EDR/NAC)
và là nền cho risk scoring kiểu VM (Tenable VPR / Nexpose Real Risk).

Asset          — 1 tài sản (host/IP/service). Dedup theo khoá ổn định.
AssetSoftware  — phần mềm/package cài trên asset (từ EDR inventory) → so khớp CVE.
AssetVuln      — lỗ hổng gắn với asset (từ scan hoặc CVE match) + điểm rủi ro.
AssetAlert     — cảnh báo EDR/XDR (đang bị tấn công thực tế) → đẩy risk lên.
"""
import enum
import uuid

from sqlalchemy import (
    Column, String, Integer, Float, DateTime, Text, Enum, ForeignKey, JSON, Boolean, UniqueConstraint
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from api.database import Base


def gen_id():
    return str(uuid.uuid4())


class AssetType(str, enum.Enum):
    HOST = "HOST"
    SERVER = "SERVER"
    WORKSTATION = "WORKSTATION"
    NETWORK_DEVICE = "NETWORK_DEVICE"
    SERVICE = "SERVICE"
    UNKNOWN = "UNKNOWN"


class Criticality(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Exposure(str, enum.Enum):
    INTERNET = "INTERNET"      # public-facing
    INTERNAL = "INTERNAL"
    ISOLATED = "ISOLATED"
    UNKNOWN = "UNKNOWN"


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("dedup_key", name="uq_asset_dedup"),)

    id = Column(String, primary_key=True, default=gen_id)
    dedup_key = Column(String(300), nullable=False, index=True)   # khoá gộp trùng (mac|hostname|ip)
    hostname = Column(String(300), nullable=True, index=True)
    ip = Column(String(64), nullable=True, index=True)
    mac = Column(String(32), nullable=True)
    asset_type = Column(Enum(AssetType), default=AssetType.UNKNOWN)
    os = Column(String(200), nullable=True)
    os_version = Column(String(100), nullable=True)

    criticality = Column(Enum(Criticality), default=Criticality.MEDIUM)
    exposure = Column(Enum(Exposure), default=Exposure.UNKNOWN)
    owner = Column(String(200), nullable=True)
    tags = Column(JSON, default=list)

    # Ngữ cảnh từ NAC
    vlan = Column(String(50), nullable=True)
    switch_port = Column(String(100), nullable=True)
    nac_status = Column(String(50), nullable=True)       # connected|quarantined|...

    # Ngữ cảnh từ XDR/EDR
    edr_agent_present = Column(Boolean, default=False)
    edr_health = Column(String(50), nullable=True)
    last_edr_alert_at = Column(DateTime, nullable=True)
    active_alert_count = Column(Integer, default=0)

    sources = Column(JSON, default=list)                 # ["fortinac","trellix",...]
    risk_score = Column(Float, default=0.0)              # 0..100 (điểm rủi ro tổng hợp)
    risk_factors = Column(JSON, nullable=True)           # breakdown để giải thích
    first_seen = Column(DateTime, server_default=func.now())
    last_seen = Column(DateTime, server_default=func.now(), onupdate=func.now())
    created_at = Column(DateTime, server_default=func.now())

    software = relationship("AssetSoftware", back_populates="asset", cascade="all, delete-orphan")
    vulns = relationship("AssetVuln", back_populates="asset", cascade="all, delete-orphan")
    alerts = relationship("AssetAlert", back_populates="asset", cascade="all, delete-orphan")


class AssetSoftware(Base):
    __tablename__ = "asset_software"

    id = Column(String, primary_key=True, default=gen_id)
    asset_id = Column(String, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(300), nullable=False)
    version = Column(String(100), nullable=True)
    vendor = Column(String(200), nullable=True)
    source = Column(String(50), nullable=True)
    cpe = Column(String(300), nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    asset = relationship("Asset", back_populates="software")


class AssetVuln(Base):
    __tablename__ = "asset_vulns"
    __table_args__ = (UniqueConstraint("asset_id", "cve", name="uq_assetvuln"),)

    id = Column(String, primary_key=True, default=gen_id)
    asset_id = Column(String, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    cve = Column(String(50), nullable=False, index=True)
    title = Column(String(500), nullable=True)
    cvss_score = Column(Float, nullable=True)
    epss = Column(Float, nullable=True)                  # 0..1 xác suất bị khai thác (EPSS)
    kev = Column(Boolean, default=False)                 # có trong CISA KEV không
    source = Column(String(50), nullable=True)           # edr|scan|manual
    severity = Column(String(10), nullable=True)
    risk_score = Column(Float, default=0.0)              # điểm rủi ro riêng của vuln này trên asset
    status = Column(String(20), default="OPEN")
    created_at = Column(DateTime, server_default=func.now())

    asset = relationship("Asset", back_populates="vulns")


class AssetAlert(Base):
    __tablename__ = "asset_alerts"

    id = Column(String, primary_key=True, default=gen_id)
    asset_id = Column(String, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    source = Column(String(50), nullable=True)           # trellix|trendmicro|...
    external_id = Column(String(200), nullable=True)
    title = Column(String(500), nullable=True)
    severity = Column(String(20), nullable=True)
    status = Column(String(50), nullable=True)
    technique = Column(String(100), nullable=True)       # MITRE ATT&CK id nếu có
    detected_at = Column(DateTime, nullable=True)
    raw = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    asset = relationship("Asset", back_populates="alerts")
