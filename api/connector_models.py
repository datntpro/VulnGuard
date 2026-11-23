"""Cấu hình connector tích hợp XDR/EDR/NAC. Secret lưu mã hoá (Fernet)."""
import enum
import uuid

from sqlalchemy import Column, String, DateTime, Enum, JSON, Boolean, Text, Integer
from sqlalchemy.sql import func

from api.database import Base


def gen_id():
    return str(uuid.uuid4())


class ConnectorKind(str, enum.Enum):
    TRELLIX_XDR = "TRELLIX_XDR"
    TRENDMICRO_VISION_ONE = "TRENDMICRO_VISION_ONE"
    FORTINAC = "FORTINAC"
    WAZUH = "WAZUH"                      # open-source SIEM/XDR/HIDS


class ConnectorConfig(Base):
    __tablename__ = "connectors"

    id = Column(String, primary_key=True, default=gen_id)
    name = Column(String(200), nullable=False)
    kind = Column(Enum(ConnectorKind), nullable=False)
    enabled = Column(Boolean, default=True)

    base_url = Column(String(500), nullable=True)
    config = Column(JSON, default=dict)        # non-secret (region, api_user, tenant...)
    secrets_enc = Column(JSON, default=dict)   # {field: fernet_token} — không bao giờ trả raw

    last_sync_at = Column(DateTime, nullable=True)
    last_sync_status = Column(String(30), nullable=True)   # ok|error|running
    last_sync_message = Column(Text, nullable=True)
    last_sync_stats = Column(JSON, nullable=True)          # {assets, alerts, software}

    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
