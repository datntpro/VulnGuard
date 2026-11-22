"""
Base connector + schema chuẩn hoá (vendor-neutral).

Mỗi adapter (Trellix / Trend Vision One / FortiNAC) kế thừa BaseConnector và
map dữ liệu vendor về NormAsset / NormAlert / NormSoftware. Nhờ chuẩn hoá, tầng
Asset + risk scoring + MCP không cần biết vendor nào.

Hành động (action) như cô lập host là DESTRUCTIVE → luôn qua approval gate ở lớp gọi.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class NormSoftware:
    name: str
    version: Optional[str] = None
    vendor: Optional[str] = None
    cpe: Optional[str] = None


@dataclass
class NormAsset:
    hostname: Optional[str] = None
    ip: Optional[str] = None
    mac: Optional[str] = None
    asset_type: Optional[str] = None          # HOST|SERVER|WORKSTATION|NETWORK_DEVICE|SERVICE
    os: Optional[str] = None
    os_version: Optional[str] = None
    criticality: Optional[str] = None
    exposure: Optional[str] = None
    vlan: Optional[str] = None
    switch_port: Optional[str] = None
    nac_status: Optional[str] = None
    edr_agent_present: Optional[bool] = None
    edr_health: Optional[str] = None
    owner: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    software: List[NormSoftware] = field(default_factory=list)
    external_id: Optional[str] = None          # id bên vendor (cho action)

    def key_fields(self) -> Dict[str, Any]:
        return {"hostname": self.hostname, "ip": self.ip, "mac": self.mac}


@dataclass
class NormAlert:
    external_id: Optional[str] = None
    title: Optional[str] = None
    severity: Optional[str] = None             # critical|high|medium|low|info
    status: Optional[str] = None
    technique: Optional[str] = None            # MITRE ATT&CK id
    detected_at: Optional[Any] = None          # datetime
    # khoá để match về asset
    hostname: Optional[str] = None
    ip: Optional[str] = None
    mac: Optional[str] = None
    raw: Optional[Dict] = None


class ConnectorError(Exception):
    pass


class BaseConnector:
    kind: str = "BASE"
    # field secret bắt buộc (dùng để validate + render form) — adapter override
    secret_fields: List[str] = []
    config_fields: List[str] = []
    supports_isolate: bool = False

    def __init__(self, base_url: Optional[str], config: Dict[str, Any], secrets: Dict[str, str]):
        self.base_url = (base_url or "").rstrip("/")
        self.config = config or {}
        self.secrets = secrets or {}

    async def test_connection(self) -> Dict[str, Any]:
        """Trả {ok, message, detail}."""
        raise NotImplementedError

    async def fetch_assets(self) -> List[NormAsset]:
        return []

    async def fetch_alerts(self) -> List[NormAlert]:
        return []

    async def isolate_host(self, external_id: str) -> Dict[str, Any]:
        """DESTRUCTIVE — chỉ gọi sau approval. Mặc định không hỗ trợ."""
        raise ConnectorError("Connector này không hỗ trợ cô lập host")
