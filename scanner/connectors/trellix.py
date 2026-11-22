"""
Trellix XDR / EDR (McAfee MVISION) connector.

Auth: OAuth2 client credentials (IAM). Lấy token tại iam_url (mặc định
https://iam.mcafee-cloud.com/iam/v1.1/token) bằng client_id/client_secret + scope,
rồi gọi API tại base_url (vd https://api.manage.trellix.com).

Endpoint (cấu hình được vì khác nhau giữa ePO SaaS / EDR):
  devices_path   mặc định /epo/v2/devices    → inventory
  detections_path mặc định /edr/v2/threats   → detection/alert
Parsing tolerant. Nếu deployment dùng path khác, chỉnh trong config.
"""
import time
from typing import Any, Dict, List, Optional

import httpx

from scanner.connectors.base import BaseConnector, ConnectorError, NormAlert, NormAsset, NormSoftware

DEFAULT_IAM = "https://iam.mcafee-cloud.com/iam/v1.1/token"
DEFAULT_SCOPE = "epo.device.r epo.device.w edr.det.r"


def parse_device(d: Dict[str, Any]) -> NormAsset:
    attr = d.get("attributes", d) if isinstance(d.get("attributes"), dict) else d
    hostname = attr.get("name") or attr.get("hostname") or attr.get("ComputerName")
    ip = attr.get("ipAddress") or attr.get("ip_address") or attr.get("IPAddress")
    mac = attr.get("macAddress") or attr.get("mac_address") or attr.get("MACAddress")
    os_name = attr.get("osType") or attr.get("os_type") or attr.get("OSType")
    health = attr.get("agentState") or attr.get("agent_state") or attr.get("ManagedState")
    return NormAsset(
        hostname=hostname, ip=ip, mac=mac, os=os_name,
        os_version=attr.get("osVersion") or attr.get("OSVersion"),
        edr_agent_present=True,
        edr_health=str(health) if health is not None else None,
        external_id=str(d.get("id") or attr.get("id") or attr.get("AgentGUID") or ""),
        tags=["trellix"],
    )


def parse_detection(t: Dict[str, Any]) -> NormAlert:
    attr = t.get("attributes", t) if isinstance(t.get("attributes"), dict) else t
    sev = attr.get("severity") or attr.get("Severity")
    sev_map = {"s5": "critical", "s4": "high", "s3": "medium", "s2": "low", "s1": "info",
               "5": "critical", "4": "high", "3": "medium", "2": "low", "1": "info"}
    sev_n = sev_map.get(str(sev).lower(), str(sev).lower() if sev else None)
    return NormAlert(
        external_id=str(t.get("id") or attr.get("threatId") or ""),
        title=attr.get("threatName") or attr.get("name") or attr.get("ruleName"),
        severity=sev_n, status=attr.get("status"),
        technique=attr.get("mitreTechniqueId") or attr.get("technique"),
        detected_at=attr.get("firstDetected") or attr.get("eventDate") or attr.get("timestamp"),
        hostname=attr.get("hostName") or attr.get("deviceName"),
        ip=attr.get("hostIpAddress") or attr.get("ipAddress"),
        raw={"rank": attr.get("rank")},
    )


class TrellixConnector(BaseConnector):
    kind = "TRELLIX_XDR"
    secret_fields = ["client_id", "client_secret"]
    config_fields = ["iam_url", "scope", "devices_path", "detections_path"]
    supports_isolate = False      # cô lập host ePO/EDR khác nhau nhiều → tắt mặc định

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._token = None
        self._token_exp = 0

    async def _get_token(self) -> str:
        if self._token and time.time() < self._token_exp - 60:
            return self._token
        cid, csec = self.secrets.get("client_id"), self.secrets.get("client_secret")
        if not cid or not csec:
            raise ConnectorError("Thiếu client_id/client_secret Trellix")
        iam = self.config.get("iam_url") or DEFAULT_IAM
        data = {"grant_type": "client_credentials", "client_id": cid, "client_secret": csec,
                "scope": self.config.get("scope") or DEFAULT_SCOPE}
        async with httpx.AsyncClient(timeout=20, trust_env=False) as c:
            r = await c.post(iam, data=data)
            r.raise_for_status()
            j = r.json()
        self._token = j["access_token"]
        self._token_exp = time.time() + int(j.get("expires_in", 3600))
        return self._token

    async def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {await self._get_token()}", "Accept": "application/json"}

    async def _get(self, path: str) -> List[Dict]:
        async with httpx.AsyncClient(timeout=30, trust_env=False) as c:
            r = await c.get(self.base_url + path, headers=await self._headers())
            r.raise_for_status()
            j = r.json()
        return j.get("data", j if isinstance(j, list) else j.get("items", []))

    async def test_connection(self) -> Dict[str, Any]:
        try:
            await self._get_token()
            return {"ok": True, "message": "Lấy token OAuth2 thành công", "detail": ""}
        except Exception as e:
            return {"ok": False, "message": str(e)[:300], "detail": ""}

    async def fetch_assets(self) -> List[NormAsset]:
        path = self.config.get("devices_path", "/epo/v2/devices")
        return [parse_device(d) for d in await self._get(path)]

    async def fetch_alerts(self) -> List[NormAlert]:
        path = self.config.get("detections_path", "/edr/v2/threats")
        return [parse_detection(t) for t in await self._get(path)]
