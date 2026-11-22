"""
FortiNAC connector.

Auth: POST /api/v2/auth {username, password} → token (Bearer). (Một số bản dùng API key.)
Host inventory: GET /api/v2/host → mac, ip, hostname, status, vlan, switch/port.
NAC là nguồn asset inventory sống + ngữ cảnh mạng (VLAN/segment → exposure).
Parsing tolerant.
"""
from typing import Any, Dict, List, Optional

import httpx

from scanner.connectors.base import BaseConnector, ConnectorError, NormAsset


def _exposure_from_vlan(vlan: Optional[str], cfg: Dict) -> Optional[str]:
    """Map VLAN → exposure theo cấu hình (vd internet_vlans=['100','dmz'])."""
    if vlan is None:
        return None
    v = str(vlan).lower()
    if v in [str(x).lower() for x in cfg.get("internet_vlans", [])]:
        return "INTERNET"
    if v in [str(x).lower() for x in cfg.get("isolated_vlans", [])]:
        return "ISOLATED"
    return "INTERNAL"


def parse_host(h: Dict[str, Any], cfg: Dict) -> NormAsset:
    vlan = h.get("vlan") or h.get("currentVlan") or h.get("logicalNetwork")
    status = h.get("status") or h.get("state") or h.get("connectionState")
    role = (h.get("role") or h.get("deviceType") or "").lower()
    atype = "NETWORK_DEVICE" if any(k in role for k in ("switch", "router", "ap", "firewall")) else "HOST"
    return NormAsset(
        hostname=h.get("hostname") or h.get("name") or h.get("hostName"),
        ip=h.get("ip") or h.get("ipAddress") or h.get("currentIp"),
        mac=h.get("mac") or h.get("macAddress") or h.get("physicalAddress"),
        asset_type=atype,
        os=h.get("operatingSystem") or h.get("os"),
        vlan=str(vlan) if vlan is not None else None,
        switch_port=h.get("port") or h.get("connectedPort") or h.get("switchPort"),
        nac_status=str(status) if status is not None else None,
        exposure=_exposure_from_vlan(vlan, cfg),
        owner=h.get("owner") or h.get("registeredUser"),
        external_id=str(h.get("id") or h.get("hostId") or ""),
        tags=["fortinac"],
    )


class FortiNACConnector(BaseConnector):
    kind = "FORTINAC"
    secret_fields = ["username", "password"]
    config_fields = ["host_path", "internet_vlans", "isolated_vlans", "verify_tls"]
    supports_isolate = True

    async def _token(self, c: httpx.AsyncClient) -> str:
        u, p = self.secrets.get("username"), self.secrets.get("password")
        if not u or not p:
            raise ConnectorError("Thiếu username/password FortiNAC")
        r = await c.post(self.base_url + "/api/v2/auth", json={"username": u, "password": p})
        r.raise_for_status()
        j = r.json()
        return j.get("token") or (j.get("data") or {}).get("token") or j.get("access_token")

    def _client(self) -> httpx.AsyncClient:
        verify = bool(self.config.get("verify_tls", True))
        return httpx.AsyncClient(timeout=30, trust_env=False, verify=verify)

    async def test_connection(self) -> Dict[str, Any]:
        try:
            async with self._client() as c:
                tok = await self._token(c)
            return {"ok": bool(tok), "message": "Đăng nhập FortiNAC thành công" if tok else "Không lấy được token",
                    "detail": ""}
        except Exception as e:
            return {"ok": False, "message": str(e)[:300], "detail": ""}

    async def fetch_assets(self) -> List[NormAsset]:
        path = self.config.get("host_path", "/api/v2/host")
        async with self._client() as c:
            tok = await self._token(c)
            r = await c.get(self.base_url + path, headers={"Authorization": f"Bearer {tok}"})
            r.raise_for_status()
            j = r.json()
        hosts = j.get("hosts") or j.get("data") or (j if isinstance(j, list) else j.get("results", []))
        return [parse_host(h, self.config) for h in hosts]

    async def isolate_host(self, external_id: str) -> Dict[str, Any]:
        """Cách ly = đổi host sang trạng thái/VLAN cách ly. Endpoint tuỳ bản → dùng config."""
        path = (self.config.get("isolate_path") or "/api/v2/host/{id}/disable").replace("{id}", external_id)
        async with self._client() as c:
            tok = await self._token(c)
            r = await c.post(self.base_url + path, headers={"Authorization": f"Bearer {tok}"})
        return {"ok": r.status_code in (200, 202, 204), "status": r.status_code, "detail": r.text[:300]}
