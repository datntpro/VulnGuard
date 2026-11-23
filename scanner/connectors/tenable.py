"""
Tenable.io connector (Vulnerability Management — cloud).

Auth: header 'X-ApiKeys: accessKey=<ak>;secretKey=<sk>' (tạo trong Tenable: Settings → API Keys).
base_url mặc định https://cloud.tenable.com
  - Asset ← GET /assets
  - Alert ← GET /workbenches/vulnerabilities  (plugin-level, severity 0..4)
Với Tenable.sc (on-prem) API khác — dùng adapter riêng nếu cần.
"""
from typing import Any, Dict, List, Optional

import httpx

from scanner.connectors.base import BaseConnector, ConnectorError, NormAlert, NormAsset

DEFAULT_BASE = "https://cloud.tenable.com"
_SEV = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}


def _first(v):
    if isinstance(v, list):
        return v[0] if v else None
    return v


def parse_asset(a: Dict[str, Any]) -> NormAsset:
    return NormAsset(
        hostname=_first(a.get("fqdn")) or _first(a.get("hostname")) or _first(a.get("netbios_name")),
        ip=_first(a.get("ipv4")) or _first(a.get("ipv6")),
        mac=_first(a.get("mac_address")),
        os=_first(a.get("operating_system")),
        external_id=str(a.get("id") or ""),
        tags=["tenable"],
    )


def parse_vuln(v: Dict[str, Any]) -> NormAlert:
    return NormAlert(
        external_id=str(v.get("plugin_id") or ""),
        title=v.get("plugin_name") or v.get("name"),
        severity=_SEV.get(int(v.get("severity", 0) or 0), "info"),
        status="OPEN",
        raw={"count": v.get("count"), "vuln_count": v.get("vulnerability_count")},
    )


class TenableConnector(BaseConnector):
    kind = "TENABLE_IO"
    secret_fields = ["access_key", "secret_key"]
    config_fields = ["assets_path", "vulns_path"]
    supports_isolate = False

    def _headers(self) -> Dict[str, str]:
        ak, sk = self.secrets.get("access_key"), self.secrets.get("secret_key")
        if not ak or not sk:
            raise ConnectorError("Thiếu access_key/secret_key Tenable")
        return {"X-ApiKeys": f"accessKey={ak};secretKey={sk}", "Accept": "application/json"}

    async def _get(self, path: str) -> Dict:
        base = self.base_url or DEFAULT_BASE
        async with httpx.AsyncClient(timeout=40, trust_env=False) as c:
            r = await c.get(base + path, headers=self._headers())
            r.raise_for_status()
            return r.json()

    async def test_connection(self) -> Dict[str, Any]:
        try:
            await self._get("/assets?limit=1")
            return {"ok": True, "message": "Kết nối Tenable.io OK", "detail": ""}
        except Exception as e:
            return {"ok": False, "message": str(e)[:300], "detail": ""}

    async def fetch_assets(self) -> List[NormAsset]:
        data = await self._get(self.config.get("assets_path", "/assets"))
        return [parse_asset(a) for a in (data.get("assets") or [])]

    async def fetch_alerts(self) -> List[NormAlert]:
        data = await self._get(self.config.get("vulns_path", "/workbenches/vulnerabilities"))
        return [parse_vuln(v) for v in (data.get("vulnerabilities") or [])]
