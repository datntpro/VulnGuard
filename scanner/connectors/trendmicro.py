"""
Trend Micro Vision One (XDR) connector.

Auth: Bearer API token (tạo trong Vision One console → API Keys).
Base URL theo region, vd https://api.xdr.trendmicro.com (US), api.eu.xdr..., api.sg...
Endpoint (v3.0):
  GET /v3.0/endpointSecurity/endpoints   → inventory endpoint (agent)
  GET /v3.0/workbench/alerts             → workbench alerts (đang bị tấn công)
Phân trang qua field `nextLink`. Parsing tolerant (schema có thể đổi nhẹ theo version).
"""
from typing import Any, Dict, List, Optional

import httpx

from scanner.connectors.base import BaseConnector, ConnectorError, NormAlert, NormAsset, NormSoftware


def _sev(v: Optional[str]) -> Optional[str]:
    m = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info",
         "informational": "info"}
    return m.get(str(v or "").lower(), (str(v).lower() if v else None))


def parse_endpoint(e: Dict[str, Any]) -> NormAsset:
    os_name = e.get("osName") or (e.get("os") or {}).get("name") if isinstance(e.get("os"), dict) else e.get("osName")
    ips = e.get("ip") or e.get("ips") or []
    if isinstance(ips, dict):
        ips = ips.get("value") or []
    ip = ips[0] if isinstance(ips, list) and ips else (ips if isinstance(ips, str) else None)
    macs = e.get("macAddress") or e.get("mac") or []
    mac = macs[0] if isinstance(macs, list) and macs else (macs if isinstance(macs, str) else None)
    etype = (e.get("endpointType") or "").lower()
    atype = "SERVER" if "server" in etype else ("WORKSTATION" if etype else None)
    return NormAsset(
        hostname=e.get("endpointName") or e.get("hostname") or e.get("displayName"),
        ip=ip, mac=mac, os=os_name, os_version=e.get("osVersion"),
        asset_type=atype,
        edr_agent_present=True,
        edr_health=(e.get("agentUpdateStatus") or e.get("componentUpdateStatus") or e.get("status")),
        external_id=e.get("agentGuid") or e.get("endpointGuid") or e.get("id"),
        tags=["trendmicro"],
        software=[NormSoftware(name=a) for a in (e.get("installedProducts") or []) if isinstance(a, str)],
    )


def parse_alert(a: Dict[str, Any]) -> List[NormAlert]:
    """1 workbench alert có thể chạm nhiều endpoint (impactScope) → nhiều NormAlert."""
    techniques = []
    for ind in (a.get("indicators") or []):
        for t in (ind.get("techniqueIds") or []):
            techniques.append(t)
    technique = techniques[0] if techniques else None
    sev = _sev(a.get("severity"))
    base = dict(external_id=a.get("id") or a.get("workbenchId"), title=a.get("model") or a.get("name"),
                severity=sev, status=a.get("status") or a.get("investigationStatus"),
                technique=technique, detected_at=a.get("createdDateTime") or a.get("firstSeenDateTime"),
                raw={"caseId": a.get("caseId"), "score": a.get("score")})
    hosts = []
    scope = a.get("impactScope") or {}
    for ent in (scope.get("entities") or scope.get("entityValue") or []):
        if isinstance(ent, dict):
            ev = ent.get("entityValue") or {}
            name = ev.get("name") if isinstance(ev, dict) else None
            ips = (ev.get("ips") if isinstance(ev, dict) else None) or []
            hosts.append((name, ips[0] if ips else None))
    if not hosts:
        hosts = [(None, None)]
    out = []
    for name, ip in hosts:
        out.append(NormAlert(hostname=name, ip=ip, **base))
    return out


class TrendMicroConnector(BaseConnector):
    kind = "TRENDMICRO_VISION_ONE"
    secret_fields = ["api_token"]
    config_fields = ["endpoints_path", "alerts_path"]
    supports_isolate = True

    def _headers(self) -> Dict[str, str]:
        tok = self.secrets.get("api_token")
        if not tok:
            raise ConnectorError("Thiếu api_token Vision One")
        return {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}

    async def _get_all(self, path: str, item_key: str = "items", limit_pages: int = 20) -> List[Dict]:
        url = self.base_url + path
        items: List[Dict] = []
        async with httpx.AsyncClient(timeout=30, trust_env=False) as c:
            for _ in range(limit_pages):
                r = await c.get(url, headers=self._headers())
                r.raise_for_status()
                data = r.json()
                items += data.get(item_key, data.get("data", []))
                nxt = data.get("nextLink") or data.get("next")
                if not nxt:
                    break
                url = nxt
        return items

    async def test_connection(self) -> Dict[str, Any]:
        try:
            path = self.config.get("endpoints_path", "/v3.0/endpointSecurity/endpoints") + "?top=1"
            async with httpx.AsyncClient(timeout=15, trust_env=False) as c:
                r = await c.get(self.base_url + path, headers=self._headers())
            return {"ok": r.status_code == 200, "message": f"HTTP {r.status_code}",
                    "detail": r.text[:300]}
        except Exception as e:
            return {"ok": False, "message": str(e)[:300], "detail": ""}

    async def fetch_assets(self) -> List[NormAsset]:
        path = self.config.get("endpoints_path", "/v3.0/endpointSecurity/endpoints")
        return [parse_endpoint(e) for e in await self._get_all(path)]

    async def fetch_alerts(self) -> List[NormAlert]:
        path = self.config.get("alerts_path", "/v3.0/workbench/alerts")
        out: List[NormAlert] = []
        for a in await self._get_all(path):
            out += parse_alert(a)
        return out

    async def isolate_host(self, external_id: str) -> Dict[str, Any]:
        body = [{"agentGuid": external_id, "description": "VulnGuard pentest isolate"}]
        async with httpx.AsyncClient(timeout=30, trust_env=False) as c:
            r = await c.post(self.base_url + "/v3.0/response/endpoints/isolate",
                             headers=self._headers(), json=body)
        return {"ok": r.status_code in (200, 202, 207), "status": r.status_code, "detail": r.text[:300]}
