"""
Wazuh connector (open-source SIEM/XDR/HIDS) — nhiều doanh nghiệp dùng miễn phí.

Auth: POST {base}/security/user/authenticate?raw=true  (HTTP Basic user:pass) → JWT.
      Gửi tiếp 'Authorization: Bearer <token>'. Wazuh Manager API mặc định cổng 55000,
      thường dùng cert self-signed (verify tắt).
Dữ liệu:
  - Asset  ← GET /agents            (agent = máy được giám sát)
  - Alert  ← GET /vulnerability/{agent_id}  (CVE theo agent; 4.x. Bản mới chuyển sang
             Indexer — nếu endpoint 404 thì bỏ qua, không làm hỏng sync)
base_url ví dụ: https://wazuh-manager:55000
"""
import time
from typing import Any, Dict, List, Optional

import httpx

from scanner.connectors.base import BaseConnector, ConnectorError, NormAlert, NormAsset

_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low",
        "untriaged": "info", "informational": "info"}


def parse_agent(a: Dict[str, Any]) -> NormAsset:
    os_ = a.get("os") or {}
    status = a.get("status")
    return NormAsset(
        hostname=a.get("name"),
        ip=a.get("ip") or (a.get("registerIP")),
        os=(os_.get("name") or os_.get("platform")),
        os_version=os_.get("version"),
        asset_type="SERVER" if (os_.get("platform") in ("centos", "ubuntu", "debian", "rhel")) else "HOST",
        edr_agent_present=True,
        edr_health="active" if status == "active" else (status or None),
        external_id=str(a.get("id") or ""),
        tags=["wazuh"] + ([a.get("group")[0]] if a.get("group") else []),
    )


def parse_vuln(v: Dict[str, Any], agent: Dict[str, Any]) -> NormAlert:
    cve = v.get("cve") or v.get("id")
    name = v.get("title") or v.get("name") or ""
    return NormAlert(
        external_id=str(cve or ""),
        title=f"{cve}: {name}".strip(": ") if name else cve,
        severity=_SEV.get(str(v.get("severity", "")).lower(), str(v.get("severity", "")).lower() or None),
        status=v.get("condition") or v.get("status"),
        detected_at=v.get("detection_time") or v.get("published"),
        hostname=agent.get("name"),
        ip=agent.get("ip"),
        raw={"cvss": v.get("cvss3_score") or v.get("cvss2_score"), "cve": cve,
             "package": v.get("name") or v.get("package")},
    )


class WazuhConnector(BaseConnector):
    kind = "WAZUH"
    secret_fields = ["username", "password"]
    config_fields = ["verify_tls", "max_agents"]
    supports_isolate = False

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._token: Optional[str] = None
        self._token_exp = 0.0

    def _verify(self) -> bool:
        return str(self.config.get("verify_tls", "")).lower() in ("1", "true", "yes")

    async def _get_token(self) -> str:
        if self._token and time.time() < self._token_exp - 30:
            return self._token
        user, pw = self.secrets.get("username"), self.secrets.get("password")
        if not user or not pw:
            raise ConnectorError("Thiếu username/password Wazuh")
        url = f"{self.base_url}/security/user/authenticate?raw=true"
        async with httpx.AsyncClient(timeout=20, trust_env=False, verify=self._verify()) as c:  # nosec B501
            r = await c.post(url, auth=(user, pw))
            r.raise_for_status()
            self._token = r.text.strip()
        self._token_exp = time.time() + 800          # token Wazuh mặc định ~900s
        return self._token

    async def _get(self, path: str) -> List[Dict]:
        token = await self._get_token()
        async with httpx.AsyncClient(timeout=30, trust_env=False, verify=self._verify()) as c:  # nosec B501
            r = await c.get(self.base_url + path, headers={"Authorization": f"Bearer {token}"})
            if r.status_code == 404:
                return []
            r.raise_for_status()
            data = r.json().get("data", {})
        return data.get("affected_items", []) if isinstance(data, dict) else (data or [])

    async def test_connection(self) -> Dict[str, Any]:
        try:
            await self._get_token()
            agents = await self._get("/agents?limit=1")
            return {"ok": True, "message": f"Kết nối Wazuh OK ({len(agents)}+ agent)", "detail": ""}
        except Exception as e:
            return {"ok": False, "message": str(e)[:300], "detail": ""}

    async def fetch_assets(self) -> List[NormAsset]:
        limit = int(self.config.get("max_agents", 2000) or 2000)
        agents = await self._get(f"/agents?limit={min(limit, 100000)}&select=id,name,ip,os,status,group")
        return [parse_agent(a) for a in agents if a.get("id") not in ("000", None)]

    async def fetch_alerts(self) -> List[NormAlert]:
        """CVE theo từng agent (Wazuh 4.x). Bản mới (Indexer) sẽ trả rỗng — không lỗi."""
        out: List[NormAlert] = []
        agents = await self._get("/agents?limit=2000&select=id,name,ip")
        for a in agents[:500]:
            aid = a.get("id")
            if aid in ("000", None):
                continue
            try:
                for v in await self._get(f"/vulnerability/{aid}?limit=500"):
                    out.append(parse_vuln(v, a))
            except Exception:
                continue
        return out
