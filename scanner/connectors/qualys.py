"""
Qualys VMDR connector (Vulnerability Management — cloud/on-prem).

Auth: HTTP Basic (username/password) + header 'X-Requested-With'. API trả XML.
base_url theo platform của bạn, vd https://qualysapi.qg2.apps.qualys.com
  - Asset ← GET /api/2.0/fo/asset/host/?action=list
  - Alert ← GET /api/2.0/fo/asset/host/vm/detection/?action=list  (QID + severity 1..5)
Severity Qualys 1..5 → info..critical.
"""
import defusedxml.ElementTree as ET
from defusedxml import DefusedXmlException
from typing import Any, Dict, List

import httpx

from scanner.connectors.base import BaseConnector, ConnectorError, NormAlert, NormAsset

_SEV = {"5": "critical", "4": "high", "3": "medium", "2": "low", "1": "info"}


def _txt(node, tag):
    el = node.find(tag)
    return el.text if el is not None else None


def parse_hosts_xml(xml_text: str) -> List[NormAsset]:
    """Pure: parse <HOST_LIST_OUTPUT> → NormAsset."""
    out = []
    try:
        root = ET.fromstring(xml_text)
    except (ET.ParseError, DefusedXmlException):
        return out
    for h in root.iter("HOST"):
        out.append(NormAsset(
            hostname=_txt(h, "DNS") or _txt(h, "NETBIOS") or _txt(h, "FQDN"),
            ip=_txt(h, "IP"),
            os=_txt(h, "OS"),
            external_id=_txt(h, "ID"),
            tags=["qualys"],
        ))
    return out


def parse_detections_xml(xml_text: str) -> List[NormAlert]:
    """Pure: parse detection list → NormAlert (mỗi DETECTION là 1 lỗ hổng theo QID)."""
    out = []
    try:
        root = ET.fromstring(xml_text)
    except (ET.ParseError, DefusedXmlException):
        return out
    for host in root.iter("HOST"):
        ip = _txt(host, "IP")
        dns = _txt(host, "DNS")
        for d in host.iter("DETECTION"):
            sev = _txt(d, "SEVERITY")
            out.append(NormAlert(
                external_id=_txt(d, "QID"),
                title=f"QID {_txt(d, 'QID')}",
                severity=_SEV.get(str(sev), "info"),
                status=_txt(d, "STATUS") or "OPEN",
                hostname=dns, ip=ip,
                raw={"type": _txt(d, "TYPE"), "last_found": _txt(d, "LAST_FOUND_DATETIME")},
            ))
    return out


class QualysConnector(BaseConnector):
    kind = "QUALYS_VMDR"
    secret_fields = ["username", "password"]
    config_fields = ["truncation_limit"]
    supports_isolate = False

    def _auth(self):
        u, p = self.secrets.get("username"), self.secrets.get("password")
        if not u or not p:
            raise ConnectorError("Thiếu username/password Qualys")
        return (u, p)

    async def _get(self, path: str) -> str:
        async with httpx.AsyncClient(timeout=60, trust_env=False) as c:
            r = await c.get(self.base_url + path, auth=self._auth(),
                            headers={"X-Requested-With": "VulnGuard"})
            r.raise_for_status()
            return r.text

    async def test_connection(self) -> Dict[str, Any]:
        try:
            xml = await self._get("/api/2.0/fo/asset/host/?action=list&truncation_limit=1")
            n = len(parse_hosts_xml(xml))
            return {"ok": True, "message": f"Kết nối Qualys OK ({n}+ host)", "detail": ""}
        except Exception as e:
            return {"ok": False, "message": str(e)[:300], "detail": ""}

    async def fetch_assets(self) -> List[NormAsset]:
        lim = int(self.config.get("truncation_limit", 1000) or 1000)
        return parse_hosts_xml(await self._get(f"/api/2.0/fo/asset/host/?action=list&truncation_limit={lim}"))

    async def fetch_alerts(self) -> List[NormAlert]:
        lim = int(self.config.get("truncation_limit", 1000) or 1000)
        return parse_detections_xml(
            await self._get(f"/api/2.0/fo/asset/host/vm/detection/?action=list&truncation_limit={lim}"))
