"""
OpenVAS / Greenbone (GVM) connector (Vulnerability Management — open source).

Giao thức GMP (Greenbone Management Protocol) qua TLS socket (mặc định cổng 9390),
dùng thư viện python-gvm. Thư viện là OPTIONAL — nếu chưa cài, test_connection báo rõ.
base_url: host[:port] của Greenbone (vd gvm.corp.vn:9390). Secret: username/password.
  - Asset ← get_assets(asset_type=host)
  - Alert ← get_results  (mỗi result = 1 phát hiện lỗ hổng, severity CVSS)
Hàm parse XML là pure (test được không cần GVM).
"""
import defusedxml.ElementTree as ET
from defusedxml import DefusedXmlException
from typing import Any, Dict, List, Tuple

from scanner.connectors.base import BaseConnector, ConnectorError, NormAlert, NormAsset


def _sev_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _txt(node, tag, default=None):
    el = node.find(tag)
    return el.text if el is not None and el.text else default


def parse_results_xml(xml_text: str) -> List[NormAlert]:
    """Pure: <get_results_response><result>… → NormAlert."""
    out = []
    try:
        root = ET.fromstring(xml_text)
    except (ET.ParseError, DefusedXmlException):
        return out
    for r in root.iter("result"):
        host_el = r.find("host")
        ip = (host_el.text or "").strip() if host_el is not None else None
        hostname = _txt(host_el, "hostname") if host_el is not None else None
        try:
            score = float(_txt(r, "severity", "0") or 0)
        except ValueError:
            score = 0.0
        nvt = r.find("nvt")
        name = _txt(nvt, "name") if nvt is not None else _txt(r, "name")
        cve = _txt(nvt, "cve") if nvt is not None else None
        title = name or "Phát hiện"
        if cve and cve not in ("NOCVE", "", None):
            title = f"{cve}: {title}"
        out.append(NormAlert(
            external_id=r.get("id"),
            title=title,
            severity=_sev_from_cvss(score),
            status="OPEN",
            hostname=hostname, ip=ip,
            raw={"cvss": score, "threat": _txt(r, "threat")},
        ))
    return out


def parse_assets_xml(xml_text: str) -> List[NormAsset]:
    """Pure: <get_assets_response><asset type=host>… → NormAsset."""
    out = []
    try:
        root = ET.fromstring(xml_text)
    except (ET.ParseError, DefusedXmlException):
        return out
    for a in root.iter("asset"):
        name = _txt(a, "name")                 # thường là IP
        host = a.find("host")
        hostname = None
        if host is not None:
            for idf in host.iter("identifier"):
                if _txt(idf, "name") == "hostname":
                    hostname = _txt(idf, "value")
                    break
        out.append(NormAsset(hostname=hostname, ip=name, external_id=a.get("id"), tags=["openvas"]))
    return out


class OpenVASConnector(BaseConnector):
    kind = "OPENVAS_GVM"
    secret_fields = ["username", "password"]
    config_fields = ["port"]
    supports_isolate = False

    def _host_port(self) -> Tuple[str, int]:
        hp = self.base_url.replace("https://", "").replace("http://", "")
        if ":" in hp:
            host, port = hp.split(":", 1)
            return host, int(port)
        return hp, int(self.config.get("port", 9390) or 9390)

    def _gmp(self):
        """Lazy import python-gvm; trả về context manager Gmp đã kết nối (chưa auth)."""
        try:
            from gvm.connections import TLSConnection
            from gvm.protocols.gmp import Gmp
        except ImportError:
            raise ConnectorError("Cần cài 'python-gvm' để kết nối OpenVAS/Greenbone (pip install python-gvm)")
        host, port = self._host_port()
        return Gmp(connection=TLSConnection(hostname=host, port=port))

    def _run(self, fn):
        user, pw = self.secrets.get("username"), self.secrets.get("password")
        if not user or not pw:
            raise ConnectorError("Thiếu username/password OpenVAS")
        with self._gmp() as gmp:
            gmp.authenticate(user, pw)
            return fn(gmp)

    async def test_connection(self) -> Dict[str, Any]:
        import asyncio
        try:
            ver = await asyncio.to_thread(self._run, lambda g: g.get_version())
            return {"ok": True, "message": "Kết nối Greenbone/GMP OK", "detail": ""}
        except Exception as e:
            return {"ok": False, "message": str(e)[:300], "detail": ""}

    async def fetch_assets(self) -> List[NormAsset]:
        import asyncio
        xml = await asyncio.to_thread(self._run, lambda g: g.get_assets(asset_type="host"))
        return parse_assets_xml(xml if isinstance(xml, str) else str(xml))

    async def fetch_alerts(self) -> List[NormAlert]:
        import asyncio
        xml = await asyncio.to_thread(self._run, lambda g: g.get_results(filter_string="rows=1000 severity>0"))
        return parse_results_xml(xml if isinstance(xml, str) else str(xml))
