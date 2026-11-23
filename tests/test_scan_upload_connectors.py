"""Upload .zip (chống zip-slip) + Wazuh connector parse."""
import io
import os
import tempfile
import zipfile


# ── zip upload: giải nén an toàn, chặn zip-slip ──
def _zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def test_safe_extract_normal():
    from api.routes.scans import _safe_extract_zip
    d = tempfile.mkdtemp()
    n = _safe_extract_zip(_zip({"app/main.py": "x=1", "README.md": "hi"}), d)
    assert n == 2
    assert os.path.isfile(os.path.join(d, "app", "main.py"))


def test_safe_extract_blocks_zip_slip():
    from api.routes.scans import _safe_extract_zip
    d = tempfile.mkdtemp()
    # member cố thoát ra ngoài dest
    n = _safe_extract_zip(_zip({"../../evil.sh": "rm -rf /", "ok.txt": "safe"}), d)
    assert n == 1                                   # chỉ ok.txt được giải nén
    assert os.path.isfile(os.path.join(d, "ok.txt"))
    # file độc KHÔNG được tạo ở thư mục cha
    assert not os.path.exists(os.path.join(os.path.dirname(os.path.dirname(d)), "evil.sh"))


# ── Wazuh connector ──
def test_wazuh_registered():
    from scanner.connectors.registry import REGISTRY
    assert "WAZUH" in REGISTRY


def test_wazuh_parse_agent_and_vuln():
    from scanner.connectors.wazuh import parse_agent, parse_vuln
    a = parse_agent({"id": "003", "name": "db-01", "ip": "10.0.0.9",
                     "os": {"name": "CentOS", "version": "7", "platform": "centos"},
                     "status": "active", "group": ["db"]})
    assert a.hostname == "db-01" and a.edr_agent_present is True and "wazuh" in a.tags
    v = parse_vuln({"cve": "CVE-2024-9", "title": "bash RCE", "severity": "Critical"},
                   {"name": "db-01", "ip": "10.0.0.9"})
    assert v.severity == "critical" and "CVE-2024-9" in v.title and v.hostname == "db-01"


# ── OpenVAS / Tenable / Qualys parse ──
def test_openvas_results_parse():
    from scanner.connectors.openvas import parse_results_xml, parse_assets_xml
    xml = '''<get_results_response><result id="r1"><name>OpenSSL</name>
      <host>10.0.0.5<hostname>web-01</hostname></host><severity>9.8</severity><threat>High</threat>
      <nvt oid="1"><name>OpenSSL RCE</name><cve>CVE-2022-1</cve></nvt></result></get_results_response>'''
    al = parse_results_xml(xml)
    assert len(al) == 1 and al[0].severity == "critical" and "CVE-2022-1" in al[0].title and al[0].ip == "10.0.0.5"
    ax = '''<get_assets_response><asset id="a1"><name>10.0.0.5</name>
      <host><identifier><name>hostname</name><value>web-01</value></identifier></host></asset></get_assets_response>'''
    assets = parse_assets_xml(ax)
    assert assets[0].ip == "10.0.0.5" and assets[0].hostname == "web-01" and "openvas" in assets[0].tags


def test_tenable_parse():
    from scanner.connectors.tenable import parse_asset, parse_vuln
    a = parse_asset({"id": "x", "fqdn": ["web-01.corp"], "ipv4": ["10.0.0.5"], "operating_system": ["Linux"]})
    assert a.hostname == "web-01.corp" and a.ip == "10.0.0.5"
    v = parse_vuln({"plugin_id": 99, "plugin_name": "TLS weak", "severity": 4})
    assert v.severity == "critical" and v.title == "TLS weak"


def test_qualys_parse():
    from scanner.connectors.qualys import parse_hosts_xml, parse_detections_xml
    hx = '<HOST_LIST_OUTPUT><HOST><ID>1</ID><IP>10.0.0.5</IP><DNS>web-01</DNS><OS>Linux</OS></HOST></HOST_LIST_OUTPUT>'
    h = parse_hosts_xml(hx)
    assert h[0].ip == "10.0.0.5" and h[0].hostname == "web-01"
    dx = '<OUTPUT><HOST><IP>10.0.0.5</IP><DNS>web-01</DNS><DETECTION_LIST><DETECTION><QID>38170</QID><SEVERITY>5</SEVERITY><STATUS>Active</STATUS></DETECTION></DETECTION_LIST></HOST></OUTPUT>'
    d = parse_detections_xml(dx)
    assert d[0].severity == "critical" and d[0].ip == "10.0.0.5" and "38170" in d[0].title
