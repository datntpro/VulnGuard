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
