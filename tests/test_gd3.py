"""GĐ3: data-flow extractor + report lọc New/Recurrent/active."""
import json
import uuid

import pytest
from fastapi.testclient import TestClient

from scanner import dataflow as D


def test_dataflow_source_to_sink():
    raw = {"extra": {"dataflow_trace": {
        "taint_source": ["CliLoc", [{"path": "a.py", "start": {"line": 1}}, "x = input()"]],
        "intermediate_vars": [{"location": {"path": "a.py", "start": {"line": 5}}, "content": "y = x"}],
        "taint_sink": ["CliLoc", [{"path": "b.py", "start": {"line": 9}}, "exec(y)"]],
    }}}
    nodes = D.extract(raw)
    assert [n["label"] for n in nodes] == ["source", "propagation", "sink"]
    assert nodes[0]["line"] == 1 and nodes[-1]["file"] == "b.py"


def test_dataflow_empty_safe():
    assert D.extract(None) == [] and D.extract({}) == [] and D.extract({"extra": {}}) == []


@pytest.fixture
def client():
    import api.main  # noqa
    from api.main import app
    from api.database import SessionLocal
    from api.auth_models import User, UserRole
    from api.security import hash_password
    email, pw = f"a{uuid.uuid4().hex[:6]}@x.vn", "Passw0rd!!23"
    db = SessionLocal()
    db.add(User(id=str(uuid.uuid4()), email=email, name="A",
                password_hash=hash_password(pw), role=UserRole.ADMIN, is_active=True))
    db.commit(); db.close()
    c = TestClient(app)
    c.post("/api/auth/login", json={"email": email, "password": pw})
    return c


def _seed_scan(statuses_firstseen):
    """statuses_firstseen: list of (status, is_new). Trả (scan_id)."""
    from api.database import SessionLocal
    from api.models import Project, Scan, Vulnerability, ScanType, Severity, ScanStatus, VulnStatus
    db = SessionLocal()
    p = Project(id=str(uuid.uuid4()), name="gd3-" + uuid.uuid4().hex[:5]); db.add(p); db.commit()
    scan = Scan(id=str(uuid.uuid4()), project_id=p.id, scan_number=1, scan_path="/w",
                scan_types=["SAST"], status=ScanStatus.COMPLETED)
    db.add(scan); db.flush()
    for i, (st, is_new) in enumerate(statuses_firstseen):
        db.add(Vulnerability(id=str(uuid.uuid4()), scan_id=scan.id, tool="t", scan_type=ScanType.SAST,
                             title=f"v{i}", severity=Severity.HIGH, fingerprint=f"fp{i}",
                             status=VulnStatus(st),
                             first_seen_scan_id=(scan.id if is_new else "older-scan")))
    db.commit()
    sid = scan.id; db.close()
    return sid


def _count(client, scan_id, **params):
    q = "&".join(f"{k}={v}" for k, v in params.items())
    r = client.get(f"/api/projects/scans/{scan_id}/export?format=json&{q}")
    assert r.status_code == 200, r.text
    return len(json.loads(r.content)["vulnerabilities"])


def test_export_diff_and_scope(client):
    sid = _seed_scan([("OPEN", True), ("OPEN", False),
                      ("NOT_EXPLOITABLE", True), ("CONFIRMED", False)])
    assert _count(client, sid) == 4                        # all
    assert _count(client, sid, diff="new") == 2            # 2 cái is_new
    assert _count(client, sid, diff="recurrent") == 2
    assert _count(client, sid, scope="active") == 3        # NOT_EXPLOITABLE bị loại
    assert _count(client, sid, diff="new", scope="active") == 1
