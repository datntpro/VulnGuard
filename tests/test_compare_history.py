"""GĐ2: compare Not Evaluated + scan-trend."""
import uuid

import pytest
from fastapi.testclient import TestClient


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


def _seed(scan_types, findings):
    """findings: list of (fingerprint, scan_type, severity). Trả scan_id."""
    import uuid as u
    from api.database import SessionLocal
    from api.models import Project, Scan, Vulnerability, ScanType, Severity, ScanStatus
    db = SessionLocal()
    p = db.query(Project).filter(Project.name == "cmp-shared").first()
    if not p:
        p = Project(id=str(u.uuid4()), name="cmp-shared"); db.add(p); db.commit()
    n = len(db.query(Scan).filter(Scan.project_id == p.id).all()) + 1
    scan = Scan(id=str(u.uuid4()), project_id=p.id, scan_number=n, scan_path="/w",
                scan_types=scan_types, status=ScanStatus.COMPLETED)
    db.add(scan); db.flush()
    for fp, st, sev in findings:
        db.add(Vulnerability(id=str(u.uuid4()), scan_id=scan.id, tool="t",
                             scan_type=ScanType(st), title="x", severity=Severity(sev), fingerprint=fp))
    db.commit()
    pid, sid = p.id, scan.id
    db.close()
    return pid, sid


def test_not_evaluated_on_settings_change(client):
    # scan cũ: SAST+SCA, có 1 SCA finding (fp-sca) + 1 SAST (fp-sast)
    pid, old = _seed(["SAST", "SCA"], [("fp-sca", "SCA", "HIGH"), ("fp-sast", "SAST", "LOW")])
    # scan mới: CHỈ SAST — fp-sast vẫn còn; fp-sca biến mất nhưng vì SCA không chạy → Not Evaluated
    _, new = _seed(["SAST"], [("fp-sast", "SAST", "LOW")])
    r = client.get(f"/api/projects/{pid}/compare?scan_old_id={old}&scan_new_id={new}")
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["summary"]["settings_changed"] is True
    ne = [v["fingerprint"] for v in d["diff"]["not_evaluated"]]
    fixed = [v["fingerprint"] for v in d["diff"]["fixed"]]
    assert "fp-sca" in ne                 # không báo nhầm "đã fix"
    assert "fp-sca" not in fixed
    assert any(v["fingerprint"] == "fp-sast" for v in d["diff"]["persisted"])


def test_scan_trend(client):
    pid, _ = _seed(["SAST"], [("t1", "SAST", "CRITICAL"), ("t2", "SAST", "LOW")])
    r = client.get(f"/api/projects/{pid}/scan-trend")
    assert r.status_code == 200
    pts = r.json()["points"]
    assert len(pts) >= 1
    assert all("CRITICAL" in p and "total" in p and "active" in p for p in pts)
