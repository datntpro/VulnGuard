"""GĐ1 triage: kế thừa qua scan + apply_triage (quyền, note, audit)."""
import uuid

import pytest

import api.main  # noqa: F401 — tạo bảng + migrations
from api.database import SessionLocal
from api.models import (Project, Scan, Vulnerability, TriageEvent, VulnStatus,
                        ScanType, Severity, ScanStatus)
from api.services import triage


def _mk(db, project, scan_number, fp, status=VulnStatus.OPEN, **kw):
    scan = Scan(id=str(uuid.uuid4()), project_id=project.id, scan_number=scan_number,
                scan_path="/w/app", scan_types=["SAST"], status=ScanStatus.COMPLETED)
    db.add(scan); db.flush()
    v = Vulnerability(id=str(uuid.uuid4()), scan_id=scan.id, tool="semgrep",
                      scan_type=ScanType.SAST, title="SQLi", severity=Severity.HIGH,
                      fingerprint=fp, status=status, **kw)
    db.add(v); db.commit()
    return scan, v


@pytest.fixture
def db():
    s = SessionLocal()
    yield s
    s.close()


def _project(db):
    p = Project(id=str(uuid.uuid4()), name="t-" + uuid.uuid4().hex[:6])
    db.add(p); db.commit()
    return p


def test_apply_triage_writes_audit_and_meta(db):
    p = _project(db)
    _, v = _mk(db, p, 1, "fp-aaa")
    triage.apply_triage(db, v, VulnStatus.CONFIRMED, note="thật", actor="an@x", is_admin=False)
    assert v.status == VulnStatus.CONFIRMED and v.triage_by == "an@x" and v.triage_at
    ev = db.query(TriageEvent).filter(TriageEvent.fingerprint == "fp-aaa").all()
    assert len(ev) == 1 and ev[0].to_status == "CONFIRMED" and ev[0].from_status == "OPEN"


def test_not_exploitable_requires_admin(db):
    p = _project(db)
    _, v = _mk(db, p, 1, "fp-bbb")
    with pytest.raises(triage.TriageError) as e:
        triage.apply_triage(db, v, VulnStatus.NOT_EXPLOITABLE, note="ok", actor="an@x", is_admin=False)
    assert e.value.status_code == 403


def test_note_required_for_not_exploitable(db):
    p = _project(db)
    _, v = _mk(db, p, 1, "fp-ccc")
    with pytest.raises(triage.TriageError) as e:
        triage.apply_triage(db, v, VulnStatus.NOT_EXPLOITABLE, note="", actor="ad@x", is_admin=True)
    assert e.value.status_code == 422
    # có note + admin → ok
    triage.apply_triage(db, v, VulnStatus.NOT_EXPLOITABLE, note="không tới sink", actor="ad@x", is_admin=True)
    assert v.status == VulnStatus.NOT_EXPLOITABLE


def test_inherit_triage_across_scans(db):
    p = _project(db)
    # scan 1: finding fp-X đánh NOT_EXPLOITABLE
    _, v1 = _mk(db, p, 1, "fp-X")
    triage.apply_triage(db, v1, VulnStatus.NOT_EXPLOITABLE, note="FP", actor="ad@x", is_admin=True)
    # scan 2: cùng fingerprint, mặc định OPEN
    scan2, v2 = _mk(db, p, 2, "fp-X")
    n = triage.inherit_triage(db, scan2)
    db.refresh(v2)
    assert n == 1
    assert v2.status == VulnStatus.NOT_EXPLOITABLE      # kế thừa, không phải triage lại
    assert v2.triage_note == "FP"
    assert v2.first_seen_at is not None
    assert triage.is_new_finding(v2) is False            # đã có ở scan trước → không "Mới"


def test_new_finding_flagged_new(db):
    p = _project(db)
    scan, v = _mk(db, p, 1, "fp-new-only")
    triage.inherit_triage(db, scan)
    db.refresh(v)
    assert triage.is_new_finding(v) is True
