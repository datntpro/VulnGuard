"""PDF PR-3: direct download, async jobs, headers, auth, errors, rate limit, audit, no print left in the UI."""
import logging
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote
from uuid import uuid4

import pytest

from api.auth_models import UserRole
from api.database import Base, SessionLocal, engine
from api.models import Project, Scan, ScanStatus, ScanType, Severity, Vulnerability, VulnStatus
from api.services import pdf_export as px
from scanner.pdf.errors import PdfBusy, PdfCompileError
from tests._authutil import bearer, login, make_user, new_client

ROOT = Path(__file__).resolve().parent.parent


def _client(role=UserRole.VIEWER):
    email, _ = make_user(role)
    c = new_client()
    return c, bearer(login(c, email)), email


def _seed_scan(name="Dự án Ngân hàng", n=3):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        p = Project(name=f"{name} {uuid4().hex[:6]}" if name else uuid4().hex)
        db.add(p)
        db.flush()
        s = Scan(project_id=p.id, scan_number=7, scan_path="/w", scan_types=["SAST"], status=ScanStatus.COMPLETED,
                 completed_at=datetime.utcnow())
        db.add(s)
        db.flush()
        for i in range(n):
            db.add(Vulnerability(scan_id=s.id, tool="semgrep", scan_type=ScanType.SAST, title=f"SQLi #{i}",
                                 severity=Severity.HIGH, status=VulnStatus.OPEN, file_path=f"a{i}.py", line_start=i + 1,
                                 description="mô tả"))
        db.commit()
        return s.id, p.name
    finally:
        db.close()


def _rename_project(scan_id, new_name):
    db = SessionLocal()
    try:
        s = db.query(Scan).filter(Scan.id == scan_id).first()
        db.query(Project).filter(Project.id == s.project_id).update({"name": new_name})
        db.commit()
    finally:
        db.close()


def _wait(c, h, job_id, want="done", t=60):
    end = time.time() + t
    while time.time() < end:
        j = c.get(f"/api/reports/pdf-jobs/{job_id}", headers=h).json()
        if j["status"] in (want, "failed"):
            return j
        time.sleep(0.3)
    raise AssertionError("job timeout")


# ── direct download ──
def test_scan_pdf_direct_download_headers():
    c, h, _ = _client()
    sid, name = _seed_scan()
    r = c.get(f"/api/scans/{sid}/report?format=pdf", headers=h)
    assert r.status_code == 200 and r.content[:5] == b"%PDF-"
    assert r.headers["content-type"] == "application/pdf"
    assert r.headers["cache-control"] == "no-store" and r.headers["x-content-type-options"] == "nosniff"
    cd = r.headers["content-disposition"]
    assert re.fullmatch(r'attachment; filename="VulnGuard_[A-Za-z0-9_-]+_Scan7_\d{8}\.pdf"; filename\*=UTF-8\'\'[A-Za-z0-9%._-]+', cd), cd
    assert "D%E1%BB%B1" in cd or "D%C6%B0" in cd or "%E1%BB" in cd   # Vietnamese kept in filename*
    assert unquote(cd.split("filename*=UTF-8''")[1]).startswith("VulnGuard_Dự_án_Ngân_hàng")


def test_scan_pdf_aliases_and_export():
    c, h, _ = _client()
    sid, _ = _seed_scan()
    for url in (f"/api/scans/{sid}/report.pdf", f"/api/projects/scans/{sid}/export?format=pdf"):
        r = c.get(url, headers=h)
        assert r.status_code == 200 and r.content[:5] == b"%PDF-", url


def test_other_formats_unchanged():
    c, h, _ = _client()
    sid, _ = _seed_scan()
    r = c.get(f"/api/scans/{sid}/report", headers=h)
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    assert "window.print" not in r.text and "/report?format=pdf" in r.text


def test_requires_auth_and_missing_or_incomplete():
    sid, _ = _seed_scan()
    assert new_client().get(f"/api/scans/{sid}/report?format=pdf").status_code == 401
    c, h, _ = _client()
    assert c.get("/api/scans/nope/report?format=pdf", headers=h).status_code == 404
    db = SessionLocal()
    db.query(Scan).filter(Scan.id == sid).update({"status": ScanStatus.RUNNING})
    db.commit()
    db.close()
    assert c.get(f"/api/scans/{sid}/report?format=pdf", headers=h).status_code == 400


# ── header injection ──
CRAFTED = [
    'x"\r\nX-Evil: 1',
    'a"; filename="evil.exe',
    "n\r\nSet-Cookie: s=1",
    "../../etc/passwd",
    "t\u00ean\u202egpj.exe",
    "%0d%0aX-Evil: 1",
    "a;b,c'd\\e",
]


@pytest.mark.parametrize("name", CRAFTED)
def test_content_disposition_helper_cannot_be_injected(name):
    cd = px.content_disposition(px.slugify(name), name)
    assert "\r" not in cd and "\n" not in cd and cd.isascii()
    assert cd.count('"') == 2                               # only the two around the ascii filename
    head, _, star = cd.partition("; filename*=UTF-8''")
    assert head.startswith('attachment; filename="') and head.endswith('.pdf"')
    assert re.fullmatch(r"[A-Za-z0-9%._-]+", star)          # no ; , " ' \ / left raw
    assert "%0D" not in star.upper() or "X-Evil" not in unquote(star).replace("\r", "").replace("\n", "")[:0]
    assert "\r" not in unquote(star) and "\n" not in unquote(star) and "/" not in unquote(star) and "\\" not in unquote(star)


@pytest.mark.parametrize("name", CRAFTED)
def test_crafted_project_name_end_to_end(name):
    c, h, _ = _client()
    sid, _ = _seed_scan()
    _rename_project(sid, f"{name}-{uuid4().hex[:6]}")
    r = c.get(f"/api/scans/{sid}/report?format=pdf", headers=h)
    assert r.status_code == 200
    assert "x-evil" not in {k.lower() for k in r.headers}
    cd = r.headers["content-disposition"]
    assert "\r" not in cd and "\n" not in cd
    assert re.fullmatch(r'attachment; filename="[A-Za-z0-9_.-]+\.pdf"; filename\*=UTF-8\'\'[A-Za-z0-9%._-]+', cd), cd


def test_slugify_rules():
    assert px.slugify("Dự án Ngân hàng Đông Á") == "Du-an-Ngan-hang-Dong-A"
    assert px.slugify("") == "report" and px.slugify("///") == "report"
    assert len(px.slugify("a" * 500)) <= 60


# ── errors ──
def test_busy_maps_to_503_with_retry_after(monkeypatch):
    from scanner.pdf import engine
    monkeypatch.setattr(engine, "render", lambda *a, **k: (_ for _ in ()).throw(PdfBusy("busy")))
    c, h, _ = _client()
    sid, _ = _seed_scan()
    r = c.get(f"/api/scans/{sid}/report?format=pdf", headers=h)
    assert r.status_code == 503 and r.headers["retry-after"]
    assert r.json()["detail"]["code"] == "pdf_busy"


def test_engine_error_is_clear_json_without_paths(monkeypatch):
    from scanner.pdf import engine
    leak = "/private/var/tmp/vgpdf_ab12/report.typ:3:1 error: secret-title"
    monkeypatch.setattr(engine, "render", lambda *a, **k: (_ for _ in ()).throw(PdfCompileError(leak)))
    c, h, _ = _client()
    sid, _ = _seed_scan()
    r = c.get(f"/api/scans/{sid}/report?format=pdf", headers=h)
    assert r.status_code == 500 and "application/json" in r.headers["content-type"]
    body = r.text
    assert r.json()["detail"]["code"] == "pdf_compile_error" and r.json()["detail"]["message"]
    assert "/private" not in body and "vgpdf" not in body and ".typ" not in body and "secret-title" not in body


# ── rate limit + audit ──
def test_rate_limited(monkeypatch):
    monkeypatch.setattr(px, "RATE_PER_MIN", 2)
    c, h, _ = _client()
    sid, _ = _seed_scan()
    codes = [c.get(f"/api/scans/{sid}/report?format=pdf", headers=h).status_code for _ in range(3)]
    assert codes == [200, 200, 429]
    r = c.get(f"/api/scans/{sid}/report?format=pdf", headers=h)
    assert r.json()["detail"]["code"] == "pdf_rate_limited" and r.headers["retry-after"]


def test_audit_log_entry(caplog):
    c, h, email = _client()
    sid, _ = _seed_scan()
    with caplog.at_level(logging.INFO, logger="vulnguard.audit"):
        assert c.get(f"/api/scans/{sid}/report?format=pdf", headers=h).status_code == 200
        c.get("/api/scans/nope/report?format=pdf", headers=h)
    lines = [r.getMessage() for r in caplog.records if r.name == "vulnguard.audit"]
    assert any(f"user={email}" in m and "kind=scan" in m and f"id={sid[:8]}" in m and "outcome=ok" in m for m in lines), lines
    assert any("outcome=denied" in m and "status=404" in m for m in lines), lines


# ── async jobs ──
def test_async_job_flow_and_isolation(monkeypatch):
    c, h, _ = _client()
    sid, _ = _seed_scan()
    r = c.get(f"/api/scans/{sid}/report?format=pdf&async=1", headers=h)
    assert r.status_code == 202 and "application/json" in r.headers["content-type"]
    jid = r.json()["job_id"]
    j = _wait(c, h, jid)
    assert j["status"] == "done" and j["pages"] >= 1 and "error" not in j
    f = c.get(f"/api/reports/pdf-jobs/{jid}/file", headers=h)
    assert f.status_code == 200 and f.content[:5] == b"%PDF-" and f.headers["content-disposition"].startswith("attachment")
    # another user — even another VIEWER — cannot see or fetch it (404, no existence oracle)
    c2, h2, _ = _client(UserRole.VIEWER)
    assert c2.get(f"/api/reports/pdf-jobs/{jid}", headers=h2).status_code == 404
    assert c2.get(f"/api/reports/pdf-jobs/{jid}/file", headers=h2).status_code == 404
    assert new_client().get(f"/api/reports/pdf-jobs/{jid}").status_code == 401
    # stored file is private
    path = px._JOBS[jid].path
    assert (path.stat().st_mode & 0o777) == 0o600


def test_auto_async_above_threshold(monkeypatch):
    monkeypatch.setattr(px, "ASYNC_THRESHOLD", 2)
    c, h, _ = _client()
    sid, _ = _seed_scan(n=3)
    r = c.get(f"/api/scans/{sid}/report?format=pdf", headers=h)
    assert r.status_code == 202
    assert _wait(c, h, r.json()["job_id"])["status"] == "done"


def test_post_job_takes_ids_only_and_checks_access():
    c, h, _ = _client()
    sid, _ = _seed_scan()
    assert c.post("/api/reports/pdf-jobs", json={"kind": "scan", "id": "nope"}, headers=h).status_code == 404
    assert c.post("/api/reports/pdf-jobs", json={"kind": "bogus", "id": sid}, headers=h).status_code == 422
    assert new_client().post("/api/reports/pdf-jobs", json={"kind": "scan", "id": sid}).status_code in (401, 403)
    assert c.post("/api/reports/pdf-jobs", json={"kind": "scan", "id": sid, "options": {"html": "<b>x</b>"}}, headers=h).status_code == 422
    r = c.post("/api/reports/pdf-jobs", json={"kind": "scan", "id": sid}, headers=h)
    assert r.status_code == 202
    assert _wait(c, h, r.json()["job_id"])["status"] == "done"


def test_job_failure_is_reported_without_paths(monkeypatch):
    from scanner.pdf import engine
    monkeypatch.setattr(engine, "render", lambda *a, **k: (_ for _ in ()).throw(PdfCompileError("/tmp/x/report.typ boom")))
    c, h, _ = _client()
    sid, _ = _seed_scan()
    jid = c.get(f"/api/scans/{sid}/report?format=pdf&async=1", headers=h).json()["job_id"]
    j = _wait(c, h, jid)
    assert j["status"] == "failed" and j["error"]["code"] == "pdf_compile_error"
    assert "/tmp" not in str(j) and ".typ" not in str(j)
    assert c.get(f"/api/reports/pdf-jobs/{jid}/file", headers=h).status_code == 409


def test_max_jobs_per_user(monkeypatch):
    import threading
    gate = threading.Event()
    from scanner.pdf import engine
    real = engine.render
    monkeypatch.setattr(engine, "render", lambda *a, **k: (gate.wait(20), real(*a, **k))[1])
    monkeypatch.setattr(px, "RATE_PER_MIN", 100)
    c, h, _ = _client()
    sid, _ = _seed_scan()
    try:
        codes = [c.get(f"/api/scans/{sid}/report?format=pdf&async=1", headers=h).status_code for _ in range(4)]
        assert codes == [202, 202, 202, 429]
    finally:
        gate.set()
        time.sleep(1)


def test_job_expiry_sweeps_file(monkeypatch):
    c, h, _ = _client()
    sid, _ = _seed_scan()
    jid = c.get(f"/api/scans/{sid}/report?format=pdf&async=1", headers=h).json()["job_id"]
    _wait(c, h, jid)
    path = px._JOBS[jid].path
    px._sweep(time.time() + px.JOB_TTL_S + 10)
    assert not path.exists() and c.get(f"/api/reports/pdf-jobs/{jid}", headers=h).status_code == 404


# ── pentest: same RBAC as the JSON/MD report (VIEWER can export what it can view; soft-deleted engagement → admin only) ──
def test_pentest_pdf_rbac():
    from api.pentest_models import Engagement, PentestRun
    from tests.pentest_fakes import make_engagement, make_run
    Base.metadata.create_all(bind=engine)
    scope = [{"type": "domain", "value": "example.com", "mode": "allow", "include_subdomains": True}]
    db = SessionLocal()
    eng = make_engagement(db, scope, name="Đợt kiểm thử ABC")
    run = make_run(db, eng, scope_snapshot=scope)
    rid, eid = run.id, eng.id
    db.close()
    cv, hv, _ = _client(UserRole.VIEWER)
    r = cv.get(f"/api/pentest/runs/{rid}/report?format=pdf", headers=hv)
    assert r.status_code == 200 and r.content[:5] == b"%PDF-"
    assert re.search(r'filename="VulnGuard_Pentest_Dot-kiem-thu-ABC_[0-9a-f]{8}_\d{8}\.pdf"', r.headers["content-disposition"])
    assert new_client().get(f"/api/pentest/runs/{rid}/report?format=pdf").status_code == 401
    db = SessionLocal()
    db.query(Engagement).filter(Engagement.id == eid).update({"deleted_at": datetime.utcnow()})
    db.commit()
    db.close()
    assert cv.get(f"/api/pentest/runs/{rid}/report?format=pdf", headers=hv).status_code == 404   # VIEWER refused
    ca, ha, _ = _client(UserRole.ADMIN)
    assert ca.get(f"/api/pentest/runs/{rid}/report?format=pdf", headers=ha).status_code == 200


def test_pentest_job_for_deleted_engagement_refused_to_viewer():
    from api.pentest_models import Engagement
    from tests.pentest_fakes import make_engagement, make_run
    scope = [{"type": "domain", "value": "example.com", "mode": "allow", "include_subdomains": True}]
    db = SessionLocal()
    eng = make_engagement(db, scope, name="gone")
    run = make_run(db, eng, scope_snapshot=scope)
    eng.deleted_at = datetime.utcnow()
    db.commit()
    rid = run.id
    db.close()
    cv, hv, _ = _client(UserRole.VIEWER)
    assert cv.post("/api/reports/pdf-jobs", json={"kind": "pentest", "id": rid}, headers=hv).status_code == 404
    assert cv.get(f"/api/pentest/runs/{rid}/report?format=pdf&async=1", headers=hv).status_code == 404


def test_webscan_and_docreview_endpoints_require_auth_and_404():
    c, h, _ = _client()
    assert new_client().get("/api/webscans/x/export?format=pdf").status_code == 401
    assert c.get("/api/webscans/x/export?format=pdf", headers=h).status_code == 404
    assert new_client().get("/api/docreview/versions/x/export?format=pdf").status_code == 401
    assert c.get("/api/docreview/versions/x/export?format=pdf", headers=h).status_code == 404


def test_webscan_and_docreview_pdf_render():
    from api.docreview_models import DocType, Document, DocumentVersion, FindingStatus, ReviewFinding
    from api.webscan_models import WebFinding, WebScan
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    ws = WebScan(domain_id="d1")
    db.add(ws)
    db.flush()
    db.add(WebFinding(scan_id=ws.id, template_id="t", name="XSS phản chiếu", severity="high", matched_at="https://a.example/x"))
    doc = Document(name="SRS thanh toán", doc_type=list(DocType)[0])
    db.add(doc)
    db.flush()
    ver = DocumentVersion(document_id=doc.id, version_number=2, original_filename="a.docx", stored_path="/x")
    db.add(ver)
    db.flush()
    db.add(ReviewFinding(version_id=ver.id, category="Xác thực", criteria_id="ASVS-2.1.1", criteria_text="Mật khẩu ≥ 12 ký tự",
                         status=FindingStatus.NOT_MET))
    db.commit()
    wid, vid = ws.id, ver.id
    db.close()
    c, h, _ = _client()
    r = c.get(f"/api/webscans/{wid}/export?format=pdf", headers=h)
    assert r.status_code == 200 and r.content[:5] == b"%PDF-" and "VulnGuard_WebScan_" in r.headers["content-disposition"]
    r = c.get(f"/api/docreview/versions/{vid}/export?format=pdf", headers=h)
    assert r.status_code == 200 and r.content[:5] == b"%PDF-" and "VulnGuard_DocReview_SRS-thanh-toan_v2_" in r.headers["content-disposition"]


# ── no print left (grep guard, like PR-0) ──
def _git_grep(pattern, *paths):
    return subprocess.run(["git", "grep", "-nE", "-e", pattern, "--", *paths], cwd=ROOT, capture_output=True, text=True)


def test_no_window_print_or_print_button_left():
    out = _git_grep(r"window\.print|Lưu PDF / In|Ctrl/Cmd\+P|PDF nhanh|@media print", "web", "api", "scanner")
    assert out.returncode == 1, out.stdout


def test_ui_pdf_functions_never_open_a_window():
    src = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    for fn in ("async function downloadPdf(", "async function pdfErrMsg(", "function downloadReportPdf(", "async function ptDownloadReport("):
        i = src.index(fn)
        end = src[i:].index("\n")
        body = src[i:i + end + 1] if src[i:i + end].rstrip().endswith("}") else src[i:i + src[i:].index("\n}\n") + 3]
        assert "window.open(" not in body and "window.print" not in body, fn
    # every PDF button goes through downloadPdf
    assert not re.search(r"window\.open\([^)]*format=pdf", src)
    assert "exportScan('${currentScanId}','pdf')" not in src
    assert "⬇ Xuất PDF" in src


def test_pdf_does_not_use_removed_renderers():
    out = _git_grep(r"build_pdf\(|to_pdf\(", "api")
    # old fpdf2 PDF builders are no longer reachable from the PDF export routes
    assert "report.py" not in out.stdout and "webscans.py" not in out.stdout


# ───────────── review round 1 (R1-R3 + follow-ups) ─────────────
def test_r1_audit_emitted_under_real_app_startup_without_caplog(tmp_path):
    """Run the real app startup in a fresh process (no pytest logging, no root config) and check stderr."""
    import os
    import sys
    code = (
        "import logging\n"
        "from fastapi.testclient import TestClient\n"
        "from api.main import app\n"
        "assert not logging.getLogger().handlers, 'root must stay unconfigured (like uvicorn)'\n"
        "with TestClient(app):\n"
        "    from api.services import pdf_export as px\n"
        "    class U: id='u1'; email='a@b.c'\n"
        "    px.audit(U(), 'scan', 'abc', 'ok', bytes=1)\n"
    )
    env = {**os.environ, "DATABASE_URL": f"sqlite:///{tmp_path}/db/t.db", "AUTH_ENABLED": "true", "APP_ENV": "development",
           "VULNGUARD_SETUP_TOKEN": "t", "DEPLOY_MODE": "native"}
    (tmp_path / "db").mkdir()
    r = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr[-800:]
    assert "vulnguard.audit" in r.stderr and "pdf_export user=a@b.c kind=scan id=abc outcome=ok" in r.stderr, r.stderr[-800:]


def test_r2_startup_sweep_deletes_orphans_and_expired(monkeypatch):
    d = px.jobs_dir()
    orphan = d / ("a" * 32 + ".pdf")
    orphan.write_bytes(b"%PDF-1.7 old")
    keep_other = d / "notes.txt"          # not matching the job-file pattern -> never touched
    keep_other.write_text("x")
    px.start_maintenance()                 # what app startup runs (simulates restart: _JOBS is empty)
    assert not orphan.exists() and keep_other.exists()
    keep_other.unlink()
    # expired-but-known file is removed by the periodic sweep too
    c, h, _ = _client()
    sid, _ = _seed_scan()
    jid = c.get(f"/api/scans/{sid}/report?format=pdf&async=1", headers=h).json()["job_id"]
    _wait(c, h, jid)
    p = px._JOBS[jid].path
    old = time.time() - px.JOB_TTL_S - 5
    import os
    os.utime(p, (old, old))
    px._JOBS[jid].finished = old
    px._sweep()
    assert not p.exists() and jid not in px._JOBS


def test_r2_periodic_timer_runs(monkeypatch):
    monkeypatch.setattr(px, "SWEEP_INTERVAL_S", 0.01)
    monkeypatch.setattr(px, "_SWEEPER", None)
    orphan = px.jobs_dir() / ("b" * 32 + ".pdf")
    px.start_maintenance()
    orphan.write_bytes(b"x")               # appears after startup: only the timer can catch it
    end = time.time() + 5
    while orphan.exists() and time.time() < end:
        time.sleep(0.1)
    assert not orphan.exists()


@pytest.mark.parametrize("opts", [{"limit": "abc"}, {"limit": 1.5}, {"limit": -1}, {"limit": 0}, {"offset": "x"},
                                  {"offset": -3}, {"include": "everything"}, {"limit": True}, {"bogus": 1}, {"_role": "ADMIN"}])
def test_r3_bad_options_are_422(opts):
    c, h, _ = _client()
    sid, _ = _seed_scan()
    r = c.post("/api/reports/pdf-jobs", json={"kind": "pentest", "id": sid, "options": opts}, headers=h)
    assert r.status_code == 422, r.text
    assert c.post("/api/reports/pdf-jobs", json={"kind": "scan", "id": sid, "options": "x"}, headers=h).status_code == 422
    assert c.post("/api/reports/pdf-jobs", json={"kind": "scan", "id": sid, "extra": 1}, headers=h).status_code == 422


def test_r3_valid_options_accepted():
    c, h, _ = _client()
    sid, _ = _seed_scan()
    r = c.post("/api/reports/pdf-jobs", json={"kind": "scan", "id": sid, "options": {"include": "all", "limit": 5, "offset": 0}}, headers=h)
    assert r.status_code == 202


def test_html_report_pdf_link_uses_async_aware_flow():
    c, h, _ = _client()
    sid, _ = _seed_scan()
    html = c.get(f"/api/scans/{sid}/report", headers=h).text
    assert 'id="vg-pdf"' in html and "/api/reports/pdf-jobs/" in html and "r.status===202" in html
    assert "window.print" not in html


def test_disk_caps_evict_oldest_first(monkeypatch):
    monkeypatch.setattr(px, "MAX_BYTES_PER_USER", 3000)
    monkeypatch.setattr(px, "MAX_BYTES_TOTAL", 10**9)
    d = px.jobs_dir()
    jobs = []
    for i in range(4):
        j = px.Job(id=uuid4().hex, user="capuser", kind="scan", rid="x", options={}, status="done", finished=1000.0 + i)
        j.path = d / f"{j.id}.pdf"
        j.path.write_bytes(b"x" * 1000)
        px._JOBS[j.id] = j
        jobs.append(j)
    px.enforce_disk_caps(jobs[-1])
    alive = [j.path.exists() for j in jobs]
    assert alive == [False, True, True, True], alive           # oldest evicted until <= 3000 bytes
    # global cap
    monkeypatch.setattr(px, "MAX_BYTES_PER_USER", 10**9)
    monkeypatch.setattr(px, "MAX_BYTES_TOTAL", 1500)
    px.enforce_disk_caps(jobs[-1])
    assert [j.path.exists() for j in jobs] == [False, False, False, True]
    for j in jobs:
        px._JOBS.pop(j.id, None)
        px._unlink(j.path)


def test_cvss_one_decimal():
    from scanner.pdf.adapters import fmt_score
    assert fmt_score(7.300000000000001) == "7.3" and fmt_score("7.300000000000001") == "7.3"
    assert fmt_score(9) == "9.0" and fmt_score(None) == "" and fmt_score("n/a") == "n/a"
    from scanner.report_pro import _fmt_cvss
    assert _fmt_cvss("7.300000000000001") == "7.3"


def test_pentest_cvss_rounded_everywhere():
    from api.pentest_models import PentestFinding
    from scanner.pentest import report as rp
    from tests.pentest_fakes import make_engagement, make_run
    scope = [{"type": "domain", "value": "example.com", "mode": "allow", "include_subdomains": True}]
    db = SessionLocal()
    eng = make_engagement(db, scope, name="cv")
    run = make_run(db, eng, scope_snapshot=scope)
    db.add(PentestFinding(run_id=run.id, title="t", severity="high", target="https://a.example.com/p", confidence="confirmed",
                          description="d", evidence="e", remediation="f", cvss_v4_score=7.300000000000001,
                          cvss_v4_severity="high", cvss_v4_vector="CVSS:4.0/AV:N", wstg_id="WSTG-INPV-05", cwe="CWE-89",
                          vuln_class="sqli"))
    db.commit()
    model = rp.build_report_model(db, run.id, include="all")
    rid = run.id
    db.close()
    assert "7.300000000000001" not in rp.to_markdown(model) and "7.3" in rp.to_markdown(model)
    assert "7.300000000000001" not in rp.to_json(model)
    from scanner.pdf import adapters
    doc = adapters.pentest_doc(model)
    assert "7.300000000000001" not in str(doc) and "7.3" in str(doc)
