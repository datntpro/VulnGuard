"""SCM integration: URL builders (pure), schedule, API CRUD smoke."""
import uuid

import pytest
from fastapi.testclient import TestClient

from scanner.scm import providers as P


def test_api_base_github():
    assert P.api_base("GITHUB", "") == "https://api.github.com"
    assert P.api_base("GITHUB", "https://github.com") == "https://api.github.com"
    assert P.api_base("GITHUB", "https://github.corp.vn") == "https://github.corp.vn/api/v3"


def test_api_base_gitlab():
    assert P.api_base("GITLAB", "") == "https://gitlab.com/api/v4"
    assert P.api_base("GITLAB", "https://gitlab.corp.vn") == "https://gitlab.corp.vn/api/v4"


def test_clone_url_embeds_token_and_redacts():
    gh = P.clone_url("GITHUB", "", "ghp_secret", "acme/app")
    assert gh == "https://x-access-token:ghp_secret@github.com/acme/app.git"
    gl = P.clone_url("GITLAB", "https://gitlab.corp.vn", "glpat-x", "grp/sub/app")
    assert gl == "https://oauth2:glpat-x@gitlab.corp.vn/grp/sub/app.git"
    assert P.redact(gh, "ghp_secret") == "https://x-access-token:***@github.com/acme/app.git"


def test_schedule_compute_next():
    from api.scm_models import ScanSchedule
    from datetime import datetime
    s = ScanSchedule(interval_minutes=60)
    base = datetime(2026, 1, 1, 0, 0, 0)
    assert s.compute_next(base) == datetime(2026, 1, 1, 1, 0, 0)


@pytest.fixture
def client():
    import api.main  # noqa — tạo bảng
    from api.main import app
    from api.database import SessionLocal
    from api.auth_models import User, UserRole
    from api.security import hash_password

    email = f"a{uuid.uuid4().hex[:6]}@x.vn"
    pw = "Passw0rd!!23"
    db = SessionLocal()
    db.add(User(id=str(uuid.uuid4()), email=email, name="Admin",
                password_hash=hash_password(pw), role=UserRole.ADMIN, is_active=True))
    db.commit(); db.close()

    c = TestClient(app)
    r = c.post("/api/auth/login", json={"email": email, "password": pw})
    assert r.status_code == 200, r.text
    return c


def test_connection_and_repo_crud(client):
    # tạo kết nối (token sẽ được mã hoá, không trả raw)
    r = client.post("/api/scm/connections", json={
        "name": "GH test", "provider": "GITHUB", "base_url": "", "token": "ghp_abc123"})
    assert r.status_code == 201, r.text
    conn = r.json()
    assert conn["token_set"] is True and "ghp_abc123" not in r.text and conn["cloud"] is True

    # thêm repo target
    r2 = client.post("/api/scm/repos", json={
        "connection_id": conn["id"], "repo_full_name": "acme/app",
        "owner_email": "owner@acme.vn", "scan_types": ["SAST"], "run_ai": False})
    assert r2.status_code == 201, r2.text
    repo = r2.json()
    assert repo["repo_full_name"] == "acme/app" and repo["owner_email"] == "owner@acme.vn"

    # tạo lịch
    r3 = client.post("/api/scm/schedules", json={
        "repo_id": repo["id"], "interval_minutes": 60, "email_report": True, "enabled": True})
    assert r3.status_code == 201, r3.text
    assert r3.json()["next_run_at"] is not None

    # interval quá nhỏ bị từ chối
    assert client.post("/api/scm/schedules", json={"repo_id": repo["id"], "interval_minutes": 1}).status_code == 422

    # cleanup: xoá connection → cascade repo + schedule
    assert client.delete(f"/api/scm/connections/{conn['id']}").status_code == 204
    assert all(x["connection_id"] != conn["id"] for x in client.get("/api/scm/repos").json())


# ── L-1: SSRF qua base_url ──
def _fake_dns(monkeypatch, ip):
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))])


@pytest.mark.parametrize("url,ip", [
    ("http://127.0.0.1", "127.0.0.1"),
    ("https://169.254.169.254", "169.254.169.254"),
    ("https://localhost", "127.0.0.1"),
    ("ftp://x", "1.2.3.4"),
    ("http://gitlab.corp", "1.2.3.4"),
    ("https://rebind.example", "169.254.169.254"),
])
def test_check_base_url_rejects(monkeypatch, url, ip):
    _fake_dns(monkeypatch, ip)
    with pytest.raises(ValueError):
        P.check_base_url(url)


def test_check_base_url_private_policy(monkeypatch):
    from api.config import settings
    _fake_dns(monkeypatch, "10.0.0.5")
    P.check_base_url("https://10.0.0.5")       # mặc định cho phép on-prem
    monkeypatch.setattr(settings, "scm_allow_private_hosts", False)
    with pytest.raises(ValueError):
        P.check_base_url("https://10.0.0.5")
    P.check_base_url("")                        # cloud mặc định


def test_create_connection_rejects_ssrf(client, monkeypatch):
    _fake_dns(monkeypatch, "169.254.169.254")
    r = client.post("/api/scm/connections", json={"name": "x", "provider": "GITLAB",
                                                  "base_url": "https://metadata.example", "token": "t"})
    assert r.status_code == 400


@pytest.mark.parametrize("ip", ["100.100.100.200", "192.0.0.192", "2002:7f00:1::", "64:ff9b::7f00:1", "::ffff:169.254.169.254"])
def test_check_base_url_extra_blocked(monkeypatch, ip):
    import socket
    from api.config import settings
    monkeypatch.setattr(settings, "scm_allow_private_hosts", False)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))])
    with pytest.raises(ValueError):
        P.check_base_url("https://x.example")


def test_metadata_blocked_even_when_private_allowed(monkeypatch):
    _fake_dns(monkeypatch, "100.100.100.200")
    with pytest.raises(ValueError):
        P.check_base_url("https://x.example")


def test_clone_disables_redirects(monkeypatch):
    from api.services import scm_service
    from api.scm_models import ScmConnection, ScmRepo, ScmProvider
    seen = []

    def fake_run(cmd, **kw):
        seen.append(cmd)
    monkeypatch.setattr(scm_service.subprocess, "run", fake_run)
    _fake_dns(monkeypatch, "93.184.216.34")
    conn = ScmConnection(name="c", provider=ScmProvider.GITLAB, base_url="https://gl.example", token_enc=None)
    repo = ScmRepo(repo_full_name="a/b", default_branch="main")
    scm_service._clone(conn, repo, "/tmp/never")
    cmd = seen[0]
    assert "http.followRedirects=false" in cmd and "protocol.allow=never" in cmd and "protocol.https.allow=always" in cmd
    assert cmd.index("clone") > cmd.index("http.followRedirects=false")
