"""M-3 / H-1 / M-5 / B-4: allow-list đường dẫn, zip bomb, File Assistant."""
import io
import os
import tempfile
import zipfile
from uuid import uuid4

import pytest

from api.auth_models import UserRole
from api.config import settings
from api.services import path_policy
from api.services.path_policy import PathNotAllowed, resolve_under_roots
from tests._authutil import bearer, login, make_user, new_client


@pytest.fixture
def root(monkeypatch):
    d = os.path.realpath(tempfile.mkdtemp(prefix="vgroot_"))
    monkeypatch.setattr(settings, "scan_allowed_roots", d)
    monkeypatch.setattr(settings, "file_assistant_allowed_roots", "")
    return d


def _client(role=UserRole.ANALYST):
    email, _ = make_user(role=role)
    c = new_client()
    return c, bearer(login(c, email))


def _project(c, h):
    r = c.post("/api/projects", json={"name": f"p{uuid4().hex[:6]}"}, headers=h)
    assert r.status_code in (200, 201), r.text
    return r.json()["id"]


@pytest.fixture(autouse=True)
def _no_bg_scan(monkeypatch):
    async def _noop(*a, **k):
        return None
    from api.routes import scans
    monkeypatch.setattr(scans, "_run_scan_background", _noop)


# ── unit: resolve_under_roots ──
def test_resolve_ok_and_rejects(root, tmp_path):
    sub = os.path.join(root, "app"); os.makedirs(sub)
    assert resolve_under_roots(sub, [root], "dir") == sub
    assert resolve_under_roots(sub + "/", [root], "dir") == sub
    outside = os.path.realpath(str(tmp_path))
    for bad in ("", "  ", "a\x00b", outside, os.path.join(root, "..", "etc"), os.path.join(root, "nope")):
        with pytest.raises(PathNotAllowed):
            resolve_under_roots(bad, [root], "dir")
    with pytest.raises(PathNotAllowed):
        resolve_under_roots(sub, [root], "file")  # sai loại


def test_symlink_escape_rejected(root, tmp_path):
    link = os.path.join(root, "evil")
    os.symlink(str(tmp_path), link)
    with pytest.raises(PathNotAllowed):
        resolve_under_roots(link, [root], "dir")


def test_storage_dir_blocked_even_inside_root(monkeypatch):
    st = os.path.realpath(settings.storage_dir)
    os.makedirs(st, exist_ok=True)
    monkeypatch.setattr(settings, "scan_allowed_roots", os.path.dirname(st))
    with pytest.raises(PathNotAllowed):
        resolve_under_roots(st, path_policy.allowed_scan_roots(), "dir")
    up = os.path.join(st, "scan_uploads", "x"); os.makedirs(up, exist_ok=True)
    assert resolve_under_roots(up, path_policy.allowed_scan_roots(), "dir") == os.path.realpath(up)


def test_default_roots_by_mode(monkeypatch):
    monkeypatch.setattr(settings, "scan_allowed_roots", "")
    monkeypatch.setattr(settings, "deploy_mode", "docker")
    assert os.path.realpath("/workspace") in path_policy.allowed_scan_roots()
    monkeypatch.setattr(settings, "deploy_mode", "native")
    assert os.path.realpath(os.path.expanduser("~")) in path_policy.allowed_scan_roots()


# ── M-3: API ──
def test_trigger_scan_etc_is_400(root):
    c, h = _client()
    pid = _project(c, h)
    r = c.post(f"/api/projects/{pid}/scans", json={"scan_path": "/etc"}, headers=h)
    assert r.status_code == 400, r.text
    assert root in r.json()["detail"]


def test_trigger_scan_inside_ok_symlink_and_dotdot_rejected(root, tmp_path):
    c, h = _client(UserRole.ADMIN)
    pid = _project(c, h)
    app = os.path.join(root, "app"); os.makedirs(app)
    r = c.post(f"/api/projects/{pid}/scans", json={"scan_path": app}, headers=h)
    assert r.status_code == 202, r.text
    assert r.json()["scan_path"] == app
    os.symlink(str(tmp_path), os.path.join(root, "ln"))
    for bad in (os.path.join(root, "ln"), root + "/../etc"):
        r = c.post(f"/api/projects/{pid}/scans", json={"scan_path": bad}, headers=h)
        assert r.status_code == 400, (bad, r.text)


# ── M-5: zip bomb ──
def _bomb_zip(path, size, name="big.bin"):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        with zf.open(name, "w", force_zip64=True) as f:
            chunk = b"\0" * (1 << 20)
            for _ in range(size >> 20):
                f.write(chunk)


def test_extract_rejects_huge_ratio(tmp_path):
    from api.routes.scans import ZipLimitExceeded, _safe_extract_zip
    z = str(tmp_path / "b.zip"); _bomb_zip(z, 64 << 20)
    d = str(tmp_path / "out")
    with pytest.raises(ZipLimitExceeded):
        _safe_extract_zip(z, d)
    assert not os.path.exists(os.path.join(d, "big.bin"))


def test_extract_rejects_total_over_limit(tmp_path, monkeypatch):
    from api.routes.scans import ZipLimitExceeded, _safe_extract_zip
    monkeypatch.setattr(settings, "upload_max_uncompressed_bytes", 1 << 20)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:  # stored → ratio 1
        zf.writestr("a", os.urandom(2 << 20))
    with pytest.raises(ZipLimitExceeded):
        _safe_extract_zip(buf.getvalue(), str(tmp_path / "o"))


def test_extract_rejects_too_many_files(tmp_path, monkeypatch):
    from api.routes.scans import ZipLimitExceeded, _safe_extract_zip
    monkeypatch.setattr(settings, "upload_max_files", 50)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(51):
            zf.writestr(f"f{i}", "x")
    with pytest.raises(ZipLimitExceeded):
        _safe_extract_zip(buf.getvalue(), str(tmp_path / "o"))


def test_extract_aborts_on_lying_header(tmp_path):
    from api.routes.scans import ZipLimitExceeded, _safe_extract_zip
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", b"A" * 5000)
    raw = bytearray(buf.getvalue())
    # sửa file_size khai báo (central directory + local header) nhỏ hơn thực tế
    import struct
    real = struct.pack("<I", 5000); fake = struct.pack("<I", 10)
    raw = bytes(raw).replace(real, fake)
    d = str(tmp_path / "o")
    with pytest.raises((ZipLimitExceeded, zipfile.BadZipFile)):
        _safe_extract_zip(raw, d)


def test_upload_over_limit_413_no_temp(monkeypatch, root):
    monkeypatch.setattr(settings, "upload_max_bytes", 1 << 20)
    c, h = _client()
    pid = _project(c, h)
    tmpd = os.path.join(settings.storage_dir, "tmp")
    before = set(os.listdir(tmpd)) if os.path.isdir(tmpd) else set()
    r = c.post(f"/api/projects/{pid}/scan-upload", headers=h,
               files={"file": ("a.zip", b"\0" * (2 << 20), "application/zip")})
    assert r.status_code == 413, r.text
    after = set(os.listdir(tmpd)) if os.path.isdir(tmpd) else set()
    assert after == before


def test_upload_zip_bomb_413_and_dest_removed(monkeypatch):
    monkeypatch.setattr(settings, "upload_max_ratio", 10)
    c, h = _client()
    pid = _project(c, h)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("z.bin", b"\0" * (8 << 20))
    r = c.post(f"/api/projects/{pid}/scan-upload", headers=h,
               files={"file": ("a.zip", buf.getvalue(), "application/zip")})
    assert r.status_code == 413, r.text
    base = os.path.join(settings.storage_dir, "scan_uploads", pid)
    assert not os.path.isdir(base) or not os.listdir(base)


def test_upload_normal_ok():
    c, h = _client()
    pid = _project(c, h)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("app/main.py", "print(1)")
    r = c.post(f"/api/projects/{pid}/scan-upload", headers=h,
               files={"file": ("a.zip", buf.getvalue(), "application/zip")})
    assert r.status_code == 202, r.text


def test_rotation_removes_upload_dir(monkeypatch):
    from api.routes import scans
    monkeypatch.setattr(settings, "max_scans_per_project", 1)
    c, h = _client()
    pid = _project(c, h)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("m.py", "x=1")
    files = {"file": ("a.zip", buf.getvalue(), "application/zip")}
    first = c.post(f"/api/projects/{pid}/scan-upload", headers=h, files=files).json()["scan_path"]
    assert os.path.isdir(first)
    c.post(f"/api/projects/{pid}/scan-upload", headers=h, files=files)
    assert not os.path.exists(first)


# ── H-1 / B-4: File Assistant ──
@pytest.fixture
def fa(monkeypatch, root):
    monkeypatch.setattr(settings, "feature_file_assistant", True)
    return root


def test_fa_disabled_by_default_404():
    assert Settings_default() is False
    c, h = _client(UserRole.ADMIN)
    assert c.get("/api/file-assistant/health", headers=h).status_code == 404


def Settings_default():
    from api.config import Settings
    return Settings.model_fields["feature_file_assistant"].default


def test_fa_outside_root_400(fa, tmp_path):
    secret = tmp_path / "secret.env"; secret.write_text("TOKEN=abc")
    c, h = _client(UserRole.ADMIN)
    body = {"files": [{"name": "s", "path": str(secret), "size_bytes": 1, "type": "text"}]}
    r = c.post("/api/file-assistant/sessions", json=body, headers=h)
    assert r.status_code == 400, r.text


def test_fa_inside_root_201_and_size_overridden(fa):
    f = os.path.join(fa, "notes.txt"); open(f, "w").write("hello")
    c, h = _client(UserRole.ADMIN)
    body = {"files": [{"name": "n", "path": f, "size_bytes": 999999, "type": "text"}]}
    r = c.post("/api/file-assistant/sessions", json=body, headers=h)
    assert r.status_code == 201, r.text
    assert r.json()["files"][0]["size_bytes"] == 5


def test_fa_stored_outside_path_rejected_on_read(fa, tmp_path):
    from api.database import SessionLocal
    from api.file_assistant_models import FileAssistantSession, FileAssistantSummary
    outside = tmp_path / "x.txt"; outside.write_text("top secret")
    db = SessionLocal()
    sid = str(uuid4())
    db.add(FileAssistantSession(id=sid, title="t", model_used="m",
                                files_json=[{"name": "x", "path": str(outside), "size_bytes": 10, "type": "text"}]))
    db.add(FileAssistantSummary(session_id=sid, file_path=str(outside), summary="s",
                                chunk_index_json=[{"chunk_id": "chunk_000"}], file_type="text"))
    db.commit(); db.close()
    c, h = _client(UserRole.ADMIN)
    r = c.get(f"/api/file-assistant/sessions/{sid}/chunks/0", headers=h)
    assert r.status_code == 400, r.text
    assert "top secret" not in r.text


def test_fa_health_flags(fa, monkeypatch):
    from api.routes import coworker, file_assistant
    async def boom(*a, **k):
        raise RuntimeError("down")
    async def ok(*a, **k):
        return {"ok": True}
    async def _ol():
        return True
    monkeypatch.setattr(file_assistant, "test_ollama_connection", _ol)
    c, h = _client(UserRole.ADMIN)
    monkeypatch.setattr(coworker, "_host_request", boom)
    j = c.get("/api/file-assistant/health", headers=h).json()
    assert j["coworker_host_available"] is False and j["database_available"] is True
    monkeypatch.setattr(coworker, "_host_request", ok)
    assert c.get("/api/file-assistant/health", headers=h).json()["coworker_host_available"] is True
