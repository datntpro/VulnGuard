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
    roots = path_policy.allowed_scan_roots()
    with pytest.raises(PathNotAllowed):
        resolve_under_roots(st, roots, "dir")
    # scan_uploads không còn là root client chọn được
    up = os.path.join(st, "scan_uploads", "x"); os.makedirs(up, exist_ok=True)
    with pytest.raises(PathNotAllowed):
        resolve_under_roots(up, roots, "dir")


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


# ══════ PR #32 verification fixes ══════
def _case_variant(p):
    head, tail = os.path.split(p)
    return os.path.join(head, tail.swapcase())


def test_storage_deny_is_case_insensitive(monkeypatch):
    """BYPASS-1: casefold + NFC cho deny-list (APFS). Phần logic chạy được trên mọi FS."""
    st = os.path.realpath(settings.storage_dir)
    os.makedirs(os.path.join(st, "db"), exist_ok=True)
    open(os.path.join(st, "ai.json"), "w").write("{}")
    monkeypatch.setattr(settings, "scan_allowed_roots", os.path.dirname(st))
    roots = path_policy.allowed_scan_roots()
    assert path_policy._deny_reason([_case_variant(st)], "dir")
    assert path_policy._deny_reason([os.path.join(_case_variant(st), "ai.json")], "file")
    variant = _case_variant(st)
    if os.path.isdir(variant):  # FS không phân biệt hoa/thường (APFS)
        with pytest.raises(PathNotAllowed):
            resolve_under_roots(variant, roots, "dir")
        with pytest.raises(PathNotAllowed):
            resolve_under_roots(os.path.join(variant, "ai.json"), roots, "file")
        c, h = _client()
        pid = _project(c, h)
        r = c.post(f"/api/projects/{pid}/scans", json={"scan_path": variant}, headers=h)
        assert r.status_code == 400


def test_unicode_nfd_variant_denied():
    import unicodedata
    assert path_policy._norm("café") == path_policy._norm(unicodedata.normalize("NFD", "café"))


@pytest.fixture
def fake_home(monkeypatch, tmp_path):
    home = tmp_path / "home"
    (home / ".docker").mkdir(parents=True)
    (home / ".docker" / "config.json").write_text('{"auths":{}}')
    (home / ".config" / "gcloud").mkdir(parents=True)
    (home / ".config" / "gcloud" / "application_default_credentials.json").write_text("{}")
    (home / "proj").mkdir()
    (home / "proj" / "app.py").write_text("x=1")
    (home / "proj" / ".env").write_text("K=v")
    (home / "proj" / "server.pem").write_text("x")
    (home / "proj" / "notes.txt").write_text("ok")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(settings, "scan_allowed_roots", "")
    monkeypatch.setattr(settings, "file_assistant_allowed_roots", "")
    monkeypatch.setattr(settings, "deploy_mode", "native")
    monkeypatch.setattr(settings, "feature_file_assistant", True)
    return os.path.realpath(str(home))


def test_native_default_fa_blocks_home_credentials(fake_home):
    """BYPASS-2: ~/.docker, gcloud ADC, .env, *.pem không đọc được dưới cấu hình mặc định."""
    c, h = _client(UserRole.ADMIN)
    bad = [f"{fake_home}/.docker/config.json",
           f"{fake_home}/.config/gcloud/application_default_credentials.json",
           f"{fake_home}/.DOCKER/config.json",
           f"{fake_home}/proj/.env", f"{fake_home}/proj/server.pem"]
    for p in bad:
        body = {"files": [{"name": "c", "path": p, "size_bytes": 1, "type": "json"}]}
        r = c.post("/api/file-assistant/sessions", json=body, headers=h)
        assert r.status_code == 400, (p, r.text)
    body = {"files": [{"name": "n", "path": f"{fake_home}/proj/notes.txt", "size_bytes": 1, "type": "text"}]}
    assert c.post("/api/file-assistant/sessions", json=body, headers=h).status_code == 201


def test_native_default_scan_blocks_credential_dirs(fake_home):
    c, h = _client()
    pid = _project(c, h)
    for p in (f"{fake_home}/.docker", f"{fake_home}/.config/gcloud", fake_home):
        r = c.post(f"/api/projects/{pid}/scans", json={"scan_path": p}, headers=h)
        assert r.status_code == 400, (p, r.text)
    r = c.post(f"/api/projects/{pid}/scans", json={"scan_path": f"{fake_home}/proj"}, headers=h)
    assert r.status_code == 202, r.text


def test_symlink_to_secret_with_innocent_name_denied(fake_home):
    link = os.path.join(fake_home, "proj", "notes2.txt")
    os.symlink(f"{fake_home}/.docker/config.json", link)
    with pytest.raises(PathNotAllowed):
        resolve_under_roots(link, path_policy.file_assistant_roots(), "file")


def test_relative_and_bad_roots_rejected(root, monkeypatch):
    with pytest.raises(PathNotAllowed):
        resolve_under_roots(".", [root], "dir")
    monkeypatch.setattr(settings, "scan_allowed_roots", "api,/definitely/not/here")
    roots = path_policy.allowed_scan_roots()
    assert all(os.path.isabs(r) for r in roots) and "api" not in roots


def test_fa_extension_rechecked_on_real_path(fa):
    real = os.path.join(fa, "id_data")  # không có đuôi hỗ trợ
    open(real, "w").write("x")
    link = os.path.join(fa, "notes.txt"); os.symlink(real, link)
    c, h = _client(UserRole.ADMIN)
    body = {"files": [{"name": "n", "path": link, "size_bytes": 1, "type": "text"}]}
    assert c.post("/api/file-assistant/sessions", json=body, headers=h).status_code == 400


def _upload(c, h, pid, name="a.zip"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("app.py", "print(1)")
    return c.post(f"/api/projects/{pid}/scan-upload", headers=h,
                  files={"file": (name, buf.getvalue(), "application/zip")})


def test_cross_project_upload_not_selectable_and_not_deleted(root, monkeypatch):
    monkeypatch.setattr(settings, "max_scans_per_project", 1)
    c, h = _client()
    pa, pb = _project(c, h), _project(c, h)
    a_dir = _upload(c, h, pa).json()["scan_path"]
    assert os.path.isdir(a_dir)
    for p in (a_dir, os.path.dirname(a_dir)):
        r = c.post(f"/api/projects/{pb}/scans", json={"scan_path": p}, headers=h)
        assert r.status_code == 400, r.text
    for _ in range(2):  # B xoay vòng scan của chính nó → upload của A còn nguyên
        assert c.post(f"/api/projects/{pb}/scans", json={"scan_path": root}, headers=h).status_code == 202
    assert os.path.isdir(a_dir)


def test_rotation_skips_running_and_shared_paths():
    from api.database import SessionLocal
    from api.models import Scan, ScanStatus
    from api.routes.scans import _remove_upload_dir
    c, h = _client()
    pid = _project(c, h)
    d = _upload(c, h, pid).json()["scan_path"]
    db = SessionLocal()
    try:
        sc = db.query(Scan).filter(Scan.project_id == pid).first()
        sc.status = ScanStatus.RUNNING; db.commit()
        _remove_upload_dir(db, sc)
        assert os.path.isdir(d)
        sc.status = ScanStatus.COMPLETED; db.commit()
        other = Scan(project_id=pid, scan_number=99, scan_path=d, scan_types=["SAST"], status=ScanStatus.COMPLETED)
        db.add(other); db.commit()
        _remove_upload_dir(db, sc)
        assert os.path.isdir(d)  # scan khác còn tham chiếu
        db.delete(other); db.commit()
        _remove_upload_dir(db, sc)
        assert not os.path.exists(d)
    finally:
        db.close()


def test_eocd_count_checked_before_zipfile_parses(tmp_path, monkeypatch):
    from api.routes import scans
    monkeypatch.setattr(settings, "upload_max_files", 10)
    p = tmp_path / "many.zip"
    with zipfile.ZipFile(p, "w") as z:
        for i in range(50):
            z.writestr(f"f{i}", b"")
    raw = p.read_bytes()

    def boom(*a, **k):
        raise AssertionError("ZipFile must not be constructed")
    monkeypatch.setattr(zipfile, "ZipFile", boom)
    with pytest.raises(scans.ZipLimitExceeded):
        scans._safe_extract_zip(str(p), str(tmp_path / "d"))
    with pytest.raises(scans.ZipLimitExceeded):
        scans._safe_extract_zip(raw, str(tmp_path / "d2"))


def test_content_length_over_limit_413_without_reading_body(monkeypatch):
    import asyncio
    from api.upload_limit import UploadSizeLimitMiddleware
    monkeypatch.setattr(settings, "upload_max_bytes", 1 << 20)
    reached = {"app": False, "recv": 0}

    async def app(scope, receive, send):
        reached["app"] = True

    async def receive():
        reached["recv"] += 1
        return {"type": "http.request", "body": b"", "more_body": False}
    sent = []

    async def send(m):
        sent.append(m)
    scope = {"type": "http", "method": "POST", "path": "/api/projects/x/scan-upload",
             "headers": [(b"content-length", str(50 << 20).encode())]}
    asyncio.run(UploadSizeLimitMiddleware(app)(scope, receive, send))
    assert sent[0]["status"] == 413 and not reached["app"] and reached["recv"] == 0


def test_chunked_body_over_limit_aborted(monkeypatch):
    import asyncio
    from api.upload_limit import UploadSizeLimitMiddleware
    monkeypatch.setattr(settings, "upload_max_bytes", 1 << 20)

    async def app(scope, receive, send):
        while True:
            m = await receive()
            if not m.get("more_body"):
                break

    async def receive():
        return {"type": "http.request", "body": b"\0" * (1 << 20), "more_body": True}
    sent = []

    async def send(m):
        sent.append(m)
    scope = {"type": "http", "method": "POST", "path": "/api/projects/x/scan-upload", "headers": []}
    asyncio.run(UploadSizeLimitMiddleware(app)(scope, receive, send))
    assert sent[0]["status"] == 413


def test_upload_api_content_length_413(monkeypatch):
    monkeypatch.setattr(settings, "upload_max_bytes", 1 << 20)
    c, h = _client()
    pid = _project(c, h)
    r = c.post(f"/api/projects/{pid}/scan-upload", headers=h,
               files={"file": ("a.zip", b"\0" * (3 << 20), "application/zip")})
    assert r.status_code == 413
