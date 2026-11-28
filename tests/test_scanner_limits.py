"""Scanner resource bounds: output cap, per-tool budget, bounded file discovery, clone limits.

Hostile inputs are generated at test time under tmp_path; nothing hostile is committed."""
import asyncio
import os
import socket
import subprocess
import sys
import textwrap
import time
import uuid

import pytest

from scanner import orchestrator
from scanner.scanners import base, iac, sca
from tests.test_run_command_timeout import _alive

posix = pytest.mark.skipif(sys.platform == "win32", reason="process groups / symlinks are POSIX")


# ── output cap ────────────────────────────────────────────────────────────────
@posix
def test_output_flood_is_capped_and_group_killed(tmp_path, monkeypatch):
    monkeypatch.setattr(base, "_KILL_GRACE_SECONDS", 1.0)
    pidfile = tmp_path / "pids"
    script = tmp_path / "flood.py"
    script.write_text(textwrap.dedent(f"""
        import os, subprocess, sys
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        open({str(pidfile)!r}, "w").write(f"{{os.getpid()}} {{child.pid}}")
        chunk = b"x" * 65536
        while True:
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
    """))
    t0 = time.monotonic()
    rc, out, err = asyncio.run(base.run_command([sys.executable, str(script)], timeout=60, max_stdout=1 << 20))
    assert time.monotonic() - t0 < 20
    assert rc == -1 and out == ""
    assert base.classify_failed_run(rc, err) == "limit"
    parent, child = map(int, pidfile.read_text().split())
    deadline = time.time() + 5
    while time.time() < deadline and (_alive(parent) or _alive(child)):
        time.sleep(0.1)
    assert not _alive(parent) and not _alive(child)


def test_stderr_keeps_tail_and_does_not_fail(tmp_path):
    script = tmp_path / "noisy.py"
    script.write_text("import sys\nsys.stderr.write('a' * 300000 + 'TAIL')\nsys.stdout.write('ok')\n")
    rc, out, err = asyncio.run(base.run_command([sys.executable, str(script)], timeout=30, max_stderr=1000))
    assert rc == 0 and out == "ok"
    assert len(err) <= 1000 and err.endswith("TAIL")


def test_normal_output_unchanged(tmp_path):
    rc, out, err = asyncio.run(base.run_command([sys.executable, "-c", "print('hello')"], timeout=30))
    assert (rc, out.strip(), err) == (0, "hello", "")


def test_limit_is_an_error_for_callers(tmp_path, monkeypatch):
    async def fake(cmd, **kw):
        return -1, "", "Command output limit exceeded: stdout over 1 bytes (x)"
    monkeypatch.setattr(iac, "run_command", fake)
    with pytest.raises(base.ScannerRunError, match="limit"):
        asyncio.run(iac.CheckovScanner(str(tmp_path)).scan())


# ── per-scanner wall clock ────────────────────────────────────────────────────
class _Sleeper(base.BaseScanner):
    scan_type = "SAST"
    tool_name = "sleeper"

    def is_available(self):
        return True

    async def scan(self):
        await asyncio.sleep(30)
        return []


def test_scanner_budget_exceeded_is_error(tmp_path, monkeypatch):
    from api.config import settings
    monkeypatch.setattr(settings, "scanner_tool_budget_s", 1)
    t0 = time.monotonic()
    findings, _, error = asyncio.run(orchestrator.Orchestrator(str(tmp_path))._run_scanner_timed(_Sleeper(str(tmp_path))))
    assert time.monotonic() - t0 < 5
    assert "exceeded 1s" in error


# ── bounded file discovery ────────────────────────────────────────────────────
@posix
def test_symlink_loop_discovery_is_bounded_and_off_loop(tmp_path):
    root = tmp_path / "t"
    root.mkdir()
    (root / "a").symlink_to(".")
    (root / "b").symlink_to(".")
    (root / "requirements.txt").write_text("x==1\n")

    async def main():
        ticks = []

        async def ticker():
            for _ in range(10):
                t = time.monotonic()
                await asyncio.sleep(0.05)
                ticks.append(time.monotonic() - t)
        tk = asyncio.create_task(ticker())
        res = await asyncio.to_thread(base.find_files, str(root), "requirements*.txt", 50)
        await tk
        return res, max(ticks)

    t0 = time.monotonic()
    (files, truncated), worst_tick = asyncio.run(main())
    assert time.monotonic() - t0 < 2
    assert len(files) == 1 and not truncated
    assert worst_tick < 0.5


@posix
def test_find_files_skips_symlinked_files_and_excluded_dirs(tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "requirements.txt").write_text("x==1\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "requirements-dev.txt").write_text("x==1\n")
    (tmp_path / "requirements.txt").symlink_to("/etc/hostname")
    links = []
    files, truncated = base.find_files(str(tmp_path), "requirements*.txt", 50, skipped_links=links)
    assert [os.path.relpath(f, tmp_path) for f in files] == ["sub/requirements-dev.txt"]
    assert links == [str(tmp_path / "requirements.txt")] and not truncated


def test_find_files_truncates(tmp_path):
    for i in range(30):
        (tmp_path / f"requirements{i}.txt").write_text("x==1\n")
    files, truncated = base.find_files(str(tmp_path), "requirements*.txt", 10)
    assert len(files) == 10 and truncated
    files, truncated = base.find_files(str(tmp_path), "requirements*.txt", 100, max_entries=5)
    assert truncated


def test_hadolint_file_cap_is_partial(tmp_path, monkeypatch):
    for i in range(300):
        (tmp_path / f"Dockerfile.{i}").write_text("FROM scratch\n")
    calls = []

    async def fake(cmd, **kw):
        calls.append(cmd)
        return 0, "[]", ""
    monkeypatch.setattr(iac, "run_command", fake)
    sc = iac.HadolintScanner(str(tmp_path))
    asyncio.run(sc.scan())
    assert len(calls) == 200
    assert sc.warnings


def test_pip_audit_file_cap_is_partial(tmp_path, monkeypatch):
    for i in range(80):
        (tmp_path / f"requirements{i}.txt").write_text("canary==1.0\n")
    calls = []

    async def fake(cmd, **kw):
        calls.append(cmd)
        return 0, '{"dependencies": []}', ""
    monkeypatch.setattr(sca, "run_command", fake)
    sc = sca.PipAuditScanner(str(tmp_path))
    asyncio.run(sc.scan())
    assert len(calls) == 50
    assert any("50" in w for w in sc.warnings)


@posix
def test_requirements_resolving_outside_scan_path_warns(tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "requirements.txt").write_text("canary==1.0\n")
    root = tmp_path / "scan"
    root.mkdir()
    (root / "requirements.txt").symlink_to(outside / "requirements.txt")

    async def fake(cmd, **kw):
        raise AssertionError("must not run")
    monkeypatch.setattr(sca, "run_command", fake)
    sc = sca.PipAuditScanner(str(root))
    assert asyncio.run(sc.scan()) == []
    assert any("outside the scan path" in w for w in sc.warnings)


# ── SCM clone ─────────────────────────────────────────────────────────────────
def test_clone_argv_and_size_limit(tmp_path, monkeypatch):
    from api.config import settings
    from api.services import scm_service
    from scanner.scm import providers
    seen = []

    def fake_run(cmd, **kw):
        seen.append(cmd)
        dest = cmd[-1]
        os.makedirs(dest, exist_ok=True)
        with open(os.path.join(dest, "big.bin"), "wb") as f:
            f.write(b"\0" * (2 * 1024 * 1024))
        return subprocess.CompletedProcess(cmd, 0, "", "")
    monkeypatch.setattr(scm_service.subprocess, "run", fake_run)
    monkeypatch.setattr(providers, "check_base_url", lambda u: None)
    monkeypatch.setattr(scm_service, "decrypt_secret", lambda v: "tok")

    class _Prov:
        value = "GITHUB"

    class Conn:
        provider = _Prov()
        base_url = ""
        token_enc = "x"

    class Repo:
        repo_full_name = "acme/app"
        default_branch = "main"
    dest = str(tmp_path / "repo")
    monkeypatch.setattr(settings, "scm_max_repo_mb", 1)
    with pytest.raises(RuntimeError, match="exceeds size limit"):
        scm_service._clone(Conn(), Repo(), dest)
    assert "core.symlinks=false" in seen[0]
    assert not os.path.exists(dest)
    monkeypatch.setattr(settings, "scm_max_repo_mb", 64)
    scm_service._clone(Conn(), Repo(), dest)
    assert os.path.exists(dest)


def test_repo_file_count_limit(tmp_path, monkeypatch):
    from api.config import settings
    from api.services import scm_service
    for i in range(20):
        (tmp_path / f"f{i}").write_text("x")
    monkeypatch.setattr(settings, "scm_max_repo_files", 10)
    with pytest.raises(RuntimeError, match="exceeds size limit"):
        scm_service._check_repo_size(str(tmp_path))


# ── socket ────────────────────────────────────────────────────────────────────
def test_has_internet_leaves_default_timeout_alone(monkeypatch):
    from scanner.scanners import sast
    assert socket.getdefaulttimeout() is None
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("offline")))
    assert sast._has_internet() is False
    assert socket.getdefaulttimeout() is None


# ── owner_email ───────────────────────────────────────────────────────────────
def _client_for(role):
    from tests._authutil import make_user, new_client, login, bearer
    from api.auth_models import UserRole
    email, _ = make_user(role=role)
    c = new_client()
    h = bearer(login(c, email))
    return c, h, email


def _conn(c, h):
    r = c.post("/api/scm/connections", headers=h,
               json={"name": "c" + uuid.uuid4().hex[:4], "provider": "GITHUB", "base_url": "", "token": "ghp_x"})
    return r


def test_owner_email_restricted_for_non_admin():
    from api.auth_models import UserRole
    from api.database import SessionLocal
    from api.scm_models import ScmConnection, ScmProvider
    ac, ah, _ = _client_for(UserRole.ADMIN)
    r = _conn(ac, ah)
    assert r.status_code == 201, r.text
    conn_id = r.json()["id"]
    c, h, me = _client_for(UserRole.ANALYST)
    body = {"connection_id": conn_id, "repo_full_name": "acme/app", "scan_types": []}
    bad = c.post("/api/scm/repos", headers=h, json={**body, "owner_email": "victim@example.com"})
    assert bad.status_code in (403, 422), bad.text
    malformed = c.post("/api/scm/repos", headers=h, json={**body, "owner_email": "not-an-email"})
    assert malformed.status_code in (403, 422)
    own = c.post("/api/scm/repos", headers=h, json={**body, "owner_email": me})
    assert own.status_code == 201, own.text
    adm = ac.post("/api/scm/repos", headers=ah, json={**body, "owner_email": "victim@example.com"})
    assert adm.status_code == 201, adm.text
