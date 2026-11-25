"""PR-C: chính sách exec của Coworker Host — token rò rỉ không được dẫn tới RCE trên host."""
import asyncio
import importlib
import logging
import os
import subprocess
import time

import pytest

def _run(coro):
    # không dùng asyncio.run: nó bỏ event loop hiện tại và làm hỏng test khác dùng get_event_loop()
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


H = {"host": "127.0.0.1", "authorization": "Bearer t0ken-xyz"}


def _make(tmp_path, monkeypatch, mode=None, roots=None):
    home = tmp_path / "home"
    (home / "proj").mkdir(parents=True)
    data = tmp_path / "data"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("COWORKER_DATA_DIR", str(data))
    monkeypatch.setenv("VULNGUARD_COWORKER_TOKEN", "t0ken-xyz")
    for k, v in (("COWORKER_EXEC_MODE", mode), ("COWORKER_ALLOWED_ROOTS", roots)):
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, v)
    import coworker_host.app as m
    importlib.reload(m)
    from fastapi.testclient import TestClient
    c = TestClient(m.app)
    return m, c, home


def _grant(c, path):
    r = c.post("/folders", json={"path": str(path)}, headers=H)
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _exec(c, fid, cmd, **kw):
    return c.post("/fs/exec", json={"folder_id": fid, "command": cmd, **kw}, headers=H)


@pytest.fixture()
def env(tmp_path, monkeypatch):
    m, c, home = _make(tmp_path, monkeypatch)
    proj = home / "proj"
    (proj / "ok.txt").write_text("hello")
    return m, c, home, proj, _grant(c, proj)


@pytest.fixture()
def trusted(tmp_path, monkeypatch):
    m, c, home = _make(tmp_path, monkeypatch, mode="trusted")
    proj = home / "proj"
    return m, c, home, proj, _grant(c, proj)


# ── exec mode ────────────────────────────────────────────────
def test_safe_mode_blocks_interpreters(env):
    _, c, _, proj, fid = env
    marker = proj / "ran"
    r = _exec(c, fid, f"python3 -c \"open('{marker}','w')\"")
    assert r.status_code == 403 and r.json()["code"] == "exec_mode_safe"
    assert not marker.exists()
    assert _exec(c, fid, "node -e 1").status_code == 403
    assert _exec(c, fid, "python3 -c 1", confirm=True).status_code == 403  # legacy flag vô tác dụng


def test_off_mode(tmp_path, monkeypatch):
    m, c, home = _make(tmp_path, monkeypatch, mode="off")
    fid = _grant(c, home / "proj")
    r = _exec(c, fid, "ls")
    assert r.status_code == 403 and r.json()["code"] == "exec_disabled"


def test_unknown_mode_falls_back_to_safe(tmp_path, monkeypatch):
    m, c, home = _make(tmp_path, monkeypatch, mode="yolo")
    assert m.EXEC_MODE == "safe"


def test_read_commands_work(env):
    _, c, _, proj, fid = env
    r = _exec(c, fid, "cat ok.txt")
    assert r.status_code == 200 and "hello" in r.json()["stdout"]
    r = _exec(c, fid, "grep -rn hello .")
    assert r.status_code == 200 and "ok.txt" in r.json()["stdout"]


def test_old_whitelist_entries_dropped(env):
    m, c, _, proj, fid = env
    m.WHITELIST_FILE.write_text('["ls","python3","bash"]')
    assert m._load_whitelist() == ["ls"]
    assert _exec(c, fid, "python3 -c 1").status_code == 403


def test_put_whitelist_rejects_unsafe(env):
    _, c, *_ = env
    assert c.put("/whitelist", json={"commands": ["bash"]}, headers=H).status_code == 400
    assert c.put("/whitelist", json={"commands": ["ls", "cat"]}, headers=H).status_code == 200


def test_path_qualified_executable_rejected(env):
    _, c, _, proj, fid = env
    (proj / "cat").write_text("#!/bin/sh\ntouch pwned\n")
    os.chmod(proj / "cat", 0o755)
    assert _exec(c, fid, "./cat").status_code == 400
    assert not (proj / "pwned").exists()


# ── trusted: server-side confirm nonce ───────────────────────
def test_trusted_confirm_flow(trusted):
    m, c, _, proj, fid = trusted
    marker = proj / "marker"
    cmd = f"python3 -c \"open('{marker}','w').write('x')\""
    r = _exec(c, fid, cmd)
    j = r.json()
    assert j["needs_confirm"] and j["confirm_id"] and j["command"] == cmd
    assert not marker.exists()
    # cờ confirm cũ không đủ
    r = _exec(c, fid, cmd, confirm=True)
    assert r.json().get("needs_confirm") and not marker.exists()
    # id của lệnh A không dùng được cho lệnh B
    cid = _exec(c, fid, cmd).json()["confirm_id"]
    r = _exec(c, fid, "python3 -c 2", confirm_id=cid)
    assert r.status_code == 409 and r.json()["code"] == "confirm_invalid"
    assert not marker.exists()
    # đúng id → chạy; dùng lại → 409
    cid = _exec(c, fid, cmd).json()["confirm_id"]
    r = _exec(c, fid, cmd, confirm_id=cid)
    assert r.status_code == 200 and marker.exists()
    assert _exec(c, fid, cmd, confirm_id=cid).status_code == 409


def test_trusted_confirm_expires(trusted, monkeypatch):
    m, c, _, proj, fid = trusted
    cid = _exec(c, fid, "python3 -c 1").json()["confirm_id"]
    real = time.time
    monkeypatch.setattr(m.time, "time", lambda: real() + m.CONFIRM_TTL_SEC + 5)
    r = _exec(c, fid, "python3 -c 1", confirm_id=cid)
    assert r.status_code == 409


def test_trusted_pending_cap(trusted):
    m, c, _, proj, fid = trusted
    for i in range(m.CONFIRM_MAX_PENDING + 10):
        _exec(c, fid, f"python3 -c {i}")
    assert len(m._PENDING) <= m.CONFIRM_MAX_PENDING


# ── argument confinement ─────────────────────────────────────
def test_find_exec_and_follow_denied(env):
    _, c, _, proj, fid = env
    r = _exec(c, fid, "find . -exec echo X ;")
    assert r.status_code == 400 and r.json()["code"] == "option_denied"
    assert _exec(c, fid, "find -L .").status_code == 400
    assert _exec(c, fid, "find . -name ok.txt").status_code == 200


def test_paths_confined(env, tmp_path):
    _, c, _, proj, fid = env
    r = _exec(c, fid, "cat /etc/hosts")
    assert r.status_code == 400 and r.json()["code"] == "arg_outside_root"
    assert _exec(c, fid, "cat ../../../etc/hosts").status_code == 400
    assert _exec(c, fid, "cat ~/x").status_code == 400
    secret = tmp_path / "secret.txt"
    secret.write_text("s")
    (proj / "link").symlink_to(secret)
    assert _exec(c, fid, "cat link").status_code == 400
    assert _exec(c, fid, "cat ok.txt").status_code == 200


def test_grep_pattern_not_path_but_file_opt_is(env):
    _, c, _, proj, fid = env
    assert _exec(c, fid, 'grep -rn "/api/" .').status_code == 200
    assert _exec(c, fid, "grep -f /etc/passwd x").status_code == 400
    assert _exec(c, fid, "grep -R hello .").status_code == 400


def test_tail_follow_tree_o_denied(env):
    _, c, *_, fid = env
    assert _exec(c, fid, "tail -f ok.txt").status_code == 400
    assert _exec(c, fid, "tree -o out.txt").status_code == 400


def _git_repo(proj):
    subprocess.run(["git", "init", "-q"], cwd=proj, check=True)
    return proj


def test_git_hardening(env):
    _, c, _, proj, fid = env
    _git_repo(proj)
    assert _exec(c, fid, "git -c core.pager=sh log").status_code == 400
    assert _exec(c, fid, "git diff --output=/tmp/x").status_code == 400
    assert _exec(c, fid, "git push").status_code == 400
    # fsmonitor trong .git/config không được chạy
    with open(proj / ".git" / "config", "a") as f:
        f.write('[core]\n\tfsmonitor = "touch PWNED"\n')
    r = _exec(c, fid, "git status")
    assert r.status_code == 200
    assert not (proj / "PWNED").exists() and not (proj / ".git" / "PWNED").exists()


def test_child_env_has_no_token(env, monkeypatch):
    m, c, _, proj, fid = env
    assert "VULNGUARD_COWORKER_TOKEN" not in m._child_env()
    assert m._child_env()["TERM"] == "dumb"


# ── folder grants ────────────────────────────────────────────
def test_folder_grant_policy(tmp_path, monkeypatch):
    m, c, home = _make(tmp_path, monkeypatch)
    (home / ".ssh").mkdir()
    (home / "Library" / "LaunchAgents").mkdir(parents=True)
    for bad in (home / ".ssh", home / "Library" / "LaunchAgents", home, home.parent, tmp_path):
        assert c.post("/folders", json={"path": str(bad)}, headers=H).status_code == 400, bad
    assert c.post("/folders", json={"path": str(home / "proj")}, headers=H).status_code == 200


def test_folder_inside_data_dir_or_containing_it(tmp_path, monkeypatch):
    m, c, home = _make(tmp_path, monkeypatch)
    # DATA_DIR nằm trong 1 folder cha khác home
    assert m._folder_allowed(m.DATA_DIR) is not None
    assert m._folder_allowed(m.DATA_DIR.parent) is not None


def test_allowed_roots(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / "work").mkdir(parents=True)
    m, c, _ = _make(tmp_path, monkeypatch, roots=str(home / "work"))
    assert c.post("/folders", json={"path": str(home / "proj")}, headers=H).status_code == 400
    assert c.post("/folders", json={"path": str(home / "work")}, headers=H).status_code == 200


def test_existing_bad_grant_refused_at_use(tmp_path, monkeypatch):
    m, c, home = _make(tmp_path, monkeypatch)
    (home / ".ssh").mkdir()
    m.FOLDERS_FILE.write_text('[{"id":"abc","path":"%s","label":"x","created_at":0}]' % (home / ".ssh"))
    r = c.get("/fs/tree", params={"folder_id": "abc"}, headers=H)
    assert r.status_code == 403


def test_write_denied_paths(env):
    _, c, _, proj, fid = env
    for p in (".git/hooks/pre-commit", ".husky/pre-commit", ".vscode/tasks.json", ".envrc", "sub/.envrc"):
        r = c.post("/fs/file", json={"folder_id": fid, "path": p, "content": "x", "create": True}, headers=H)
        assert r.status_code == 403 and r.json()["code"] == "write_denied", p
    r = c.post("/fs/file", json={"folder_id": fid, "path": "new.py", "content": "x", "create": True}, headers=H)
    assert r.status_code == 200


# ── Host header / token logging ──────────────────────────────
def test_ipv6_host_and_empty_host(env):
    _, c, *_ = env
    assert c.get("/folders", headers={"host": "[::1]:8765", "authorization": "Bearer t0ken-xyz"}).status_code == 200
    assert c.get("/folders", headers={"host": "", "authorization": "Bearer t0ken-xyz"}).status_code == 421
    assert c.get("/folders", headers={"host": "evil.example:80", "authorization": "Bearer t0ken-xyz"}).status_code == 421


def test_generated_token_not_logged(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("COWORKER_DATA_DIR", str(tmp_path / "d"))
    monkeypatch.delenv("VULNGUARD_COWORKER_TOKEN", raising=False)
    import coworker_host.app as m
    with caplog.at_level(logging.DEBUG):
        importlib.reload(m)
    assert m.COWORKER_TOKEN
    assert all(m.COWORKER_TOKEN not in r.getMessage() for r in caplog.records)
    assert (tmp_path / "d" / "token").read_text().strip() == m.COWORKER_TOKEN


# ── API side ─────────────────────────────────────────────────
def test_run_command_scrubs_secrets(monkeypatch):
    from scanner.scanners.base import run_command
    monkeypatch.setenv("VULNGUARD_COWORKER_TOKEN", "zzz-secret")
    monkeypatch.setenv("KEEP_ME", "yes")
    rc, out, _ = _run(run_command(["env"]))
    assert "zzz-secret" not in out and "KEEP_ME=yes" in out
    rc, out, _ = _run(run_command(["env"], env={"X": "1", "VULNGUARD_COWORKER_TOKEN": "explicit"}))
    assert "X=1" in out and "VULNGUARD_COWORKER_TOKEN=explicit" in out


def test_agent_exec_uses_server_confirm_id(monkeypatch):
    from api.routes import coworker_agent as ca
    calls = []

    async def fake(method, path, **kw):
        calls.append(kw["json"])
        if "confirm_id" not in kw["json"]:
            return {"needs_confirm": True, "confirm_id": "cid1", "command": "python3 -c 1"}
        return {"needs_confirm": False, "exit_code": 0, "stdout": "ok"}

    monkeypatch.setattr(ca, "_host_request", fake)
    out = _run(ca._run_sideeffect("f1", "exec", {"command": "python3 -c 1"}))
    assert "exit=0" in out
    assert "confirm" not in calls[0] and calls[1]["confirm_id"] == "cid1"


def test_agent_exec_safe_mode_is_observation(monkeypatch):
    from fastapi import HTTPException
    from api.routes import coworker_agent as ca

    async def fake(method, path, **kw):
        raise HTTPException(403, "safe", headers={"X-Coworker-Code": "exec_mode_safe"})

    monkeypatch.setattr(ca, "_host_request", fake)
    out = _run(ca._run_sideeffect("f1", "exec", {"command": "python3 -c 1"}))
    assert out.startswith("LỖI") and "safe" in out


def test_git_info_attributes_filter_not_run(env):
    _, c, _, proj, fid = env
    _git_repo(proj)
    cfg = proj / ".git" / "config"
    cfg.write_text(cfg.read_text() + '[filter "x"]\n\tclean = "touch PWNED_INFO; cat"\n')
    (proj / ".git" / "info").mkdir(exist_ok=True)
    (proj / ".git" / "info" / "attributes").write_text("*.txt filter=x\n")
    time.sleep(1.1)
    (proj / "ok.txt").write_text("changed\n")
    assert _exec(c, fid, "git status").status_code == 200
    assert _exec(c, fid, "git diff").status_code == 200
    assert not (proj / "PWNED_INFO").exists()


def test_stdin_is_devnull(env):
    _, c, _, proj, fid = env
    r = _exec(c, fid, "cat", timeout=5)
    assert r.status_code == 200 and r.json()["stdout"] == ""
