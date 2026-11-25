"""PR #31 adversarial policy table (ported from the independent verifier's scratch suite).
Everything runs in tmp_path (HOME, DATA_DIR, granted folder, "outside" secrets) via FastAPI TestClient.
Every row that was a BYPASS before the fix must now be rejected (4xx) / not leak.
"""
import importlib
import json
import os
import subprocess
import time
from pathlib import Path

import pytest

TOK = "t0ken-xyz"
H = {"host": "127.0.0.1", "authorization": f"Bearer {TOK}"}
SECRET = "SECRET-XYZ-0001"
SSHKEY = "SSHKEY-XYZ-0002"


def _make(tmp_path, monkeypatch, mode=None, roots=None):
    home = tmp_path / "home"
    proj = home / "proj"
    proj.mkdir(parents=True)
    (home / ".ssh").mkdir()
    (home / ".ssh" / "id_rsa").write_text(SSHKEY + "\n")
    (home / "Library" / "LaunchAgents").mkdir(parents=True)
    out = tmp_path / "outside"
    (out / "sub").mkdir(parents=True)
    (out / "secret.txt").write_text(SECRET + "\n")
    (out / "sub" / "deep.txt").write_text(SECRET + "\n")
    data = tmp_path / "data"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("COWORKER_DATA_DIR", str(data))
    monkeypatch.setenv("VULNGUARD_COWORKER_TOKEN", TOK)
    for k, v in (("COWORKER_EXEC_MODE", mode), ("COWORKER_ALLOWED_ROOTS", roots)):
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, v)
    import coworker_host.app as m
    importlib.reload(m)
    from fastapi.testclient import TestClient
    c = TestClient(m.app)
    (proj / "ok.txt").write_text("hello\n")
    (proj / "guess.txt").write_text(SECRET + "\n")
    (proj / "empty").mkdir()
    os.symlink(out / "secret.txt", proj / "link_file")
    os.symlink(out, proj / "link_dir")
    os.link(out / "secret.txt", proj / "hardlink")
    r = c.post("/folders", json={"path": str(proj)}, headers=H)
    assert r.status_code == 200, r.text
    return m, c, home, proj, out, r.json()["id"]


def ex(c, fid, cmd, **kw):
    return c.post("/fs/exec", json={"folder_id": fid, "command": cmd, **kw}, headers=H)


def summ(r):
    try:
        j = r.json()
    except Exception:
        return f"{r.status_code}"
    if r.status_code == 200 and isinstance(j, dict) and "exit_code" in j:
        o = (j.get("stdout") or "") + (j.get("stderr") or "")
        return f"200 exit={j['exit_code']} out={o[:70]!r}"
    if isinstance(j, dict) and j.get("needs_confirm"):
        return "200 needs_confirm"
    code = j.get("code") if isinstance(j, dict) else None
    return f"{r.status_code} {code or ''}".strip()


def leaked(r, *markers):
    return any(mk in r.text for mk in (markers or (SECRET, SSHKEY)))


def rec(cat, mode, inp, expected, actual, ok, note=""):
    if not ok:
        print(f"FAIL [{cat}/{mode}] {inp!r}: expected {expected}, got {actual} {note}")
    return bool(ok)


def check_block(cat, mode, c, fid, cmd, out=None, note="", marker_file=None, **kw):
    cmd = cmd.replace("{OUT}", str(out) if out else "")
    r = ex(c, fid, cmd, **kw)
    j = {}
    try:
        j = r.json()
    except Exception:
        pass
    executed = r.status_code == 200 and "exit_code" in j
    bad = leaked(r) or (marker_file is not None and Path(marker_file).exists())
    if mode == "trusted" and j.get("needs_confirm"):
        ok = True
    else:
        ok = (not executed or j.get("exit_code") != 0) and not bad
        # executed with nonzero exit but leaked → still bypass
        if bad:
            ok = False
    return rec(cat, mode, cmd, "reject (4xx) / needs_confirm, no leak", summ(r), ok, note)


SAFE_BLOCK = [
    # interpreters / shells / non-whitelisted
    ("interpreter", "python3 -c 1"), ("interpreter", "node -e 1"), ("interpreter", "sh -c id"),
    ("interpreter", "bash -c id"), ("interpreter", "zsh -c id"), ("interpreter", "perl -e 1"),
    ("interpreter", "osascript -e 1"), ("interpreter", "awk 'BEGIN{system(\"id\")}'"),
    ("interpreter", "sed -n 1p ok.txt"), ("interpreter", "xargs id"), ("interpreter", "env id"),
    ("interpreter", "tar -cf x.tar ok.txt"), ("interpreter", "rsync -e sh a b"), ("interpreter", "make"),
    ("interpreter", "npm test"), ("interpreter", "Cat ok.txt"), ("interpreter", "GIT status"),
    # path-qualified / symlinked binaries
    ("binary-path", "/bin/cat ok.txt"), ("binary-path", "./cat ok.txt"), ("binary-path", "../proj/cat"),
    ("binary-path", "/usr/bin/env python3"),
    # env-var injection (no shell)
    ("env-inject", "FOO=1 cat ok.txt"), ("env-inject", "PATH=. cat ok.txt"),
    ("env-inject", "GIT_CONFIG_PARAMETERS=x git status"),
    # shell metachar (no shell → must not execute second command)
    ("shell-meta", "cat ok.txt; id"), ("shell-meta", "cat ok.txt | sh"), ("shell-meta", "cat $(id)"),
    ("shell-meta", "cat `id`"), ("shell-meta", "cat ok.txt && id"),
    # find sub-command features
    ("find", "find . -exec cat {} ;"), ("find", "find . -execdir id ;"), ("find", "find . -ok id ;"),
    ("find", "find . -okdir id ;"), ("find", "find . -delete"), ("find", "find . -fprint x"),
    ("find", "find . -fls x"), ("find", "find -L . -name secret.txt"), ("find", "find . -follow"),
    ("find", "find {OUT}"), ("find", "find ../../outside"), ("find", "find link_dir/"),
    ("find", "find -H {OUT} -name '*.txt'"), ("find", "find -P {OUT}"), ("find", "find -x {OUT}"),
    ("find", "find -E {OUT}"), ("find", "find -f {OUT}"), ("find", "find -H link_dir"),
    # path escapes for path commands
    ("path-escape", "cat {OUT}/secret.txt"), ("path-escape", "cat ../../outside/secret.txt"),
    ("path-escape", "cat link_file"), ("path-escape", "cat link_dir/secret.txt"),
    ("path-escape", "cat ~/.ssh/id_rsa"), ("path-escape", "cat '~'/.ssh/id_rsa"),
    ("path-escape", "cat ../.ssh/id_rsa"), ("path-escape", "cat ../*/id_rsa"),
    ("path-escape", "cat ../.ssh/*"), ("path-escape", "head -n1 {OUT}/secret.txt"),
    ("path-escape", "tail -c 50 {OUT}/secret.txt"), ("path-escape", "wc {OUT}/secret.txt"),
    ("path-escape", "ls {OUT}"), ("path-escape", "ls link_dir"), ("path-escape", "ls -RL ."),
    ("path-escape", "cat -- {OUT}/secret.txt"), ("path-escape", "cat ok.txt {OUT}/secret.txt"),
    ("path-escape", "diff {OUT}/secret.txt ok.txt"), ("path-escape", "diff --from-file={OUT}/secret.txt ok.txt"),
    ("path-escape", "diff -r link_dir empty"),
    # grep option tricks
    ("grep", "grep -R x ."), ("grep", "grep --dereference-recursive x ."), ("grep", "grep -rR SECRET ."),
    ("grep", "grep -rS SECRET ."), ("grep", "grep -rO SECRET link_dir"),
    ("grep", "grep SECRET {OUT}/secret.txt"), ("grep", "grep -e SECRET {OUT}/secret.txt"),
    ("grep", "grep --regexp=SECRET {OUT}/secret.txt"), ("grep", "grep -f {OUT}/secret.txt guess.txt"),
    ("grep", "grep --file={OUT}/secret.txt guess.txt"), ("grep", "grep -f{OUT}/secret.txt guess.txt"),
    ("grep", "grep -rf {OUT}/secret.txt guess.txt"), ("grep", "grep -hf {OUT}/secret.txt guess.txt"),
    ("grep", "grep -- SECRET {OUT}/secret.txt"), ("grep", "grep -ef SECRET {OUT}/secret.txt"),
    ("grep", "grep -nf{OUT}/secret.txt guess.txt"), ("grep", "grep -C pat {OUT}/secret.txt"),
    ("grep", "grep --exclude-from={OUT}/secret.txt -r x ."), ("grep", "grep -nrS SECRET ."),
    ("tail", "tail -nf1 ok.txt"), ("tree", "tree -o x"), ("tree", "tree -lo x"), ("ls", "ls -L link_dir"),
    ("ls", "ls -lH link_dir"),
    # tail
    ("tail", "tail -f ok.txt"), ("tail", "tail -F ok.txt"), ("tail", "tail --follow ok.txt"),
    # git
    ("git", "git -c core.pager=sh log"), ("git", "git -C {OUT} status"), ("git", "git --git-dir=x status"),
    ("git", "git --exec-path=. status"), ("git", "git --work-tree={OUT} status"),
    ("git", "git config core.pager sh"), ("git", "git checkout ."), ("git", "git clone {OUT} x"),
    ("git", "git submodule update"), ("git", "git apply x"), ("git", "git am x"), ("git", "git grep -O sh x"),
    ("git", "git diff --output={OUT}/w.txt"), ("git", "git diff --output {OUT}/w.txt"),
    ("git", "git log --ext-diff"), ("git", "git show --textconv"), ("git", "git log -O x"),
    ("git", "git diff --no-index {OUT}/secret.txt ok.txt"), ("git", "git diff --no-index ../../outside/secret.txt ok.txt"),
    ("git", "git blame --contents {OUT}/secret.txt ok.txt"), ("git", "git branch evil"),
    ("git", "git branch -m main renamed"), ("git", "git branch -D main"), ("git", "git branch -f x HEAD"),
    ("git", "git branch --set-upstream-to=origin/x"), ("git", "git ls-files --exclude-from={OUT}/secret.txt"),
    ("git", "git log --show-signature"), ("git", "git diff -O{OUT}/secret.txt"),
    ("git", "git blame --ignore-revs-file={OUT}/secret.txt ok.txt"),
]


@pytest.mark.parametrize("cat,cmd", SAFE_BLOCK)
def test_safe_block(tmp_path, monkeypatch, cat, cmd):
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch)
    _gitrepo(proj)
    assert check_block(cat, "safe", c, fid, cmd, out=out)


def _gitrepo(proj):
    e = {"GIT_CONFIG_NOSYSTEM": "1", "HOME": str(proj.parent), "PATH": os.environ["PATH"],
         "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    if (proj / ".git").exists():
        return e
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=proj, check=True, env=e)
    subprocess.run(["git", "add", "ok.txt", "guess.txt"], cwd=proj, check=True, env=e)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=proj, check=True, env=e)
    return e


# Cases where the attack works through an option spelling the denylist does not know (git abbreviations etc.)
GIT_TRICKS = [
    ("git-abbrev", "git diff --outp={OUT}/w.txt HEAD", "w.txt"),
    ("git-abbrev", "git log -p --outpu={OUT}/w.txt", "w.txt"),
    ("git-abbrev", "git diff --ext-dif HEAD", None),
    ("git-read", "git blame --contents={OUT}/secret.txt ok.txt", None),
    ("git-read", "git blame --cont={OUT}/secret.txt ok.txt", None),
    ("git-read", "git diff --no-index link_file ok.txt", None),
    ("git-read", "git diff --no-index link_dir/secret.txt ok.txt", None),
    ("git-read", "git diff -O{OUT}/secret.txt", None),
]


@pytest.mark.parametrize("cat,cmd,wfile", GIT_TRICKS)
def test_git_tricks(tmp_path, monkeypatch, cat, cmd, wfile):
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch)
    _gitrepo(proj)
    (proj / "ok.txt").write_text("changed\n")
    assert check_block(cat, "safe", c, fid, cmd, out=out, marker_file=(out / wfile) if wfile else None)


def test_git_branch_mutates(tmp_path, monkeypatch):
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch)
    _gitrepo(proj)
    r = ex(c, fid, "git branch evil")
    r2 = ex(c, fid, "git branch -m main renamed")
    heads = sorted(p.name for p in (proj / ".git" / "refs" / "heads").iterdir())
    ok = rec("git-write", "safe", "git branch evil ; git branch -m main renamed", "read-only (no ref changes)",
             f"{summ(r)} / {summ(r2)} heads={heads}", "evil" not in heads and "renamed" not in heads,
             "safe mode is documented as read-only; `git branch` can create/rename/delete refs")
    assert ok


def test_git_preexisting_config_fsmonitor_and_filter(tmp_path, monkeypatch):
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch)
    _gitrepo(proj)
    with open(proj / ".git" / "config", "a") as f:
        f.write('[core]\n\tfsmonitor = "touch PWNED_FSM"\n[filter "x"]\n\tclean = "touch PWNED_FILTER; cat"\n')
    (proj / ".gitattributes").write_text("*.txt filter=x\n")
    time.sleep(1.1)
    (proj / "ok.txt").write_text("changed again\n")
    r = ex(c, fid, "git status")
    r2 = ex(c, fid, "git diff")
    a = rec("git-config", "safe", "git status (pre-existing core.fsmonitor in .git/config)", "PWNED_FSM not created",
            summ(r), not (proj / "PWNED_FSM").exists())
    b = rec("git-config", "safe", "git status / git diff (pre-existing filter.x.clean + .gitattributes)",
            "no command executed", f"{summ(r)} / {summ(r2)} PWNED_FILTER={(proj / 'PWNED_FILTER').exists()}",
            not (proj / "PWNED_FILTER").exists(),
            "core.fsmonitor is neutralised by -c, but filter.<x>.clean/process is not")
    assert a and b


def test_write_case_trick_then_git_rce(tmp_path, monkeypatch):
    """Write .GIT/config via /fs/file (case-insensitive APFS), then safe-mode `git status` runs a clean filter."""
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch)
    _gitrepo(proj)
    cfg = (proj / ".git" / "config").read_text()
    payload = cfg + '[filter "x"]\n\tclean = "touch PWNED_CASE; cat"\n'
    w = c.post("/fs/file", json={"folder_id": fid, "path": ".GIT/config", "content": payload}, headers=H)
    w2 = c.post("/fs/file", json={"folder_id": fid, "path": ".gitattributes", "content": "*.txt filter=x\n",
                                  "create": True}, headers=H)
    time.sleep(1.1)
    (proj / "ok.txt").write_text("x\n")
    r = ex(c, fid, "git status")
    ok1 = rec("write-denylist", "safe", "POST /fs/file path=.GIT/config", "403 write_denied", summ(w), w.status_code == 403)
    ok2 = rec("write->exec", "safe", "write .GIT/config filter + .gitattributes, then `git status`",
              "no command executed", f"write={w.status_code},{w2.status_code} status={summ(r)} "
              f"PWNED_CASE={(proj / 'PWNED_CASE').exists()}", not (proj / "PWNED_CASE").exists(),
              "full RCE in default safe mode with only the token")
    assert ok1 and ok2


WRITE_CASES = [".git/hooks/pre-commit", ".git/config", ".GIT/hooks/pre-commit", ".Git/config", "sub/.git/config",
               ".husky/pre-commit", ".HUSKY/pre-commit", ".vscode/tasks.json", ".VSCode/tasks.json", ".idea/x.xml",
               ".direnv/x", ".envrc", ".ENVRC", "a/../.git/config", "link_dir/evil.txt", "../outside.txt",
               "/etc/x", "%2e%2e/x"]


@pytest.mark.parametrize("p", WRITE_CASES)
def test_write_denylist(tmp_path, monkeypatch, p):
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch)
    (proj / ".git" / "hooks").mkdir(parents=True, exist_ok=True)
    w = c.post("/fs/file", json={"folder_id": fid, "path": p, "content": "#!/bin/sh\nid\n", "create": True}, headers=H)
    # lstrip("/") turns /etc/x into proj/etc/x — inside root, that's acceptable
    acceptable = w.status_code >= 400 or p in ("/etc/x", "%2e%2e/x")
    assert rec("write-denylist", "-", f"POST /fs/file path={p}", "4xx (or harmless in-root path)",
               f"{w.status_code} {w.json().get('code', '') if w.headers.get('content-type','').startswith('application/json') else ''}",
               acceptable)


# ── trusted mode ──────────────────────────────────────────────
def test_trusted_confirm_matrix(tmp_path, monkeypatch):
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch, mode="trusted")
    (proj / "d2").mkdir()
    fid2 = c.post("/folders", json={"path": str(home / "proj2")}, headers=H)
    (home / "proj2").mkdir()
    fid2 = c.post("/folders", json={"path": str(home / "proj2")}, headers=H).json()["id"]
    mk = proj / "RAN"
    cmd = f"touch {mk}"
    oks = []
    r0 = ex(c, fid, cmd)
    oks.append(rec("confirm", "trusted", cmd, "needs_confirm, not executed", summ(r0),
                   r0.json().get("needs_confirm") and not mk.exists()))
    cid = r0.json()["confirm_id"]
    r = ex(c, fid, cmd, confirm=True)
    oks.append(rec("confirm", "trusted", "legacy confirm=true, no id", "needs_confirm, not executed", summ(r),
                   r.json().get("needs_confirm") and not mk.exists()))
    r = ex(c, fid, cmd, confirm_id="forged-" + cid[7:])
    oks.append(rec("confirm", "trusted", "forged confirm_id", "409 confirm_invalid", summ(r), r.status_code == 409))
    r = ex(c, fid, cmd + " x", confirm_id=cid)  # wrong command; consumes the id
    oks.append(rec("confirm", "trusted", "id for A used with command B", "409", summ(r), r.status_code == 409 and not mk.exists()))
    r = ex(c, fid, cmd, confirm_id=cid)
    oks.append(rec("confirm", "trusted", "retry A after id burned by B", "409 (single-use even on mismatch)", summ(r),
                   r.status_code == 409 and not mk.exists()))
    cid = ex(c, fid, cmd).json()["confirm_id"]
    r = ex(c, fid, cmd, confirm_id=cid, cwd="d2")
    oks.append(rec("confirm", "trusted", "id used with different cwd", "409", summ(r), r.status_code == 409))
    rel = "touch RAN2"  # relative: confinement must not preempt the nonce check
    cid = ex(c, fid, rel).json()["confirm_id"]
    r = ex(c, fid2, rel, confirm_id=cid)
    oks.append(rec("confirm", "trusted", "id used with different folder_id", "409", summ(r), r.status_code == 409))
    cid = ex(c, fid, cmd).json()["confirm_id"]
    r = ex(c, fid, " " + cmd + " ", confirm_id=cid)
    oks.append(rec("confirm", "trusted", "same command with surrounding spaces", "executes (normalised by strip) — fine",
                   summ(r), True, "informational"))
    mk.unlink(missing_ok=True)
    cid = ex(c, fid, cmd).json()["confirm_id"]
    r = ex(c, fid, cmd, confirm_id=cid)
    oks.append(rec("confirm", "trusted", "correct id", "executes", summ(r), r.status_code == 200 and mk.exists()))
    r = ex(c, fid, cmd, confirm_id=cid)
    oks.append(rec("confirm", "trusted", "replay same id", "409", summ(r), r.status_code == 409))
    cid = ex(c, fid, cmd).json()["confirm_id"]
    real = time.time
    monkeypatch.setattr(m.time, "time", lambda: real() + 121)
    r = ex(c, fid, cmd, confirm_id=cid)
    monkeypatch.setattr(m.time, "time", real)
    oks.append(rec("confirm", "trusted", "expired id (+121s)", "409", summ(r), r.status_code == 409))
    # cross-session: nonce is not bound to anything but folder|cwd|command; a second client with the token can use it
    c2 = __import__("fastapi.testclient", fromlist=["TestClient"]).TestClient(m.app)
    mk.unlink(missing_ok=True)
    cid = ex(c, fid, cmd).json()["confirm_id"]
    r = ex(c2, fid, cmd, confirm_id=cid)
    oks.append(rec("confirm", "trusted", "id issued to client A, redeemed by client B (same token)",
                   "by design: accepted (nonce is not a human-presence proof)", summ(r), True,
                   "token holder can self-confirm: trusted mode == RCE for token holder (documented residual)"))
    # header-less legacy client
    assert all(oks)


TRUSTED_BLOCK = [
    ("trusted-args", "cp {OUT}/secret.txt ."), ("trusted-args", "cp link_file x"), ("trusted-args", "cp ok.txt {OUT}/x"),
    ("trusted-args", "/usr/bin/python3 -c 1"), ("trusted-args", "./x"),
    ("trusted-args", "find -H {OUT}"), ("trusted-args", "cat {OUT}/secret.txt"),
    ("trusted-args", "git -c core.pager=sh log"),
]


@pytest.mark.parametrize("cat,cmd", TRUSTED_BLOCK)
def test_trusted_block(tmp_path, monkeypatch, cat, cmd):
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch, mode="trusted")
    assert check_block(cat, "trusted", c, fid, cmd, out=out)


def test_trusted_interpreter_escape_by_design(tmp_path, monkeypatch):
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch, mode="trusted")
    cmd = f"python3 -c \"print(open('{out}/secret.txt').read())\""
    cid = ex(c, fid, cmd).json().get("confirm_id")
    r = ex(c, fid, cmd, confirm_id=cid)
    rec("trusted-args", "trusted", cmd + " (+confirm_id)", "by design: runs (documented residual)", summ(r), True,
        "interpreters escape arg confinement; acceptable only because trusted is opt-in")


def test_off_mode(tmp_path, monkeypatch):
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch, mode="off")
    oks = []
    for cmd in ("ls", "cat ok.txt", "git status", "python3 -c 1"):
        r = ex(c, fid, cmd)
        oks.append(rec("mode-off", "off", cmd, "403 exec_disabled", summ(r), r.status_code == 403))
    r = ex(c, fid, "ls", confirm_id="x", confirm=True)
    oks.append(rec("mode-off", "off", "ls + confirm_id/confirm", "403 exec_disabled", summ(r), r.status_code == 403))
    assert all(oks)


def test_bad_mode(tmp_path, monkeypatch):
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch, mode="TRUSTED ")
    r = ex(c, fid, "python3 -c 1")
    rec("mode", "env=' TRUSTED '", "python3 -c 1", "documented: unknown→safe; here normalised to trusted",
        summ(r), True, "strip/lower makes 'TRUSTED ' == trusted — acceptable")
    m, c, home, proj, out, fid = _make(tmp_path / "b", monkeypatch, mode="yolo")
    r = ex(c, fid, "python3 -c 1")
    assert rec("mode", "env=yolo", "python3 -c 1", "403 exec_mode_safe", summ(r), r.status_code == 403)


def test_whitelist_put(tmp_path, monkeypatch):
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch, mode="trusted")
    oks = []
    for body in (["bash"], ["python3"], ["ls", "sh"], [" ls", "cat"], ["LS"], ["/bin/ls"]):
        r = c.put("/whitelist", json={"commands": body}, headers=H)
        exp_ok = body in ([" ls", "cat"],)
        oks.append(rec("whitelist", "trusted", f"PUT /whitelist {body}", "200" if exp_ok else "400", str(r.status_code),
                       (r.status_code == 200) == exp_ok))
    (m.DATA_DIR / "whitelist.json").write_text(json.dumps(["ls", "python3", "bash"]))
    r = ex(c, fid, "python3 -c 1")
    oks.append(rec("whitelist", "trusted", "pre-seeded whitelist.json [python3,bash] then python3 -c 1",
                   "needs_confirm (dropped at load)", summ(r), r.json().get("needs_confirm") is True))
    assert all(oks)


# ── folder grants ────────────────────────────────────────────
def test_folder_grants(tmp_path, monkeypatch):
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch)
    (home / ".config" / "sub").mkdir(parents=True)
    (home / "work").mkdir()
    os.symlink(home / ".ssh", home / "proj" / "sshlink")
    os.symlink(home / ".ssh", home / "sshlink_outside")
    cases = [
        (home / ".ssh", 400), (home, 400), (home.parent, 400), (m.DATA_DIR, 400), (m.DATA_DIR.parent, 400),
        (home / "Library" / "LaunchAgents", 400), (home / ".config" / "sub", 400), (home / "proj" / "sshlink", 400),
        (home / "sshlink_outside", 400), (str(home / "proj" / ".." / ".ssh"), 400), ("~/.ssh", 400),
        (home / ".SSH", 400), (home / ".Ssh", 400), (home / "library" / "LaunchAgents", 400),
        (home / "LIBRARY", 400), (home / ".CONFIG" / "sub", 400), (home / "work", 200),
    ]
    oks = []
    for p, exp in cases:
        r = c.post("/folders", json={"path": str(p)}, headers=H)
        oks.append(rec("folder-grant", "-", f"POST /folders {str(p).replace(str(tmp_path), '$TMP')}", str(exp),
                       f"{r.status_code}", r.status_code == exp))
    # follow-through: with the case-variant grant, read the key and write a LaunchAgent
    r = c.post("/folders", json={"path": str(home / ".SSH")}, headers=H)
    if r.status_code == 200:
        rr = c.get("/fs/file", params={"folder_id": r.json()["id"], "path": "id_rsa"}, headers=H)
        oks.append(rec("folder-grant", "-", "grant $HOME/.SSH then GET /fs/file id_rsa", "no key", f"{rr.status_code} leaked={leaked(rr)}",
                       not leaked(rr)))
    r = c.post("/folders", json={"path": str(home / "library" / "LaunchAgents")}, headers=H)
    if r.status_code == 200:
        w = c.post("/fs/file", json={"folder_id": r.json()["id"], "path": "com.evil.plist", "content": "<plist/>",
                                     "create": True}, headers=H)
        oks.append(rec("folder-grant", "-", "grant $HOME/library/LaunchAgents then write com.evil.plist",
                       "no write", f"{w.status_code} exists={(home / 'Library/LaunchAgents/com.evil.plist').exists()}",
                       w.status_code >= 400))
    # use-time enforcement
    m._save_folders(m._load_folders() + [{"id": "evil1", "path": str(home / ".ssh"), "label": "x", "created_at": 0},
                                          {"id": "evil2", "path": str(home / ".SSH"), "label": "x", "created_at": 0}])
    for fid_ in ("evil1", "evil2"):
        rr = c.get("/fs/tree", params={"folder_id": fid_}, headers=H)
        oks.append(rec("folder-grant", "-", f"pre-seeded folders.json grant ({'.ssh' if fid_=='evil1' else '.SSH'}) → GET /fs/tree",
                       "403", str(rr.status_code), rr.status_code == 403))
    assert all(oks)


def test_folder_allowed_system_case(tmp_path, monkeypatch):
    """Pure _folder_allowed() checks on real system paths (resolve only, nothing granted/touched)."""
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch)
    oks = []
    for p in ("/etc", "/ETC", "/private/etc", "/PRIVATE/etc", "/usr/local", "/USR/local", "/Library", "/LIBRARY/LaunchAgents",
              "/System", "/SYSTEM", "/opt/homebrew", "/OPT/homebrew", "/bin", "/BIN"):
        reason = m._folder_allowed(p)
        oks.append(rec("folder-grant", "-", f"_folder_allowed({p!r})", "reason (denied)", repr(reason)[:50], reason is not None))
    # real-home case variant (pure check, nothing granted): /USERS/<me>
    real_home = Path(os.path.expanduser("~" + os.environ.get("USER", "")))
    monkeypatch.setattr(m.Path, "home", classmethod(lambda cls: real_home))
    for p in (str(real_home), str(real_home).upper(), str(real_home / ".SSH"), str(real_home / "library")):
        reason = m._folder_allowed(p)
        oks.append(rec("folder-grant", "-", f"_folder_allowed(<real home variant {p.replace(str(real_home), '~').replace(str(real_home).upper(), '~UPPER')}>)",
                       "reason (denied)", repr(reason)[:50], reason is not None))
    assert all(oks)


def test_allowed_roots(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / "work").mkdir(parents=True)
    m, c, _ = None, None, None
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("COWORKER_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("VULNGUARD_COWORKER_TOKEN", TOK)
    monkeypatch.setenv("COWORKER_ALLOWED_ROOTS", str(home / "work"))
    monkeypatch.delenv("COWORKER_EXEC_MODE", raising=False)
    import coworker_host.app as m
    importlib.reload(m)
    from fastapi.testclient import TestClient
    c = TestClient(m.app)
    (home / "proj").mkdir()
    assert c.post("/folders", json={"path": str(home / "proj")}, headers=H).status_code == 400
    assert c.post("/folders", json={"path": str(home / "WORK")}, headers=H).status_code in (200, 400)


# ── Host header / token ──────────────────────────────────────
HOSTS = [("127.0.0.1", 200), ("127.0.0.1:8765", 200), ("localhost:8765", 200), ("LOCALHOST", 200), ("[::1]:8765", 200),
         ("[::1]", 200), ("::1", 200), ("host.docker.internal:8765", 200), ("", 421), (" ", 421), ("evil.example", 421),
         ("evil.example:8765", 421), ("localhost.evil.example", 421), ("127.0.0.1.nip.io", 421), ("[::ffff:7f00:1]", 421),
         ("[::1]evil.example", 421), ("[::1].evil.example:80", 421), ("localhost:80:80", 421), ("0.0.0.0", 421),
         ("127.1", 421), ("[::1", 421), ("evil.example@localhost", 421)]


@pytest.mark.parametrize("host,exp", HOSTS)
def test_host(tmp_path, monkeypatch, host, exp):
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch)
    r = c.get("/folders", headers={"host": host, "authorization": f"Bearer {TOK}"})
    assert rec("host", "-", f"Host: {host!r}", str(exp), str(r.status_code), r.status_code == exp,
               "not browser-reachable (URL parser rejects it)" if host.startswith("[::1]") and "evil" in host else "")


def test_token(tmp_path, monkeypatch):
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch)
    oks = []
    for auth, exp in (("", 401), ("Bearer ", 401), ("Bearer wrong", 401), (f"bearer {TOK}", 200), (f"Basic {TOK}", 401),
                      (f"Bearer {TOK}x", 401)):
        r = c.get("/folders", headers={"host": "127.0.0.1", "authorization": auth})
        oks.append(rec("token", "-", f"Authorization: {auth.replace(TOK, '<tok>')!r}", str(exp), str(r.status_code), r.status_code == exp))
    r = c.get("/health", headers={"host": "127.0.0.1"})
    oks.append(rec("token", "-", "GET /health without token", "200 (public, no secrets)", f"{r.status_code}", r.status_code == 200 and TOK not in r.text))
    assert all(oks)


def test_child_env(tmp_path, monkeypatch):
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch)
    monkeypatch.setenv("GIT_DIR", str(out))
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "'core.pager'='sh'")
    monkeypatch.setenv("LD_PRELOAD", "/x.so")
    monkeypatch.setenv("DYLD_INSERT_LIBRARIES", "/x.dylib")
    e = m._child_env()
    bad = [k for k in e if k not in ("PATH", "HOME", "LANG", "LC_ALL", "TERM", "GIT_TERMINAL_PROMPT", "GIT_CONFIG_NOSYSTEM", "GIT_ATTR_NOSYSTEM", "PAGER")]
    assert rec("child-env", "-", "_child_env() with TOKEN/GIT_DIR/GIT_CONFIG_PARAMETERS/LD_PRELOAD/DYLD_* set in parent",
               "only allowlisted keys", f"keys={sorted(e)}", not bad and TOK not in json.dumps(e))


# ═══════════════ Re-verify rows (second adversarial round) ═══════════════
import unicodedata  # noqa: E402


def rec2(cat, inp, expected, actual, ok, note=""):
    if not ok:
        print(f"FAIL [{cat}] {inp!r}: expected {expected}, got {actual} {note}")
    return bool(ok)


def blocked_no_leak(r, marker=None):
    j = {}
    try:
        j = r.json()
    except Exception:
        pass
    executed_ok = r.status_code == 200 and j.get("exit_code") == 0
    return not executed_ok and not leaked(r) and not (marker and Path(marker).exists())


NEW_SAFE = [
    # find: clustered BSD leading flags / '--'
    ("find-cluster", "find -xL {OUT}"), ("find-cluster", "find -xH {OUT}"), ("find-cluster", "find -sL link_dir"),
    ("find-cluster", "find -Ef {OUT}"), ("find-cluster", "find -sx {OUT}"), ("find-cluster", "find -dP {OUT}"),
    ("find--", "find -- {OUT}"), ("find--", "find -x -- {OUT}"), ("find--", "find -P -- {OUT}"),
    ("find-operand", "find . -newer {OUT}/secret.txt"), ("find-operand", "find . -newermm {OUT}/secret.txt"),
    ("find-operand", "find . -samefile {OUT}/secret.txt"),
    # grep long-option abbreviations & ordering
    ("grep-abbrev", "grep -r --deref SECRET ."), ("grep-abbrev", "grep -r --dereference SECRET ."),
    ("grep-abbrev", "grep --fil {OUT}/secret.txt guess.txt"), ("grep-abbrev", "grep --fil={OUT}/secret.txt guess.txt"),
    ("grep-abbrev", "grep --exclude-f={OUT}/secret.txt x ."),
    ("grep-order", "grep SECRET guess.txt -f {OUT}/secret.txt"), ("grep-order", "grep SECRET guess.txt {OUT}/secret.txt"),
    ("grep-order", "grep -- -f {OUT}/secret.txt"), ("grep-order", "grep -e x -- {OUT}/secret.txt"),
    ("grep-cluster", "grep -hif {OUT}/secret.txt guess.txt"), ("grep-cluster", "grep -cRn SECRET ."),
    ("grep-cluster", "grep -rnS SECRET ."), ("grep-cluster", "grep -m1 -rO SECRET link_dir"),
    ("grep-pattern-slot", "grep SECRET link_file"), ("grep-pattern-slot", "grep {OUT}/secret.txt guess.txt"),
    # other generic
    ("ls", "ls -lL link_dir"), ("ls", "ls -RL ."), ("ls", "ls -- {OUT}"), ("ls", "ls . {OUT}"),
    ("tail", "tail -5f ok.txt"), ("tail", "tail -nF 1 ok.txt"), ("tail", "tail --foll ok.txt"),
    ("tail", "tail --retry ok.txt"),
    ("diff", "diff -X{OUT}/secret.txt ok.txt guess.txt"), ("diff", "diff --exclude-from {OUT}/secret.txt ok.txt guess.txt"),
    ("diff", "diff ok.txt -- {OUT}/secret.txt"), ("cat", "cat ok.txt -- {OUT}/secret.txt"),
    ("cat", "cat - {OUT}/secret.txt"),
    # git: abbreviations, options after paths, '--', -c neutralisers
    ("git-abbrev", "git blame --con={OUT}/secret.txt ok.txt"), ("git-abbrev", "git blame --c={OUT}/secret.txt ok.txt"),
    ("git-abbrev", "git blame --conte {OUT}/secret.txt ok.txt"), ("git-abbrev", "git diff --no-i link_file ok.txt"),
    ("git-abbrev", "git diff --no-in link_dir/secret.txt ok.txt"), ("git-abbrev", "git blame --ignore-revs-f={OUT}/secret.txt ok.txt"),
    ("git-abbrev", "git blame -S{OUT}/secret.txt ok.txt"), ("git-abbrev", "git blame -S {OUT}/secret.txt ok.txt"),
    ("git-abbrev", "git log --show-sig"), ("git-abbrev", "git log --ext-diff"),  ("git-order", "git diff HEAD -- {OUT}/secret.txt"), ("git-order", "git log ok.txt --output={OUT}/w"),
    ("git-order", "git diff ok.txt --no-index {OUT}/secret.txt"), ("git-order", "git blame ok.txt --contents {OUT}/secret.txt"),
     ("git-pathspec", "git show HEAD:../outside/secret.txt"),  ("git-pathspec", "git ls-files --exclude-from={OUT}/secret.txt -o"), ("git-pathspec", "git ls-files -X {OUT}/secret.txt -o"),
    ("git-pathspec", "git rev-parse --resolve-git-dir {OUT}"),
    ("git-branch", "git branch evil"), ("git-branch", "git branch -D main"), ("git-branch", "git branch -m x"),
    ("git-branch", "git branch -c main x"), ("git-branch", "git branch --list evil -D"),
     ("git-branch", "git branch --set-upstream-to=main"),
    ("git-branch", "git branch -f main HEAD"), ("git-branch", "git branch --edit-description"),
    ("git-branch", "git branch --contains HEAD newbr"), ("git-branch", "git branch --sort -D main"),
    ("git-branch", "git branch --format=%(refname) newbr"),
]


@pytest.mark.parametrize("cat,cmd", NEW_SAFE)
def test_new_safe(tmp_path, monkeypatch, cat, cmd):
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch)
    _gitrepo(proj)
    (proj / "ok.txt").write_text("changed\n")
    heads0 = sorted(p.name for p in (proj / ".git" / "refs" / "heads").iterdir())
    cmd = cmd.replace("{OUT}", str(out))
    r = ex(c, fid, cmd, timeout=5)
    heads = sorted(p.name for p in (proj / ".git" / "refs" / "heads").iterdir())
    ok = blocked_no_leak(r, marker=out / "w") and heads == heads0
    if cat.startswith("find") or cat == "ls":
        # listing outside tree: outside dir name leaks via 'deep.txt' / 'secret.txt'
        ok = ok and "deep.txt" not in r.text and ("secret.txt" not in r.text or "arg_outside" in r.text)
    if cat == "git-branch" and r.status_code == 200 and cmd.startswith("git branch -l evil"):
        ok = heads == heads0
    assert rec2(cat, cmd.replace(str(out), "$OUT"), "4xx or no effect, no leak", summ(r).replace(str(out), "$OUT")
               + ("" if heads == heads0 else f" heads={heads}"), ok)


# ── Unicode / case normalisation on folder grants and writes ──
def test_unicode_grants(tmp_path, monkeypatch):
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch)
    (home / ".kube").mkdir()
    (home / ".config").mkdir()
    oks = []
    cases = [home / ".Kube", home / ".SSH", home / ".ſſh", home / "LİBRARY",
             home / ".config‍", Path(str(home).upper()) if False else home / ".Config"]
    for p in cases:
        exists = p.exists()
        r = c.post("/folders", json={"path": str(p)}, headers=H)
        exp_block = exists  # if APFS maps it to a sensitive dir it must be refused; if it doesn't exist → 400 anyway
        oks.append(rec2("unicode-grant", f"POST /folders $HOME/{p.name!r} (exists on APFS={exists})", "400",
                       str(r.status_code), r.status_code == 400))
    assert all(oks)


def test_nfd_home(tmp_path, monkeypatch):
    """Home whose name has a non-ASCII char: grant the other normalisation form of ~/.ssh and of ~ itself."""
    nfc = tmp_path / unicodedata.normalize("NFC", "đạt")
    home_name = unicodedata.normalize("NFC", "José")
    # build env manually: HOME = NFC path
    root = tmp_path / "u"
    m, c, home0, proj0, out, fid = _make(root, monkeypatch)
    home = root / home_name
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "id_rsa").write_text(SSHKEY)
    (home / "proj").mkdir()
    monkeypatch.setenv("HOME", str(home))
    nfd_home = Path(unicodedata.normalize("NFD", str(home)))
    oks = []
    oks.append(rec2("unicode-nfd", "APFS: NFD form of $HOME exists?", "info", str(nfd_home.exists()), True))
    for label, p in (("NFD $HOME/.ssh", nfd_home / ".ssh"), ("NFD $HOME", nfd_home), ("NFC $HOME/.ssh", home / ".ssh")):
        reason = m._folder_allowed(str(p))
        r = c.post("/folders", json={"path": str(p)}, headers=H)
        leak = ""
        if r.status_code == 200:
            rr = c.get("/fs/file", params={"folder_id": r.json()["id"], "path": "id_rsa" if label.endswith(".ssh") else ".ssh/id_rsa"}, headers=H)
            leak = f" then read id_rsa → {rr.status_code} leaked={leaked(rr)}"
        oks.append(rec2("unicode-nfd", f"POST /folders {label} (HOME stored NFC)", "400", f"{r.status_code}{leak}",
                       r.status_code == 400))
    assert all(oks)


@pytest.mark.parametrize("p", [".GIT/config", ".gIt/hooks/x", ".g‍it/config", ".GITATTRIBUTES", ".GitModules",
                               "sub/.GITATTRIBUTES", ".Kube", "Ｇｉｔ", ".git /config", ".git./config",
                               ".git\u0000/config", ".gitattributes ", ".git\\config", "./.git/config", ".//.git/config"])
def test_write_variants(tmp_path, monkeypatch, p):
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch)
    _gitrepo(proj)
    before = (proj / ".git" / "config").read_text()
    try:
        w = c.post("/fs/file", json={"folder_id": fid, "path": p, "content": "[filter \"x\"]\n", "create": True}, headers=H)
        st = w.status_code
    except Exception as e:  # NUL byte
        st = f"exc {type(e).__name__}"
    after = (proj / ".git" / "config").read_text()
    ga = any(x.name.casefold() == ".gitattributes" for x in proj.iterdir())
    ok = after == before and not ga
    assert rec2("write-variant", f"POST /fs/file path={p!r}", ".git/config & .gitattributes untouched",
               f"{st} config_changed={after != before} gitattributes={ga}", ok)


# ── git config vectors from a pre-existing hostile .git (documented residual) ──
GIT_CFG = [
    ("core.fsmonitor", '[core]\n\tfsmonitor = "touch PWN"\n', "status"),
    ("core.hooksPath+post-index-change", '[core]\n\thooksPath = h\n', "status"),
    ("filter via .git/info/attributes", '[filter "x"]\n\tclean = "touch PWN; cat"\n\tprocess = "touch PWN"\n', "status"),
    ("diff.textconv via info/attributes", '[diff "x"]\n\ttextconv = "touch PWN; cat"\n\tcommand = "touch PWN"\n', "diff"),
    ("include.path → filter", '[include]\n\tpath = ../inc.cfg\n', "status"),
    ("core.sshCommand", '[core]\n\tsshCommand = "touch PWN"\n', "log"),
    ("gpg.program + showSignature", '[gpg]\n\tprogram = "./pwn.sh"\n[log]\n\tshowSignature = true\n', "log"),
    ("core.pager / pager.log", '[core]\n\tpager = "touch PWN"\n[pager]\n\tlog = "touch PWN"\n\tstatus = "touch PWN"\n', "log"),
    ("core.askPass/credential", '[credential]\n\thelper = "!touch PWN"\n[core]\n\taskPass = "./pwn.sh"\n', "status"),
    ("alias (not reachable)", '[alias]\n\tstatus = "!touch PWN"\n', "status"),
    ("core.editor/sequence", '[core]\n\teditor = "touch PWN"\n', "status"),
    ("blame.ignoreRevsFile", '[blame]\n\tignoreRevsFile = ../../outside/secret.txt\n', "blame ok.txt"),
    ("diff.external", '[diff]\n\texternal = "./pwn.sh"\n', "diff"),
    ("core.untrackedCache/split", '[core]\n\tuntrackedCache = true\n\tsplitIndex = true\n', "status"),
    ("status.showUntrackedFiles + submodule", '[submodule "s"]\n\tupdate = "!touch PWN"\n', "status"),
]


@pytest.mark.parametrize("name,cfg,sub", GIT_CFG)
def test_hostile_git_config(tmp_path, monkeypatch, name, cfg, sub):
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch)
    env = _gitrepo(proj)
    (proj / "pwn.sh").write_text("#!/bin/sh\ntouch PWN\ncat\n")
    os.chmod(proj / "pwn.sh", 0o755)
    if "hooksPath" in name:
        (proj / "h").mkdir()
        for hk in ("post-index-change", "reference-transaction", "post-checkout"):
            (proj / "h" / hk).write_text("#!/bin/sh\ntouch PWN\n")
            os.chmod(proj / "h" / hk, 0o755)
    if "include" in name:
        (proj.parent / "inc.cfg").write_text('[filter "x"]\n\tclean = "touch PWN; cat"\n[core]\n\tfsmonitor = "touch PWN"\n')
        (proj / ".git" / "info").mkdir(exist_ok=True)
        (proj / ".git" / "info" / "attributes").write_text("* filter=x\n")
    if "attributes" in name:
        (proj / ".git" / "info").mkdir(exist_ok=True)
        (proj / ".git" / "info" / "attributes").write_text("* filter=x diff=x\n")
    with open(proj / ".git" / "config", "a") as f:
        f.write(cfg)
    time.sleep(1.05)
    (proj / "ok.txt").write_text("changed\n")
    outs = []
    for s in (sub, "status", "diff", "log -p", "show", "blame ok.txt", "ls-files", "branch"):
        r = ex(c, fid, "git " + s, timeout=5)
        outs.append(f"{s}:{r.status_code}")
    pwn = (proj / "PWN").exists()
    leak = leaked(r)
    assert rec2("hostile-.git/config", f"pre-existing {name}; ran git {sub}/status/diff/log -p/show/blame/ls-files/branch",
               "no command executed", f"PWN={pwn} " + " ".join(outs[:3]), not pwn)


def test_hostile_core_worktree(tmp_path, monkeypatch):
    """Pre-existing .git with core.worktree pointing outside root + crafted index → content of outside files."""
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch)
    env = _gitrepo(proj)
    # craft index listing secret.txt with an empty blob, worktree → $OUT
    e = dict(env, GIT_DIR=str(proj / ".git"), GIT_WORK_TREE=str(out))
    subprocess.run(["git", "add", "secret.txt"], cwd=out, env=e, check=True)
    blob = subprocess.run(["git", "hash-object", "-w", "--stdin"], input="", text=True, capture_output=True, env=e).stdout.strip()
    subprocess.run(["git", "update-index", "--cacheinfo", f"100644,{blob},secret.txt"], env=e, cwd=out, check=True)
    subprocess.run(["git", "config", "core.worktree", str(out)], cwd=proj, env=env, check=True)
    oks = []
    for cmd in ("git status", "git diff", "git ls-files", "git blame secret.txt"):
        r = ex(c, fid, cmd, timeout=5)
        oks.append(rec2("hostile-core.worktree", f"pre-existing core.worktree=$OUT, {cmd}", "no outside content",
                       summ(r).replace(str(out), "$OUT"), not leaked(r), "documented residual"))
    assert all(oks)


def test_git_discovery_above_root(tmp_path, monkeypatch):
    """Dotfiles repo at $HOME (common!), grant $HOME/proj (allowed). Safe-mode git sees the HOME repo."""
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch)
    env = dict(_gitrepo.__globals__["os"].environ)
    e = {"GIT_CONFIG_NOSYSTEM": "1", "HOME": str(home), "PATH": os.environ["PATH"], "GIT_AUTHOR_NAME": "t",
         "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    (home / ".aws").mkdir()
    (home / ".aws" / "credentials").write_text(SECRET + "\n")
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=home, check=True, env=e)
    subprocess.run(["git", "add", ".aws/credentials", ".ssh/id_rsa"], cwd=home, check=True, env=e)
    subprocess.run(["git", "commit", "-qm", "dotfiles"], cwd=home, check=True, env=e)
    (home / ".ssh" / "id_rsa").write_text(SSHKEY + " modified\n")
    oks = []
    for cmd in ("git show HEAD:.aws/credentials", "git log -p", "git diff", "git ls-files --full-name :/",
                "git show HEAD:.ssh/id_rsa", "git rev-parse --show-toplevel"):
        r = ex(c, fid, cmd, timeout=5)
        oks.append(rec2("git-discovery", f"$HOME is a git repo, granted $HOME/proj: {cmd}", "no content outside root",
                       summ(r).replace(str(home), "$HOME"), not leaked(r)))
    assert all(oks)


def test_git_dotgit_file_pointer(tmp_path, monkeypatch):
    """Pre-existing `.git` FILE with gitdir: pointing at another repo outside root."""
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch)
    other = tmp_path / "other"
    other.mkdir()
    e = {"GIT_CONFIG_NOSYSTEM": "1", "HOME": str(home), "PATH": os.environ["PATH"], "GIT_AUTHOR_NAME": "t",
         "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    (other / "s.txt").write_text(SECRET + "\n")
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=other, check=True, env=e)
    subprocess.run(["git", "add", "s.txt"], cwd=other, check=True, env=e)
    subprocess.run(["git", "commit", "-qm", "x"], cwd=other, check=True, env=e)
    (proj / ".git").write_text(f"gitdir: {other}/.git\n")
    r = ex(c, fid, "git show HEAD:s.txt", timeout=5)
    assert rec2("git-dotgit-file", "pre-existing .git file → gitdir outside root; git show HEAD:s.txt", "no outside content",
               summ(r), not leaked(r), "same class as hostile .git (pre-existing)")


def test_symlink_traversal_diff(tmp_path, monkeypatch):
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch)
    p2 = home / "p2"
    (p2 / "a").mkdir(parents=True)
    (p2 / "b").mkdir()
    os.symlink(out, p2 / "b" / "ld")
    fid2 = c.post("/folders", json={"path": str(p2)}, headers=H).json()["id"]
    oks = []
    for cmd in ("diff -rN a b", "diff -r a b", "grep -r SECRET b", "find b -type f", "ls -R b", "git status",
                "wc b/ld/secret.txt", "head b/ld/secret.txt"):
        r = ex(c, fid2, cmd, timeout=5)
        oks.append(rec2("symlink-walk", f"folder has b/ld → $OUT: {cmd}", "no outside content",
                       summ(r).replace(str(out), "$OUT"), not leaked(r) and "deep.txt" not in r.text))
    assert all(oks)


def test_hosts_more(tmp_path, monkeypatch):
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch)
    oks = []
    for h, exp in (("[::1]:8765", 200), ("[::1]", 200), ("[::1]evil", 421), ("[::1]:80:80", 421), ("[::1]:", 421),
                   ("[0:0:0:0:0:0:0:1]", 421), ("[::1%lo0]", 421), ("[::1]:8765 ", 200), ("[::1]\t", 200),
                   ("localhost.", 421), ("127.0.0.1:abc", 421), ("[::1],evil", 421), ("localhost,evil.example", 421)):
        r = c.get("/folders", headers={"host": h, "authorization": f"Bearer {TOK}"})
        oks.append(rec2("host", f"Host: {h!r}", str(exp), str(r.status_code), r.status_code == exp))
    assert all(oks)


def test_stdin_devnull(tmp_path, monkeypatch):
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch)
    t = time.time()
    r = ex(c, fid, "cat", timeout=20)
    dt = time.time() - t
    assert rec2("stdin", "cat (no args)", "returns immediately (stdin=/dev/null)", f"{summ(r)} in {dt:.1f}s", dt < 5)


def test_git_too_old(tmp_path, monkeypatch):
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch)
    _gitrepo(proj)
    monkeypatch.setattr(m, "_GIT_ATTR_SUPPORT", False)
    r = ex(c, fid, "git status")
    assert rec2("git-old", "git status with git<2.40 (simulated)", "403 git_too_old", summ(r), r.status_code == 403)


# ═══════════════ Re-verify 2 rows ═══════════════
@pytest.mark.parametrize("cmd", ["find -f{OUT}", "find -xf{OUT}", "find -Ef{OUT}", "find -sf{OUT} -name '*.txt'",
                                 "find -f {OUT}", "find -x -f {OUT}"])
def test_r2_find_f_attached(tmp_path, monkeypatch, cmd):
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch)
    r = ex(c, fid, cmd.replace("{OUT}", str(out)), timeout=5)
    assert r.status_code == 400 and "deep.txt" not in r.text and "secret.txt" not in r.text


@pytest.mark.parametrize("cmd", ["diff a b", "diff -N a b", "diff --new-file a b", "diff -s a b"])
def test_r2_diff_dir_operands(tmp_path, monkeypatch, cmd):
    m, c, home, proj, out, fid0 = _make(tmp_path, monkeypatch)
    p2 = home / "p2"
    (p2 / "a").mkdir(parents=True)
    (p2 / "b").mkdir()
    (p2 / "a" / "x").write_text("")
    os.symlink(out / "secret.txt", p2 / "b" / "x")
    fid = c.post("/folders", json={"path": str(p2)}, headers=H).json()["id"]
    r = ex(c, fid, cmd, timeout=5)
    assert r.status_code == 400 and not leaked(r)
    # file operands still work
    (p2 / "f1").write_text("1\n")
    (p2 / "f2").write_text("2\n")
    assert ex(c, fid, "diff f1 f2", timeout=5).json()["exit_code"] == 1


def _submodule_repo(proj, marker):
    """Parent repo with gitlink `sub` whose own gitdir has filter+info/attributes (hostile submodule)."""
    e = _gitrepo(proj)
    sub = proj / "sub"
    sub.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=sub, check=True, env=e)
    (sub / "f.txt").write_text("one\n")
    subprocess.run(["git", "add", "f.txt"], cwd=sub, check=True, env=e)
    subprocess.run(["git", "commit", "-qm", "s"], cwd=sub, check=True, env=e)
    subprocess.run(["git", "add", "sub"], cwd=proj, check=True, env=e)
    subprocess.run(["git", "commit", "-qm", "gitlink"], cwd=proj, check=True, env=e)
    with open(sub / ".git" / "config", "a") as f:
        f.write(f'[filter "x"]\n\tclean = "touch {marker}; cat"\n[diff "x"]\n\ttextconv = "touch {marker}; cat"\n')
    (sub / ".git" / "info").mkdir(exist_ok=True)
    (sub / ".git" / "info" / "attributes").write_text("* filter=x diff=x\n")
    time.sleep(1.1)
    (sub / "f.txt").write_text("two\n")
    return e


@pytest.mark.parametrize("cmd", ["git diff --submodule=diff", "git diff --submodule", "git diff --ignore-submodules=none",
                                 "git status --ignore-submodules=none"])
def test_r2_submodule_options_denied(tmp_path, monkeypatch, cmd):
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch)
    marker = proj / "PWN_SUB"
    _submodule_repo(proj, marker)
    r = ex(c, fid, cmd, timeout=10)
    assert r.status_code == 400 and not marker.exists()


def test_r2_submodule_config_diff_submodule_overridden(tmp_path, monkeypatch):
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch)
    marker = proj / "PWN_SUB2"
    _submodule_repo(proj, marker)
    with open(proj / ".git" / "config", "a") as f:
        f.write("[diff]\n\tsubmodule = diff\n[status]\n\tsubmoduleSummary = true\n")
    for cmd in ("git diff", "git status", "git log -p"):
        ex(c, fid, cmd, timeout=10)
    assert not marker.exists()


def test_r2_alternates_outside_root_refused(tmp_path, monkeypatch):
    m, c, home, proj, out, fid = _make(tmp_path, monkeypatch)
    e = _gitrepo(proj)
    other = tmp_path / "other"
    other.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=other, check=True, env=e)
    (other / "s.txt").write_text(SECRET + "\n")
    subprocess.run(["git", "add", "s.txt"], cwd=other, check=True, env=e)
    subprocess.run(["git", "commit", "-qm", "x"], cwd=other, check=True, env=e)
    (proj / ".git" / "objects" / "info").mkdir(parents=True, exist_ok=True)
    (proj / ".git" / "objects" / "info" / "alternates").write_text(str(other / ".git" / "objects") + "\n")
    r = ex(c, fid, "git rev-parse --disambiguate=f9", timeout=10)
    assert r.status_code == 403 and r.json()["code"] == "git_repo_outside_root"
    # in-root alternates are fine
    (proj / ".git" / "objects" / "info" / "alternates").write_text(str(proj / ".git" / "objects") + "\n")
    assert ex(c, fid, "git status", timeout=10).status_code == 200
