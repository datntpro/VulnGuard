"""run_command must kill the whole process group on timeout (#101 PR-C): no orphan burning CPU."""
import asyncio
import os
import sys
import textwrap
import time

import pytest

from scanner.scanners import base, sast

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="process groups are POSIX")


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # zombie (killed, not yet reaped by init) counts as gone
    try:
        import subprocess
        st = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
        return bool(st) and not st.startswith("Z")
    except Exception:
        return True


def test_timeout_kills_tool_and_its_child(tmp_path, monkeypatch):
    monkeypatch.setattr(base, "_KILL_GRACE_SECONDS", 1.0)
    pidfile = tmp_path / "pids"
    script = tmp_path / "tool.py"
    script.write_text(textwrap.dedent(f"""
        import os, subprocess, sys, time
        child = subprocess.Popen([sys.executable, "-c", "import time\\nwhile True: time.sleep(1)"])
        open({str(pidfile)!r}, "w").write(f"{{os.getpid()}} {{child.pid}}")
        while True: time.sleep(1)
    """))
    t0 = time.time()
    rc, out, err = asyncio.run(base.run_command([sys.executable, str(script)], timeout=2))
    assert rc == -1 and "timeout" in err.lower()
    assert base.classify_failed_run(rc, err) == "timeout"
    assert time.time() - t0 < 15
    parent, child = map(int, pidfile.read_text().split())
    deadline = time.time() + 5
    while time.time() < deadline and (_alive(parent) or _alive(child)):
        time.sleep(0.1)
    assert not _alive(parent), "tool survived the timeout"
    assert not _alive(child), "tool's child survived the timeout"


def test_sigterm_ignoring_tool_is_sigkilled(tmp_path, monkeypatch):
    monkeypatch.setattr(base, "_KILL_GRACE_SECONDS", 0.5)
    pidfile = tmp_path / "pid"
    script = tmp_path / "stubborn.py"
    script.write_text(textwrap.dedent(f"""
        import os, signal, time
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        open({str(pidfile)!r}, "w").write(str(os.getpid()))
        while True: time.sleep(1)
    """))
    rc, _, err = asyncio.run(base.run_command([sys.executable, str(script)], timeout=2))
    assert rc == -1 and "timeout" in err.lower()
    pid = int(pidfile.read_text())
    deadline = time.time() + 5
    while time.time() < deadline and _alive(pid):
        time.sleep(0.1)
    assert not _alive(pid)


def test_semgrep_timeout_is_an_error_not_clean(tmp_path, monkeypatch):
    async def fake(cmd, **kw):
        return -1, "", "Command timeout after 90s: semgrep"
    monkeypatch.setattr(sast, "run_command", fake)
    with pytest.raises(base.ScannerRunError, match="timeout"):
        asyncio.run(sast.SemgrepScanner(str(tmp_path))._run_semgrep(["--config", "x"]))


# --- registry glob guard (CVE-2026-132276, wcmatch ReDoS) ---
def test_glob_star_count_ignores_globstar():
    assert sast.glob_star_count("**/wp-content/plugins/**/*.php") == 1
    assert sast.glob_star_count("*conf*") == 2
    assert sast.glob_star_count("*a*a*a*a*b") == 5


def test_risky_globs_detected():
    ok = "rules:\n- id: a\n  paths:\n    include: ['**/x/*.php', '*conf*']\n"
    bad = "rules:\n- id: b\n  paths:\n    exclude: ['*a*a*a*a*b']\n"
    assert sast.risky_registry_globs(ok) == []
    assert sast.risky_registry_globs(bad) == ["*a*a*a*a*b"]
    assert sast.risky_registry_globs("not: [valid") == []


def test_registry_pass_skipped_when_glob_risky(tmp_path, monkeypatch):
    calls = []

    async def fake(cmd, **kw):
        calls.append(cmd)
        return 0, '{"results": []}', ""
    monkeypatch.setattr(sast, "run_command", fake)
    monkeypatch.setattr(sast, "_has_internet", lambda *a, **k: True)
    monkeypatch.setattr(sast, "_fetch_ruleset_yaml",
                        lambda rs, timeout=20.0: "rules:\n- id: b\n  paths:\n    exclude: ['*a*a*a*a*b']\n")
    sc = sast.SemgrepScanner(str(tmp_path))
    asyncio.run(sc.scan())
    assert len(calls) == 1 and not any("--config p/" in " ".join(c) for c in calls)  # bundled only


def test_registry_pass_runs_when_globs_ok_or_fetch_fails(tmp_path, monkeypatch):
    calls = []

    async def fake(cmd, **kw):
        calls.append(cmd)
        return 0, '{"results": []}', ""
    monkeypatch.setattr(sast, "run_command", fake)
    monkeypatch.setattr(sast, "_has_internet", lambda *a, **k: True)
    def boom(rs, timeout=20.0):
        raise OSError("net down")
    monkeypatch.setattr(sast, "_fetch_ruleset_yaml", boom)
    asyncio.run(sast.SemgrepScanner(str(tmp_path)).scan())
    assert len(calls) == 2  # bundled + registry (fail-open)
