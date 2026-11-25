"""P1-2 (review F1–F5): kill switch phủ MỌI tool, con cháu cứng đầu, không spawn sau STOP, không ghi đè STOPPED,
backfill finding cũ. Không chạm mạng."""
import ast
import asyncio
import os
import pathlib
import stat
import sys
import time
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, text

from api.database import Base, SessionLocal, engine
from api.pentest_models import PentestRun, RiskTier, RunStatus
from scanner.pentest import agent as agent_mod
from scanner.pentest import toolbelt
from scanner.pentest.procs import REGISTRY, RunStopped, current_run_id, spawn
from tests.test_agent_loop import (_drive, _fake_tool, _get, _run_status, _setup, _wait)  # noqa: F401

ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _fast(monkeypatch):
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(agent_mod, "APPROVAL_POLL_SECONDS", 0.05)
    monkeypatch.setattr(agent_mod, "WATCHDOG_SECONDS", 0.1)
    import api.services.ai_config as ai
    monkeypatch.setattr(ai, "load_config", lambda: {})


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


async def _until(cond, timeout=5.0):
    t0 = time.monotonic()
    while not cond():
        if time.monotonic() - t0 > timeout:
            return False
        await asyncio.sleep(0.02)
    return True


# ── F1: audit — không tool nào được tự spawn process ngoài registry ──
_FORBIDDEN = {"create_subprocess_exec", "create_subprocess_shell", "Popen", "system", "popen",
              "run", "check_output", "check_call", "call", "posix_spawn", "fork", "execv", "execve"}


def _spawn_sites(path: pathlib.Path):
    tree = ast.parse(path.read_text())
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            f = n.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
            base = f.value.id if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) else None
            if name in ("create_subprocess_exec", "create_subprocess_shell", "Popen", "popen", "posix_spawn"):
                out.append((path.name, n.lineno, name))
            elif base in ("subprocess", "os") and name in _FORBIDDEN:
                out.append((path.name, n.lineno, f"{base}.{name}"))
    return out


def test_no_pentest_tool_spawns_process_outside_registry():
    files = [p for p in (ROOT / "scanner" / "pentest").glob("*.py") if p.name != "procs.py"]
    files.append(ROOT / "scanner" / "crawler" / "nuclei_runner.py")
    bad = [s for p in files for s in _spawn_sites(p)]
    assert not bad, f"spawn ngoài scanner.pentest.procs.spawn(): {bad}"


def test_audit_detects_a_bypass(tmp_path):
    f = tmp_path / "evil.py"
    f.write_text("import asyncio\nasync def x():\n    await asyncio.create_subprocess_exec('ls')\n")
    assert _spawn_sites(f)


def test_nuclei_runner_registers_and_dies_on_kill_and_cancel(monkeypatch, tmp_path):
    from scanner.crawler import nuclei_runner
    stub = tmp_path / "nuclei"
    stub.write_text(f"#!{sys.executable}\nimport time\ntime.sleep(60)\n")
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setattr(nuclei_runner, "NUCLEI_BIN", str(stub))

    async def go(mode):
        rid = f"nuc-{mode}"
        tok = current_run_id.set(rid)
        try:
            task = asyncio.ensure_future(nuclei_runner.run_nuclei(
                ["http://10.0.0.5/"], ["high"], [], False, 10, 120, safe_net=True))
            assert await _until(lambda: REGISTRY.count(rid) == 1)       # F1: đã đăng ký
            proc = list(REGISTRY._procs[rid])[0]
            t0 = time.monotonic()
            if mode == "kill":
                await REGISTRY.kill_all(rid, 1.0)
                await asyncio.wait_for(task, 5)
            else:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            assert proc.returncode is not None and time.monotonic() - t0 < 5
            assert REGISTRY.count(rid) == 0
        finally:
            current_run_id.reset(tok)
            REGISTRY.clear_stopped(rid)

    _run(go("kill"))
    _run(go("cancel"))


# ── F2: con cháu bỏ qua SIGTERM vẫn chết khi leader đã thoát ──
GRANDCHILD = """
import os, signal, sys, time
pidfile = sys.argv[1]
if os.fork() == 0:                       # grandchild: bỏ qua SIGTERM, giữ stdout pipe
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    open(pidfile, "w").write(str(os.getpid()))
    time.sleep(120)
    os._exit(0)
time.sleep(120)                          # leader: chết ngay khi nhận SIGTERM
"""


@pytest.mark.parametrize("via", ["kill_all", "timeout"])
def test_sigterm_ignoring_grandchild_is_killed(tmp_path, via):
    pidfile = tmp_path / "gc.pid"

    async def go():
        rid = f"gc-{via}"
        t0 = time.monotonic()
        task = asyncio.ensure_future(toolbelt._run_argv(
            [sys.executable, "-c", GRANDCHILD, str(pidfile)], timeout=(1 if via == "timeout" else 120), run_id=rid))
        assert await _until(lambda: pidfile.exists() and pidfile.read_text().strip())
        gpid = int(pidfile.read_text())
        assert _alive(gpid)
        if via == "kill_all":
            await REGISTRY.kill_all(rid, grace_s=0.5)
        res = await asyncio.wait_for(task, 10)                 # communicate() không bị treo bởi pipe của cháu
        assert await _until(lambda: not _alive(gpid), 3), "grandchild còn sống sau kill"
        assert time.monotonic() - t0 < 8
        REGISTRY.clear_stopped(rid)
        return res

    res = _run(go())
    if via == "timeout":
        assert res.get("timed_out")


# ── F3: không spawn sau STOP ──
def test_spawn_refused_and_registered_proc_killed_for_stopped_run():
    async def go():
        rid = "stopped-run"
        REGISTRY.mark_stopped(rid)
        try:
            with pytest.raises(RunStopped):
                await spawn(sys.executable, "-c", "pass", run_id=rid)
            r = await toolbelt._run_argv([sys.executable, "-c", "print(1)"], 5, run_id=rid)
            assert r["ran"] is False and r.get("stopped")
            # register() trên run đã dừng giết ngay
            p = await asyncio.create_subprocess_exec(sys.executable, "-c", "import time; time.sleep(60)",
                                                     start_new_session=True)
            assert REGISTRY.register(rid, p) is False
            await asyncio.wait_for(p.wait(), 5)
        finally:
            REGISTRY.clear_stopped(rid)

    _run(go())


def test_multi_process_tool_does_not_spawn_next_after_stop(monkeypatch):
    spawned = []

    async def runner(inp, ctx):
        for _ in range(3):                   # như port_scan lặp qua nhiều IP
            r = await toolbelt._run_argv([sys.executable, "-c", "import time; time.sleep(60)"], 120)
            spawned.append(r.get("ran"))
        return {"done": True}

    _fake_tool(monkeypatch, "fake_multi", RiskTier.RECON, runner)
    _, rid = _setup()

    async def stopper():
        await _wait(lambda: REGISTRY.count(rid) == 1)
        db = SessionLocal()
        try:
            db.query(PentestRun).filter(PentestRun.id == rid).first().status = RunStatus.STOPPED
            db.commit()
        finally:
            db.close()
        REGISTRY.kill_all_nowait(rid, 0.5)   # như route STOP: giết process hiện tại, KHÔNG huỷ task

    _drive(rid, [[{"name": "fake_multi", "input": {"target": "10.0.0.5"}}]], stopper, timeout=20)
    assert spawned.count(True) == 1                      # chỉ process đầu chạy; 2 lần sau bị từ chối
    assert _run_status(rid) == RunStatus.STOPPED


def test_queued_calls_do_not_start_after_stop(monkeypatch):
    started = []

    async def runner(inp, ctx):
        started.append(inp["target"])
        return await toolbelt._run_argv([sys.executable, "-c", "import time; time.sleep(60)"], 120)

    _fake_tool(monkeypatch, "fake_slow", RiskTier.RECON, runner)
    _, rid = _setup(max_parallel=1)

    async def stopper():
        await _wait(lambda: REGISTRY.count(rid) == 1)
        db = SessionLocal()
        try:
            db.query(PentestRun).filter(PentestRun.id == rid).first().status = RunStatus.STOPPED
            db.commit()
        finally:
            db.close()
        REGISTRY.kill_all_nowait(rid, 0.5)

    call = {"name": "fake_slow", "input": {"target": "10.0.0.5"}}
    _drive(rid, [[call, call, call]], stopper, timeout=20)
    assert len(started) == 1
    assert _run_status(rid) == RunStatus.STOPPED


# ── F4: không ghi đè STOPPED ──
def test_release_approval_never_overwrites_stopped():
    _, rid = _setup()
    db = SessionLocal()
    try:
        db.query(PentestRun).filter(PentestRun.id == rid).first().status = RunStatus.STOPPED
        db.commit()
    finally:
        db.close()
    a = agent_mod.PentestAgent(rid)
    a._pending_approvals = 1
    a._release_approval()
    assert _run_status(rid) == RunStatus.STOPPED


# ── F5: finding cũ tự-verify ──
def test_legacy_auto_verified_findings_backfilled(tmp_path):
    import api.pentest_migrations as pm
    eng = create_engine(f"sqlite:///{tmp_path}/old.db")
    with eng.connect() as c:
        c.execute(text("CREATE TABLE pentest_findings (id TEXT, verified BOOLEAN, evidence_traffic_id TEXT)"))
        c.execute(text("INSERT INTO pentest_findings VALUES ('auto',1,NULL),('bound',1,'t1'),('plain',0,NULL)"))
        c.commit()
    pm.run(eng)
    pm.run(eng)                                          # idempotent
    with eng.connect() as c:
        rows = {r[0]: r[1:] for r in c.execute(text(
            "SELECT id, verified, confidence, validator FROM pentest_findings"))}
    assert rows["auto"] == (0, "suspected", None)         # model tự khẳng định → không còn verified
    assert rows["bound"] == (1, "confirmed", "human")     # người đã bind → giữ
    assert rows["plain"] == (0, "suspected", None)


def test_finding_out_not_verified_without_confirmation():
    from api.routes.pentest import _finding_out
    base = dict(id="1", title="t", severity="low", target="x", description="", evidence="", reproduction="",
                remediation="", cwe=None, cve=None, status="OPEN", evidence_traffic_id=None, created_at=None,
                validator=None)
    assert _finding_out(SimpleNamespace(**base, verified=True, confidence="suspected"))["verified"] is False
    assert _finding_out(SimpleNamespace(**base, verified=True, confidence="confirmed"))["verified"] is True
