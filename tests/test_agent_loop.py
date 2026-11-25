"""P1-2: vòng lặp agent đúng đắn + kill switch thật (B7, B11, B12, B17, B18, refusal). Không chạm mạng."""
import asyncio
import sys
import time
from datetime import datetime, timedelta

import pytest

from api.database import Base, SessionLocal, engine
from api.pentest_models import (
    AgentStep, ApprovalRequest, ApprovalStatus, Engagement, PentestFinding, PentestRun,
    RiskTier, RunStatus,
)
from scanner.pentest import agent as agent_mod
from scanner.pentest import toolbelt
from scanner.pentest.agent import PentestAgent
from scanner.pentest.procs import REGISTRY
from scanner.pentest.toolbelt import Tool
from tests.pentest_fakes import ScriptedDriver, make_engagement, make_run

SCOPE = [{"type": "ip", "value": "10.0.0.5", "mode": "allow"}]
SCHEMA = {"type": "object", "properties": {"target": {"type": "string"}},
          "required": ["target"], "additionalProperties": False}


@pytest.fixture(autouse=True)
def _fast(monkeypatch):
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(agent_mod, "APPROVAL_POLL_SECONDS", 0.05)
    monkeypatch.setattr(agent_mod, "WATCHDOG_SECONDS", 0.1)
    import api.services.ai_config as ai
    monkeypatch.setattr(ai, "load_config", lambda: {})


def _fake_tool(monkeypatch, name, risk, runner):
    t = Tool(name, risk, "fake", SCHEMA, runner, ["target"])
    real = toolbelt.get_tool
    monkeypatch.setattr(toolbelt, "get_tool", lambda n: t if n == name else real(n))
    return t


def _setup(**eng_kw):
    db = SessionLocal()
    try:
        eng = make_engagement(db, SCOPE, **eng_kw)
        run = make_run(db, eng)
        return eng.id, run.id
    finally:
        db.close()


def _run_status(rid):
    db = SessionLocal()
    try:
        return db.query(PentestRun).filter(PentestRun.id == rid).first().status
    finally:
        db.close()


def _get(model, **flt):
    db = SessionLocal()
    try:
        return db.query(model).filter_by(**flt).all()
    finally:
        db.close()


def _drive(rid, turns, *side, timeout=30, strict=False):
    """Chạy agent + các coroutine phụ (side) trong loop riêng; trả driver."""
    drv = ScriptedDriver(turns, strict=strict)

    async def main():
        task = asyncio.ensure_future(PentestAgent(rid, driver_factory=lambda cfg: drv).run())
        extra = [asyncio.ensure_future(s()) for s in side]
        await asyncio.wait_for(task, timeout)
        for e in extra:
            e.cancel()
        await asyncio.gather(*extra, return_exceptions=True)

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(main())
    finally:
        loop.close()
    return drv


async def _wait(cond, timeout=15):
    t0 = time.monotonic()
    while not cond():
        if time.monotonic() - t0 > timeout:
            raise AssertionError("điều kiện không đạt kịp thời")
        await asyncio.sleep(0.02)


def _approve(rid, which=None):
    db = SessionLocal()
    try:
        ps = db.query(ApprovalRequest).filter(ApprovalRequest.run_id == rid,
                                              ApprovalRequest.status == ApprovalStatus.PENDING).order_by(
            ApprovalRequest.step_number).all()
        a = ps[which or 0]
        a.status = ApprovalStatus.APPROVED
        db.commit()
    finally:
        db.close()


def _pending(rid):
    return len([a for a in _get(ApprovalRequest, run_id=rid) if a.status == ApprovalStatus.PENDING])


# ── B11: trạng thái WAITING_APPROVAL phản ánh đúng số approval đang chờ ──
def test_status_back_to_running_after_approval_and_stays_waiting_with_two_pending(monkeypatch):
    seen = []

    async def runner(inp, ctx):
        seen.append((inp["target"], _run_status(ctx["run_id"])))
        return {"ok": True}

    _fake_tool(monkeypatch, "fake_intrusive", RiskTier.INTRUSIVE, runner)
    _, rid = _setup()

    async def approver():
        await _wait(lambda: _pending(rid) == 2)
        _approve(rid)                       # duyệt 1/2
        await _wait(lambda: len(seen) == 1)
        # còn 1 approval chờ → vẫn WAITING_APPROVAL
        assert _run_status(rid) == RunStatus.WAITING_APPROVAL
        _approve(rid)                       # duyệt nốt

    _drive(rid, [[{"name": "fake_intrusive", "input": {"target": "10.0.0.5"}},
                  {"name": "fake_intrusive", "input": {"target": "10.0.0.5"}}], []], approver)
    assert len(seen) == 2
    assert seen[0][1] == RunStatus.WAITING_APPROVAL      # lúc chạy cái đầu, cái sau còn chờ
    assert seen[1][1] == RunStatus.RUNNING               # hết approval chờ → RUNNING trở lại
    assert _run_status(rid) == RunStatus.COMPLETED


# ── B17: chờ duyệt không giữ semaphore ──
def test_pending_approval_does_not_hold_semaphore(monkeypatch):
    ran = []

    async def runner(inp, ctx):
        ran.append(inp["target"])
        return {"ok": True}

    _fake_tool(monkeypatch, "fake_intrusive", RiskTier.INTRUSIVE, runner)
    _fake_tool(monkeypatch, "fake_recon", RiskTier.RECON, runner)
    _, rid = _setup(max_parallel=1)

    async def approver():
        await _wait(lambda: _pending(rid) == 1)
        await _wait(lambda: "10.0.0.5" in ran)   # RECON đã chạy khi approval còn chờ
        assert _pending(rid) == 1
        _approve(rid)

    _drive(rid, [[{"name": "fake_intrusive", "input": {"target": "10.0.0.5"}},
                  {"name": "fake_recon", "input": {"target": "10.0.0.5"}}], []], approver, timeout=20)
    assert len(ran) == 2


# ── B7: STOP giết thật process con ──
def _sleeper_runner():
    async def runner(inp, ctx):
        return await toolbelt._run_argv([sys.executable, "-c", "import time; time.sleep(60)"], timeout=120)
    return runner


def test_stop_kills_running_subprocess_within_5s(monkeypatch):
    _fake_tool(monkeypatch, "fake_slow", RiskTier.RECON, _sleeper_runner())
    _, rid = _setup()
    info = {}

    async def stopper():
        await _wait(lambda: REGISTRY.count(rid) == 1)
        info["proc"] = list(REGISTRY._procs[rid])[0]
        info["t0"] = time.monotonic()
        db = SessionLocal()
        try:
            r = db.query(PentestRun).filter(PentestRun.id == rid).first()
            r.status = RunStatus.STOPPED
            db.commit()
        finally:
            db.close()

    _drive(rid, [[{"name": "fake_slow", "input": {"target": "10.0.0.5"}}]], stopper, timeout=20)
    assert time.monotonic() - info["t0"] < 5
    assert info["proc"].returncode is not None            # process chết thật
    assert _run_status(rid) == RunStatus.STOPPED
    assert REGISTRY.count(rid) == 0


@pytest.mark.parametrize("how", ["revoked", "expired"])
def test_authorization_revoked_or_expired_mid_run_stops(monkeypatch, how):
    _fake_tool(monkeypatch, "fake_slow", RiskTier.RECON, _sleeper_runner())
    eid, rid = _setup()

    async def revoker():
        await _wait(lambda: REGISTRY.count(rid) == 1)
        db = SessionLocal()
        try:
            e = db.query(Engagement).filter(Engagement.id == eid).first()
            if how == "revoked":
                e.authorized = False
            else:
                e.expiry_date = datetime.utcnow() - timedelta(seconds=1)
            db.commit()
        finally:
            db.close()

    t0 = time.monotonic()
    _drive(rid, [[{"name": "fake_slow", "input": {"target": "10.0.0.5"}}]], revoker, timeout=20)
    assert time.monotonic() - t0 < 10
    r = _get(PentestRun, id=rid)[0]
    assert r.status == RunStatus.STOPPED
    assert "authorization revoked/expired" in (r.error_message or "")


def test_unauthorized_engagement_stops_before_next_turn(monkeypatch):
    """Kiểm lại uỷ quyền MỖI LƯỢT: huỷ giữa 2 lượt LLM → lượt sau không chạy."""
    eid, rid = _setup()

    async def runner(inp, ctx):
        db = SessionLocal()
        try:
            db.query(Engagement).filter(Engagement.id == eid).first().authorized = False
            db.commit()
        finally:
            db.close()
        return {"ok": True}

    _fake_tool(monkeypatch, "fake_recon", RiskTier.RECON, runner)
    drv = _drive(rid, [[{"name": "fake_recon", "input": {"target": "10.0.0.5"}}], []])
    assert drv.i == 1 and _run_status(rid) == RunStatus.STOPPED


# ── B12 / B18: finding không tự verified; liên kết step/traffic ──
def _finding_turn(**extra):
    inp = {"title": "t", "severity": "low", "target": "10.0.0.5", "description": "d", "evidence": "trust me"}
    inp.update(extra)
    return [{"name": "report_finding", "input": inp}]


def test_finding_without_evidence_traffic_is_suspected_not_verified():
    _, rid = _setup()
    _drive(rid, [_finding_turn(), []])
    f = _get(PentestFinding, run_id=rid)[0]
    assert f.verified is False and f.confidence == "suspected" and f.evidence_traffic_id is None


def test_finding_with_traffic_of_this_run_is_likely_and_linked_to_step(monkeypatch):
    from scanner.pentest.traffic import record
    _, rid = _setup()
    tid = record(run_id=rid, source="http_probe", method="GET", url="http://10.0.0.5/")

    async def runner(inp, ctx):
        return {"traffic_id": tid}

    _fake_tool(monkeypatch, "fake_recon", RiskTier.RECON, runner)
    _drive(rid, [[{"name": "fake_recon", "input": {"target": "10.0.0.5"}}], _finding_turn(traffic_id=tid), []])
    f = _get(PentestFinding, run_id=rid)[0]
    assert f.verified is False and f.confidence == "likely" and f.evidence_traffic_id == tid
    src = [s for s in _get(AgentStep, run_id=rid) if s.id == f.source_step_id][0]
    assert src.tool_name == "fake_recon" and tid in src.output      # link tới step đã thực thi chứa traffic_id


def test_finding_with_traffic_id_inside_evidence_text_counts(monkeypatch):
    from scanner.pentest.traffic import record
    _, rid = _setup()
    tid = record(run_id=rid, source="http_probe", method="GET", url="http://10.0.0.5/")
    _drive(rid, [_finding_turn(evidence=f"HTTP/1.1 200 (traffic {tid})"), []])
    assert _get(PentestFinding, run_id=rid)[0].confidence == "likely"


def test_finding_with_foreign_run_traffic_stays_suspected():
    from scanner.pentest.traffic import record
    _, other = _setup()
    _, rid = _setup()
    tid = record(run_id=other, source="http_probe", method="GET", url="http://10.0.0.5/")
    _drive(rid, [_finding_turn(traffic_id=tid), []])
    f = _get(PentestFinding, run_id=rid)[0]
    assert f.confidence == "suspected" and f.evidence_traffic_id is None
    assert f.source_step_id                                           # B18: luôn có source_step_id


# ── Refusal ──
def test_refusal_fails_run_with_refused_step_and_category():
    _, rid = _setup()
    _drive(rid, [{"stop_reason": "refusal", "stop_details": {"category": "cyber"}}])
    r = _get(PentestRun, id=rid)[0]
    assert r.status == RunStatus.FAILED and "cyber" in r.error_message
    steps = _get(AgentStep, run_id=rid)
    assert [s.outcome for s in steps] == ["refused"] and "cyber" in steps[0].output


# ── llm.py: refusal_category + fallbacks ──
def test_llm_parse_refusal_category_and_fallback_kwargs():
    from types import SimpleNamespace as NS
    from scanner.pentest.llm import LLMDriver
    d = LLMDriver(None, "claude-opus-5-5", "anthropic", first_party=True)
    raw = NS(content=[], stop_reason="refusal", stop_details=NS(category="cyber"),
             usage=NS(input_tokens=1, output_tokens=2))
    r = d.parse(raw)
    assert r.refused and r.refusal_category == "cyber" and r.tokens_in == 1 and r.tokens_out == 2

    calls = {}

    class Msgs:
        async def create(self, **kw):
            calls["plain"] = kw

    class Beta:
        class messages:
            @staticmethod
            async def create(**kw):
                calls["beta"] = kw

    client = NS(messages=Msgs(), beta=Beta())
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(LLMDriver(client, "claude-opus-5-5", "anthropic", True).create("s", [], []))
        assert calls["beta"]["fallbacks"] == "default"
        assert calls["beta"]["betas"] == ["server-side-fallback-2026-07-01"]
        loop.run_until_complete(LLMDriver(client, "claude-opus-5-5", "anthropic", False).create("s", [], []))   # Bedrock
        assert "plain" in calls
        calls.clear()
        loop.run_until_complete(LLMDriver(client, "claude-haiku-5-5", "anthropic", True).create("s", [], []))
        assert "plain" in calls and "beta" not in calls
    finally:
        loop.close()


# ── Routes: confidence trong output, bind_evidence cùng engagement, stop_run giết process ──
@pytest.fixture
def admin_client():
    """Admin tạm; xoá user sau test (test_app giả định chưa có user → setup_required)."""
    from api.auth_models import User
    from tests import _authutil as au
    email, uid = au.make_user()
    c = au.new_client()
    c.headers.update(au.bearer(au.login(c, email)))
    yield c
    db = SessionLocal()
    try:
        db.query(User).filter(User.id == uid).delete()
        db.commit()
    finally:
        db.close()


def test_bind_evidence_same_engagement_confirms_and_cross_engagement_rejected(admin_client):
    from scanner.pentest.traffic import record
    c = admin_client
    _, rid = _setup()
    _, other_rid = _setup()
    db = SessionLocal()
    try:
        f = PentestFinding(run_id=rid, title="t", severity="low", target="x", confidence="suspected")
        db.add(f)
        db.commit()
        fid = f.id
    finally:
        db.close()
    good = record(run_id=rid, source="http_probe", method="GET", url="http://10.0.0.5/")
    bad = record(run_id=other_rid, source="http_probe", method="GET", url="http://10.0.0.5/")
    assert c.post(f"/api/pentest/findings/{fid}/evidence", json={"traffic_id": bad}).status_code == 409
    r = c.post(f"/api/pentest/findings/{fid}/evidence", json={"traffic_id": good})
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["verified"] is True and j["confidence"] == "confirmed" and j["validator"] == "human"


def test_stop_route_kills_registered_process(admin_client):
    c = admin_client
    _, rid = _setup()
    db = SessionLocal()
    try:
        db.query(PentestRun).filter(PentestRun.id == rid).first().status = RunStatus.RUNNING
        db.commit()
    finally:
        db.close()

    async def go():
        proc = await asyncio.create_subprocess_exec(sys.executable, "-c", "import time; time.sleep(60)",
                                                    start_new_session=True)
        REGISTRY.register(rid, proc)
        # route sync chạy trong threadpool của TestClient → không có loop ở thread đó → SIGTERM + Timer SIGKILL
        await asyncio.get_event_loop().run_in_executor(None, lambda: c.post(f"/api/pentest/runs/{rid}/stop"))
        await asyncio.wait_for(proc.wait(), 5)
        REGISTRY.unregister(rid, proc)
        return proc.returncode

    loop = asyncio.new_event_loop()
    try:
        assert loop.run_until_complete(go()) is not None
    finally:
        loop.close()
    assert _run_status(rid) == RunStatus.STOPPED
