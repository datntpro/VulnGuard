"""Chạy 1 kịch bản BÊN TRONG container vg-under-test:  python -m eval.harness.inproc /tmp/scenario.json

Tạo engagement + run trong SQLite tạm, chạy PentestAgent thật với ScriptedDriver, tự quyết định approval
theo kịch bản. In ra đúng 1 dòng `RESULT:{json}` (steps + trạng thái run). KHÔNG đụng DB thật.
"""
import asyncio
import json
import os
import sys
import tempfile
import time


def _setup_env():
    d = tempfile.mkdtemp(prefix="vglab_")
    os.environ["DATABASE_URL"] = f"sqlite:///{d}/lab.db"
    os.environ.setdefault("AI_CONFIG_FILE", f"{d}/ai.json")


async def _approver(policy: str, stop: asyncio.Event):
    from api.database import SessionLocal
    from api.pentest_models import ApprovalRequest, ApprovalStatus
    if policy == "none":
        return                          # không ai duyệt → agent chờ tới timeout (đã rút ngắn)
    status = ApprovalStatus.APPROVED if policy == "approve_all" else ApprovalStatus.DENIED
    while not stop.is_set():
        db = SessionLocal()
        try:
            for a in db.query(ApprovalRequest).filter(ApprovalRequest.status == ApprovalStatus.PENDING).all():
                a.status = status
                a.decided_by = "lab-approver"
            db.commit()
        finally:
            db.close()
        await asyncio.sleep(0.1)


def _procs(names=("nmap", "ffuf", "sqlmap", "nuclei")) -> int:
    n = 0
    for p in os.listdir("/proc"):
        if p.isdigit():
            try:
                if open(f"/proc/{p}/comm").read().strip() in names:
                    n += 1
            except OSError:
                pass
    return n


async def _stopper(rid: str, after_s: float, out: dict):
    """Mô phỏng người bấm STOP: gọi ĐÚNG handler `POST /runs/{id}/stop` rồi đo thời gian tới khi tool con biến mất."""
    from api.database import SessionLocal
    from api.routes.pentest import stop_run
    await asyncio.sleep(after_s)
    out["procs_alive_at_stop"] = _procs()
    t0 = time.monotonic()
    db = SessionLocal()
    try:
        stop_run(rid, db)
    finally:
        db.close()
    while _procs() and time.monotonic() - t0 < 30:
        await asyncio.sleep(0.05)
    out["stop_latency_ms"] = int((time.monotonic() - t0) * 1000)


async def run(spec: dict) -> dict:
    from api.database import SessionLocal, Base, engine
    import api.pentest_models as pm
    from scanner.pentest import agent as agent_mod
    from tests.pentest_fakes import ScriptedDriver, make_engagement, make_run
    Base.metadata.create_all(bind=engine)
    agent_mod.APPROVAL_POLL_SECONDS = 0.1
    agent_mod.APPROVAL_TIMEOUT_SECONDS = 3      # policy "none" → hết hạn nhanh
    db = SessionLocal()
    try:
        eng = make_engagement(db, spec["scope_rules"], max_steps=30)
        run_ = make_run(db, eng, mode=pm.AutonomyMode(spec["mode"]), targets=spec["targets"])
        rid = run_.id
    finally:
        db.close()
    stop = asyncio.Event()
    appr = asyncio.create_task(_approver(spec["approvals"], stop))
    stop_out: dict = {}
    stopper = asyncio.create_task(_stopper(rid, spec["stop_after_s"], stop_out)) if spec.get("stop_after_s") else None
    try:
        driver = ScriptedDriver(spec["turns"])
        await agent_mod.PentestAgent(rid, driver_factory=lambda cfg: driver).run()
    finally:
        if stopper:
            await stopper
        stop.set()
        await appr
    db = SessionLocal()
    try:
        r = db.query(pm.PentestRun).filter(pm.PentestRun.id == rid).first()
        steps = [{"n": s.step_number, "tool": s.tool_name, "risk": s.risk_tier.value if s.risk_tier else None,
                  "decided_by": s.decided_by, "outcome": s.outcome, "output": (s.output or "")[:2000],
                  "input": s.tool_input}
                 for s in db.query(pm.AgentStep).filter(pm.AgentStep.run_id == rid)
                 .order_by(pm.AgentStep.step_number, pm.AgentStep.created_at).all()]
        return {"run_status": r.status.value, "error": r.error_message, "steps": steps,
                "script_exhausted": driver.exhausted, "turns_consumed": driver.i, **stop_out}
    finally:
        db.close()


def main(path: str):
    _setup_env()
    spec = json.load(open(path))
    res = asyncio.run(run(spec))
    print("RESULT:" + json.dumps(res, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main(sys.argv[1])
