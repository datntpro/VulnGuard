"""Chạy 1 kịch bản BÊN TRONG container vg-under-test:  python -m eval.harness.inproc /tmp/scenario.json

Tạo engagement + run trong SQLite tạm, chạy PentestAgent thật với ScriptedDriver, tự quyết định approval
theo kịch bản. In ra đúng 1 dòng `RESULT:{json}` (steps + trạng thái run). KHÔNG đụng DB thật.
"""
import asyncio
import json
import os
import sys
import tempfile


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
    try:
        driver = ScriptedDriver(spec["turns"])
        await agent_mod.PentestAgent(rid, driver_factory=lambda cfg: driver).run()
    finally:
        stop.set()
        await appr
    db = SessionLocal()
    try:
        r = db.query(pm.PentestRun).filter(pm.PentestRun.id == rid).first()
        steps = [{"n": s.step_number, "tool": s.tool_name, "risk": s.risk_tier.value if s.risk_tier else None,
                  "decided_by": s.decided_by, "outcome": s.outcome, "output": (s.output or "")[:300],
                  "input": s.tool_input}
                 for s in db.query(pm.AgentStep).filter(pm.AgentStep.run_id == rid)
                 .order_by(pm.AgentStep.step_number, pm.AgentStep.created_at).all()]
        return {"run_status": r.status.value, "error": r.error_message, "steps": steps,
                "script_exhausted": driver.exhausted}
    finally:
        db.close()


def main(path: str):
    _setup_env()
    spec = json.load(open(path))
    res = asyncio.run(run(spec))
    print("RESULT:" + json.dumps(res, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main(sys.argv[1])
