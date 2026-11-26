"""Helper cho tests/test_pentest_worker.py — chạy trong TIẾN TRÌNH RIÊNG (DATABASE_URL do test đặt).

  seed                       → tạo schema + engagement + run, in run_id
  work --start-turn N        → chạy Worker (ScriptedDriver chậm) tới khi bị kill / hết job
Kịch bản: turn0 report_finding A, turn1 report_finding B (create() chờ SLOW giây), turn2 kết thúc.
"""
import argparse
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.database import Base, SessionLocal, engine  # noqa: E402
from api import pentest_models  # noqa: E402,F401
from tests.pentest_fakes import ScriptedDriver, make_engagement, make_run  # noqa: E402

TURNS = [
    [{"name": "report_finding", "input": {"title": "A", "severity": "low", "target": "10.0.0.5",
                                          "description": "d", "evidence": "e"}}],
    [{"name": "report_finding", "input": {"title": "B", "severity": "low", "target": "10.0.0.5",
                                          "description": "d", "evidence": "e"}}],
    [],
]


class SlowDriver(ScriptedDriver):
    def __init__(self, turns, slow_from):
        super().__init__(turns)
        self.slow_from = slow_from

    async def create(self, system, messages, native_tools, **kw):
        if self.i >= self.slow_from:
            await asyncio.sleep(float(os.environ.get("SLOW", "0")))
        return await super().create(system, messages, native_tools, **kw)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd")
    ap.add_argument("--start-turn", type=int, default=0)
    a = ap.parse_args()
    if a.cmd == "seed":
        Base.metadata.create_all(bind=engine)
        from api.pentest_migrations import run as migrate
        migrate(engine)
        db = SessionLocal()
        eng = make_engagement(db, [{"type": "ip", "value": "10.0.0.5", "mode": "allow"}])
        run = make_run(db, eng)
        from scanner.pentest.jobs import enqueue
        enqueue(db, run.id, commit=True)
        print(run.id)
        return
    import api.services.ai_config as ai
    ai.load_config = lambda: {}
    from scanner.pentest.worker import Worker
    turns = TURNS[a.start_turn:]
    fresh = a.start_turn == 0
    # Lượt 0 nhanh, lượt 1 chậm (để test kill giữa chừng): slow_from = chỉ số lượt trong KỊCH BẢN cục bộ
    drv = SlowDriver(turns, slow_from=(1 if fresh else 0))
    w = Worker(driver_factory=lambda cfg: drv, lease_s=1.5, heartbeat_s=0.4, poll_s=0.2)

    async def go():
        t = asyncio.ensure_future(w.run_forever())
        while True:
            await asyncio.sleep(0.3)
            if drv.i >= len(turns):
                w.request_shutdown()
                break
        await t

    asyncio.run(go())


if __name__ == "__main__":
    main()
