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


def ensure_schema():
    """create_all cho MỌI model (P1-3 tra bảng domains để xác minh sở hữu) — không chỉ model pentest."""
    import glob
    import importlib
    from api.database import Base, engine
    for f in glob.glob(os.path.join(os.path.dirname(__import__("api").__file__), "*models.py")):
        importlib.import_module("api." + os.path.basename(f)[:-3])
    Base.metadata.create_all(bind=engine)


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
    ensure_schema()
    agent_mod.APPROVAL_POLL_SECONDS = 0.1
    agent_mod.APPROVAL_TIMEOUT_SECONDS = 3      # policy "none" → hết hạn nhanh
    db = SessionLocal()
    try:
        from api.domain_models import Domain
        # D8 (P1-3): domain công khai phải xác minh sở hữu mới được quét chủ động — đặt đúng trạng thái theo kịch bản
        for d in db.query(Domain).filter(Domain.url.like("%.lab")).all():
            db.delete(d)
        db.commit()
        for h in spec.get("verified_domains", []):
            db.add(Domain(name=f"lab:{h}", url=f"http://{h}", ownership_verified=True, ownership_method="well_known"))
        db.commit()
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


# ── Kịch bản kind="api": gọi THẲNG proxy/replay thật (P1-4) thay vì vòng lặp agent ──
async def _raw_http(port: int, url: str, auth=None, extra=""):
    """Gửi 1 request absolute-URI qua proxy bằng socket thô → (status, headers[list], body)."""
    from urllib.parse import urlsplit
    u = urlsplit(url)
    head = f"GET {url} HTTP/1.1\r\nHost: {u.netloc}\r\nConnection: close\r\n{extra}"
    if auth is not None:
        import base64
        head += "Proxy-Authorization: Basic " + base64.b64encode(f"vg:{auth}".encode()).decode() + "\r\n"
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write((head + "\r\n").encode())
    await w.drain()
    data = b""
    try:
        while True:
            c = await asyncio.wait_for(r.read(65536), 15)
            if not c:
                break
            data += c
    finally:
        w.close()
    h, _, body = data.partition(b"\r\n\r\n")
    lines = h.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1]) if lines and lines[0].startswith("HTTP/") else 0
    return status, [tuple(x.split(":", 1)) for x in lines[1:] if ":" in x], body


async def _api_proxy(spec: dict, out: dict):
    from scanner.pentest.proxy import RecordingProxy
    proxy = RecordingProxy(spec["scope_rules"], engagement_id="lab-eng", run_id=None)
    port = await proxy.start("127.0.0.1", 0)
    try:
        if spec["api_script"] == "proxy_without_token":
            out["no_token_status"] = (await _raw_http(port, "http://inscope.lab/", None))[0]
            out["wrong_token_status"] = (await _raw_http(port, "http://inscope.lab/", "not-the-token"))[0]
            out["ok_status"] = (await _raw_http(port, "http://inscope.lab/", proxy.token))[0]
            out["oos_status"] = (await _raw_http(port, "http://oos.lab/", proxy.token))[0]
        else:   # proxy_login_keeps_cookie
            st, hdrs, _ = await _raw_http(port, "http://inscope.lab/login", proxy.token)
            out["login_status"] = st
            out["set_cookie_forwarded"] = sum(1 for k, v in hdrs if k.lower() == "set-cookie" and "sid=" in v)
            from api.database import SessionLocal
            from api.pentest_models import TrafficEntry
            db = SessionLocal()
            try:
                rows = db.query(TrafficEntry).filter(TrafficEntry.engagement_id == "lab-eng").all()
                out["cookie_recorded"] = sum(1 for r in rows if "sid=" in str((r.response_headers or {}).get("set-cookie", "")
                                                                              or (r.response_headers or {}).get("Set-Cookie", "")))
            finally:
                db.close()
    finally:
        await proxy.stop()


async def _api_replay(spec: dict, out: dict):
    from fastapi import HTTPException
    from api.database import SessionLocal
    from api.routes.pentest import replay_traffic
    from scanner.pentest.traffic import record
    from tests.pentest_fakes import make_engagement
    db = SessionLocal()
    try:
        eng_a = make_engagement(db, spec["scope_rules"], name="lab-A")
        eng_b = make_engagement(db, [{"type": "domain", "value": "metadata.lab", "include_subdomains": False, "mode": "allow"},
                                     {"type": "ip", "value": "172.31.250.254", "mode": "allow"}], name="lab-B")
        # request ghi dưới engagement B nhưng nhắm host chỉ nằm trong scope của A
        foreign = record(run_id=None, source="proxy", method="GET", url="http://inscope.lab/admin", status_code=200,
                         engagement_id=eng_b.id, db=db)
        own = record(run_id=None, source="proxy", method="GET", url="http://inscope.lab/admin", status_code=200,
                     engagement_id=eng_a.id, db=db)
        for key, tid in (("cross_replay_status", foreign), ("own_replay_status", own)):
            try:
                r = await replay_traffic(tid, db)
                out[key] = r["status_code"]
            except HTTPException as e:
                out[key] = e.status_code
    finally:
        db.close()


async def run_api(spec: dict) -> dict:
    ensure_schema()
    out: dict = {}
    if spec["api_script"] == "replay_cross_engagement":
        await _api_replay(spec, out)
    else:
        await _api_proxy(spec, out)
    return {"run_status": "COMPLETED", "steps": [], "turns_consumed": 0, "api": out}


def main(path: str):
    _setup_env()
    spec = json.load(open(path))
    res = asyncio.run(run_api(spec) if spec.get("api_script") else run(spec))
    print("RESULT:" + json.dumps(res, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main(sys.argv[1])
