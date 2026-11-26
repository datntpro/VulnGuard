"""P2-4: exec backend (local | sandbox) — ownership rid→eid, parity local↔sandbox, degraded mode, kill. Không Docker/mạng."""
import asyncio
import base64
import json

import httpx
import pytest

from api.database import Base, SessionLocal, engine
from api import webscan_models  # noqa: F401
from api.domain_models import Domain  # noqa: F401
from api.pentest_models import AgentStep, AutonomyMode, RiskTier, RunStatus
from scanner.pentest import agent as agent_mod
from scanner.pentest import exec_backend as eb
from scanner.pentest import policy, toolbelt
from scanner.pentest.agent import PentestAgent
from scanner.pentest.gating import decide_action
from scanner.pentest.runner_client import RunnerError
from scanner.pentest.settings import PentestSettings, pentest_settings
from tests.pentest_fakes import ScriptedDriver, make_engagement, make_run

M = AutonomyMode.AUTONOMOUS_IN_SCOPE
IP = "10.0.0.5"
RULES = [{"type": "ip", "value": IP, "mode": "allow"}]


@pytest.fixture(autouse=True)
def _db():
    Base.metadata.create_all(bind=engine)


def run_(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class FakeRunner:
    """RunnerClient giả: ghi lại MỌI lời gọi; responder(argv) → (stdout, stderr, returncode)."""

    def __init__(self, responder=None, status="finished"):
        self.calls, self.execs, self.n = [], {}, 0
        self.responder = responder or (lambda argv: ("", "", 0))
        self.status = status

    def _rec(self, name, *a):
        self.calls.append((name, *a))

    async def create_network(self, eid, policy):
        self._rec("create_network", eid)
        return {"network": f"vg-eng-{eid}"}

    async def create_sandbox(self, rid, eid, limits=None):
        self._rec("create_sandbox", rid, eid)
        return {"sandbox_id": "x"}

    async def delete_sandbox(self, rid):
        self._rec("delete_sandbox", rid)

    async def delete_network(self, eid):
        self._rec("delete_network", eid)

    async def exec(self, rid, step_id, tool, argv, timeout_s=600, env=None, stdin=None):
        self.n += 1
        xid = f"x{self.n}"
        self.last_stdin = stdin
        self.execs[xid] = {"rid": rid, "step_id": step_id, "tool": tool, "argv": list(argv), "timeout": timeout_s,
                           "stdin": stdin}
        self._rec("exec", rid, step_id, tool)
        return xid

    async def exec_status(self, rid, xid):
        self._rec("exec_status", rid, xid)
        return {"status": self.status, "returncode": self.responder(self.execs[xid]["argv"])[2], "timed_out": False}

    async def exec_output_chunk(self, rid, xid, stream="stdout", offset=0):
        self._rec("exec_output", rid, xid)
        out, err, _ = self.responder(self.execs[xid]["argv"])
        data = (out if stream == "stdout" else err).encode()[offset:]
        return data, offset + len(data), False

    async def kill(self, rid):
        self._rec("kill", rid)
        return 1

    async def aclose(self):
        pass

    @property
    def execed(self):
        return list(self.execs.values())


def sandbox(client=None, rid="r1", eid="e1", owner=None, others=0):
    client = client or FakeRunner()
    return eb.SandboxBackend(client, run_id=rid, engagement_id=eid, owner_lookup=owner or (lambda r: eid),
                             other_active_runs=lambda e, r: others, poll_s=0.001), client


# ───────────────────────── ownership (REQUIRED by P2-2 review) ─────────────────────────
def test_every_runner_call_is_owner_checked_and_nothing_reaches_runner_when_run_belongs_elsewhere():
    b, c = sandbox(owner=lambda r: "SOMEONE-ELSE")
    calls = [lambda: b.ensure(), lambda: b.run_argv(["nmap", "-sV", IP], 5), lambda: b.http(eb.HttpSpec("GET", "http://x/")),
             lambda: b.kill_run("r1"), lambda: b.close()]
    for fn in calls:
        with pytest.raises(eb.OwnershipError):
            run_(fn())
    assert c.calls == []          # KHÔNG có request nào tới runner


def test_backend_cannot_be_pointed_at_another_run():
    b, c = sandbox()
    for fn in (lambda: b.run_argv(["nmap", IP], 5, run_id="OTHER"), lambda: b.kill_run("OTHER")):
        with pytest.raises(eb.OwnershipError):
            run_(fn())
    with pytest.raises(eb.OwnershipError):
        run_(b._guard("r1", "OTHER-ENG"))
    assert c.calls == []


def test_owner_lookup_is_rechecked_on_each_call_not_cached():
    owner = {"e": "e1"}
    b, c = sandbox(owner=lambda r: owner["e"])
    run_(b.run_argv(["nmap", IP], 5))
    owner["e"] = "e2"             # run bị chuyển/ gán sai engagement giữa chừng
    before = len(c.calls)
    with pytest.raises(eb.OwnershipError):
        run_(b.run_argv(["nmap", IP], 5))
    assert len(c.calls) == before


def test_unknown_run_is_not_owned():
    b, c = sandbox(owner=lambda r: None)
    with pytest.raises(eb.OwnershipError):
        run_(b.ensure())
    assert c.calls == []


def test_ownership_against_the_real_db():
    db = SessionLocal()
    try:
        ea = make_engagement(db, RULES)
        eb_ = make_engagement(db, RULES)
        ra = make_run(db, ea)
        ids = (ea.id, eb_.id, ra.id)
    finally:
        db.close()
    ea_id, eb_id, ra_id = ids
    c = FakeRunner()
    good = eb.SandboxBackend(c, run_id=ra_id, engagement_id=ea_id, other_active_runs=lambda e, r: 0, poll_s=0.001)
    run_(good.ensure())
    assert ("create_sandbox", ra_id, ea_id) in c.calls
    c2 = FakeRunner()
    bad = eb.SandboxBackend(c2, run_id=ra_id, engagement_id=eb_id, poll_s=0.001)   # run của A, khai là engagement B
    with pytest.raises(eb.OwnershipError):
        run_(bad.ensure())
    with pytest.raises(eb.OwnershipError):
        run_(bad.kill_run(ra_id))
    assert c2.calls == []


def test_ids_are_validated_before_use():
    for rid, eid in (("../x", "e"), ("r", "e/../x"), ("", "e"), ("r", "a b")):
        with pytest.raises(ValueError):
            eb.SandboxBackend(FakeRunner(), run_id=rid, engagement_id=eid)


# ───────────────────────── lifecycle ─────────────────────────
def test_lazy_ensure_once_network_then_sandbox_and_close_removes_network_only_when_last_run():
    b, c = sandbox()
    assert c.calls == []                     # lazy
    run_(b.run_argv(["nmap", IP], 5))
    run_(b.run_argv(["nmap", IP], 5))
    assert [x[0] for x in c.calls].count("create_sandbox") == 1
    assert [x[0] for x in c.calls][:2] == ["create_network", "create_sandbox"]
    run_(b.close())
    assert ("delete_sandbox", "r1") in c.calls and ("delete_network", "e1") in c.calls
    b2, c2 = sandbox(others=1)               # engagement còn run khác đang chạy
    run_(b2.run_argv(["nmap", IP], 5))
    run_(b2.close())
    assert ("delete_sandbox", "r1") in c2.calls and not any(x[0] == "delete_network" for x in c2.calls)


def test_default_policy_denies_everything_until_p2_3():
    assert eb.default_policy("e1")["allow"] == []


def test_step_ids_unique_per_exec_and_valid():
    b, c = sandbox()
    for _ in range(3):
        run_(b.run_argv(["nmap", IP], 5, step_id="s7"))
    ids = [e["step_id"] for e in c.execed]
    assert len(set(ids)) == 3 and all(i.startswith("s7-") for i in ids)


@pytest.mark.parametrize("argv", [["sh", "-c", "id"], ["/bin/nmap", IP], ["python3", "-c", "x"], ["curl", "http://x"], [], ["nmap", "a\x00b"]])
def test_api_side_allowlist_refuses_before_runner(argv):
    b, c = sandbox()
    r = run_(b.run_argv(argv, 5))
    assert r["ran"] is False and not c.execed


def test_runner_error_and_exec_error_become_ran_false_not_exceptions():
    class Boom(FakeRunner):
        async def exec(self, *a, **k):
            raise RunnerError(422, "argv refused")
    b, _ = sandbox(Boom())
    r = run_(b.run_argv(["nmap", IP], 5))
    assert r["ran"] is False and "argv refused" in r["error"]
    b, _ = sandbox(FakeRunner(status="error"))
    assert run_(b.run_argv(["nmap", IP], 5))["ran"] is False


def test_timeout_and_killed_results():
    class T(FakeRunner):
        async def exec_status(self, rid, xid):
            return {"status": "finished", "returncode": None, "timed_out": True}
    r = run_(sandbox(T())[0].run_argv(["nmap", IP], 7))
    assert r["timed_out"] and r["ran"] and "Timeout" in r["error"]
    r = run_(sandbox(FakeRunner(status="killed"))[0].run_argv(["nmap", IP], 7))
    assert r.get("stopped") is True


def test_stopped_run_does_not_exec():
    from scanner.pentest.procs import REGISTRY
    b, c = sandbox(rid="rstop")
    REGISTRY.mark_stopped("rstop")
    try:
        r = run_(b.run_argv(["nmap", IP], 5))
    finally:
        REGISTRY.clear_stopped("rstop")
    assert r["stopped"] and not c.execed          # như spawn() ở local


def test_cancel_during_exec_kills_in_sandbox():
    class Hang(FakeRunner):
        async def exec_status(self, rid, xid):
            return {"status": "running"}
    c = Hang()
    b, _ = sandbox(c)

    async def main():
        t = asyncio.ensure_future(b.run_argv(["nmap", IP], 600))
        await asyncio.sleep(0.05)
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t
    run_(main())
    assert ("kill", "r1") in c.calls


# ───────────────────────── backend_for / degraded ─────────────────────────
def S(**kw):
    return PentestSettings(_env_file=None, **kw)


def test_default_is_local_and_sandbox_is_opt_in():
    assert PentestSettings(_env_file=None).exec_backend == "local"
    assert isinstance(eb.backend_for("e1", "r1", S()), eb.LocalBackend)
    assert not eb.backend_for("e1", "r1", S()).degraded


def test_sandbox_selected_when_configured():
    s = S(exec_backend="sandbox", runner_token="t" * 40)
    b = eb.backend_for("e1", "r1", s, client_factory=FakeRunner)
    assert isinstance(b, eb.SandboxBackend) and b.name == "sandbox" and not b.degraded


def test_sandbox_unconfigured_degrades_to_local_unless_required():
    b = eb.backend_for("e1", "r1", S(exec_backend="sandbox"))
    assert isinstance(b, eb.LocalBackend) and b.degraded
    with pytest.raises(eb.SandboxUnavailable):
        eb.backend_for("e1", "r1", S(exec_backend="sandbox", require_sandbox="true"))
    with pytest.raises(eb.SandboxUnavailable):   # require=true tự nó cũng đòi sandbox dù exec_backend=local
        eb.backend_for("e1", "r1", S(require_sandbox="true"))


def test_runtime_failure_degrades_or_raises():
    class Down(FakeRunner):
        async def create_network(self, *a):
            raise RunnerError(503, "docker down")
    b, _ = sandbox(Down())
    d = run_(eb.prepare(b, S(exec_backend="sandbox")))
    assert isinstance(d, eb.LocalBackend) and d.degraded
    with pytest.raises(eb.SandboxUnavailable):
        run_(eb.prepare(sandbox(Down())[0], S(exec_backend="sandbox", require_sandbox="true")))


def test_ownership_failure_during_prepare_is_never_degraded_away():
    b, _ = sandbox(owner=lambda r: "x")
    with pytest.raises(eb.OwnershipError):
        run_(eb.prepare(b, S(exec_backend="sandbox")))


class _T:
    def __init__(self, risk, bin_name="nmap", keys=("host",)):
        self.name, self.risk, self.bin_name, self.target_keys = "t", risk, bin_name, list(keys)
        self.escalate = self.escalate_tier = None
        self.active_probe = False

    def available(self, sandbox=False):
        return sandbox   # binary chỉ có trong image runner, không có trên máy chủ API

    def targets(self, inp):
        return [inp["host"]]


def test_degraded_blocks_intrusive_and_destructive_with_sandbox_unavailable():
    for tier in (RiskTier.INTRUSIVE, RiskTier.DESTRUCTIVE):
        d, why = decide_action(type("X", (_T,), {"available": lambda self, sandbox=False: True})(tier), {"host": IP}, M,
                               RULES, degraded=True)
        assert d == "block_policy" and "sandbox unavailable" in why
    ok = type("X", (_T,), {"available": lambda self, sandbox=False: True})(RiskTier.ACTIVE_SAFE)
    assert decide_action(ok, {"host": IP}, M, RULES, degraded=True)[0] == "execute"


def test_gating_is_identical_across_backends():
    """Cùng input → cùng quyết định (scope, tier, approval); backend chỉ đổi chỗ kiểm binary."""
    class X(_T):
        def available(self, sandbox=False):
            return True
    cases = [({"host": IP}, RiskTier.RECON), ({"host": IP}, RiskTier.ACTIVE_SAFE), ({"host": IP}, RiskTier.INTRUSIVE),
             ({"host": "10.9.9.9"}, RiskTier.RECON), ({"host": "169.254.169.254"}, RiskTier.ACTIVE_SAFE)]
    for inp, tier in cases:
        loc = decide_action(X(tier), inp, M, RULES)
        sbx = decide_action(X(tier), inp, M, RULES, sandbox=True)
        assert loc == sbx, (inp, tier, loc, sbx)


def test_sandbox_checks_binary_in_image_not_host(monkeypatch):
    monkeypatch.setattr(toolbelt.shutil, "which", lambda n: None)     # API host không có nmap/ffuf/...
    t = toolbelt.get_tool("port_scan")
    assert decide_action(t, {"host": IP}, M, RULES)[0] == "block_unavail"
    assert decide_action(t, {"host": IP}, M, RULES, sandbox=True)[0] == "execute"
    names = {d["name"] for d in toolbelt.tool_defs_for_llm(sandbox=True)}
    assert {"port_scan", "content_discovery", "sqlmap", "web_vuln_scan"} <= names


def test_sandbox_cap_reason_without_degraded_is_unchanged(monkeypatch):
    monkeypatch.setattr(policy, "degraded_mode", lambda: False)
    assert policy.sandbox_cap_reason("INTRUSIVE") is None and policy.sandbox_cap_reason("INTRUSIVE", False) is None
    monkeypatch.setattr(policy, "degraded_mode", lambda: True)
    assert "suy giảm" in policy.sandbox_cap_reason("DESTRUCTIVE")


# ───────────────────────── parity: argv của mọi tool đi qua cả hai backend giống hệt ─────────────────────────
def _ctx(backend=None, **kw):
    c = {"scope_rules": RULES, "run_id": "r1", "step_id": "s1", **kw}
    if backend is not None:
        c["backend"] = backend
    return c


def _both(monkeypatch, tool, inp, ctx_extra=None):
    """Chạy `tool` ở local (patch _run_argv) và sandbox (FakeRunner); trả (argv_local, argv_sandbox, out_local, out_sbx)."""
    seen = []

    async def fake(argv, timeout, run_id=None):
        seen.append((list(argv), timeout))
        return {"ran": True, "returncode": 0, "stdout": "OUT", "stderr": ""}
    monkeypatch.setattr(toolbelt, "_run_argv", fake)
    monkeypatch.setattr(toolbelt.shutil, "which", lambda n: "/bin/" + n)
    real_wl = toolbelt.resolve_wordlist
    monkeypatch.setattr(toolbelt, "resolve_wordlist", lambda p, sandbox=False: real_wl(p, sandbox=True) if sandbox else p
                        if p == toolbelt.DEFAULT_WORDLIST else real_wl(p))   # host dev không có seclists
    t = toolbelt.get_tool(tool)
    lo = run_(t.runner(dict(inp), _ctx(eb.LocalBackend(), **(ctx_extra or {}))))
    b, c = sandbox(FakeRunner(lambda argv: ("OUT", "", 0)))
    so = run_(t.runner(dict(inp), _ctx(b, **(ctx_extra or {}))))
    return seen, c.execed, lo, so


@pytest.mark.parametrize("tool,inp", [
    ("port_scan", {"host": IP, "top_ports": 50, "timeout": 99}),
    ("content_discovery", {"url": f"http://{IP}/FUZZ", "rate": 5, "timeout": 77}),
    ("sqlmap", {"url": f"http://{IP}/p?id=1", "level": 2, "enumerate_dbs": True, "timeout": 88}),
])
def test_argv_parity_local_vs_sandbox(monkeypatch, tool, inp):
    seen, ex, lo, so = _both(monkeypatch, tool, inp)
    assert len(seen) == len(ex) >= 1
    for (argv, timeout), e in zip(seen, ex):
        assert e["argv"] == argv                       # argv byte-for-byte
        assert e["timeout"] == timeout                 # cùng timeout đã clamp
        assert e["rid"] == "r1" and e["tool"] == eb.tool_label(argv)
    assert {k: v for k, v in lo.items() if k not in ("stderr",)} == {k: v for k, v in so.items() if k not in ("stderr",)}


def test_validation_rejections_identical_and_never_reach_runner(monkeypatch):
    for tool, inp in [("sqlmap", {"url": f"http://{IP}/", "technique": "X;rm"}), ("port_scan", {"host": "--script=x"}),
                      ("content_discovery", {"url": f"http://{IP}/FUZZ", "wordlist": "/etc/passwd"}),
                      ("content_discovery", {"url": f"http://{IP}/FUZZ", "wordlist": "/usr/share/seclists/../../etc/passwd"})]:
        seen, ex, lo, so = _both(monkeypatch, tool, inp)
        assert lo.get("ran") is False and so.get("ran") is False and not seen and not ex
        assert lo["error"].split(":")[0] == so["error"].split(":")[0]


def test_sandbox_wordlist_validated_against_manifest():
    assert toolbelt.resolve_wordlist(toolbelt.DEFAULT_WORDLIST, sandbox=True) == toolbelt.DEFAULT_WORDLIST
    for bad in ("/usr/share/seclists/Discovery/Web-Content/other.txt", "/etc/passwd", "relative.txt",
                "/usr/share/seclists//Discovery/Web-Content/common.txt", "x:KEYWORD"):
        with pytest.raises(ValueError):
            toolbelt.resolve_wordlist(bad, sandbox=True)


def test_sandbox_never_starts_host_pin_proxy_or_capture(monkeypatch):
    seen, ex, lo, so = _both(monkeypatch, "content_discovery", {"url": "http://web.lab/FUZZ"},
                             {"_resolver": lambda h: [IP], "graph_capture": True,
                              "scope_rules": RULES + [{"type": "domain", "value": "web.lab", "mode": "allow"}]})
    assert ex and "-x" not in ex[0]["argv"] and "-o" not in ex[0]["argv"]          # proxy host không tới được sandbox; gateway ép
    assert "-x" in seen[0][0]                                                         # local vẫn ghim qua PinProxy
    assert "_raw_json" not in so


def test_nuclei_same_flags_in_sandbox_with_u_instead_of_l(monkeypatch):
    from scanner.crawler import nuclei_runner as nr
    line = json.dumps({"template-id": "t1", "info": {"name": "n", "severity": "high"}, "matched-at": f"http://{IP}/"})
    b, c = sandbox(FakeRunner(lambda argv: (line + "\n", "", 0)))
    t = toolbelt.get_tool("web_vuln_scan")
    out = run_(t.runner({"targets": [f"http://{IP}/"], "severities": ["high"], "timeout": 120, "rate_limit": 10}, _ctx(b)))
    assert out["finding_count"] == 1 and out["ran"]
    argv = c.execed[0]["argv"]
    local = nr.build_command("F", ["high"], [], False, 10, capture_traffic=True,
                             exclude_tags=sorted(toolbelt.DANGEROUS_NUCLEI_TAGS), safe_net=True, proxy=None)
    i = local.index("-l")
    assert argv == local[:i] + ["-u", f"http://{IP}/"] + local[i + 2:]


def _http_pair(monkeypatch, tool, inp, handler):
    seen = []

    def local_handler(req):
        seen.append((req.method, str(req.url), req.headers.get("user-agent"), req.content.decode()))
        return handler(req)
    monkeypatch.setattr("scanner.pentest.traffic.record", lambda **k: "tid")
    lo = run_(toolbelt.get_tool(tool).runner(dict(inp), _ctx(eb.LocalBackend(), _transport=httpx.MockTransport(local_handler))))

    def responder(argv):
        assert argv == ["python3", "-m", "vg_http"]   # F2: request đi qua stdin, KHÔNG qua argv
        req = json.loads(runner.last_stdin)
        r = handler(httpx.Request(req["method"], req["url"], headers=req["headers"], content=(req["body"] or "").encode()))
        return json.dumps({"status": r.status_code, "headers": dict(r.headers), "body": r.text,
                           "body_truncated": False, "elapsed_ms": 1}), "", 0
    runner = FakeRunner(responder)
    b, c = sandbox(runner)
    so = run_(toolbelt.get_tool(tool).runner(dict(inp), _ctx(b)))
    return seen, c, lo, so


def test_http_probe_parity_including_redirect_and_scope_block(monkeypatch):
    def handler(req):
        if str(req.url).endswith("/start"):
            return httpx.Response(302, headers={"location": "http://evil.example/x"})
        return httpx.Response(200, text="<title>Hi</title>ok")
    seen, c, lo, so = _http_pair(monkeypatch, "http_probe", {"url": f"http://{IP}/start"}, handler)
    assert "redirect_blocked" in lo and "redirect_blocked" in so            # hop ngoài scope bị API chặn ở cả hai backend
    assert lo["status_code"] == so["status_code"] == 302 and lo["final_url"] == so["final_url"]
    assert len(c.execed) == 1 and len(seen) == 1                            # KHÔNG có request thứ hai tới evil.example
    seen, c, lo, so = _http_pair(monkeypatch, "http_probe", {"url": f"http://{IP}/"}, handler)
    for k in ("status_code", "final_url", "title", "body_preview", "content_length"):
        assert lo[k] == so[k], k
    assert so["title"] == "Hi"


def test_active_http_parity(monkeypatch):
    handler = lambda req: httpx.Response(201, text="made")   # noqa: E731
    inp = {"url": f"http://{IP}/api", "method": "POST", "body": "a=1", "headers": [{"name": "X-T", "value": "1"}]}
    seen, c, lo, so = _http_pair(monkeypatch, "active_http", inp, handler)
    for k in ("status_code", "body_preview", "ran"):
        assert lo[k] == so[k]
    sent = json.loads(c.execed[0]["stdin"])
    assert (sent["method"], sent["url"], sent["body"]) == (seen[0][0], seen[0][1], seen[0][3])
    assert sent["headers"]["X-T"] == "1"


def test_active_http_without_scope_rules_refused_on_both(monkeypatch):
    b, c = sandbox()
    for ctx in ({"backend": eb.LocalBackend()}, {"backend": b}):
        r = run_(toolbelt.get_tool("active_http").runner({"url": f"http://{IP}/", "method": "POST"}, ctx))
        assert r["ran"] is False
    assert not c.execed


def test_http_sandbox_error_paths():
    b, c = sandbox(FakeRunner(lambda argv: (json.dumps({"error": "ConnectError: boom"}), "", 1)))
    r = run_(b.http(eb.HttpSpec("GET", "http://x/")))
    assert "boom" in r["error"]
    b, c = sandbox(FakeRunner(lambda argv: ("not json", "", 0)))
    assert "error" in run_(b.http(eb.HttpSpec("GET", "http://x/")))


# ───────────────────────── agent: gating/redaction/kill giống nhau ở cả hai backend ─────────────────────────
def _drive_agent(monkeypatch, backend_factory, turns):
    import api.services.ai_config as ai
    monkeypatch.setattr(ai, "load_config", lambda: {})
    monkeypatch.setattr(agent_mod, "WATCHDOG_SECONDS", 0.05)
    monkeypatch.setattr(toolbelt.shutil, "which", lambda n: "/bin/" + n)
    db = SessionLocal()
    try:
        eng = make_engagement(db, RULES + [{"type": "cidr", "value": "10.1.0.0/24", "mode": "deny"}])
        run = make_run(db, eng)
        eid, rid = eng.id, run.id
    finally:
        db.close()
    holder = {}

    def bf(engagement_id, run_id, *a, **k):
        holder["b"] = backend_factory(engagement_id, run_id)
        return holder["b"]
    monkeypatch.setattr(eb, "backend_for", bf)
    drv = ScriptedDriver(turns)
    run_(asyncio.wait_for(PentestAgent(rid, driver_factory=lambda cfg: drv).run(), 30))
    db = SessionLocal()
    try:
        steps = [(s.tool_name, s.outcome, s.output) for s in
                 db.query(AgentStep).filter(AgentStep.run_id == rid).order_by(AgentStep.step_number).all()]
        status = db.query(type(run)).filter_by(id=rid).first().status
    finally:
        db.close()
    return holder["b"], steps, status, drv


def test_agent_parity_scope_gating_redaction_and_sandbox_cleanup(monkeypatch):
    LEAK = "10.200.0.77"        # IP ngoài scope xuất hiện trong output tool → redaction phải che ở CẢ HAI backend
    turns = [[{"name": "port_scan", "input": {"host": IP}},
              {"name": "port_scan", "input": {"host": "10.9.9.9"}},       # ngoài scope → chặn trước khi chạy
              {"name": "sqlmap", "input": {"url": f"http://{IP}/?id=1"}}],  # DESTRUCTIVE → cần duyệt, không tự chạy
             []]
    out = f"22/tcp open ssh via {LEAK}\n"

    async def fake(argv, timeout, run_id=None):
        return {"ran": True, "returncode": 0, "stdout": out, "stderr": ""}
    monkeypatch.setattr(toolbelt, "_run_argv", fake)
    monkeypatch.setattr(policy, "degraded_mode", lambda: False)

    def mk_local(eid, rid):
        return eb.LocalBackend()
    created = {}

    def mk_sbx(eid, rid):
        cl = FakeRunner(lambda argv: (out, "", 0))
        created["c"] = cl
        return eb.SandboxBackend(cl, run_id=rid, engagement_id=eid, other_active_runs=lambda e, r: 0, poll_s=0.001)

    turns[0].pop()   # sqlmap cần duyệt (sẽ treo chờ người) → bỏ khỏi run; kiểm needs_approval bằng decide_action ở cuối
    _, steps_l, st_l, _ = _drive_agent(monkeypatch, mk_local, turns)
    sb, steps_s, st_s, _ = _drive_agent(monkeypatch, mk_sbx, [list(t) if t else t for t in turns])
    assert [(n, o) for n, o, _ in steps_l] == [(n, o) for n, o, _ in steps_s]
    assert ("port_scan", "blocked_scope") in [(n, o) for n, o, _ in steps_s]
    for _, o, text in steps_l + steps_s:
        if o == "executed":
            assert "22/tcp" in text
    assert st_l == st_s == RunStatus.COMPLETED
    c = created["c"]
    assert any(x[0] == "exec" for x in c.calls)                                   # tool thật đã chạy trong sandbox
    assert ("delete_sandbox", sb.run_id) in c.calls and ("delete_network", sb.engagement_id) in c.calls   # dọn cuối run
    assert decide_action(toolbelt.get_tool("sqlmap"), {"url": f"http://{IP}/?id=1"}, M, RULES, sandbox=True)[0] == "needs_approval"


def test_agent_failing_ownership_never_runs_tools(monkeypatch):
    called = []

    async def fake(argv, timeout, run_id=None):
        called.append(argv)
        return {"ran": True, "returncode": 0, "stdout": "", "stderr": ""}
    monkeypatch.setattr(toolbelt, "_run_argv", fake)
    c = FakeRunner()
    mk = lambda eid, rid: eb.SandboxBackend(c, run_id=rid, engagement_id="NOT-MINE", poll_s=0.001)   # noqa: E731
    _, steps, status, _ = _drive_agent(monkeypatch, mk, [[{"name": "port_scan", "input": {"host": IP}}], []])
    assert status == RunStatus.FAILED and c.calls == [] and not called            # fail closed, không rơi về local


def test_agent_stop_kills_sandbox_exec(monkeypatch):
    c = FakeRunner()
    b = eb.SandboxBackend(c, run_id="rk", engagement_id="ek", owner_lookup=lambda r: "ek", poll_s=0.001)
    a = PentestAgent("rk")
    a._backend = b
    from scanner.pentest.procs import REGISTRY

    async def noop(*x, **k):
        return 0
    monkeypatch.setattr(REGISTRY, "kill_all", noop)
    monkeypatch.setattr(agent_mod, "SessionLocal", lambda: type("D", (), {
        "query": lambda s, *a: type("Q", (), {"filter": lambda s, *a: type("F", (), {"first": lambda s: None, "all": lambda s: []})()})(),
        "commit": lambda s: None, "rollback": lambda s: None, "close": lambda s: None})())
    run_(a._trigger_stop("stopped"))
    assert ("kill", "rk") in c.calls


def test_local_backend_kill_run_uses_registry(monkeypatch):
    from scanner.pentest.procs import REGISTRY
    got = []

    async def fake(rid, grace=None):
        got.append(rid)
        return 2
    monkeypatch.setattr(REGISTRY, "kill_all", fake)
    assert run_(eb.LocalBackend().kill_run("rz")) == 2 and got == ["rz"]


def test_start_run_503_when_sandbox_required_but_unconfigured(monkeypatch):
    from api.auth_models import UserRole
    from tests._authutil import bearer, login, make_user, new_client
    email, _ = make_user(UserRole.ADMIN)
    c = new_client()
    h = bearer(login(c, email))
    db = SessionLocal()
    try:
        eid = make_engagement(db, RULES).id
    finally:
        db.close()
    monkeypatch.setattr(pentest_settings, "worker_mode", "worker")      # không chạy agent nền thật
    monkeypatch.setattr(pentest_settings, "require_sandbox", "true")
    monkeypatch.setattr(pentest_settings, "runner_token", "")
    r = c.post(f"/api/pentest/engagements/{eid}/runs", headers=h, json={"goal": "g"})
    assert r.status_code == 503, r.text
    monkeypatch.setattr(pentest_settings, "runner_token", "t" * 40)
    assert c.post(f"/api/pentest/engagements/{eid}/runs", headers=h, json={"goal": "g"}).status_code == 201


def test_vg_http_accepts_request_via_argv_b64(capsys):
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location("vg_http_t", Path(__file__).resolve().parent.parent / "docker" / "pentest-runner" / "vg_http.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    enc = base64.b64encode(json.dumps({"method": "TRACE", "url": "http://x/"}).encode()).decode()
    assert m.main(["--req-b64", enc]) == 1                      # đọc được request → bị từ chối vì method, không phải lỗi giải mã
    assert "method not allowed" in capsys.readouterr().out
    assert m.main(["--req-b64", "!!notb64"]) == 1


def test_http_credentials_go_via_stdin_not_argv():
    """F2: header credential không bao giờ nằm trong argv (→ /proc/*/cmdline của sandbox)."""
    secret = "Bearer PR83-SECRET-xyz"
    runner = FakeRunner(lambda argv: (json.dumps({"status": 200, "headers": {}, "body": "ok"}), "", 0))
    b, _ = sandbox(runner)
    run_(b.http(eb.HttpSpec(method="GET", url=f"http://{IP}/x", headers=[("Authorization", secret)], body=None, timeout=5)))
    ex = runner.execed[-1]
    assert secret not in json.dumps(ex["argv"]) and "--req-b64" not in ex["argv"]
    assert json.loads(ex["stdin"])["headers"]["Authorization"] == secret
