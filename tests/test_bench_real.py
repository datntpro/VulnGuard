"""P2-15b: LLM thật cho bench — OFFLINE (relay + upstream giả trên loopback, không Docker, không mạng, không LLM)."""
import asyncio
import http.client
import importlib.util
import io
import json
import os
import tarfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from eval.bench import srccache
from eval.harness import bench, bench_compare, budget, capability as C, inproc, prices, runner
from tests.pentest_fakes import ScriptedDriver

ROOT = os.path.join(os.path.dirname(__file__), "..")
TOKEN = "tok-15b"
OPUS, SONNET, HAIKU = "claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5"
QWEN = "qwen2.5:7b"


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ───────────── relay: allowlist nhiều model / provider ollama ─────────────
class _Up(BaseHTTPRequestHandler):
    seen = []
    reply = None

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        _Up.seen.append((self.path, dict(self.headers), body))
        status, out = _Up.reply or (200, b"{}")
        self.send_response(status)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


def _anthropic_reply(model, tin=1000, tout=100):
    return (200, json.dumps({"model": model, "usage": {"input_tokens": tin, "output_tokens": tout}}).encode())


def _start_relay(monkeypatch, provider, **env):
    up = HTTPServer(("127.0.0.1", 0), _Up)
    threading.Thread(target=up.serve_forever, daemon=True).start()
    base = {"RELAY_UPSTREAM_HOST": "127.0.0.1", "RELAY_UPSTREAM_PORT": str(up.server_port), "RELAY_UPSTREAM_TLS": "0",
            "RELAY_TOKEN": TOKEN, "RELAY_PROVIDER": provider, "RELAY_BUDGET_USD": "1.0"}
    if provider == "anthropic":
        base["ANTHROPIC_API_KEY"] = "sk-real-key"
    for k in ("RELAY_MODEL", "RELAY_MODELS", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    for k, v in {**base, **env}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.syspath_prepend(os.path.join(ROOT, "eval/harness"))
    spec = importlib.util.spec_from_file_location(f"relay_{provider}", os.path.join(ROOT, "eval/lab/llm-relay/relay.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m.LOG = os.devnull
    from http.server import HTTPServer as H
    srv = H(("127.0.0.1", 0), m.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _Up.seen.clear()
    _Up.reply = None
    return m, srv, up


@pytest.fixture
def multi(monkeypatch):
    m, srv, up = _start_relay(monkeypatch, "anthropic", RELAY_MODELS=f"{OPUS},{HAIKU}")
    yield srv.server_port
    srv.shutdown()
    up.shutdown()


@pytest.fixture
def ollama(monkeypatch):
    m, srv, up = _start_relay(monkeypatch, "ollama", RELAY_MODELS=QWEN)
    yield srv.server_port
    srv.shutdown()
    up.shutdown()


def _req(port, method, path, body=b"{}", headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request(method, path, body=body, headers={"Content-Type": "application/json", **(headers or {})})
    r = c.getresponse()
    return r.status, r.read()


def _msg(port, model, **kw):
    body = {"model": model, "max_tokens": 8000, "messages": [], **kw}
    return _req(port, "POST", "/v1/messages", json.dumps(body).encode(), {"x-api-key": TOKEN, "anthropic-version": "2023-06-01"})


def _meter(port):
    return json.loads(_req(port, "GET", "/_meter", headers={"x-api-key": TOKEN})[1])


def test_relay_models_allowlist_allows_each_listed_model_and_refuses_others(multi):
    _Up.reply = _anthropic_reply(OPUS)
    assert _msg(multi, OPUS)[0] == 200
    _Up.reply = _anthropic_reply(HAIKU)
    assert _msg(multi, HAIKU)[0] == 200
    n = len(_Up.seen)
    assert _msg(multi, SONNET)[0] == 400                      # hợp lệ về giá nhưng KHÔNG nằm trong allowlist của run
    assert _msg(multi, "claude-fable-5-2")[0] == 400
    assert len(_Up.seen) == n                                 # không có gì tới upstream


def test_relay_meter_is_one_usd_clock_shared_across_models(multi):
    _Up.reply = _anthropic_reply(OPUS)
    _msg(multi, OPUS)
    _Up.reply = _anthropic_reply(HAIKU)
    _msg(multi, HAIKU)
    m = _meter(multi)
    assert m["calls"] == 2 and m["usd"] == pytest.approx(prices.call_usd(OPUS, 1000, 100) + prices.call_usd(HAIKU, 1000, 100))
    assert m["tokens_in"] == 2000 and m["tokens_out"] == 200


def test_relay_shared_cap_stops_all_models(monkeypatch):
    m, srv, up = _start_relay(monkeypatch, "anthropic", RELAY_MODELS=f"{OPUS},{HAIKU}", RELAY_BUDGET_USD="0.01")
    try:
        _Up.reply = _anthropic_reply(OPUS)                    # 1000 in + 100 out ≈ 0.006 USD
        codes = [_msg(srv.server_port, OPUS)[0] for _ in range(3)]
        assert codes[-1] == 402                               # trần chạm bằng model này...
        assert _msg(srv.server_port, HAIKU)[0] == 402         # ...thì model kia cũng bị chặn
    finally:
        srv.shutdown()
        up.shutdown()


def test_relay_refuses_when_any_listed_model_has_no_price(monkeypatch):
    m, srv, up = _start_relay(monkeypatch, "anthropic", RELAY_MODELS=f"{OPUS},claude-future-9")
    try:
        _Up.reply = _anthropic_reply(OPUS)
        assert _msg(srv.server_port, OPUS)[0] == 503 and not _Up.seen          # fail closed: một model chưa có giá ⇒ cả relay từ chối
    finally:
        srv.shutdown()
        up.shutdown()


def test_relay_single_model_env_still_works(monkeypatch):
    m, srv, up = _start_relay(monkeypatch, "anthropic", RELAY_MODEL=OPUS)
    try:
        _Up.reply = _anthropic_reply(OPUS)
        assert _msg(srv.server_port, OPUS)[0] == 200 and _msg(srv.server_port, HAIKU)[0] == 400
    finally:
        srv.shutdown()
        up.shutdown()


def test_relay_startup_check_is_fail_closed():
    src = open(os.path.join(ROOT, "eval/lab/llm-relay/relay.py")).read()
    assert "prices.require_known(_m)" in src and "SystemExit" in src            # model chưa có giá ⇒ tiến trình không khởi động


def _chat(port, model=QWEN, token=TOKEN, **kw):
    body = {"model": model, "messages": [{"role": "user", "content": "hi"}], "max_completion_tokens": 8000, **kw}
    return _req(port, "POST", "/v1/chat/completions", json.dumps(body).encode(), {"Authorization": f"Bearer {token}"})


def test_ollama_relay_forwards_counts_tokens_zero_usd(ollama):
    _Up.reply = (200, json.dumps({"choices": [], "usage": {"prompt_tokens": 321, "completion_tokens": 45}}).encode())
    assert _chat(ollama)[0] == 200
    path, hdrs, body = _Up.seen[0]
    assert path == "/v1/chat/completions" and json.loads(body)["max_tokens"] == 8000 and "max_completion_tokens" not in json.loads(body)
    assert not any(k.lower() in ("authorization", "x-api-key") for k in hdrs)      # token của run không lọt tới Ollama
    m = _meter(ollama)
    assert m["usd"] == 0 and m["calls"] == 1 and m["tokens_in"] == 321 and m["tokens_out"] == 45 and m["provider"] == "ollama"


def test_ollama_relay_policy(ollama):
    assert _chat(ollama, token="bad")[0] == 401
    assert _chat(ollama, model="llama3:8b")[0] == 400
    assert _chat(ollama, stream=True)[0] == 400
    assert _chat(ollama, max_completion_tokens=128000)[0] == 400
    assert _req(ollama, "POST", "/v1/messages", b"{}", {"x-api-key": TOKEN})[0] == 404       # đường Anthropic không tồn tại ở relay local
    assert not _Up.seen


def test_ollama_relay_never_forwards_a_real_key(monkeypatch):
    m, srv, up = _start_relay(monkeypatch, "ollama", RELAY_MODELS=QWEN, ANTHROPIC_API_KEY="sk-must-not-leak")
    try:
        _Up.reply = (200, json.dumps({"usage": {"prompt_tokens": 1, "completion_tokens": 1}}).encode())
        _chat(srv.server_port)
        assert all("sk-must-not-leak" not in str(v) for _, h, _b in _Up.seen for v in h.values())
    finally:
        srv.shutdown()
        up.shutdown()


# ───────────── SharedBudget ─────────────
def _drv(model=OPUS, n=5):
    d = ScriptedDriver([[{"name": "http_probe", "input": {"url": "http://x.lab/"}}]] * n)
    d.model = model
    return d


def _turn(d):
    async def go():
        return d.parse(await d.create("s", [], []))
    return _run(go())


def test_shared_budget_two_drivers_stop_together():
    sb = budget.SharedBudget(0.0005)                           # 10 in + 5 out ≈ 0.00014 USD / lượt (opus)
    a, b = budget.BudgetedDriver(_drv(OPUS), sb), budget.BudgetedDriver(_drv(SONNET), sb)
    for _ in range(10):
        if sb.exhausted:
            break
        _turn(a)
        if not sb.exhausted:
            _turn(b)
    assert sb.exhausted and a.budget_exhausted and b.budget_exhausted
    with pytest.raises(RuntimeError, match="budget"):
        _run(b.create("s", [], []))                            # driver KIA cũng không gọi thêm
    assert a.calls + b.calls == sb.calls and a.usage()["usd"] == b.usage()["usd"] == sb.usage()["usd"]


def test_budgeted_driver_float_signature_and_keyword_still_work():
    d = budget.BudgetedDriver(_drv(), 1.0)
    assert d.budget_usd == 1.0 and not d.budget_exhausted
    d2 = budget.BudgetedDriver(_drv(), budget_usd=0.0001)
    _turn(d2)
    assert d2.budget_exhausted


def test_local_budgeted_driver_has_no_price_table_but_counts_tokens():
    inner = ScriptedDriver([[{"name": "http_probe", "input": {"url": "http://x.lab/"}}]] * 3)
    inner.model = QWEN
    with pytest.raises(prices.UnknownModel):
        budget.BudgetedDriver(inner, 1.0)                      # Anthropic: model lạ ⇒ từ chối (không đổi)
    d = budget.BudgetedDriver(inner, 1.0, local=True)
    _turn(d)
    u = d.usage()
    assert u["usd"] == 0 and u["tokens_in"] > 0 and u["llm_calls"] == 1 and not d.budget_exhausted


# ───────────── inproc: model theo vai ─────────────
CAP = {"model": OPUS, "models": [OPUS, HAIKU], "role_models": {"planner": OPUS, "executor": SONNET, "summarizer": HAIKU},
       "provider": "anthropic", "budget_usd": 3.0, "relay_url": "http://127.0.0.1:1", "relay_token": TOKEN}


def test_pick_model_only_inside_allowlist():
    assert inproc.pick_model(CAP, {"_pentest_role": "summarizer"}) == HAIKU
    assert inproc.pick_model(CAP, {"_pentest_role": "executor"}) == OPUS            # sonnet ngoài allowlist ⇒ model mặc định (không bị relay từ chối)
    assert inproc.pick_model(CAP, {"_pentest_model": "claude-future-9"}) == OPUS
    assert inproc.pick_model(CAP, {"_pentest_model": HAIKU}) == HAIKU
    assert inproc.pick_model(CAP, {}) == OPUS


def test_graph_roles_build_drivers_on_one_shared_budget():
    cap = {**CAP, "models": [OPUS, SONNET, HAIKU]}
    f = inproc._capability_factory(cap)
    p, e, s = f({"_pentest_role": "planner"}), f({"_pentest_role": "executor"}), f({"_pentest_role": "summarizer"})
    assert (p.model, e.model, s.model) == (OPUS, SONNET, HAIKU)
    assert p.shared is e.shared is s.shared is f.budget and f.budget.budget_usd == 3.0
    assert f({"_pentest_role": "executor"}) is e                                      # dùng lại driver theo model
    assert f.roles == ["planner", "executor", "summarizer", "executor"]


def test_ollama_factory_uses_openai_client_local_budget():
    cap = {"model": QWEN, "models": [QWEN], "role_models": {"planner": QWEN, "executor": QWEN, "summarizer": QWEN}, "provider": "ollama",
           "budget_usd": 1.0, "relay_url": "http://172.31.252.30:8080", "relay_token": TOKEN}
    f = inproc._capability_factory(cap)
    d = f({"_pentest_role": "planner"})
    assert d.family == "openai" and d.model == QWEN and str(d.client.base_url).rstrip("/") == "http://172.31.252.30:8080/v1"
    assert f({"_pentest_role": "summarizer"}) is d                                    # mọi vai → cùng một model/driver


# ───────────── capability.resolve_profile ─────────────
def test_resolve_profile_roles_and_allowlist():
    g = C.resolve_profile("opus", "graph")
    assert g["models"] == [OPUS, SONNET, HAIKU] and g["role_models"]["executor"] == SONNET and g["provider"] == "anthropic"
    l = C.resolve_profile("opus", "legacy")
    assert l["models"] == [OPUS, HAIKU] and l["model"] == OPUS                       # legacy: planner + summarizer (nén context)
    assert C.resolve_profile("sonnet", "graph")["models"] == [SONNET, HAIKU]
    o = C.resolve_profile("ollama", "graph")
    assert o["provider"] == "ollama" and o["models"] == [C.OLLAMA_MODEL] and set(o["role_models"].values()) == {C.OLLAMA_MODEL}
    assert C.resolve_profile("ollama", "legacy", "llama3.2:3b")["models"] == ["llama3.2:3b"]
    with pytest.raises(ValueError):
        C.resolve_profile("nope", "legacy")
    with pytest.raises(ValueError):
        C.resolve_profile("opus", "x")


def test_ollama_default_model_and_local_config_are_lab_safe():
    assert C.OLLAMA_MODEL == "qwen2.5:7b"
    import yaml
    cfg = yaml.safe_load(open(runner.COMPOSE_FILE))
    C.assert_capability_safe(cfg)                                                    # thêm RELAY_MODELS/RELAY_PROVIDER không phá bất biến
    env = cfg["services"]["llm-relay"]["environment"]
    assert {"RELAY_MODELS", "RELAY_PROVIDER"} <= set(env) and "extra_hosts" not in cfg["services"]["llm-relay"]
    assert "ANTHROPIC_API_KEY" not in (cfg["services"]["vg-under-test"].get("environment") or {})


# ───────────── bench real (fake relay/attempt) ─────────────
def _fake_attempt(usd, flag=True):
    def f(task, profile, arch, budget_usd):
        f.calls.append((task.id, round(budget_usd, 4)))
        return bench._attempt(flag_captured=flag and task.suite == "stub", usd=usd, tokens_billed=1000, steps=3, safety={})
    f.calls = []
    return f


def test_bench_real_splits_budget_per_attempt_and_fills_report(monkeypatch):
    monkeypatch.setattr(bench, "_git_sha", lambda: "x")
    fake = _fake_attempt(0.5)
    rep = bench.run_bench("core", "graph", "opus", k=1, budget_usd=12.0, driver_mode="real", real_attempt_fn=fake)
    n = len(rep["tasks"])
    assert n >= 3 and fake.calls[0][1] == pytest.approx(12.0 / n, abs=1e-3)           # chia đều phần còn lại cho các attempt còn lại
    assert rep["driver_mode"] == "real" and rep["arch"] == "graph" and rep["provider"] == "anthropic"
    assert rep["models"] == {"planner": OPUS, "executor": SONNET, "summarizer": HAIKU}
    assert bench.validate_report(rep) == []
    assert rep["totals"]["usd"] == pytest.approx(0.5 * n) and rep["totals"]["flags"] == 1


def test_bench_real_stops_arm_at_cap_and_uses_relay_meter(monkeypatch):
    monkeypatch.setattr(bench, "_git_sha", lambda: "x")
    spent = {"usd": 0.0}
    calls = []

    def real(task, profile, arch, budget_usd):
        calls.append(budget_usd)
        spent["usd"] += 2.0
        return bench._attempt(usd=2.0, safety={})
    rep = bench.run_bench("core", "legacy", "opus", budget_usd=5.0, driver_mode="real", real_attempt_fn=real, usd_fn=lambda: spent["usd"])
    skipped = [a for t in rep["tasks"] for a in t["attempts"] if a.get("skipped")]
    assert skipped and all(a["error"] == "hết ngân sách của arm" for a in skipped)
    assert len(calls) < len(rep["tasks"])                                             # arm dừng khi chạm trần
    assert spent["usd"] <= 5.0 + 2.0                                                  # vượt tối đa một attempt (relay chặn cứng ở trần)
    assert rep["totals"]["usd"] == pytest.approx(spent["usd"])                        # usd báo cáo = relay meter


def test_bench_real_budget_is_clamped_to_25(monkeypatch):
    monkeypatch.setattr(bench, "_git_sha", lambda: "x")
    rep = bench.run_bench("stub", "legacy", "opus", budget_usd=1000.0, driver_mode="real", real_attempt_fn=_fake_attempt(0.1))
    assert rep["budget_usd"] == 25.0


def test_bench_real_ollama_ignores_usd_and_runs_every_task(monkeypatch):
    monkeypatch.setattr(bench, "_git_sha", lambda: "x")
    fake = _fake_attempt(0.0)
    rep = bench.run_bench("core", "graph", "opus", driver_mode="real", provider="ollama", real_attempt_fn=fake)
    assert len(fake.calls) == len(rep["tasks"]) and all(b == bench.OLLAMA_PER_TASK_USD for _, b in fake.calls)
    assert rep["provider"] == "ollama" and rep["model_profile"] == "ollama" and set(rep["models"].values()) == {C.OLLAMA_MODEL}


def test_attempt_from_result_maps_tokens_and_safety():
    t = bench.BenchTask("stub-flag", "stub", "plumbing", None)
    res = {"status": "ok", "flag_captured": True, "steps": 4, "tokens_in": 100, "tokens_out": 50, "tokens_cache_read": 1000, "tokens_cache_write": 200,
           "usd": 0.5, "wall_s": 3.0, "safety": {"scope_violations": 0, "unapproved_intrusive": 1, "tripwire_hits": 2, "capture_violations": 0,
                                                 "dns_violations": 1}, "relay_broken": "", "llm_calls": 3}
    a = bench.attempt_from_result(t, res)
    assert a["tokens_billed"] == int(100 + 50 + 1.25 * 200 + 0.1 * 1000) and a["flag_captured"] and a["usd"] == 0.5
    assert a["safety"] == {"scope_violations": 3, "unapproved_intrusive": 1, "injection_escape": 0, "relay_broken": 0}
    inj = bench.attempt_from_result(bench.BenchTask("i", "injection", "p", None), {**res, "relay_broken": "x"})
    assert inj["safety"]["injection_escape"] == 4 and inj["safety"]["relay_broken"] == 1 and inj["blocked"] is False
    ok = bench.attempt_from_result(bench.BenchTask("i", "injection", "p", None), {"status": "ok", "safety": {}})
    assert ok["blocked"] is True
    err = bench.attempt_from_result(t, {"status": "error", "failures": ["0 lượt gọi LLM thành công qua relay"]})
    assert err["error"] and bench._task_success(t, err) is False


def test_check_safety_fails_on_real_report_with_safety_metric(tmp_path, monkeypatch):
    monkeypatch.setattr(bench, "_git_sha", lambda: "x")

    def bad(task, profile, arch, budget_usd):
        return bench._attempt(safety={"scope_violations": 1})
    rep = bench.run_bench("stub", "legacy", "opus", budget_usd=5.0, driver_mode="real", real_attempt_fn=bad)
    bench.write_report(rep, str(tmp_path))
    assert bench.check_safety(str(tmp_path)) == 1
    good = bench.run_bench("stub", "legacy", "opus", budget_usd=5.0, driver_mode="real", real_attempt_fn=_fake_attempt(0.1))
    ok_dir = tmp_path / "ok"
    bench.write_report(good, str(ok_dir))
    assert bench.check_safety(str(ok_dir)) == 0                                       # capability (cờ/thành công) là thông tin, không phải cổng


def test_bench_compare_append_trend(tmp_path, monkeypatch):
    monkeypatch.setattr(bench, "_git_sha", lambda: "x")
    paths = []
    for arch in ("legacy", "graph"):
        rep = bench.run_bench("stub", arch, "opus", budget_usd=5.0, driver_mode="real", real_attempt_fn=_fake_attempt(0.1))
        paths.append(bench.write_report(rep, str(tmp_path / arch)))
    trend = str(tmp_path / "trend" / "bench-real.jsonl")
    assert bench_compare.main(["--legacy", paths[0], "--graph", paths[1], "--append-trend", trend]) == 0
    assert bench_compare.main(["--legacy", paths[0], "--graph", paths[1], "--append-trend", trend]) == 0
    assert len(open(trend).read().splitlines()) == 4                                  # tăng dần qua các lần chạy


# ───────────── srccache: giải nén tối thiểu (Defender/AV) ─────────────
TOP = "xbow-validation-benchmarks-0123"


def _tar(entries):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, kind, data in entries:
            ti = tarfile.TarInfo(name)
            if kind == "dir":
                ti.type = tarfile.DIRTYPE
                t.addfile(ti)
            elif kind == "file":
                ti.size = len(data)
                t.addfile(ti, io.BytesIO(data))
            elif kind == "sym":
                ti.type = tarfile.SYMTYPE
                ti.linkname = data
                t.addfile(ti)
    buf.seek(0)
    return buf


def _entries():
    return [(TOP, "dir", b""), (f"{TOP}/README.md", "file", b"x"),
            (f"{TOP}/benchmarks/XBEN-004-24", "dir", b""), (f"{TOP}/benchmarks/XBEN-004-24/docker-compose.yml", "file", b"services: {}"),
            (f"{TOP}/benchmarks/XBEN-004-24/app/main.py", "file", b"print(1)"),
            (f"{TOP}/benchmarks/XBEN-004-24/link", "sym", "/etc/passwd"),
            (f"{TOP}/benchmarks/XBEN-0040-24/docker-compose.yml", "file", b"other"),          # tiền tố giống nhưng KHÁC challenge
            (f"{TOP}/benchmarks/XBEN-099-24/docker-compose.yml", "file", b"not selected"),
            (f"{TOP}/xben-benchmark-results/XBEN-022-24/deliverables/comprehensive_security_assessment_report.md", "file", b"payloads"),
            (f"{TOP}/benchmarks/XBEN-005-24/docker-compose.yml", "file", b"second")]


def test_extractor_writes_only_selected_challenge_dirs(tmp_path):
    with tarfile.open(fileobj=_tar(_entries()), mode="r|gz") as t:
        written = srccache.extract_selected(t, TOP, ["benchmarks/XBEN-004-24/", "benchmarks/XBEN-005-24/"], str(tmp_path))
    on_disk = sorted(os.path.relpath(os.path.join(dp, f), tmp_path) for dp, _, fs in os.walk(tmp_path) for f in fs)
    assert on_disk == sorted([f"{TOP}/benchmarks/XBEN-004-24/docker-compose.yml", f"{TOP}/benchmarks/XBEN-004-24/app/main.py",
                              f"{TOP}/benchmarks/XBEN-005-24/docker-compose.yml"])
    assert all(w.startswith(("benchmarks/XBEN-004-24", "benchmarks/XBEN-005-24")) for w in written)
    assert not os.path.exists(tmp_path / TOP / "xben-benchmark-results") and not os.path.exists(tmp_path / TOP / "README.md")
    assert not os.path.lexists(tmp_path / TOP / "benchmarks" / "XBEN-004-24" / "link")     # symlink không bao giờ được ghi
    assert not os.path.exists(tmp_path / TOP / "benchmarks" / "XBEN-0040-24")


def test_extractor_refuses_wrong_top_dir_and_traversal(tmp_path):
    with tarfile.open(fileobj=_tar([("evil-top/benchmarks/XBEN-004-24/x", "file", b"x")]), mode="r|gz") as t:
        with pytest.raises(ValueError, match="SHA ghim"):
            srccache.extract_selected(t, TOP, ["benchmarks/XBEN-004-24/"], str(tmp_path))
    with tarfile.open(fileobj=_tar([(f"{TOP}/benchmarks/XBEN-004-24/../../escape", "file", b"x")]), mode="r|gz") as t:
        with pytest.raises(ValueError, match="đường dẫn lạ"):
            srccache.extract_selected(t, TOP, ["benchmarks/XBEN-004-24/"], str(tmp_path))
    assert not (tmp_path.parent / "escape").exists()


def test_cache_dir_is_repo_local_and_always_removed(tmp_path):
    assert srccache.CACHE_ROOT.startswith(os.path.abspath(ROOT)) and "eval/lab/src-cache" in srccache.CACHE_ROOT
    assert "eval/lab/src-cache/" in open(os.path.join(ROOT, ".gitignore")).read()
    kept = None
    with pytest.raises(RuntimeError):
        with srccache.cache_dir("t_", root=str(tmp_path)) as d:
            kept = d
            open(os.path.join(d, "f"), "w").write("x")
            raise RuntimeError("boom")
    assert kept and not os.path.exists(kept)


def test_prepare_uses_selected_extraction_not_extractall():
    src = open(os.path.join(ROOT, "eval/harness/xbow.py")).read()
    assert "extractall" not in src and "extract_selected" in src and "tempfile" not in src
    apb = open(os.path.join(ROOT, "eval/bench/autopenbench/fetch.py")).read()
    assert "tempfile" not in apb and "srccache.cache_dir" in apb


# ───────────── metrics: ARP tới host được phép không phải vi phạm (false positive thấy ở lần chạy local đầu) ─────────────
def test_arp_to_allowed_host_is_not_a_capture_violation_but_other_arp_is():
    from eval.harness import metrics as M
    arp = lambda dst: {"proto": "arp", "src": "172.31.250.2", "dst": dst, "dport": None}  # noqa: E731
    allowed = ["172.31.250.61", "172.31.252.30"]
    assert M.capture_violations([arp("172.31.250.61"), arp("172.31.250.53")], allowed, [M.ANY_PORT]) == []
    assert M.capture_violations([arp("172.31.250.20")], allowed, [M.ANY_PORT]) == [arp("172.31.250.20")]      # ARP dò host ngoài scope vẫn bị bắt
    assert M.capture_violations([{"proto": "tcp", "dst": "172.31.250.20", "dport": 80}], allowed, [M.ANY_PORT])
