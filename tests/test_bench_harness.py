"""P2-15a: harness bench — OFFLINE (không Docker, không LLM, không mạng; docker/lab được giả bằng monkeypatch)."""
import copy
import importlib.util
import ipaddress
import json
import os
import re
import threading
import urllib.request
from http.server import ThreadingHTTPServer

import pytest
import yaml

from eval.bench import isolation
from eval.bench.autopenbench import fetch
from eval.harness import bench, bench_compare, runner, xbow

ROOT = os.path.join(os.path.dirname(__file__), "..")


def _zone():
    spec = importlib.util.spec_from_file_location("dns_server_b", os.path.join(ROOT, "eval/lab/dns/dns_server.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m.ZONE


# ── selection ──
def test_selection_yamls_parse_and_are_sane():
    assert len(xbow.SELECTION) == 20
    assert len(fetch.load_selection()) >= 5
    assert len(xbow.BENCHMARKS) == 3 and set(xbow.BENCHMARKS) <= set(xbow.SELECTION)     # 3 task P1-7 vẫn nguyên
    for bid, m in xbow.SELECTION.items():
        assert re.fullmatch(r"XBEN-\d{3}-24", bid) and m["name"].endswith(".lab") and isinstance(m["core"], bool)


def test_ips_unique_in_lab_range_and_in_dns_zone():
    zone = _zone()
    rows = [(i, m["name"], m["ip"]) for i, m in xbow.SELECTION.items()] + \
           [(t["id"], t["name"], t["ip"]) for t in fetch.load_selection()] + [("stub", bench.STUB_NAME, bench.STUB_IP)]
    ips = [r[2] for r in rows]
    names = [r[1] for r in rows]
    assert len(set(ips)) == len(ips) and len(set(names)) == len(names)
    net = ipaddress.ip_network("172.31.250.0/24")
    for i, name, ip in rows:
        assert ipaddress.ip_address(ip) in net, i
        assert 61 <= int(ip.rsplit(".", 1)[1]) <= 99, i                      # dải dành cho bench (.61-.99)
        assert zone[name] == [ip], f"{i}: ZONE[{name}] != {ip}"
        assert runner._host_ok(name) and runner._host_ok(ip)
    for t in bench_ctasks():
        runner.assert_scenario_safe(__import__("eval.harness.capability", fromlist=["x"]).task_scenario(t.cap))


def bench_ctasks():
    return [t for t in bench.load_suite("full") if t.cap is not None]


def test_apb_selection_is_http_web_only_and_flags_are_randomised():
    for t in fetch.load_selection():
        assert t["upstream"]["category"] == "web_security"                  # không SSH/crypto/network (cần NET_RAW…)
        assert t["flag_static"] is False and t["flag_path"].startswith("/")
        assert t["milestones"] and runner._host_ok(t["name"])
    assert len(fetch.PINNED_SHA) == 40 and fetch.PINNED_SHA.startswith("9c4890a7")


def test_suites_core_is_subset_of_full():
    full = {t.id for t in bench.load_suite("full")}
    core = {t.id for t in bench.load_suite("core")}
    assert core and core < full
    assert {t.id for t in bench.load_suite("stub")} == {"stub-flag"} and "stub-flag" in core
    assert len(bench.load_suite("xbow")) == 20
    assert {t.id for t in bench.load_suite("xbow")} | {t.id for t in bench.load_suite("autopenbench")} | \
           {t.id for t in bench.load_suite("injection")} | {"stub-flag"} == full
    assert all(t.scenario is not None and t.expect_success for t in bench.load_suite("injection"))
    assert len(bench.load_suite("injection")) >= 9
    with pytest.raises(ValueError):
        bench.load_suite("nope")


def test_injection_suite_reuses_payload_files():
    payloads = {f[:-4] for f in os.listdir(os.path.join(ROOT, "eval/lab/targets/inscope-web/injections")) if f.endswith(".txt")}
    used = {t.scenario.id[len("injection_"):] for t in bench.load_suite("injection")}
    assert payloads <= used


# ── AutoPenBench: phần thuần ──
def test_apb_flag_injection_into_dockerfile():
    df = "FROM php:7.4-apache\nCOPY app /var/www/html\nUSER www-data\nEXPOSE 80"
    out = fetch.inject_flag_dockerfile(df, "/root/flag.txt")
    assert out.index("ARG FLAG") < out.index("USER www-data")               # chạy khi còn root
    assert "printf '%s\\n' \"$FLAG\" > /root/flag.txt" in out and "mkdir -p /root" in out
    for bad in ("/x; rm -rf /", "/a'b", "/$HOME/x"):
        with pytest.raises(ValueError):
            fetch.inject_flag_dockerfile(df, bad)
    with pytest.raises(ValueError):
        fetch.inject_flag_dockerfile("COPY a b", "/f")


def test_every_apb_task_passes_isolation_when_built_from_upstream_shape():
    up = {"build": "./in-vitro/web_security/vm0", "tty": True, "init": True, "container_name": "x", "restart": "unless-stopped",
          "networks": {"net-main_network": {"ipv4_address": "192.168.2.0"}}, "command": 'bash -c "php -S 0.0.0.0:80 && tail -f /dev/null"',
          "volumes": ["./in-vitro/web_security/vm0/flag.txt:/root/flag.txt"]}
    for t in fetch.load_selection():
        cfg = fetch.build_compose(t, up)
        assert "volumes" not in cfg["services"]["web"]                      # bind mount flag.txt của upstream KHÔNG được mang theo
        out = isolation.rewrite_and_check(cfg, t["ip"], entry="web")
        assert out["x-vg-entry-port"] == 80 and out["services"]["web"]["networks"]["lab_net"] == {"ipv4_address": t["ip"]}
        assert out["services"]["web"]["build"]["args"] == {"FLAG": "${FLAG}"}
    with pytest.raises(isolation.UnsafeCompose):                           # upstream thật (bind mount) sẽ bị từ chối nếu dùng thẳng
        isolation.assert_bench_compose_safe({"services": {"web": up}}, ["172.31.250.81"], "pre")


# ── stub-flag fixture + compose + DNS ──
def _load_stub(flag):
    spec = importlib.util.spec_from_file_location("stub_server", os.path.join(ROOT, "eval/bench/fixtures/stub-flag/server.py"))
    m = importlib.util.module_from_spec(spec)
    os.environ["FLAG"] = flag
    try:
        spec.loader.exec_module(m)
    finally:
        os.environ.pop("FLAG", None)
    return m


def test_stub_flag_server_serves_only_the_runtime_flag():
    flag = xbow.new_flag()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _load_stub(flag).H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        assert urllib.request.urlopen(base + "/flag", timeout=5).read().decode() == flag
        assert flag not in urllib.request.urlopen(base + "/", timeout=5).read().decode()
        with pytest.raises(urllib.error.HTTPError):
            urllib.request.urlopen(base + "/other", timeout=5)
    finally:
        srv.shutdown()
    empty = ThreadingHTTPServer(("127.0.0.1", 0), _load_stub("").H)        # không có cờ ⇒ không phục vụ gì (fail closed)
    threading.Thread(target=empty.serve_forever, daemon=True).start()
    try:
        with pytest.raises(urllib.error.HTTPError):
            urllib.request.urlopen(f"http://127.0.0.1:{empty.server_address[1]}/flag", timeout=5)
    finally:
        empty.shutdown()


def test_stub_flag_compose_service_is_lab_only_and_hardened():
    cap = yaml.safe_load(open(os.path.join(ROOT, "eval/lab/docker-compose.capability.yml")))
    s = cap["services"]["stub-flag"]
    assert s["profiles"] == ["capability"] and set(s["networks"]) == {"lab_net"}
    assert s["networks"]["lab_net"]["ipv4_address"] == bench.STUB_IP
    assert not s.get("ports") and not s.get("cap_add") and not s.get("privileged") and not s.get("network_mode")
    assert s["read_only"] is True and s["cap_drop"] == ["ALL"] and "@sha256:" in s["image"]
    assert all(not str(v).startswith(("/", "~")) and "docker.sock" not in str(v) for v in s["volumes"])
    merged = {"networks": yaml.safe_load(open(os.path.join(ROOT, "eval/lab/docker-compose.lab.yml")))["networks"],
              "services": {**yaml.safe_load(open(os.path.join(ROOT, "eval/lab/docker-compose.lab.yml")))["services"], "stub-flag": s}}
    merged["services"]["vg-under-test"] = {**merged["services"]["vg-under-test"],
                                          "networks": {"lab_net": {}, "llm_net": {}}}
    runner.assert_compose_safe(merged)


# ── BenchReport ──
def _report(arch="legacy", suite="stub", flags=1, tokens=1000, safety=None, tasks=2):
    ts = []
    for i in range(tasks):
        got = i < flags
        ts.append({"id": f"t{i}", "category": "web", "success_at_k": got, "expect_success": True,
                   "attempts": [bench._attempt(flag_captured=got, tokens_billed=tokens, usd=0.5, steps=3)]})
    return {"schema": 1, "suite": suite, "arch": arch, "driver_mode": "scripted", "model_profile": "opus",
            "models": {"planner": "p", "executor": "e", "summarizer": "s"}, "git_sha": "abc", "ts": "20260101-000000", "k": 1,
            "tasks": ts, "totals": bench.totals(ts), "safety": {**bench._safety(ts), **(safety or {})}}


def test_report_schema_validation():
    assert bench.validate_report(_report()) == []
    for key in bench.TOP_KEYS:
        r = _report()
        del r[key]
        assert any(key in e for e in bench.validate_report(r)), key
    r = _report()
    del r["tasks"][0]["attempts"][0]["usd"]
    assert any("usd" in e for e in bench.validate_report(r))
    r = _report()
    r["schema"] = 2
    assert bench.validate_report(r)
    r = _report()
    del r["safety"]["injection_escape"]
    assert any("injection_escape" in e for e in bench.validate_report(r))
    assert bench.validate_report([]) and bench.validate_report(_report(arch="x")) and bench.validate_report(_report(suite="s") | {"driver_mode": "?"})


def test_totals_never_divide_by_zero():
    t = bench.totals([{"id": "a", "success_at_k": False, "attempts": [bench._attempt(tokens_billed=500, usd=1.0)]}])
    assert t["tokens_per_flag"] is None and t["usd_per_flag"] is None and t["success"] == 0
    assert bench.totals([])["success_rate"] == 0.0
    t = bench.totals([{"id": "a", "success_at_k": True, "attempts": [bench._attempt(flag_captured=True, tokens_billed=500, usd=1.0)]}])
    assert t["tokens_per_flag"] == 500 and t["usd_per_flag"] == 1.0


def test_run_bench_real_is_not_wired_in_15a():
    with pytest.raises(NotImplementedError):
        bench.run_bench("stub", "legacy", "opus", driver_mode="real")
    with pytest.raises(ValueError):
        bench.run_bench("stub", "x", "opus")
    with pytest.raises(ValueError):
        bench.run_bench("stub", "legacy", "opus", task_ids=["nope"])


def test_run_bench_with_fake_attempts_builds_valid_report_and_isolates_errors(tmp_path, monkeypatch):
    monkeypatch.delenv("VG_AGENT_ARCH", raising=False)
    seen = []

    def fake(task):
        seen.append(os.environ["VG_AGENT_ARCH"])                           # arch đi tới runner.run_scenario qua env
        if task.id == "inj-boom":
            raise RuntimeError("boom")
        return bench._attempt(flag_captured=task.suite == "stub", blocked=task.suite == "injection", steps=2, safety={"scope_violations": 0})

    rep = bench.run_bench("core", "graph", "opus", attempt_fn=fake)
    assert set(seen) == {"graph"} and "VG_AGENT_ARCH" not in os.environ        # trả lại môi trường
    assert bench.validate_report(rep) == [] and rep["arch"] == "graph" and rep["driver_mode"] == "scripted"
    byid = {t["id"]: t for t in rep["tasks"]}
    assert byid["stub-flag"]["success_at_k"] is True
    path = bench.write_report(rep, str(tmp_path))
    assert path.endswith("/results/core.jsonl")
    bench.write_report(rep, str(tmp_path), ts=rep["ts"])                      # append, không ghi đè
    assert len(open(path).read().splitlines()) == 2

    def boom(task):
        raise RuntimeError("boom")
    r2 = bench.run_bench("stub", "legacy", "opus", attempt_fn=boom)
    assert r2["tasks"][0]["attempts"][0]["error"].startswith("RuntimeError") and r2["totals"]["success"] == 0


def test_write_report_refuses_invalid(tmp_path):
    r = _report()
    del r["safety"]
    with pytest.raises(ValueError):
        bench.write_report(r, str(tmp_path))


# ── chạy scripted với lab giả ──
def _fake_lab(monkeypatch, flag_holder, steps_fn, status="pass"):
    monkeypatch.setattr(bench, "start_stub", lambda f: flag_holder.append(f))
    monkeypatch.setattr(bench, "stop_stub", lambda: None)
    monkeypatch.setattr(bench, "_py_get", lambda url: flag_holder[-1])
    monkeypatch.setattr(runner, "run_scenario",
                        lambda sc: {"status": status, "failures": [], "steps": steps_fn(sc),
                                    "metrics": {"scope_violations": 0, "unapproved_intrusive": 0, "injection_escape": 0}})


def _stub_steps(sc):
    calls = [c for turn in sc.turns for c in turn]
    return [{"n": i, "tool": c["name"], "outcome": "executed", "input": c["input"],
             "output": sc.turns[0][0]["input"]["url"] if c["name"] == "http_probe" else "finding saved"} for i, c in enumerate(calls)]


def test_stub_attempt_captures_flag_from_scripted_finding(monkeypatch):
    holder = []

    def steps(sc):
        flag = holder[-1]
        return [{"n": 1, "tool": "http_probe", "outcome": "executed", "input": {"url": "http://stub-flag.lab/flag"}, "output": flag},
                {"n": 2, "tool": "report_finding", "outcome": "executed", "input": sc.turns[1][0]["input"], "output": "finding saved"}]
    _fake_lab(monkeypatch, holder, steps)
    task = bench.load_suite("stub")[0]
    a = bench.attempt_stub(task)
    assert a["flag_captured"] is True and not a["error"] and a["safety"]["scope_violations"] == 0
    sc = bench.stub_scenario(task, holder[-1])
    assert sc.turns[1][0]["input"]["evidence"].endswith(holder[-1]) and runner.scenario_lint(sc) is None
    runner.assert_scenario_safe(sc)
    assert sc.allowed_ips == [bench.STUB_IP] and sc.allowed_dns == [bench.STUB_NAME]
    assert bench.run_bench("stub", "legacy", "opus")["totals"]["success"] == 1


def test_stub_attempt_without_the_flag_is_not_a_success(monkeypatch):
    holder = []
    _fake_lab(monkeypatch, holder, lambda sc: [{"n": 1, "tool": "http_probe", "outcome": "executed", "input": {}, "output": "nothing"}])
    rep = bench.run_bench("stub", "legacy", "opus")
    assert rep["tasks"][0]["attempts"][0]["flag_captured"] is False and rep["totals"]["success"] == 0


def test_stub_flag_readback_mismatch_is_error(monkeypatch):
    holder = []
    _fake_lab(monkeypatch, holder, lambda sc: [])
    monkeypatch.setattr(bench, "_py_get", lambda url: "something-else")
    a = bench.attempt_stub(bench.load_suite("stub")[0])
    assert a["error"] and not a["flag_captured"]


def test_injection_attempt_success_means_blocked_and_safety_is_collected(monkeypatch):
    monkeypatch.setattr(runner, "run_scenario", lambda sc: {"status": "pass", "failures": [], "steps": [{"tool": "x"}],
                                                            "metrics": {"scope_violations": 0, "unapproved_intrusive": 0, "injection_escape": 0}})
    rep = bench.run_bench("injection", "legacy", "opus")
    assert rep["totals"]["success"] == rep["totals"]["tasks"] >= 9 and rep["safety"]["injection_escape"] == 0
    monkeypatch.setattr(runner, "run_scenario", lambda sc: {"status": "fail", "failures": ["injection_escape=1"], "steps": [],
                                                            "metrics": {"scope_violations": 1, "unapproved_intrusive": 0, "injection_escape": 1}})
    bad = bench.run_bench("injection", "legacy", "opus", task_ids=["injection_ignore_previous"])
    assert bad["safety"]["injection_escape"] == 1 and bad["safety"]["scope_violations"] == 1 and bad["totals"]["success"] == 0


def test_challenge_without_prepare_is_error_not_pass(tmp_path, monkeypatch):
    monkeypatch.setattr(xbow, "OUT_DIR", str(tmp_path))
    rep = bench.run_bench("xbow", "legacy", "opus", task_ids=["XBEN-004-24"])
    assert "chưa prepare" in rep["tasks"][0]["attempts"][0]["error"]


def test_challenge_attempt_brings_up_probes_root_and_always_tears_down(tmp_path, monkeypatch):
    bid = "XBEN-004-24"
    d = tmp_path / bid
    d.mkdir()
    cfg = xbow.transform_compose({"services": {"web": {"build": "./a", "ports": ["8080:80"]}}}, xbow.SELECTION[bid]["ip"])
    (d / "docker-compose.vglab.yml").write_text(yaml.safe_dump(cfg))
    flag = xbow.new_flag()
    (d / "flag.txt").write_text(flag)
    monkeypatch.setattr(xbow, "OUT_DIR", str(tmp_path))
    calls = []

    class P:
        stdout = "cid1\n"

    from eval.harness import capability as C
    monkeypatch.setattr(C, "_xbow_compose", lambda xdir, *a, **k: calls.append(a[0]) or P())
    monkeypatch.setattr(C, "live_check", lambda ids: calls.append("live"))
    monkeypatch.setattr(C, "wait_ready", lambda url, timeout_s=180: calls.append(url))
    monkeypatch.setattr(runner, "run_scenario", lambda sc: {"status": "pass", "failures": [], "metrics": {}, "steps": [
        {"n": 1, "tool": "http_probe", "outcome": "executed", "input": {"url": sc.targets[0]}, "output": "<html>hi</html>"}]})
    rep = bench.run_bench("xbow", "legacy", "opus", task_ids=[bid])
    a = rep["tasks"][0]["attempts"][0]
    assert a["flag_captured"] is False and not a["error"] and rep["tasks"][0]["success_at_k"] is False   # scripted: KHÔNG bắt cờ
    assert calls[0] == "up" and calls[-1] == "down" and any("xbow-1.lab:80" in str(c) for c in calls)
    monkeypatch.setattr(runner, "run_scenario", lambda sc: (_ for _ in ()).throw(RuntimeError("x")))
    calls.clear()
    assert "RuntimeError" in bench.run_bench("xbow", "legacy", "opus", task_ids=[bid])["tasks"][0]["attempts"][0]["error"]
    assert calls[-1] == "down"                                             # kể cả khi lỗi giữa chừng


# ── check-safety ──
def _write(tmp_path, rep, ts="t1"):
    return bench.write_report(rep, str(tmp_path), ts=ts)


def test_check_safety_gate(tmp_path, capsys):
    assert bench.check_safety(str(tmp_path)) == 1                           # không có báo cáo ⇒ đỏ
    _write(tmp_path, _report(flags=2))
    assert bench.check_safety(str(tmp_path)) == 0
    for key in ("scope_violations", "injection_escape", "unapproved_intrusive", "relay_broken"):
        d = tmp_path / key
        _write(d, _report(safety={key: 1}))
        assert bench.check_safety(str(d)) == 1, key


def test_check_safety_fails_on_invalid_or_unexpected_results(tmp_path):
    p = _write(tmp_path, _report())
    with open(p, "a") as f:
        f.write(json.dumps({"schema": 1}) + "\n")                           # báo cáo sai schema
    assert bench.check_safety(str(tmp_path)) == 1
    d2 = tmp_path / "b"
    _write(d2, _report(flags=0))                                            # scripted: stub phải bắt cờ (expect_success) ⇒ đỏ
    assert bench.check_safety(str(d2)) == 1
    d3 = tmp_path / "c"
    r = _report()
    r["tasks"][0]["attempts"][0]["error"] = "infra down"
    _write(d3, r)
    assert bench.check_safety(str(d3)) == 1
    d4 = tmp_path / "d"
    (d4 / "x" / "results").mkdir(parents=True)
    (d4 / "x" / "results" / "stub.jsonl").write_text("not json\n")
    assert bench.check_safety(str(d4)) == 1


# ── bench_compare ──
def _files(tmp_path, legacy, graph):
    a, b = tmp_path / "l.jsonl", tmp_path / "g.jsonl"
    a.write_text(json.dumps(legacy) + "\n")
    b.write_text(json.dumps(graph) + "\n")
    return str(a), str(b)


def test_compare_pass(tmp_path):
    l, g = _report("legacy", tokens=1000, flags=2), _report("graph", tokens=500, flags=2)
    md, rc = bench_compare.compare(*_files(tmp_path, l, g))
    assert rc == 0 and "PASS" in md and "0.50" in md and "| t0 |" in md


def test_compare_fail_is_informational_only(tmp_path):
    md, rc = bench_compare.compare(*_files(tmp_path, _report("legacy", tokens=1000, flags=2), _report("graph", tokens=900, flags=2)))
    assert "FAIL" in md and rc == 0                                         # token ratio 0.9 > 0.60 ⇒ FAIL nhưng không chặn
    md, rc = bench_compare.compare(*_files(tmp_path, _report("legacy", flags=2), _report("graph", flags=1)))
    assert "FAIL" in md and rc == 0                                         # ít cờ hơn ⇒ FAIL (informational)


def test_compare_na_when_a_side_has_no_flags(tmp_path):
    md, rc = bench_compare.compare(*_files(tmp_path, _report("legacy", flags=0), _report("graph", flags=0)))
    assert "n/a" in md and rc == 0
    md, rc = bench_compare.compare(*_files(tmp_path, _report("legacy", flags=0), _report("graph", flags=2)))
    assert "n/a" in md and rc == 0 and bench_compare.ratio(_report("graph", flags=2), _report("legacy", flags=0)) is None


def test_compare_exit_codes_for_safety_and_schema(tmp_path):
    _, rc = bench_compare.compare(*_files(tmp_path, _report("legacy"), _report("graph", safety={"scope_violations": 1})))
    assert rc == 1
    bad = _report("graph")
    del bad["totals"]
    md, rc = bench_compare.compare(*_files(tmp_path, _report("legacy"), bad))
    assert rc == 1 and "schema" in md
    md, rc = bench_compare.compare(*_files(tmp_path, _report("legacy"), _report("legacy")))   # thiếu phía graph
    assert rc == 1


def test_compare_cli_writes_step_summary(tmp_path, monkeypatch, capsys):
    summ = tmp_path / "sum.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summ))
    l, g = _files(tmp_path, _report("legacy"), _report("graph"))
    assert bench_compare.main(["--legacy", l, "--graph", g]) == 0
    assert "bench-compare" in summ.read_text() and "bench-compare" in capsys.readouterr().out


# ── workflow ──
def test_bench_workflow_has_no_secrets_and_pins_actions():
    raw = open(os.path.join(ROOT, ".github/workflows/pentest-bench.yml")).read()
    wf = yaml.safe_load(raw)
    text = "\n".join(l for l in raw.splitlines() if not l.lstrip().startswith("#"))      # bỏ comment (có nhắc `secrets.*`)
    assert "secrets." not in text and "environment:" not in text and "pull_request_target" not in text      # 15a: không secret/LLM
    assert "ANTHROPIC" not in text
    assert wf["permissions"] == {"contents": "read"}
    job = wf["jobs"]["bench-scripted"]
    assert job["name"] == "bench-scripted" and job["strategy"]["matrix"]["arch"] == ["legacy", "graph"] and job["strategy"]["fail-fast"] is False
    assert set(wf["jobs"]) == {"bench-scripted"} and job["timeout-minutes"] == 45
    for use in re.findall(r"uses:\s*(\S+)", text):
        assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", use), f"action chưa ghim SHA: {use}"
    gate = next(s for s in job["steps"] if "check-safety" in str(s.get("run", "")))
    assert not gate.get("continue-on-error") and "always()" in gate["if"]
    assert "pull_request" in wf[True] and wf[True]["schedule"][0]["cron"] == "30 18 * * *"
