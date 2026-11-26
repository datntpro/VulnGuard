"""P2-2: pentest-runner service + RunnerClient, với docker client giả (không Docker, không mạng ngoài)."""
import asyncio
import base64
import builtins
import json
import time
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from scanner.pentest.runner_client import RunnerClient, RunnerError
from services.pentest_runner.app import Settings, create_app

TOKEN = "t0ken-for-tests-0123456789abcdef0123456789"
H = {"Authorization": f"Bearer {TOKEN}"}
POLICY = {"engagement_id": "e1", "version": 1, "allow": []}


def _iso(age_s: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=age_s)).strftime("%Y-%m-%dT%H:%M:%S.%f") + "123Z"


class FakeContainer:
    def __init__(self, kw, cid):
        self.kw, self.id, self.labels = kw, cid, kw["labels"]
        self.attrs = {"Created": _iso(0)}  # như SDK thật: không có created_ts
        self.removed = self.killed = False
        self.files = {}
        self.exec_calls = []
        self.block = None  # threading.Event: giữ exec "đang chạy"

    def put_archive(self, path, data):  # Docker thật từ chối trên rootfs read-only (B1) — fake mô phỏng đúng
        raise RuntimeError("400: container rootfs is marked read-only")

    def exec_run(self, cmd, user=None, environment=None, demux=False):
        self.exec_calls.append((cmd, user, environment))
        if cmd[0].endswith("vg-exec"):
            if self.block:
                self.block.wait(5)
            step = cmd[cmd.index("--step") + 1]
            self.files[f"/work/{step}/result.json"] = json.dumps({"returncode": 0, "timed_out": False}).encode()
            self.files[f"/work/{step}/stdout"] = b"hello-out"
            self.files[f"/work/{step}/stderr"] = b""
            return (0, b"{}")
        if cmd[0] == "dd":
            path = cmd[1][3:]
            skip, count = int(cmd[3][5:]), int(cmd[4][6:])
            data = self.files.get(path)
            return (1, b"") if data is None else (0, data[skip:skip + count])
        if cmd[0] == "tail":
            data = self.files.get(cmd[3])
            return (1, b"") if data is None else (0, data[-int(cmd[2]):])
        return (0, b"")  # sh -c kill

    def kill(self):
        self.killed = True

    def remove(self, force=False):
        self.removed = True


class FakeNet:
    def __init__(self, name, labels):
        self.name, self.attrs, self.removed = name, {"Labels": labels, "Containers": {}, "Created": _iso(0)}, False

    def reload(self): pass

    def remove(self): self.removed = True


class _Coll:
    def __init__(self, owner): self.o = owner


class FakeDocker:
    def __init__(self, runtimes=("runc",)):
        self.runtimes, self.containers_, self.nets = runtimes, [], []
        outer = self

        class Containers:
            def run(self, **kw):
                c = FakeContainer(kw, f"cid{len(outer.containers_)}")
                outer.containers_.append(c)
                return c

            def list(self, all=False, filters=None):
                labs = (filters or {}).get("label") or []
                labs = [labs] if isinstance(labs, str) else labs
                kv = [x.partition("=") for x in labs]
                return [c for c in outer.containers_ if not c.removed and builtins.all(c.labels.get(k) == v for k, _, v in kv)]

        class Networks:
            def create(self, name, **kw):
                outer.net_kw = kw
                outer.nets.append(FakeNet(name, kw["labels"]))

            def list(self, names=None, filters=None):
                out = [n for n in outer.nets if not n.removed]
                if names:
                    out = [n for n in out if n.name in names]
                return out

        class Images:
            def get(self, name):
                if outer.no_image:
                    raise RuntimeError("not found")

        self.no_image = False
        self.containers, self.networks, self.images = Containers(), Networks(), Images()

    def info(self):
        return {"Runtimes": {r: {} for r in self.runtimes}}


def _mk(runtimes=("runc",), image="vg-runner@sha256:abc", **sk):
    d = FakeDocker(runtimes)
    app = create_app(Settings({"PENTEST_RUNNER_TOKEN": TOKEN, "PENTEST_RUNNER_IMAGE": image, "PENTEST_RUNNER_GC_INTERVAL_S": "0", **sk}), lambda: d)
    return TestClient(app), d, app.state.runner


def _sandbox(c, rid="r1", eid="e1"):
    assert c.post(f"/v1/engagements/{eid}/network", json={"policy": POLICY}, headers=H).status_code == 200
    r = c.post(f"/v1/runs/{rid}/sandbox", json={"eid": eid, "limits": {}}, headers=H)
    assert r.status_code == 200, r.text
    return r.json()


# ── auth / fail-closed ──
def test_requires_token_to_start():
    with pytest.raises(RuntimeError):
        create_app(Settings({}), lambda: None)
    with pytest.raises(RuntimeError):  # quá ngắn
        create_app(Settings({"PENTEST_RUNNER_TOKEN": "short"}), lambda: None)


@pytest.mark.parametrize("hdr", [{}, {"Authorization": "Bearer nope"}, {"Authorization": TOKEN}, {"Authorization": "Basic " + TOKEN}])
def test_auth_rejected(hdr):
    c, d, _ = _mk()
    assert c.get("/v1/health", headers=hdr).status_code == 401
    assert c.post("/v1/runs/r1/kill", headers=hdr).status_code == 401
    assert d.containers_ == []
    assert c.get("/v1/health", headers=H).json() == {"docker": True, "runtime": ["runc"]}


# ── sandbox spec ──
def test_sandbox_kwargs_hardened():
    c, d, _ = _mk()
    out = _sandbox(c)
    assert out["runtime"] == "runc"
    kw = d.containers_[0].kw
    assert kw["read_only"] is True and kw["cap_drop"] == ["ALL"] and kw["privileged"] is False
    assert kw["security_opt"] == ["no-new-privileges:true"]
    assert kw["user"] == "10002:10002" and kw["pids_limit"] == 512 and kw["mem_limit"] == "2048m"
    assert kw["nano_cpus"] == 2_000_000_000 and kw["network"] == "vg-eng-e1"
    assert "volumes" not in kw and "binds" not in kw and kw["extra_hosts"] == {}
    assert kw["environment"] == {"NO_PROXY": ""}  # không secret, không env khác
    assert kw["labels"]["vulnguard.run"] == "r1" and kw["labels"]["vulnguard.eng"] == "e1"
    assert kw["tmpfs"]["/tmp"] == "size=256m" and "uid=10002" in kw["tmpfs"]["/work"] and "runtime" not in kw
    assert d.net_kw["internal"] is True  # fail-closed: không đường ra Internet khi chưa có gateway


def test_proxy_env_only_when_configured():
    c, d, _ = _mk(PENTEST_SANDBOX_PROXY="http://10.9.0.2:3128")
    _sandbox(c)
    assert d.containers_[0].kw["environment"] == {"NO_PROXY": "", "HTTP_PROXY": "http://10.9.0.2:3128", "HTTPS_PROXY": "http://10.9.0.2:3128"}


def test_runtime_selection():
    c, d, _ = _mk(runtimes=("runc", "runsc"))
    assert _sandbox(c)["runtime"] == "runsc" and d.containers_[0].kw["runtime"] == "runsc"
    c, d, _ = _mk(runtimes=("runc",), PENTEST_SANDBOX_RUNTIME="runsc")
    c.post("/v1/engagements/e1/network", json={"policy": POLICY}, headers=H)
    assert c.post("/v1/runs/r1/sandbox", json={"eid": "e1"}, headers=H).status_code == 503  # không hạ cấp âm thầm
    c, d, _ = _mk(runtimes=("runc", "runsc"), PENTEST_SANDBOX_RUNTIME="runc")
    assert _sandbox(c)["runtime"] == "runc"


def test_sandbox_preconditions():
    c, d, _ = _mk(image="")
    c.post("/v1/engagements/e1/network", json={"policy": POLICY}, headers=H)
    assert c.post("/v1/runs/r1/sandbox", json={"eid": "e1"}, headers=H).status_code == 503
    c, d, _ = _mk()
    assert c.post("/v1/runs/r1/sandbox", json={"eid": "e1"}, headers=H).status_code == 409  # chưa có network/policy
    _sandbox(c)
    assert c.post("/v1/runs/r1/sandbox", json={"eid": "e1"}, headers=H).status_code == 409  # trùng
    assert c.post("/v1/runs/r1/sandbox", json={"eid": "../x"}, headers=H).status_code == 422
    assert c.post("/v1/runs/r2/sandbox", json={"eid": "e1", "limits": {"mem_mb": 10**6}}, headers=H).status_code == 422


# ── policy version ──
def test_policy_versioning_and_network_lifecycle():
    c, d, rn = _mk()
    c.post("/v1/engagements/e1/network", json={"policy": POLICY}, headers=H)
    assert c.put("/v1/engagements/e1/policy", json={"policy": {**POLICY, "version": 1}}, headers=H).status_code == 409
    assert c.put("/v1/engagements/e1/policy", json={"policy": {**POLICY, "version": 2}}, headers=H).status_code == 204
    assert c.put("/v1/engagements/zz/policy", json={"policy": POLICY}, headers=H).status_code == 404
    assert c.post("/v1/engagements/e1/network", json={"policy": {**POLICY, "version": 1}}, headers=H).status_code == 409
    assert c.post("/v1/runs/r1/sandbox", json={"eid": "e1"}, headers=H).status_code == 200
    assert c.delete("/v1/engagements/e1/network", headers=H).status_code == 204
    assert d.containers_[0].removed and d.nets[0].removed and "e1" not in rn.policies


# ── exec ──
def _wait(c, rid, xid):
    for _ in range(100):
        r = c.get(f"/v1/runs/{rid}/exec/{xid}", headers=H).json()
        if r["status"] != "running":
            return r
        time.sleep(0.02)
    raise AssertionError("exec did not finish")


def test_exec_roundtrip_and_output():
    c, d, _ = _mk()
    _sandbox(c)
    r = c.post("/v1/runs/r1/exec", headers=H, json={"step_id": "s1", "tool": "nmap", "argv": ["nmap", "-sV", "10.0.0.5"],
                                                     "timeout_s": 30, "env": {"LANG": "C"}})
    assert r.status_code == 200
    xid = r.json()["exec_id"]
    st = _wait(c, "r1", xid)
    assert st["status"] == "finished" and st["returncode"] == 0 and st["timed_out"] is False
    assert st["stdout_tail"] == "hello-out"
    cont = d.containers_[0]
    cmd, user, env = cont.exec_calls[0]
    assert cmd[:3] == ["/usr/local/bin/vg-exec", "run", "--tool"] and user == "10002:10002" and env == {"LANG": "C"}
    assert json.loads(base64.b64decode(cmd[cmd.index("--argv-b64") + 1])) == ["nmap", "-sV", "10.0.0.5"]  # không put_archive (B1)
    o = c.get(f"/v1/runs/r1/exec/{xid}/output?stream=stdout&offset=6", headers=H)
    assert o.content == b"out" and o.headers["x-next-offset"] == "9"
    assert c.get(f"/v1/runs/r1/exec/{xid}/output?stream=../x", headers=H).status_code == 422
    assert c.get(f"/v1/runs/other/exec/{xid}", headers=H).status_code == 404  # exec gắn với run
    assert c.post("/v1/runs/r1/exec", headers=H, json={"step_id": "s1", "tool": "nmap", "argv": ["nmap", "x"]}).status_code == 409


@pytest.mark.parametrize("argv,tool", [
    (["sh", "-c", "id"], "sh"), (["/bin/sh"], "/bin/sh"), (["nmap", "10.0.0.1\x00x"], "nmap"),
    (["nmap", "-sV", "10.0.0.1"], "ffuf"), (["python3", "-c", "x"], "python3"), (["curl", "http://x"], "curl"), ([], "nmap"),
])
def test_exec_argv_allowlist(argv, tool):
    c, d, _ = _mk()
    _sandbox(c)
    r = c.post("/v1/runs/r1/exec", headers=H, json={"step_id": "s1", "tool": tool, "argv": argv})
    assert r.status_code == 422
    assert d.containers_[0].exec_calls == []


@pytest.mark.parametrize("k", ["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy", "AWS_SECRET"])
def test_caller_cannot_set_proxy_or_other_env(k):  # M1
    c, d, _ = _mk()
    _sandbox(c)
    r = c.post("/v1/runs/r1/exec", headers=H, json={"step_id": "s1", "tool": "nmap", "argv": ["nmap", "x"], "env": {k: "*"}})
    assert r.status_code == 422 and d.containers_[0].exec_calls == []


def test_exec_rejects_bad_step_env_and_missing_sandbox():
    c, d, _ = _mk()
    b = {"step_id": "s1", "tool": "nmap", "argv": ["nmap", "x"]}
    assert c.post("/v1/runs/r1/exec", headers=H, json=b).status_code == 404
    _sandbox(c)
    assert c.post("/v1/runs/r1/exec", headers=H, json={**b, "step_id": "../etc"}).status_code == 422
    assert c.post("/v1/runs/r1/exec", headers=H, json={**b, "env": {"AWS_SECRET": "x"}}).status_code == 422
    assert d.containers_[0].exec_calls == []


# ── kill / delete / gc ──
def test_kill_stops_running_exec_and_falls_back_to_docker_kill():
    import threading
    c, d, _ = _mk()
    _sandbox(c)
    ev = threading.Event()
    d.containers_[0].block = ev
    xid = c.post("/v1/runs/r1/exec", headers=H, json={"step_id": "s1", "tool": "nmap", "argv": ["nmap", "x"]}).json()["exec_id"]
    time.sleep(0.1)
    t0 = time.monotonic()
    assert c.post("/v1/runs/r1/kill", headers=H).json() == {"killed": 1}
    assert time.monotonic() - t0 < 2
    ev.set()
    assert _wait(c, "r1", xid)["status"] == "killed"
    assert not d.containers_[0].killed  # kill ở mức tiến trình đã đủ

    # exec-level kill lỗi → docker kill
    c, d, _ = _mk()
    _sandbox(c)
    d.containers_[0].block = threading.Event()
    orig = d.containers_[0].exec_run
    d.containers_[0].exec_run = lambda cmd, **k: (1, b"") if cmd[0] == "/bin/sh" else orig(cmd, **k)
    c.post("/v1/runs/r1/exec", headers=H, json={"step_id": "s1", "tool": "nmap", "argv": ["nmap", "x"]})
    time.sleep(0.1)
    assert c.post("/v1/runs/r1/kill", headers=H).json() == {"killed": 1}
    assert d.containers_[0].killed
    d.containers_[0].block.set()


def test_delete_sandbox_and_gc():
    c, d, rn = _mk()
    _sandbox(c, "r1")
    _sandbox(c, "r2")
    assert c.delete("/v1/runs/r1/sandbox", headers=H).status_code == 204
    assert d.containers_[0].removed and not d.containers_[1].removed
    # gc: r2 không active → xoá; sandbox trẻ (<60s) được giữ để tránh race tạo mới
    d.containers_[1].attrs["Created"] = _iso(0)
    assert c.post("/v1/gc", headers=H, json={"active_runs": [], "active_engagements": ["e1"]}).json()["removed_sandboxes"] == 0
    d.containers_[1].attrs["Created"] = _iso(3600)
    assert c.post("/v1/gc", headers=H, json={"active_runs": ["r2"], "active_engagements": ["e1"]}).json()["removed_sandboxes"] == 0
    assert c.post("/v1/gc", headers=H, json={"active_runs": [], "active_engagements": ["e1"]}).json()["removed_sandboxes"] == 1
    assert d.containers_[1].removed and not d.nets[0].removed  # engagement còn active → giữ network
    d.nets[0].attrs["Created"] = _iso(3600)
    assert c.post("/v1/gc", headers=H, json={"active_runs": [], "active_engagements": []}).json()["removed_networks"] == 1
    assert "e1" not in rn.policies  # state được dọn → create_sandbox sau đó là 409, không phải 500
    assert c.post("/v1/runs/r9/sandbox", json={"eid": "e1"}, headers=H).status_code == 409


def test_gateway_hook_called_and_dns_set():
    class GW:
        calls = []

        def create(self, cli, eid, net, policy):
            self.calls.append(("create", eid)); return "gw1", "10.9.0.2"

        def reload(self, cli, eid, gid, policy):
            self.calls.append(("reload", gid))

        def remove(self, cli, eid, gid):
            self.calls.append(("remove", gid))

    d, gw = FakeDocker(), GW()
    app = create_app(Settings({"PENTEST_RUNNER_TOKEN": TOKEN, "PENTEST_RUNNER_IMAGE": "img@sha256:abc", "PENTEST_RUNNER_GC_INTERVAL_S": "0"}), lambda: d, gw)
    c = TestClient(app)
    assert c.post("/v1/engagements/e1/network", json={"policy": POLICY}, headers=H).json() == {"network": "vg-eng-e1", "gateway_id": "gw1"}
    c.put("/v1/engagements/e1/policy", json={"policy": {**POLICY, "version": 2}}, headers=H)
    c.post("/v1/runs/r1/sandbox", json={"eid": "e1"}, headers=H)
    assert d.containers_[0].kw["dns"] == ["10.9.0.2"]
    c.delete("/v1/engagements/e1/network", headers=H)
    assert [x[0] for x in GW.calls] == ["create", "reload", "remove"]


# ── client ──
def test_client_against_service_and_errors():
    c, d, rn = _mk()
    app = c.app

    async def go():
        async with RunnerClient(url="http://runner", token=TOKEN, transport=httpx.ASGITransport(app=app)) as cl:
            assert (await cl.health())["docker"] is True
            assert (await cl.create_network("e1", POLICY))["network"] == "vg-eng-e1"
            assert "sandbox_id" in await cl.create_sandbox("r1", "e1")
            xid = await cl.exec("r1", "s1", "nmap", ["nmap", "x"])
            for _ in range(100):
                st = await cl.exec_status("r1", xid)
                if st["status"] != "running":
                    break
                await asyncio.sleep(0.02)
            assert st["status"] == "finished" and await cl.exec_output("r1", xid, "stdout", 0) == b"hello-out"
            with pytest.raises(RunnerError) as ei:
                await cl.exec("r1", "s2", "sh", ["sh"])
            assert ei.value.status == 422
            assert await cl.kill("r1") == 0
            await cl.delete_sandbox("r1")
            await cl.delete_network("e1")
        bad = RunnerClient(url="http://runner", token="wrong", transport=httpx.ASGITransport(app=app))
        with pytest.raises(RunnerError) as ei:
            await bad.health()
        assert ei.value.status == 401
        await bad.aclose()

    asyncio.run(go())


def test_client_requires_token_and_uds_url():
    with pytest.raises(ValueError):
        RunnerClient(url="unix:///x.sock", token="")
    cl = RunnerClient(url="unix:///run/vulnguard/pentest-runner.sock", token="t")
    assert str(cl._c.base_url).startswith("http://pentest-runner")
    asyncio.run(cl.aclose())


def test_default_settings_unchanged_legacy():
    from scanner.pentest.settings import PentestSettings
    assert PentestSettings().exec_backend == "local"  # sandbox là opt-in


# ── regressions from review of #67 ──
def test_gc_keeps_just_created_sandbox():  # B2: tuổi lấy từ attrs.Created như Docker thật
    c, d, _ = _mk()
    _sandbox(c)
    assert not hasattr(d.containers_[0], "created_ts")
    assert c.post("/v1/gc", headers=H, json={"active_runs": [], "active_engagements": []}).json() == {"removed_sandboxes": 0, "removed_networks": 0}
    assert not d.containers_[0].removed


def test_parse_ts_is_fail_safe():
    from services.pentest_runner.app import _parse_ts
    assert abs(_parse_ts("garbage") - time.time()) < 2 and abs(_parse_ts(None) - time.time()) < 2
    assert abs(_parse_ts("2026-01-01T00:00:00.5Z") - (datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp() + 0.5)) < 1e-3


def test_periodic_gc_startup_lease_and_hard_age():
    c, d, rn = _mk(PENTEST_RUNNER_MAX_SANDBOX_AGE_S="1000")
    _sandbox(c)
    d.containers_[0].attrs["Created"] = _iso(500)
    assert rn.periodic_gc()["removed_sandboxes"] == 0  # chưa có lease, chưa quá trần tuổi
    d.containers_[0].attrs["Created"] = _iso(5000)
    c.post("/v1/gc", headers=H, json={"active_runs": ["r1"], "active_engagements": ["e1"]})
    assert rn.periodic_gc()["removed_sandboxes"] == 0  # lease còn hạn, r1 active
    rn.gc_lease = (rn.gc_lease[0] - 10**6, *rn.gc_lease[1:])  # lease hết hạn → chỉ còn trần tuổi cứng
    assert rn.periodic_gc()["removed_sandboxes"] == 1
    c2, d2, rn2 = _mk()
    _sandbox(c2)
    d2.containers_[0].attrs["Created"] = _iso(3600)
    assert rn2.periodic_gc(startup=True)["removed_sandboxes"] == 1  # khởi động: state RAM đã mất → dọn mồ côi


def test_lifespan_runs_gc_task():
    d = FakeDocker()
    app = create_app(Settings({"PENTEST_RUNNER_TOKEN": TOKEN, "PENTEST_RUNNER_IMAGE": "i@sha256:a", "PENTEST_RUNNER_GC_INTERVAL_S": "1"}), lambda: d)
    called = []
    app.state.runner.periodic_gc = lambda startup=False: called.append(startup) or {}
    with TestClient(app) as cl:
        for _ in range(100):
            if called:
                break
            time.sleep(0.02)
    assert called and called[0] is True


def test_image_must_be_pinned_and_present_never_pulled():
    c, d, _ = _mk(image="vulnguard-pentest-runner:latest")
    c.post("/v1/engagements/e1/network", json={"policy": POLICY}, headers=H)
    assert c.post("/v1/runs/r1/sandbox", json={"eid": "e1"}, headers=H).status_code == 503
    c, d, _ = _mk(image="vulnguard-pentest-runner:latest", PENTEST_ALLOW_UNPINNED_IMAGE="1")
    assert _sandbox(c)
    c, d, _ = _mk()
    d.no_image = True
    c.post("/v1/engagements/e1/network", json={"policy": POLICY}, headers=H)
    assert c.post("/v1/runs/r1/sandbox", json={"eid": "e1"}, headers=H).status_code == 503
    assert d.containers_ == []


def test_sandbox_quotas_and_server_side_limit_maxima():
    c, d, _ = _mk(PENTEST_RUNNER_MAX_SANDBOXES="3", PENTEST_RUNNER_MAX_SANDBOXES_PER_ENG="2")
    _sandbox(c, "r1")
    assert c.post("/v1/runs/r2/sandbox", json={"eid": "e1"}, headers=H).status_code == 200
    assert c.post("/v1/runs/r3/sandbox", json={"eid": "e1"}, headers=H).status_code == 429  # per-engagement
    c.post("/v1/engagements/e2/network", json={"policy": POLICY}, headers=H)
    assert c.post("/v1/runs/r4/sandbox", json={"eid": "e2"}, headers=H).status_code == 200
    assert c.post("/v1/runs/r5/sandbox", json={"eid": "e2"}, headers=H).status_code == 429  # global
    c, d, _ = _mk(PENTEST_RUNNER_MAX_MEM_MB="512")
    c.post("/v1/engagements/e1/network", json={"policy": POLICY}, headers=H)
    assert c.post("/v1/runs/r1/sandbox", json={"eid": "e1", "limits": {"mem_mb": 1024}}, headers=H).status_code == 422
    assert c.post("/v1/runs/r1/sandbox", json={"eid": "e1", "limits": {"mem_mb": 512, "cpus": 1}}, headers=H).status_code == 200


def test_exec_concurrency_and_rate_limits_and_pruning():
    import threading
    c, d, rn = _mk(PENTEST_RUNNER_MAX_EXECS_PER_RUN="2", PENTEST_RUNNER_EXEC_RATE_PER_MIN="5")
    _sandbox(c)
    ev = threading.Event()
    d.containers_[0].block = ev
    post = lambda i: c.post("/v1/runs/r1/exec", headers=H, json={"step_id": f"s{i}", "tool": "nmap", "argv": ["nmap", "x"]}).status_code  # noqa: E731
    assert post(1) == 200 and post(2) == 200 and post(3) == 429  # đồng thời
    ev.set()
    time.sleep(0.3)
    assert [post(i) for i in (4, 5, 6)] == [200, 200, 200] and post(7) == 429  # rate: 5/phút (2 + 3 đã nhận)
    for k in list(rn.execs):
        rn.execs[k]["status"] = "finished"
    from services.pentest_runner import app as appmod
    appmod.KEEP_FINISHED_EXECS = 2
    rn.s.exec_rate_per_min = 10**6
    for i in range(10, 16):
        assert post(i) == 200
        time.sleep(0.05)
    assert len(rn.execs) <= 2 + 2 + 1


def test_output_is_bounded_with_truncated_flag():
    c, d, _ = _mk()
    _sandbox(c)
    xid = c.post("/v1/runs/r1/exec", headers=H, json={"step_id": "s1", "tool": "nmap", "argv": ["nmap", "x"]}).json()["exec_id"]
    _wait(c, "r1", xid)
    big = b"A" * (3 * (1 << 20))
    d.containers_[0].files["/work/s1/stdout"] = big
    o = c.get(f"/v1/runs/r1/exec/{xid}/output?offset=0", headers=H)
    assert len(o.content) == 1 << 20 and o.headers["x-truncated"] == "1" and o.headers["x-next-offset"] == str(1 << 20)
    o2 = c.get(f"/v1/runs/r1/exec/{xid}/output?offset={2 * (1 << 20) + 5}", headers=H)
    assert len(o2.content) == (1 << 20) - 5 and o2.headers["x-truncated"] == "0"
    cmds = [x[0] for x in d.containers_[0].exec_calls if x[0][0] == "dd"]
    assert cmds and all(any(a.startswith("count=") for a in x) for x in cmds)  # giới hạn thực thi TRONG sandbox
    st = c.get(f"/v1/runs/r1/exec/{xid}", headers=H).json()
    assert len(st["stdout_tail"]) <= 4096


def test_delete_network_purges_state_and_requires_managed_label():
    c, d, rn = _mk()
    _sandbox(c)
    c.post("/v1/runs/r1/exec", headers=H, json={"step_id": "s1", "tool": "nmap", "argv": ["nmap", "x"]})
    time.sleep(0.1)
    d.containers_.append(FakeContainer({"labels": {"vulnguard.run": "foreign", "vulnguard.eng": "e1"}}, "x"))  # không managed
    c.delete("/v1/engagements/e1/network", headers=H)
    assert not rn.execs and "e1" not in rn.policies and not d.containers_[-1].removed
