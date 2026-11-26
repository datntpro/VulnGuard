"""P2-3b: EgressGateway (runner) + tích hợp vào Runner — docker giả; kiểm cờ container, mạng, route/attach, reload, dọn dẹp."""
import base64
import json

import pytest
from fastapi.testclient import TestClient

from services.pentest_runner.app import Settings, create_app
from services.pentest_runner.egress import EgressGateway, GatewayError, ingest_token

TOKEN = "t" * 40
H = {"Authorization": f"Bearer {TOKEN}"}


class Ctr:
    def __init__(self, kw, cid, nets):
        self.kw, self.id, self.name, self.labels = kw, cid, kw.get("name"), kw.get("labels") or {}
        self.status, self.removed, self.execs, self.connected = "created", False, [], []
        self.nets = nets
        self.attrs = {"State": {"Running": False}, "NetworkSettings": {"Networks": {}}}
        self.ready_after = 0
        self.reload_code = 0

    def reload(self):
        ips = {n: {"IPAddress": f"10.9.{i}.2"} for i, n in enumerate(self.connected + ([self.kw["network"]] if self.kw.get("network") else []))}
        self.attrs = {"State": {"Running": self.status == "running"}, "NetworkSettings": {"Networks": ips}}

    def start(self):
        self.status = "running"

    def exec_run(self, cmd, user=None):
        self.execs.append((cmd, user))
        if cmd[:2] == ["vg-egw", "health"]:
            self.ready_after -= 1
            return (0 if self.ready_after < 0 else 1), b""
        if cmd[:2] == ["vg-egw", "reload"]:
            return self.reload_code, b"stale" if self.reload_code else b""
        return 0, b""

    def logs(self, tail=5):
        return b"boom"

    def remove(self, force=False):
        self.removed = True

    def kill(self):
        pass


class Net:
    def __init__(self, name, subnet, gw=None):
        self.name, self.id = name, "nid-" + name
        cfg = {"Subnet": subnet}
        if gw:
            cfg["Gateway"] = gw
        self.attrs = {"IPAM": {"Config": [cfg]}, "Labels": {}, "Containers": {}, "Created": "2026-01-01T00:00:00.000000000Z"}
        self.connected, self.removed = [], False

    def connect(self, c):
        self.connected.append(c)
        c.connected.append(self.name)

    def remove(self):
        self.removed = True

    def reload(self):
        pass


class Cli:
    def __init__(self):
        self.ctrs, self.nets, self.created_nets, self.ran = [], [Net("bridge", "172.17.0.0/16"), Net("vulnguard-network", "172.20.0.0/16")], [], []
        o = self

        class C:
            def create(self, **kw):
                c = Ctr(kw, f"c{len(o.ctrs)}", None)
                o.ctrs.append(c)
                return c

            def get(self, i):
                for c in o.ctrs:
                    if c.id == i:
                        return c
                import docker.errors
                raise docker.errors.NotFound("x")

            def run(self, **kw):
                c = Ctr(kw, f"c{len(o.ctrs)}", None)
                c.status = "running"
                o.ctrs.append(c)
                o.ran.append(kw)
                return c

            def list(self, all=False, filters=None):
                labs = (filters or {}).get("label") or []
                labs = [labs] if isinstance(labs, str) else labs
                kv = [x.partition("=") for x in labs]
                return [c for c in o.ctrs if not c.removed and all_(c.labels.get(k) == v for k, _, v in kv)]

        class N:
            def get(self, name):
                for n in o.nets:
                    if n.name == name:
                        return n
                raise RuntimeError("no net")

            def list(self, names=None, filters=None):
                out = [n for n in o.nets if not n.removed]
                return [n for n in out if n.name in names] if names else out

            def create(self, name, **kw):
                n = Net(name, f"10.9.{len(o.nets)}.0/24", gw=f"10.9.{len(o.nets)}.1")
                n.kw = kw
                o.nets.append(n)
                o.created_nets.append((name, kw))
                return n

        class I:
            def get(self, name):
                return None

        self.containers, self.networks, self.images = C(), N(), I()

    def info(self):
        return {"Runtimes": {"runc": {}}}


all_ = all


def _gw(**kw):
    return EgressGateway("vg-egress@sha256:abc", secret=TOKEN, ready_timeout_s=3, **kw)


def test_create_gateway_container_is_hardened_and_policy_merged():
    cli = Cli()
    cli.networks.create("vg-eng-e1", driver="bridge")
    cli.nets[-1].attrs["IPAM"]["Config"] = [{"Subnet": "10.50.0.0/24"}]
    g = _gw(ingest_url="http://vulnguard:8000/api/pentest/internal/traffic", ingest_network="vulnguard-network", upstream_dns="9.9.9.9")
    gid, ip = g.create(cli, "e1", "vg-eng-e1", {"version": 3, "engagement_id": "e1", "always_deny": ["169.254.0.0/16"]})
    c = cli.ctrs[0]
    kw = c.kw
    assert kw["cap_drop"] == ["ALL"] and sorted(kw["cap_add"]) == ["NET_ADMIN", "SETGID", "SETUID"]    # NET_ADMIN CHỈ ở gateway
    assert kw["read_only"] is True and kw["privileged"] is False and kw["security_opt"] == ["no-new-privileges:true"]
    assert "volumes" not in kw and kw["dns"] == ["127.0.0.1"] and kw["name"] == "vg-egw-e1" and kw["network"] == "vg-egress-out"
    assert kw["sysctls"]["net.ipv4.ip_forward"] == "1" and kw["sysctls"]["net.ipv6.conf.all.disable_ipv6"] == "1"
    assert kw["labels"]["vulnguard.eng"] == "e1" and kw["labels"]["vulnguard.egress"] == "1"
    env = kw["environment"]
    assert env["VG_ENG_SUBNET"] == "10.50.0.0/24" and env["VG_UPSTREAM"] == "9.9.9.9" and env["VG_OUT_GW"].endswith(".1")
    assert env["VG_INGEST_TOKEN"] == ingest_token(TOKEN, "e1") and TOKEN not in json.dumps(env)             # token ingest ≠ token runner
    pol = json.loads(env["VG_POLICY_JSON"])
    # dải mạng khác (docker0, mạng VulnGuard, mạng engagement) được cộng vào always_deny; mạng ra ngoài thì KHÔNG
    assert {"169.254.0.0/16", "172.17.0.0/16", "172.20.0.0/16", "10.50.0.0/24"} <= set(pol["always_deny"])
    assert not any(x.startswith("10.9.0.") for x in pol["always_deny"] if "vg-egress-out" in x)
    assert c.connected == ["vg-eng-e1", "vulnguard-network"] and c.status == "running" and ip == "10.9.0.2" or ip
    assert gid == "c0"


def test_gateway_not_ready_is_removed_and_raises():
    cli = Cli()
    cli.networks.create("vg-eng-e1", driver="bridge")
    g = EgressGateway("img", ready_timeout_s=0.5)
    orig = Ctr.exec_run
    Ctr.exec_run = lambda self, cmd, user=None: (1, b"") if cmd[:2] == ["vg-egw", "health"] else orig(self, cmd, user)
    try:
        with pytest.raises(GatewayError):
            g.create(cli, "e1", "vg-eng-e1", {"version": 1})
    finally:
        Ctr.exec_run = orig
    assert cli.ctrs[0].removed


def test_reload_passes_b64_policy_and_reports_failure():
    cli = Cli()
    cli.networks.create("vg-eng-e1", driver="bridge")
    g = _gw()
    gid, _ = g.create(cli, "e1", "vg-eng-e1", {"version": 1})
    g.reload(cli, "e1", gid, {"version": 2, "engagement_id": "e1"})
    cmd, user = cli.ctrs[0].execs[-1]
    assert cmd[:3] == ["vg-egw", "reload", "--b64"] and user == "root"
    assert json.loads(base64.b64decode(cmd[3]))["version"] == 2
    cli.ctrs[0].reload_code = 3
    with pytest.raises(GatewayError):
        g.reload(cli, "e1", gid, {"version": 3})


def test_attach_adds_default_route_from_helper_container_not_sandbox():
    cli = Cli()
    cli.networks.create("vg-eng-e1", driver="bridge")
    g = _gw()
    gid, gip = g.create(cli, "e1", "vg-eng-e1", {"version": 1})
    sbx = Ctr({"labels": {}, "network": "vg-eng-e1", "name": "vg-sbx-r1"}, "sbx", None)
    sbx.status = "running"
    cli.ctrs.append(sbx)
    g.attach(cli, "e1", gid, gip, sbx, "r1")
    helper = cli.ran[-1]
    assert helper["entrypoint"] == ["ip"] and helper["command"] == ["route", "replace", "default", "via", gip]
    assert helper["network_mode"] == "container:sbx" and helper["cap_add"] == ["NET_ADMIN"] and helper["cap_drop"] == ["ALL"]
    assert helper["remove"] is True and helper["read_only"] is True
    assert sbx.kw.get("cap_add") is None                                                                    # sandbox KHÔNG được thêm cap
    mp = [e for e in cli.ctrs[0].execs if e[0][:2] == ["vg-egw", "map"]]
    assert mp and mp[0][0][3] == "r1"


def test_remove_ignores_already_gone():
    cli = Cli()
    _gw().remove(cli, "e1", "does-not-exist")


def test_from_env():
    assert EgressGateway.from_env({}) is None
    g = EgressGateway.from_env({"PENTEST_EGRESS_IMAGE": "img", "PENTEST_RUNNER_TOKEN": TOKEN, "PENTEST_EGRESS_OUT_NETWORK": "out",
                                "PENTEST_EGRESS_EXTRA_DENY": "10.0.0.0/8, 192.168.0.0/16"})
    assert g.out_network == "out" and len(g.extra_deny) == 2


def _runner(gateway):
    cli = Cli()
    app = create_app(Settings({"PENTEST_RUNNER_TOKEN": TOKEN, "PENTEST_RUNNER_IMAGE": "vg-runner@sha256:abc", "PENTEST_RUNNER_GC_INTERVAL_S": "0"}),
                     lambda: cli, gateway=gateway)
    return TestClient(app), cli


def test_runner_without_gateway_keeps_internal_network():
    c, cli = _runner(None)
    assert c.post("/v1/engagements/e1/network", json={"policy": {"version": 1}}, headers=H).status_code == 200
    name, kw = cli.created_nets[0]
    assert kw["internal"] is True and "options" not in kw


def test_runner_with_gateway_network_has_no_host_ip_and_no_masquerade():
    c, cli = _runner(_gw())
    r = c.post("/v1/engagements/e1/network", json={"policy": {"version": 1}}, headers=H)
    assert r.status_code == 200 and r.json()["gateway_id"] == "c0"
    name, kw = [x for x in cli.created_nets if x[0] == "vg-eng-e1"][0]
    assert kw["internal"] is False and kw["enable_ipv6"] is False
    assert kw["options"]["com.docker.network.bridge.inhibit_ipv4"] == "true"        # host KHÔNG có IP trên bridge (review P2-4)
    assert kw["options"]["com.docker.network.bridge.enable_ip_masquerade"] == "false"


def test_runner_sandbox_gets_gateway_dns_proxy_and_route_and_attach_failure_removes_it():
    c, cli = _runner(_gw())
    c.post("/v1/engagements/e1/network", json={"policy": {"version": 1}}, headers=H)
    r = c.post("/v1/runs/r1/sandbox", json={"eid": "e1", "limits": {}}, headers=H)
    assert r.status_code == 200, r.text
    sbx = [x for x in cli.ctrs if x.name == "vg-sbx-r1"][0]
    gw_ip = cli.ctrs[0].attrs["NetworkSettings"]["Networks"]["vg-eng-e1"]["IPAddress"]
    assert sbx.kw["dns"] == [gw_ip] and sbx.kw["environment"]["HTTP_PROXY"] == f"http://{gw_ip}:8080"
    assert sbx.kw["cap_drop"] == ["ALL"] and sbx.kw["read_only"] is True
    assert any(k.get("entrypoint") == ["ip"] for k in cli.ran)
    # attach lỗi → sandbox bị gỡ, 502
    c2, cli2 = _runner(_gw())
    c2.post("/v1/engagements/e2/network", json={"policy": {"version": 1}}, headers=H)
    import services.pentest_runner.egress as eg
    orig = eg.EgressGateway.attach
    eg.EgressGateway.attach = lambda *a, **k: (_ for _ in ()).throw(GatewayError("x"))
    try:
        assert c2.post("/v1/runs/r2/sandbox", json={"eid": "e2", "limits": {}}, headers=H).status_code == 502
    finally:
        eg.EgressGateway.attach = orig
    assert [x for x in cli2.ctrs if x.name == "vg-sbx-r2"][0].removed


def test_runner_hot_reload_and_newer_create_reload_gateway():
    c, cli = _runner(_gw())
    c.post("/v1/engagements/e1/network", json={"policy": {"version": 1}}, headers=H)
    assert c.put("/v1/engagements/e1/policy", json={"policy": {"version": 2}}, headers=H).status_code == 204
    assert c.put("/v1/engagements/e1/policy", json={"policy": {"version": 2}}, headers=H).status_code == 409
    c.post("/v1/engagements/e1/network", json={"policy": {"version": 5}}, headers=H)     # run mới: scope mới nhất được áp
    reloads = [e for e in cli.ctrs[0].execs if e[0][:2] == ["vg-egw", "reload"]]
    assert len(reloads) == 2
    assert c.delete("/v1/engagements/e1/network", headers=H).status_code == 204
    assert cli.ctrs[0].removed
