"""P2-15a: cô lập compose benchmark bên thứ ba — OFFLINE (không Docker, không mạng). Chạy ở bench-scripted (self-tests) và CI."""
import copy

import pytest

from eval.bench import isolation as I
from eval.harness import runner, xbow

IP = "172.31.250.61"
SRC = {
    "services": {
        "db": {"build": "./mysql", "expose": [3306], "networks": ["n1"], "volumes": ["dbdata:/var/lib/mysql"]},
        "web": {"build": {"context": "./app", "args": ["FLAG"]}, "ports": ["8080:80"], "networks": ["n1"], "container_name": "x",
                "healthcheck": {"test": ["CMD", "curl", "x"]}, "depends_on": {"db": {"condition": "service_healthy"}}},
    },
    "volumes": {"dbdata": {}},
    "networks": {"n1": {"name": "xben-network"}},
}


def _mut(**kw):
    c = copy.deepcopy(SRC)
    c["services"]["db"].update(kw)
    return c


FORBIDDEN = [
    {"network_mode": "host"}, {"network_mode": "bridge"}, {"network_mode": "service:web"}, {"privileged": True},
    {"cap_add": ["SYS_ADMIN"]}, {"cap_add": ["NET_RAW"]}, {"devices": ["/dev/fuse"]}, {"pid": "host"}, {"ipc": "host"}, {"uts": "host"},
    {"userns_mode": "host"}, {"security_opt": ["seccomp=unconfined"]}, {"security_opt": ["apparmor:unconfined"]},
    {"volumes": ["/var/run/docker.sock:/x"]}, {"volumes": ["./data:/x"]}, {"volumes": ["/etc:/mnt:ro"]}, {"volumes": ["../x:/mnt"]},
    {"volumes": ["~/x:/mnt"]}, {"volumes": ["$HOME:/mnt"]},
    {"volumes": [{"type": "bind", "source": "./a", "target": "/b"}]},
    {"volumes": [{"type": "bind", "source": "/var/run/docker.sock", "target": "/s"}]},
    {"extra_hosts": ["host.docker.internal:host-gateway"]}, {"dns": ["8.8.8.8"]}, {"dns_search": ["example.com"]},
    {"sysctls": {"net.ipv4.ip_forward": 1}}, {"cgroup_parent": "x"}, {"volumes_from": ["web"]}, {"links": ["web"]},
    {"build": {"context": ".", "network": "host"}}, {"secrets": ["s"]}, {"configs": ["c"]},
]


@pytest.mark.parametrize("bad", FORBIDDEN, ids=lambda b: next(iter(b)) + ":" + str(next(iter(b.values())))[:24])
def test_every_forbidden_key_is_refused_before_rewrite(bad):
    with pytest.raises(I.UnsafeCompose):
        I.assert_bench_compose_safe(_mut(**bad), [IP], "pre")


def test_refusal_is_applied_to_the_entry_service_too():
    c = copy.deepcopy(SRC)
    c["services"]["web"]["privileged"] = True
    with pytest.raises(I.UnsafeCompose, match="privileged"):
        I.rewrite_and_check(c, IP)


def test_named_volumes_and_clean_compose_are_allowed():
    I.assert_bench_compose_safe(SRC, [IP], "pre")                      # `ports` ở phase pre OK: transform xoá hết
    c = _mut(volumes=[{"type": "volume", "source": "dbdata", "target": "/x"}, {"type": "tmpfs", "target": "/t"}])
    I.assert_bench_compose_safe(c, [IP], "pre")


def test_external_and_exotic_networks_refused_before_rewrite():
    for net in ({"external": True}, {"external": True, "name": "host"}, {"driver": "macvlan"}, {"driver": "host"}):
        c = copy.deepcopy(SRC)
        c["networks"]["n1"] = net
        with pytest.raises(I.UnsafeCompose):
            I.assert_bench_compose_safe(c, [IP], "pre")


def test_empty_or_missing_services_refused():
    for c in ({}, {"services": {}}, {"services": None}):
        with pytest.raises(I.UnsafeCompose):
            I.assert_bench_compose_safe(c, [IP], "pre")


def test_ip_must_be_inside_lab():
    for ip in ("10.0.0.5", "172.31.250.1", "172.31.250.0", "172.31.250.255", "172.31.251.20", "8.8.8.8"):
        with pytest.raises(I.UnsafeCompose, match="ngoài lab"):
            I.assert_bench_compose_safe(SRC, [ip], "pre")


def test_transform_is_pure_and_isolates():
    before = copy.deepcopy(SRC)
    out = I.transform_compose(SRC, IP)
    assert SRC == before                                               # THUẦN: input không đổi
    out["services"]["web"]["networks"]["lab_net"]["ipv4_address"] = "x"  # và output không dùng chung object với input
    assert SRC == before
    out = I.transform_compose(SRC, IP)
    assert out["x-vg-entry-port"] == 80
    for name, svc in out["services"].items():                          # mọi service CHỈ trên lab_net/bench_internal, không ports, không healthcheck
        assert "ports" not in svc and "healthcheck" not in svc and "container_name" not in svc
        assert set(svc["networks"]) <= {"lab_net", "bench_internal"}
    assert out["services"]["web"]["networks"]["lab_net"] == {"ipv4_address": IP}
    assert set(out["services"]["db"]["networks"]) == {"bench_internal"}    # helper: không IP lab, không lab_net
    assert out["services"]["web"]["expose"] == ["80"]
    assert out["services"]["web"]["depends_on"]["db"]["condition"] == "service_started"
    assert out["networks"] == {"lab_net": {"external": True, "name": I.LAB_NETWORK}, "bench_internal": {"internal": True}}
    assert set(out["networks"]) == {"lab_net", "bench_internal"}       # mạng tuỳ biến của upstream bị bỏ


def test_transform_needs_exactly_one_entry():
    with pytest.raises(ValueError):
        I.transform_compose({"services": {"a": {}, "b": {}}}, IP)
    with pytest.raises(ValueError):
        I.transform_compose({"services": {"a": {"ports": ["1:1"]}, "b": {"ports": ["2:2"]}}}, IP)
    with pytest.raises(ValueError):
        I.transform_compose({"services": {"a": {}}}, IP, entry="a")        # entry không khai báo cổng
    out = I.transform_compose({"services": {"a": {"expose": ["8000"]}, "b": {}}}, IP, entry="a")
    assert out["x-vg-entry-port"] == 8000


def test_rewrite_and_check_roundtrip_passes_post_phase():
    out = I.rewrite_and_check(SRC, IP)
    I.assert_bench_compose_safe({k: v for k, v in out.items() if k != "x-vg-entry-port"}, [IP], "post")


POST_MUTATIONS = [
    (lambda c: c["services"]["db"].update(ports=["3306:3306"]), "ports"),
    (lambda c: c["services"]["db"].update(privileged=True), "privileged"),
    (lambda c: c["services"]["db"].update(network_mode="host"), "network_mode"),
    (lambda c: c["networks"]["bench_internal"].update(internal=False), "bench_internal"),
    (lambda c: c["networks"].update(extra={}), "networks phải là"),
    (lambda c: c["networks"]["lab_net"].update(external=False), "lab_net"),
    (lambda c: c["networks"]["lab_net"].update(name="bridge"), "lab_net"),
    (lambda c: c["services"]["db"]["networks"].update(default={}), "network lạ"),
    (lambda c: c["services"]["db"].update(networks={}), "network lạ"),
    (lambda c: c["services"]["db"].pop("networks"), "network lạ"),
    (lambda c: c["services"]["web"]["networks"]["lab_net"].update(ipv4_address="172.31.250.20"), "allowed_ips"),
    (lambda c: c["services"]["db"]["networks"]["bench_internal"].update(ipv4_address=IP), "bench_internal"),
    (lambda c: c["services"]["db"].update(volumes=["/var/run/docker.sock:/s"]), "docker.sock"),
    (lambda c: c["services"]["db"].update(volumes=["./x:/y"]), "bind mount"),
]


@pytest.mark.parametrize("mutate,match", POST_MUTATIONS)
def test_post_rewrite_check_bites(mutate, match):
    good = {k: v for k, v in I.transform_compose(SRC, IP).items() if k != "x-vg-entry-port"}
    cfg = copy.deepcopy(good)
    mutate(cfg)
    with pytest.raises(I.UnsafeCompose, match=match):
        I.assert_bench_compose_safe(cfg, [IP], "post")


def test_phase_must_be_known():
    with pytest.raises(ValueError):
        I.assert_bench_compose_safe(SRC, [IP], "later")


def test_unpinned_image_only_warns_for_local_builds(caplog):
    c = {"services": {"web": {"image": "nginx:latest", "ports": ["80:80"]}}}
    with caplog.at_level("WARNING"):
        I.assert_bench_compose_safe(c, [IP], "pre")                    # cho phép nhưng log (nhìn thấy được trong CI)
    assert "digest" in caplog.text
    caplog.clear()
    with caplog.at_level("WARNING"):
        I.assert_bench_compose_safe({"services": {"web": {"build": "./a", "image": "x:1"}}}, [IP], "pre")
    assert not caplog.text


# ── xbow.py vẫn giữ tên + hành vi cũ (tests/test_pentest_capability.py) ──
def test_xbow_wrappers_delegate_to_isolation():
    out = xbow.transform_compose(SRC, IP)
    assert out["x-vg-entry-port"] == 80
    for svc in out["services"].values():
        assert svc["environment"]["FLAG"] == "${FLAG}"
    cfg = {k: v for k, v in out.items() if k != "x-vg-entry-port"}
    xbow.assert_xbow_compose_safe(cfg, IP)
    cfg["services"]["db"]["privileged"] = True
    with pytest.raises(runner.LabSafetyError, match="privileged"):    # ngoại lệ cũ (LabSafetyError) được giữ
        xbow.assert_xbow_compose_safe(cfg, IP)
    with pytest.raises(runner.LabSafetyError, match="ngoài lab"):
        xbow.assert_xbow_compose_safe(cfg, "10.0.0.5")
