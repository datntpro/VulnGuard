"""P2-2 (VG_LAB=1): runner THẬT trên Docker thật — exec nmap/vg_http qua runner, kill, timeout, gc.

Fake docker trong test_runner_service.py không thể lộ lỗi đặc thù Docker (put_archive trên rootfs read-only, `Created`
của container...) nên test này là bắt buộc. Cần: Docker, image `vulnguard-pentest-runner` (make pentest-images);
đặt PENTEST_LAB_RUNNER_IMAGE nếu tên khác. Không chạm Internet: mạng engagement là `internal`, chỉ nmap -sL / loopback / subnet nội bộ.
"""
import ipaddress
import os
import time
import uuid

import pytest
from fastapi.testclient import TestClient

pytestmark = pytest.mark.skipif(os.environ.get("VG_LAB") != "1", reason="cần VG_LAB=1 + Docker + image runner")

TOKEN = "lab-token-" + "x" * 40
H = {"Authorization": f"Bearer {TOKEN}"}
IMAGE = os.environ.get("PENTEST_LAB_RUNNER_IMAGE", "vulnguard-pentest-runner:latest")


@pytest.fixture()
def lab():
    import docker

    from services.pentest_runner.app import Settings, create_app
    cli = docker.from_env()
    cli.images.get(IMAGE)
    app = create_app(Settings({"PENTEST_RUNNER_TOKEN": TOKEN, "PENTEST_RUNNER_IMAGE": IMAGE,
                               "PENTEST_ALLOW_UNPINNED_IMAGE": "1", "PENTEST_RUNNER_GC_INTERVAL_S": "0"}), lambda: cli)
    eid, rid = "lab" + uuid.uuid4().hex[:8], "lab" + uuid.uuid4().hex[:8]
    c = TestClient(app)
    assert c.post(f"/v1/engagements/{eid}/network", json={"policy": {"version": 1}}, headers=H).status_code == 200
    r = c.post(f"/v1/runs/{rid}/sandbox", json={"eid": eid, "limits": {}}, headers=H)
    assert r.status_code == 200, r.text
    try:
        yield c, cli, eid, rid
    finally:
        c.delete(f"/v1/runs/{rid}/sandbox", headers=H)
        c.delete(f"/v1/engagements/{eid}/network", headers=H)


def _run(c, rid, step, tool, argv, timeout=60, wait=90):
    r = c.post(f"/v1/runs/{rid}/exec", headers=H, json={"step_id": step, "tool": tool, "argv": argv, "timeout_s": timeout})
    assert r.status_code == 200, r.text
    xid = r.json()["exec_id"]
    for _ in range(int(wait / 0.25)):
        st = c.get(f"/v1/runs/{rid}/exec/{xid}", headers=H).json()
        if st["status"] != "running":
            return xid, st
        time.sleep(0.25)
    raise AssertionError("exec did not finish")


def test_exec_nmap_and_vg_http_output_roundtrip(lab):  # B1: exec THẬT trên rootfs read-only
    c, cli, eid, rid = lab
    xid, st = _run(c, rid, "n1", "nmap", ["nmap", "-sL", "127.0.0.1", "-n"])
    assert st["status"] == "finished" and st["returncode"] == 0, st
    out = c.get(f"/v1/runs/{rid}/exec/{xid}/output?stream=stdout", headers=H)
    assert b"127.0.0.1" in out.content and out.headers["x-truncated"] == "0"
    xid2, st2 = _run(c, rid, "h1", "python3 -m vg_http", ["python3", "-m", "vg_http"])
    assert st2["status"] == "finished", st2  # module chạy được (stdin rỗng → JSON error), không phải lỗi giao argv


def test_proxy_env_cannot_be_overridden_for_real(lab):
    c, cli, eid, rid = lab
    r = c.post(f"/v1/runs/{rid}/exec", headers=H, json={"step_id": "e1", "tool": "nmap", "argv": ["nmap", "-sL", "127.0.0.1"],
                                                         "env": {"NO_PROXY": "*"}})
    assert r.status_code == 422


def _slow_target(cli, eid):
    net = cli.networks.get(f"vg-eng-{eid}")
    sub = ipaddress.ip_network(net.attrs["IPAM"]["Config"][0]["Subnet"])
    return str(list(sub.hosts())[-5])  # địa chỉ trong mạng internal, không ai trả lời


def test_kill_and_timeout_and_container_survives(lab):
    c, cli, eid, rid = lab
    tgt = _slow_target(cli, eid)
    slow = ["nmap", "-Pn", "-sT", "-p", "1-1000", "-T1", tgt]
    _, st = _run(c, rid, "t1", "nmap", slow, timeout=3, wait=60)
    assert st["status"] == "finished" and st["timed_out"] is True
    xid = c.post(f"/v1/runs/{rid}/exec", headers=H, json={"step_id": "k1", "tool": "nmap", "argv": slow, "timeout_s": 120}).json()["exec_id"]
    time.sleep(1.5)
    t0 = time.monotonic()
    assert c.post(f"/v1/runs/{rid}/kill", headers=H).json() == {"killed": 1}
    assert time.monotonic() - t0 < 5
    for _ in range(80):
        if c.get(f"/v1/runs/{rid}/exec/{xid}", headers=H).json()["status"] != "running":
            break
        time.sleep(0.25)
    assert c.get(f"/v1/runs/{rid}/exec/{xid}", headers=H).json()["status"] == "killed"
    assert cli.containers.list(filters={"label": f"vulnguard.run={rid}"})  # container vẫn chạy


def test_gc_keeps_just_created_sandbox(lab):  # B2 trên Docker thật
    c, cli, eid, rid = lab
    assert c.post("/v1/gc", headers=H, json={"active_runs": [], "active_engagements": []}).json() == {"removed_sandboxes": 0, "removed_networks": 0}
    assert cli.containers.list(filters={"label": f"vulnguard.run={rid}"})
