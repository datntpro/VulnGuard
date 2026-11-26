"""P2-4 (VG_LAB=1): SandboxBackend THẬT trên runner + Docker thật — nmap/vg_http qua backend, ownership, kill.

Cần Docker + image `vulnguard-pentest-runner` (make pentest-images; PENTEST_LAB_RUNNER_IMAGE nếu tên khác). Không chạm Internet:
mạng engagement `internal`, chỉ nmap -sL / loopback.
"""
import asyncio
import os
import uuid

import httpx
import pytest

pytestmark = pytest.mark.skipif(os.environ.get("VG_LAB") != "1", reason="cần VG_LAB=1 + Docker + image runner")

TOKEN = "lab-token-" + "x" * 40
IMAGE = os.environ.get("PENTEST_LAB_RUNNER_IMAGE", "vulnguard-pentest-runner:latest")


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@pytest.fixture()
def lab():
    import docker

    from scanner.pentest.exec_backend import SandboxBackend
    from scanner.pentest.runner_client import RunnerClient
    from services.pentest_runner.app import Settings, create_app
    cli = docker.from_env()
    cli.images.get(IMAGE)
    app = create_app(Settings({"PENTEST_RUNNER_TOKEN": TOKEN, "PENTEST_RUNNER_IMAGE": IMAGE,
                               "PENTEST_ALLOW_UNPINNED_IMAGE": "1", "PENTEST_RUNNER_GC_INTERVAL_S": "0"}), lambda: cli)
    eid, rid = "lab" + uuid.uuid4().hex[:8], "lab" + uuid.uuid4().hex[:8]
    client = RunnerClient(url="http://runner", token=TOKEN, transport=httpx.ASGITransport(app=app))
    b = SandboxBackend(client, run_id=rid, engagement_id=eid, owner_lookup=lambda r: eid,
                       other_active_runs=lambda e, r: 0, poll_s=0.2)
    try:
        yield b, cli, eid, rid
    finally:
        try:
            _run(b.close())
        finally:
            _run(client.aclose())


def test_sandbox_backend_runs_nmap_and_http_for_real(lab):
    b, cli, eid, rid = lab
    r = _run(b.run_argv(["nmap", "-sL", "127.0.0.1", "-n"], 60, step_id="n1"))
    assert r["ran"] and r["returncode"] == 0 and "127.0.0.1" in r["stdout"], r
    assert cli.containers.list(filters={"label": f"vulnguard.run={rid}"})
    from scanner.pentest.exec_backend import HttpSpec
    h = _run(b.http(HttpSpec("GET", "http://127.0.0.1:9/", timeout=3)))
    assert "error" in h and "vg_http" not in h["error"].lower()   # cổng đóng → lỗi kết nối của vg_http (đi hết backend→runner→vg_http)


def test_sandbox_backend_kill_and_timeout_for_real(lab):
    import ipaddress
    b, cli, eid, rid = lab
    _run(b.ensure())
    net = cli.networks.get(f"vg-eng-{eid}")
    sub = ipaddress.ip_network(net.attrs["IPAM"]["Config"][0]["Subnet"])
    tgt = str(list(sub.hosts())[-5])
    slow = ["nmap", "-Pn", "-sT", "-p", "1-1000", "-T1", tgt]
    r = _run(b.run_argv(slow, 3))
    assert r["timed_out"] is True

    async def main():
        t = asyncio.ensure_future(b.run_argv(slow, 120))
        await asyncio.sleep(2)
        n = await b.kill_run(rid)
        res = await asyncio.wait_for(t, 30)
        return n, res
    n, res = _run(main())
    assert n == 1 and res.get("stopped") is True


def test_ownership_enforced_against_real_runner(lab):
    from scanner.pentest.exec_backend import OwnershipError, SandboxBackend
    b, cli, eid, rid = lab
    evil = SandboxBackend(b.client, run_id=rid, engagement_id="other" + uuid.uuid4().hex[:6],
                          owner_lookup=lambda r: eid, poll_s=0.2)
    with pytest.raises(OwnershipError):
        _run(evil.ensure())
    assert not cli.containers.list(filters={"label": f"vulnguard.run={rid}"})   # runner không bao giờ nhận lời gọi
