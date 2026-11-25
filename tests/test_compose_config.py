"""docker-compose: UI và proxy MITM có biến bind riêng; env của app đi qua compose."""
import json
import os
import pathlib
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(shutil.which("docker") is None, reason="docker không có")


def _cfg(extra_env=None, files=("docker-compose.yml",)):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("VULNGUARD_", "PENTEST_", "AUTH_", "ALLOWED_", "COOKIE_"))}
    env.update(extra_env or {})
    cmd = ["docker", "compose"]
    for f in files:
        cmd += ["-f", str(ROOT / f)]
    cmd += ["--project-directory", str(ROOT), "config", "--format", "json"]
    r = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"docker compose config không chạy được: {r.stderr[:100]}")
    return json.loads(r.stdout)["services"]["vulnguard"]


def _hosts(svc):
    return {int(p["target"]): p.get("host_ip") for p in svc["ports"]}


def test_default_both_loopback():
    assert _hosts(_cfg()) == {8080: "127.0.0.1", 8788: "127.0.0.1"}


def test_bind_opens_ui_only():
    h = _hosts(_cfg({"VULNGUARD_BIND": "0.0.0.0"}))
    assert h[8080] == "0.0.0.0" and h[8788] == "127.0.0.1"


def test_app_env_passthrough():
    env = _cfg({"ALLOWED_HOSTS": "vulnguard.lan", "AUTH_ENABLED": "true", "COOKIE_SECURE": "true",
                "VULNGUARD_BIND": "0.0.0.0"})["environment"]
    assert env["ALLOWED_HOSTS"] == "vulnguard.lan" and env["COOKIE_SECURE"] == "true"
    assert env["AUTH_ENABLED"] == "true" and env["VULNGUARD_BIND"] == "0.0.0.0"


def test_lan_override_keeps_proxy_loopback():
    h = _hosts(_cfg(files=("docker-compose.yml", "docker-compose.lan.yml")))
    assert h == {8080: "0.0.0.0", 8788: "127.0.0.1"}
