"""run.sh / install/run.sh: một biến VULNGUARD_BIND, alias VULNGUARD_HOST, từ chối auth-off + LAN."""
import os
import pathlib
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _fake_project(tmp_path, script):
    proj = tmp_path / "p"
    proj.mkdir()
    shutil.copy(ROOT / script, proj / pathlib.Path(script).name)
    venv = proj / (".venv" if script == "run.sh" else "venv")
    (venv / "bin").mkdir(parents=True)
    uv = venv / "bin" / "uvicorn"
    uv.write_text('#!/bin/sh\necho "UVICORN $@"\n')
    uv.chmod(0o755)
    if script == "install/run.sh":
        (proj / "install").mkdir()
        shutil.move(str(proj / "run.sh"), str(proj / "install" / "run.sh"))
        (proj / ".env").write_text("")
    return proj


def _run(proj, script, **env):
    base = {k: v for k, v in os.environ.items()
            if not k.startswith(("VULNGUARD_", "AUTH_ENABLED"))}
    base.update(env)
    path = proj / script
    return subprocess.run(["bash", str(path)], cwd=proj, env=base, capture_output=True, text=True)


@pytest.mark.parametrize("script", ["run.sh", "install/run.sh"])
def test_default_loopback(tmp_path, script):
    p = _fake_project(tmp_path, script)
    r = _run(p, script)
    assert "--host 127.0.0.1" in r.stdout, r.stderr


@pytest.mark.parametrize("script", ["run.sh", "install/run.sh"])
def test_bind_var_opens_lan(tmp_path, script):
    p = _fake_project(tmp_path, script)
    r = _run(p, script, VULNGUARD_BIND="0.0.0.0")
    assert "--host 0.0.0.0" in r.stdout and "deprecated" not in r.stderr


@pytest.mark.parametrize("script", ["run.sh", "install/run.sh"])
def test_host_alias_works_with_deprecation(tmp_path, script):
    p = _fake_project(tmp_path, script)
    r = _run(p, script, VULNGUARD_HOST="0.0.0.0")
    assert "--host 0.0.0.0" in r.stdout and "deprecated" in r.stderr


@pytest.mark.parametrize("script", ["run.sh", "install/run.sh"])
def test_auth_off_lan_refused(tmp_path, script):
    p = _fake_project(tmp_path, script)
    r = _run(p, script, VULNGUARD_BIND="0.0.0.0", AUTH_ENABLED="false")
    assert r.returncode == 1 and "UVICORN" not in r.stdout
