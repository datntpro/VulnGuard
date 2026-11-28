"""Scanner invocation never acts on configuration, state or build steps supplied by the scanned tree.

Hostile inputs are generated at test time under tmp_path; nothing hostile is committed.
"""
import asyncio
import os
import shutil
import tarfile
import textwrap
from urllib.parse import urlparse

import httpx
import pytest

from scanner.scanners import sca, sonarqube
from scanner.scanners.base import ScannerRunError, scrubbed_env


def _run(coro):
    return asyncio.run(coro)


def _under(path, root):
    return os.path.realpath(path).startswith(os.path.realpath(str(root)) + os.sep)


# ── pip-audit ────────────────────────────────────────────────────────────────

def test_pip_audit_passes_only_pinned_copy_and_disables_pip(monkeypatch, tmp_path):
    (tmp_path / "requirements.txt").write_text(textwrap.dedent("""\
        --index-url http://127.0.0.1:9/simple
        -r other.txt
        -e .
        canary @ file:./canary-1.0.tar.gz
        ./canary-1.0.tar.gz
        flask>=1
        requests==2.0.0 --hash=sha256:00
    """))
    seen = []

    async def fake(cmd, cwd=None, **k):
        path = cmd[cmd.index("-r") + 1]
        seen.append((cmd, cwd, open(path).read()))
        return 0, '{"dependencies": []}', ""

    monkeypatch.setattr(sca, "run_command", fake)
    _run(sca.PipAuditScanner(str(tmp_path)).scan())
    assert seen
    for cmd, cwd, content in seen:
        assert "--disable-pip" in cmd and "--no-deps" in cmd
        assert not _under(cmd[cmd.index("-r") + 1], tmp_path)
        assert cwd and not _under(cwd, tmp_path)
        assert content == "requests==2.0.0"


def test_pip_audit_ignores_pyproject_and_pipfile_lock(monkeypatch, tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    (tmp_path / "Pipfile.lock").write_text("{}")
    calls = []

    async def fake(cmd, **k):
        calls.append(cmd)
        return 0, '{"dependencies": []}', ""

    monkeypatch.setattr(sca, "run_command", fake)
    assert _run(sca.PipAuditScanner(str(tmp_path)).scan()) == []
    assert calls == []


def test_pip_audit_unpinned_only_is_partial_not_error(monkeypatch, tmp_path):
    (tmp_path / "requirements.txt").write_text("flask>=1\n")
    monkeypatch.setattr(sca, "run_command", lambda *a, **k: pytest.fail("must not run"))
    sc = sca.PipAuditScanner(str(tmp_path))
    assert _run(sc.scan()) == []
    assert sc.warnings


def _make_canary_tree(root, marker):
    """Target whose requirement is a local sdist with an in-tree build backend that writes `marker`."""
    root.mkdir(parents=True, exist_ok=True)
    pkg = root / "src" / "canary-1.0"
    pkg.mkdir(parents=True)
    (pkg / "pyproject.toml").write_text(
        '[build-system]\nrequires = []\nbuild-backend = "b"\nbackend-path = ["."]\n')
    (pkg / "b.py").write_text(textwrap.dedent(f"""\
        def _m():
            open({str(marker)!r}, "w").write("x")
        def get_requires_for_build_wheel(c=None):
            _m(); return []
        def build_wheel(*a, **k):
            _m(); raise SystemExit(1)
        def prepare_metadata_for_build_wheel(*a, **k):
            _m(); raise SystemExit(1)
    """))
    with tarfile.open(root / "canary-1.0.tar.gz", "w:gz") as t:
        t.add(pkg, arcname="canary-1.0")
    shutil.rmtree(root / "src")
    (root / "requirements.txt").write_text("./canary-1.0.tar.gz\nrequests==2.0.0\n")


@pytest.mark.skipif(not shutil.which("pip-audit"), reason="pip-audit not installed")
def test_pip_audit_real_tool_never_builds_target_packages(tmp_path):
    marker = tmp_path / "MARKER"
    target = tmp_path / "t"
    _make_canary_tree(target, marker)
    sc = sca.PipAuditScanner(str(target))
    try:
        _run(sc.scan())
    except ScannerRunError as e:  # advisory service may be unreachable
        text = str(e)
    else:
        text = " ".join(sc.warnings)
    assert not marker.exists()
    assert "isolated environment" not in text and "Failed to upgrade" not in text


# ── SonarQube ────────────────────────────────────────────────────────────────

def _sonar(monkeypatch, tmp_path, handler, fake_run):
    monkeypatch.setattr(sonarqube.shutil, "which", lambda n: "/x/sonar-scanner")
    monkeypatch.setattr(sonarqube, "_cfg", lambda name, default=None: {
        "SONARQUBE_URL": "http://sonar.test:9000", "SONARQUBE_TOKEN": "tok-123"}.get(name, default))
    monkeypatch.setattr(sonarqube, "run_command", fake_run)
    real = httpx.AsyncClient
    monkeypatch.setattr(sonarqube.httpx, "AsyncClient",
                        lambda **kw: real(transport=httpx.MockTransport(handler), **kw))

    async def nosleep(_):
        return None
    monkeypatch.setattr(sonarqube.asyncio, "sleep", nosleep)
    return sonarqube.SonarQubeScanner(str(tmp_path))


def _ok_handler(requests):
    def h(req):
        requests.append(req)
        if req.url.path == "/api/ce/task":
            return httpx.Response(200, json={"task": {"status": "SUCCESS"}})
        return httpx.Response(200, json={"issues": [], "total": 0, "hotspots": []})
    return h


def test_sonar_never_reads_target_scanner_state(monkeypatch, tmp_path):
    target = tmp_path / "t"
    (target / ".scannerwork").mkdir(parents=True)
    (target / ".w").mkdir()
    for d in (".scannerwork", ".w"):
        (target / d / "report-task.txt").write_text("ceTaskId=ZZ\nceTaskUrl=http://canary.invalid/x\n")
    (target / "sonar-project.properties").write_text(
        "sonar.working.directory=.w\nsonar.scanner.javaExePath=./x.sh\n"
        "sonar.scanner.proxyHost=canary.invalid\nsonar.projectDescription=${env.SONAR_TOKEN}\n")
    captured = {}

    async def fake_run(cmd, cwd=None, timeout=0, env=None):
        captured.update(cmd=cmd, cwd=cwd, env=env)
        wd = next(a.split("=", 1)[1] for a in cmd if a.startswith("-Dsonar.working.directory="))
        os.makedirs(wd, exist_ok=True)
        with open(os.path.join(wd, "report-task.txt"), "w") as f:
            f.write("ceTaskId=AX1\n")
        return 0, "", ""

    requests = []
    sc = _sonar(monkeypatch, target, _ok_handler(requests), fake_run)
    _run(sc.scan())
    assert requests
    for r in requests:
        assert r.url.host == urlparse(sc.url).hostname
        assert "canary.invalid" not in str(r.url)
    cmd = captured["cmd"]
    for key in ("-Dproject.settings=", "-Dsonar.working.directory="):
        val = next(a.split("=", 1)[1] for a in cmd if a.startswith(key))
        assert not _under(val, target)
    assert not _under(captured["cwd"], target)
    assert not any("tok-123" in a for a in cmd)
    assert captured["env"]["SONAR_TOKEN"] == "tok-123"


def _fake_run_factory(rc=0, err="", task="ceTaskId=AX1\n"):
    async def fake_run(cmd, cwd=None, timeout=0, env=None):
        wd = next(a.split("=", 1)[1] for a in cmd if a.startswith("-Dsonar.working.directory="))
        if task is not None:
            os.makedirs(wd, exist_ok=True)
            with open(os.path.join(wd, "report-task.txt"), "w") as f:
                f.write(task)
        return rc, "", err
    return fake_run


def _handler(ce="SUCCESS", issues_status=200):
    def h(req):
        if req.url.path == "/api/ce/task":
            return httpx.Response(200, json={"task": {"status": ce}})
        return httpx.Response(issues_status, json={"issues": [], "total": 0})
    return h


_CASES = {
    "rc1": (_fake_run_factory(rc=1, err="boom"), _handler()),
    "timeout": (_fake_run_factory(rc=-1, err="Command timeout after 1s: x"), _handler()),
    "issues-500": (_fake_run_factory(), _handler(issues_status=500)),
    "ce-failed": (_fake_run_factory(), _handler(ce="FAILED")),
    "ce-never-terminal": (_fake_run_factory(), _handler(ce="IN_PROGRESS")),
    "no-report": (_fake_run_factory(task=None), _handler()),
    "bad-task-id": (_fake_run_factory(task="ceTaskId=../x\n"), _handler()),
}


@pytest.mark.parametrize("case", list(_CASES))
def test_sonar_failure_is_error_not_clean(monkeypatch, tmp_path, case):
    fake_run, handler = _CASES[case]
    sc = _sonar(monkeypatch, tmp_path, handler, fake_run)
    with pytest.raises(ScannerRunError):
        _run(sc.scan())


def test_sonar_failure_marks_orchestrator_error(monkeypatch, tmp_path):
    from scanner.orchestrator import Orchestrator
    fake_run, handler = _CASES["rc1"]
    _sonar(monkeypatch, tmp_path, handler, fake_run)
    monkeypatch.setattr(sonarqube.SonarQubeScanner, "is_available", lambda self: True)
    _, logs = _run(Orchestrator(str(tmp_path), scan_types=["SAST"]).run())
    assert logs["sonar-scanner"]["status"] == "error"


def test_scanner_param_envs_are_not_forwarded():
    base = {"SONAR_SCANNER_JSON_PARAMS": "x", "SONARQUBE_SCANNER_PARAMS": "y", "SONAR_SCANNER_OPTS": "z"}
    assert scrubbed_env(base=base) == {}
