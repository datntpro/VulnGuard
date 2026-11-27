"""N-4: một scanner chạy hỏng KHÔNG được báo "ok, 0 findings"."""
import asyncio
import json

import pytest

from scanner.scanners import sast, container, iac, sca, secrets
from scanner.scanners.base import ScannerRunError


def _run(coro):
    return asyncio.run(coro)


def _patch(monkeypatch, module, result):
    async def fake(cmd, *a, **k):
        return result(cmd) if callable(result) else result
    monkeypatch.setattr(module, "run_command", fake)


IMPORT_ERR = (1, "", "ImportError: cannot import name '_ExtendedAttributes'")


def test_semgrep_import_error_raises(monkeypatch, tmp_path):
    _patch(monkeypatch, sast, IMPORT_ERR)
    monkeypatch.setattr(sast, "_has_internet", lambda: False)
    with pytest.raises(ScannerRunError):
        _run(sast.SemgrepScanner(str(tmp_path)).scan())


def test_semgrep_error_surfaces_in_orchestrator(monkeypatch, tmp_path):
    from scanner.orchestrator import Orchestrator
    _patch(monkeypatch, sast, IMPORT_ERR)
    monkeypatch.setattr(sast, "_has_internet", lambda: False)
    monkeypatch.setattr(sast.SemgrepScanner, "is_available", lambda self: True)
    _, logs = _run(Orchestrator(str(tmp_path), scan_types=["SAST"]).run())
    assert logs["semgrep"]["status"] == "error"


def test_semgrep_timeout_raises(monkeypatch, tmp_path):
    _patch(monkeypatch, sast, (-1, "", "Command timeout after 90s: semgrep"))
    monkeypatch.setattr(sast, "_has_internet", lambda: False)
    with pytest.raises(ScannerRunError):
        _run(sast.SemgrepScanner(str(tmp_path)).scan())


def test_semgrep_non_json_raises(monkeypatch, tmp_path):
    _patch(monkeypatch, sast, (0, "not json", ""))
    with pytest.raises(ScannerRunError):
        _run(sast.SemgrepScanner(str(tmp_path))._run_semgrep(["--config", "x"]))


def test_semgrep_findings_rc1_ok(monkeypatch, tmp_path):
    data = {"results": [{"check_id": "a.b.rule", "path": "x.py",
                         "start": {"line": 3}, "end": {"line": 3},
                         "extra": {"severity": "ERROR", "message": "m", "metadata": {}}}]}
    _patch(monkeypatch, sast, (1, json.dumps(data), ""))
    out = _run(sast.SemgrepScanner(str(tmp_path))._run_semgrep(["--config", "x"]))
    assert len(out) == 1


def test_semgrep_rc0_empty_stdout_raises(monkeypatch, tmp_path):
    _patch(monkeypatch, sast, (0, "", ""))
    with pytest.raises(ScannerRunError):
        _run(sast.SemgrepScanner(str(tmp_path))._run_semgrep(["--config", "x"]))


def test_semgrep_clean_json_is_ok(monkeypatch, tmp_path):
    _patch(monkeypatch, sast, (0, json.dumps({"results": [], "errors": []}), ""))
    assert _run(sast.SemgrepScanner(str(tmp_path))._run_semgrep(["--config", "x"])) == []


def test_semgrep_json_without_results_raises(monkeypatch, tmp_path):
    _patch(monkeypatch, sast, (0, "{}", ""))
    with pytest.raises(ScannerRunError):
        _run(sast.SemgrepScanner(str(tmp_path))._run_semgrep(["--config", "x"]))


def test_semgrep_rc2_errors_no_results_raises(monkeypatch, tmp_path):
    body = json.dumps({"results": [], "errors": [{"message": "Invalid rule"}]})
    _patch(monkeypatch, sast, (2, body, ""))
    with pytest.raises(ScannerRunError, match="Invalid rule"):
        _run(sast.SemgrepScanner(str(tmp_path))._run_semgrep(["--config", "x"]))


def test_bandit_non_json_raises(monkeypatch, tmp_path):
    _patch(monkeypatch, sast, (2, "Traceback", "boom"))
    with pytest.raises(ScannerRunError):
        _run(sast.BanditScanner(str(tmp_path)).scan())


def test_bandit_rc1_with_json_ok(monkeypatch, tmp_path):
    data = {"results": [{"filename": "a.py", "line_number": 1, "test_id": "B101",
                         "test_name": "assert_used", "issue_severity": "LOW",
                         "issue_confidence": "HIGH", "issue_text": "t", "code": "c"}]}
    _patch(monkeypatch, sast, (1, json.dumps(data), ""))
    assert len(_run(sast.BanditScanner(str(tmp_path)).scan())) == 1


def _trivy(ok_image):
    def f(cmd):
        if cmd[-1] == ok_image:
            return 0, json.dumps({"Results": [{"Target": "t", "Vulnerabilities": [
                {"VulnerabilityID": "CVE-1", "PkgName": "p", "InstalledVersion": "1",
                 "Severity": "HIGH"}]}]}), ""
        return 1, "", "FATAL unable to pull"
    return f


def _compose(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  a:\n    image: img/a:1\n  b:\n    image: img/b:1\n")


def test_container_all_fail_raises(monkeypatch, tmp_path):
    _compose(tmp_path)
    _patch(monkeypatch, container, _trivy(None))
    with pytest.raises(ScannerRunError):
        _run(container.TrivyContainerScanner(str(tmp_path)).scan())


def test_container_partial_failure_keeps_findings(monkeypatch, tmp_path):
    _compose(tmp_path)
    _patch(monkeypatch, container, _trivy("img/a:1"))
    assert len(_run(container.TrivyContainerScanner(str(tmp_path)).scan())) == 1


# ── F-1: bandit crash exit 1 / invalid JSON rc 0 ─────────────────────────────
@pytest.mark.parametrize("res", [
    (1, "", "ImportError: cannot import name 'x'"),   # crash: exit 1, empty stdout
    (1, "Traceback (most recent call last)", "boom"),  # crash, non-JSON
    (0, "garbage", ""),                                # invalid JSON, rc 0
    (0, "", ""),                                       # empty, rc 0
    (0, "[]", ""),                                     # JSON but not bandit report
    (0, "{}", ""),                                     # JSON without "results"
])
def test_bandit_failure_modes_raise(monkeypatch, tmp_path, res):
    _patch(monkeypatch, sast, res)
    with pytest.raises(ScannerRunError):
        _run(sast.BanditScanner(str(tmp_path)).scan())


def test_bandit_clean_report_is_ok(monkeypatch, tmp_path):
    _patch(monkeypatch, sast, (0, json.dumps({"errors": [], "results": []}), ""))
    assert _run(sast.BanditScanner(str(tmp_path)).scan()) == []


# ── F-3 / every scanner: empty stdout with rc 0 is not "clean" ───────────────
def test_trivy_all_empty_rc0_raises(monkeypatch, tmp_path):
    _compose(tmp_path)
    _patch(monkeypatch, container, (0, "", ""))
    with pytest.raises(ScannerRunError):
        _run(container.TrivyContainerScanner(str(tmp_path)).scan())


def test_trivy_clean_json_ok(monkeypatch, tmp_path):
    _compose(tmp_path)
    _patch(monkeypatch, container, (0, json.dumps({"Results": []}), ""))
    assert _run(container.TrivyContainerScanner(str(tmp_path)).scan()) == []


@pytest.mark.parametrize("res", [(1, "", "crash"), (0, "", ""), (0, "nope", "")])
def test_grype_failure_modes_raise(monkeypatch, tmp_path, res):
    _patch(monkeypatch, container, res)
    with pytest.raises(ScannerRunError):
        _run(container.GrypeScanner(str(tmp_path)).scan())


def test_grype_clean_ok(monkeypatch, tmp_path):
    _patch(monkeypatch, container, (0, json.dumps({"matches": []}), ""))
    assert _run(container.GrypeScanner(str(tmp_path)).scan()) == []


# ── F-2: Dockerfile must not use the invalid --dry-run flag or swallow failures ─
def test_dockerfile_precache_is_valid_and_loud():
    import pathlib
    text = (pathlib.Path(__file__).parent.parent / "api" / "Dockerfile").read_text()
    assert "--dry-run" not in text
    assert "semgrep --version" in text
    for line in text.splitlines():
        if "semgrep" in line and not line.lstrip().startswith("#"):
            assert "|| true" not in line and "2>/dev/null" not in line
    # semgrep nay nằm trong venv riêng cài từ lockfile (PR-H) — từ bước đó trở đi không nuốt lỗi
    assert "/tmp/scanners/$t.txt" in text
    assert "|| echo" not in text.split("/tmp/scanners/$t.txt")[1]


# ── PR-7a: IaC / SCA / secrets ─────────────────────────────────────────────
MISSING = (-1, "", "Tool not found: x")
TIMEOUT = (-1, "", "Command timeout after 300s: x")
GARBAGE = (0, "not json", "")

_CHECKOV_OK = json.dumps({"results": {"failed_checks": [{
    "check_id": "CKV_X_1", "check_type": "terraform", "file_path": "/a/main.tf",
    "file_line_range": [1, 2], "resource": "r"}]}})
_TRIVY_IAC_OK = json.dumps({"Results": [{"Target": "t", "Type": "dockerfile", "Misconfigurations": [
    {"ID": "DS001", "Title": "t", "Severity": "HIGH"}]}]})
_TRIVY_SCA_OK = json.dumps({"Results": [{"Target": "t", "Vulnerabilities": [
    {"VulnerabilityID": "CVE-1", "PkgName": "p", "InstalledVersion": "1", "Severity": "HIGH"}]}]})
_PIPAUDIT_OK = json.dumps({"dependencies": [{"name": "p", "version": "1", "vulns": [
    {"id": "PYSEC-1", "description": "d", "fix_versions": ["2"], "aliases": []}]}]})


@pytest.mark.parametrize("res", [TIMEOUT, (2, "", "boom"), (1, "", ""), (1, "Traceback", "x"), GARBAGE],
                         ids=["timeout", "bad-exit", "rc1-empty", "rc1-garbage", "garbage-rc0"])
def test_checkov_failure_modes_raise(monkeypatch, tmp_path, res):
    _patch(monkeypatch, iac, res)
    with pytest.raises(ScannerRunError):
        _run(iac.CheckovScanner(str(tmp_path)).scan())


def test_checkov_missing_and_clean_ok(monkeypatch, tmp_path):
    _patch(monkeypatch, iac, MISSING)
    assert _run(iac.CheckovScanner(str(tmp_path)).scan()) == []
    _patch(monkeypatch, iac, (0, "", ""))
    assert _run(iac.CheckovScanner(str(tmp_path)).scan()) == []
    _patch(monkeypatch, iac, (1, _CHECKOV_OK, ""))
    assert len(_run(iac.CheckovScanner(str(tmp_path)).scan())) == 1


@pytest.mark.parametrize("res", [TIMEOUT, (1, "", "FATAL"), GARBAGE, (0, "[]", "")],
                         ids=["timeout", "bad-exit", "garbage", "non-object"])
def test_trivy_iac_failure_modes_raise(monkeypatch, tmp_path, res):
    _patch(monkeypatch, iac, res)
    with pytest.raises(ScannerRunError):
        _run(iac.TrivyIaCScanner(str(tmp_path)).scan())


def test_trivy_iac_missing_and_ok(monkeypatch, tmp_path):
    _patch(monkeypatch, iac, MISSING)
    assert _run(iac.TrivyIaCScanner(str(tmp_path)).scan()) == []
    _patch(monkeypatch, iac, (0, _TRIVY_IAC_OK, ""))
    assert len(_run(iac.TrivyIaCScanner(str(tmp_path)).scan())) == 1


def _dockerfiles(tmp_path, n=1):
    for i in range(n):
        (tmp_path / f"Dockerfile{i}").write_text("FROM x\n")


@pytest.mark.parametrize("res", [TIMEOUT, (2, "", "boom"), (1, "", ""), GARBAGE[:0] + (0, "{}", "")],
                         ids=["timeout", "bad-exit", "rc1-empty", "non-list"])
def test_hadolint_all_fail_raises(monkeypatch, tmp_path, res):
    _dockerfiles(tmp_path)
    _patch(monkeypatch, iac, res)
    with pytest.raises(ScannerRunError):
        _run(iac.HadolintScanner(str(tmp_path)).scan())


def test_hadolint_missing_clean_partial(monkeypatch, tmp_path):
    _dockerfiles(tmp_path, 2)
    _patch(monkeypatch, iac, MISSING)
    assert _run(iac.HadolintScanner(str(tmp_path)).scan()) == []
    _patch(monkeypatch, iac, (0, "[]", ""))
    assert _run(iac.HadolintScanner(str(tmp_path)).scan()) == []
    issue = json.dumps([{"code": "DL3006", "level": "warning", "line": 1, "message": "m"}])
    _patch(monkeypatch, iac, lambda cmd: (1, issue, "") if cmd[-1].endswith("Dockerfile0") else (2, "", "x"))
    assert len(_run(iac.HadolintScanner(str(tmp_path)).scan())) == 1


@pytest.mark.parametrize("res", [TIMEOUT, (1, "", "FATAL db update failed"), GARBAGE, (0, "[]", "")],
                         ids=["timeout", "bad-exit", "garbage", "non-object"])
def test_trivy_sca_failure_modes_raise(monkeypatch, tmp_path, res):
    _patch(monkeypatch, sca, res)
    with pytest.raises(ScannerRunError):
        _run(sca.TrivySCAScanner(str(tmp_path)).scan())


def test_trivy_sca_missing_and_ok(monkeypatch, tmp_path):
    _patch(monkeypatch, sca, MISSING)
    assert _run(sca.TrivySCAScanner(str(tmp_path)).scan()) == []
    _patch(monkeypatch, sca, (0, _TRIVY_SCA_OK, ""))
    assert len(_run(sca.TrivySCAScanner(str(tmp_path)).scan())) == 1


@pytest.mark.parametrize("res", [TIMEOUT, (2, "", "boom"), (1, "", "network error"), GARBAGE],
                         ids=["timeout", "bad-exit", "rc1-nojson", "garbage"])
def test_pip_audit_all_fail_raises(monkeypatch, tmp_path, res):
    (tmp_path / "requirements.txt").write_text("p==1\n")
    _patch(monkeypatch, sca, res)
    with pytest.raises(ScannerRunError):
        _run(sca.PipAuditScanner(str(tmp_path)).scan())


def test_pip_audit_missing_ok_and_partial(monkeypatch, tmp_path):
    (tmp_path / "requirements.txt").write_text("p==1\n")
    (tmp_path / "requirements-dev.txt").write_text("p==1\n")
    _patch(monkeypatch, sca, MISSING)
    assert _run(sca.PipAuditScanner(str(tmp_path)).scan()) == []
    _patch(monkeypatch, sca, lambda cmd: (1, _PIPAUDIT_OK, "") if cmd[2].endswith("requirements.txt") else (2, "", "x"))
    assert len(_run(sca.PipAuditScanner(str(tmp_path)).scan())) == 1


def _gitleaks(rc=0, report=None, stderr=""):
    async def fake(cmd, *a, **k):
        if report is not None:
            with open(cmd[cmd.index("--report-path") + 1], "w") as f:
                f.write(report)
        return rc, "", stderr
    return fake


@pytest.mark.parametrize("kw", [dict(rc=-1, stderr="Command timeout after 120s: gitleaks"),
                                dict(rc=2, stderr="boom"),
                                dict(rc=0, report="not json"),
                                dict(rc=0, report="{}")],
                         ids=["timeout", "bad-exit", "garbage-report", "non-list"])
def test_gitleaks_failure_modes_raise(monkeypatch, tmp_path, kw):
    monkeypatch.setattr(secrets, "run_command", _gitleaks(**kw))
    with pytest.raises(ScannerRunError):
        _run(secrets.GitleaksScanner(str(tmp_path)).scan())


def test_gitleaks_missing_clean_and_findings(monkeypatch, tmp_path):
    monkeypatch.setattr(secrets, "run_command", _gitleaks(rc=-1, stderr="Tool not found: gitleaks"))
    assert _run(secrets.GitleaksScanner(str(tmp_path)).scan()) == []
    monkeypatch.setattr(secrets, "run_command", _gitleaks(rc=0, report="null"))
    assert _run(secrets.GitleaksScanner(str(tmp_path)).scan()) == []
    monkeypatch.setattr(secrets, "run_command", _gitleaks(rc=0, report=json.dumps(
        [{"RuleID": "r", "File": "a.py", "StartLine": 1, "Match": "m"}])))
    assert len(_run(secrets.GitleaksScanner(str(tmp_path)).scan())) == 1


def test_detect_secrets_internal_error_raises(monkeypatch, tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    pytest.importorskip("detect_secrets")
    import detect_secrets.settings as ds
    def boom(*a, **k):
        raise RuntimeError("plugin crash")
    monkeypatch.setattr(ds, "transient_settings", boom)
    with pytest.raises(ScannerRunError):
        _run(secrets.DetectSecretsScanner(str(tmp_path)).scan())


def test_iac_failure_surfaces_in_orchestrator(monkeypatch, tmp_path):
    from scanner.orchestrator import Orchestrator
    _patch(monkeypatch, iac, (2, "", "boom"))
    monkeypatch.setattr(iac.CheckovScanner, "is_available", lambda self: True)
    _, logs = _run(Orchestrator(str(tmp_path), scan_types=["IAC"]).run())
    assert logs["checkov"]["status"] == "error"
