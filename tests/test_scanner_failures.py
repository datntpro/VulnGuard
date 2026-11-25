"""N-4: một scanner chạy hỏng KHÔNG được báo "ok, 0 findings"."""
import asyncio
import json

import pytest

from scanner.scanners import sast, container
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
    assert "|| echo" not in text.split("semgrep==")[1]
