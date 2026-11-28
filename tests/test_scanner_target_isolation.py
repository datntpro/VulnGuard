"""Scanners run with VulnGuard-owned configuration and never act on config supplied by the scanned tree."""
import asyncio
import os
import shutil
from pathlib import Path

import pytest

from scanner.scanners import iac, sast, secrets
from scanner.scanners import selftest

ROOT = Path(__file__).resolve().parent.parent
CFG = ROOT / "scanner" / "config"
FX = str(ROOT / "tests" / "fixtures")


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _capture(monkeypatch, module, scanner, stdout="{}", rc=0):
    seen = {}

    async def fake(cmd, *a, **k):
        seen["cmd"], seen["kw"] = cmd, k
        if k.get("cwd") and os.path.isdir(k["cwd"]):
            seen["cwd_listing"] = os.listdir(k["cwd"])
        return rc, stdout, ""
    monkeypatch.setattr(module, "run_command", fake)
    try:
        _run(scanner.scan())
    except Exception:  # noqa: BLE001 - only the argv matters here
        pass
    return seen


def test_checkov_argv_uses_single_token_directory_and_empty_cwd(monkeypatch, tmp_path):
    seen = _capture(monkeypatch, iac, iac.CheckovScanner(str(tmp_path)))
    cmd, kw = seen["cmd"], seen["kw"]
    assert "-d" not in cmd and "--directory" not in cmd and "--config-file" not in cmd
    assert [a for a in cmd if a.startswith("--directory=")] == [f"--directory={tmp_path}"]
    assert kw["cwd"] and not str(kw["cwd"]).startswith(str(tmp_path))
    assert seen["cwd_listing"] == []
    key = kw["env"]["CKV_EXTERNAL_CHECKS_PUBLIC_KEY"]
    assert os.path.isfile(key) and os.path.dirname(os.path.realpath(key)) == os.path.realpath(CFG)
    try:
        from checkov.common.util.config_utils import get_default_config_paths
    except Exception:  # noqa: BLE001
        pytest.skip("checkov not installed")
    assert not [p for p in get_default_config_paths(cmd[1:]) if str(tmp_path) in str(p)]


def test_gitleaks_argv_has_owned_config_and_ignore_path(monkeypatch, tmp_path):
    seen = _capture(monkeypatch, secrets, secrets.GitleaksScanner(str(tmp_path)))
    cmd = seen["cmd"]
    cfg = cmd[cmd.index("--config") + 1]
    assert os.path.realpath(cfg) == os.path.realpath(CFG / "gitleaks.toml")
    assert "--ignore-gitleaks-allow" in cmd and "--follow-symlinks" not in cmd
    ign = cmd[cmd.index("--gitleaks-ignore-path") + 1]
    assert not ign.startswith(str(tmp_path))
    assert seen["kw"]["cwd"] and not str(seen["kw"]["cwd"]).startswith(str(tmp_path))


def test_gitleaks_target_ignore_file_marks_partial(monkeypatch, tmp_path):
    (tmp_path / ".gitleaksignore").write_text("x:y:z:1\n")
    sc = secrets.GitleaksScanner(str(tmp_path))
    _capture(monkeypatch, secrets, sc)
    assert sc.warnings
    clean = secrets.GitleaksScanner(str(tmp_path / "nope"))
    _capture(monkeypatch, secrets, clean)
    assert not clean.warnings


def test_bandit_uses_owned_ini(monkeypatch, tmp_path):
    seen = _capture(monkeypatch, sast, sast.BanditScanner(str(tmp_path)), stdout='{"results": []}')
    cmd = seen["cmd"]
    assert os.path.realpath(cmd[cmd.index("--ini") + 1]) == os.path.realpath(CFG / "bandit.ini")
    assert (CFG / "bandit.ini").read_text() == "[bandit]\n"
    assert seen["kw"]["cwd"] and not str(seen["kw"]["cwd"]).startswith(str(tmp_path))


def test_semgrep_ignores_target_ignore_files(monkeypatch, tmp_path):
    seen = _capture(monkeypatch, sast, sast.SemgrepScanner(str(tmp_path)), stdout='{"results": []}')
    # first run_command call is the one captured last; both runs share the same flags
    cmd = seen["cmd"]
    assert "--x-ignore-semgrepignore-files" in cmd
    excl = {cmd[i + 1] for i, a in enumerate(cmd) if a == "--exclude"}
    assert set(sast.SEMGREP_DEFAULT_IGNORES) <= excl


# Real-tool checks (skipped when the binary is absent; also run in the image by scanner.scanners.selftest).
def _real(tool, fn):
    if not shutil.which(tool):
        pytest.skip(f"{tool} not installed")
    n, _ = fn(FX)
    assert n >= 1


def test_checkov_ignores_target_config():
    _real("checkov", selftest._checkov_isolation)


def test_gitleaks_ignores_target_config():
    _real("gitleaks", selftest._gitleaks_isolation)


def test_bandit_ignores_target_ini():
    _real("bandit", selftest._bandit_isolation)


def test_semgrep_ignores_target_ignore_file():
    _real("semgrep", selftest._semgrep_isolation)
