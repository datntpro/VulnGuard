"""Offline tests for scripts/audit_scanner_locks.py (#101 PR-C): pip-audit is injected."""
import copy
import datetime as dt
import importlib.util
import sys
from pathlib import Path

import pytest

if sys.version_info < (3, 11):
    pytest.skip("audit_scanner_locks needs tomllib (3.11+)", allow_module_level=True)

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("audit_scanner_locks", ROOT / "scripts" / "audit_scanner_locks.py")
asl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(asl)

TODAY = dt.date(2026, 11, 28)
ENTRY = {"id": "CVE-1", "aliases": ["GHSA-x"], "lock": "semgrep", "package": "mcp", "version": "1.29.0",
         "reason": "r", "evidence": "e", "added": dt.date(2026, 11, 28), "expires": dt.date(2027, 2, 26),
         "tracking": "#101"}
REPORT = {"dependencies": [{"name": "mcp", "version": "1.29.0",
                            "vulns": [{"id": "GHSA-x", "aliases": ["CVE-1"], "fix_versions": ["1.30.0"]}]}]}


def entry(**kw):
    e = copy.deepcopy(ENTRY)
    e.update(kw)
    return e


def test_valid_ignore_passes():
    ok, errs = asl.validate([entry()], TODAY)
    assert ok and not errs
    errors, warnings, applied = asl.evaluate("semgrep", ok, REPORT)
    assert not errors and not warnings and applied == ["GHSA-x"]


def test_unignored_vuln_fails_with_id():
    errors, _, _ = asl.evaluate("semgrep", [], REPORT)
    assert len(errors) == 1 and "GHSA-x" in errors[0]


def test_expired_ignore_fails():
    ok, errs = asl.validate([entry(expires=dt.date(2026, 11, 27))], TODAY)
    assert not ok and "expired 2026-11-27" in errs[0]


def test_missing_field_fails():
    e = entry()
    del e["evidence"]
    _, errs = asl.validate([e], TODAY)
    assert "evidence" in errs[0]


def test_expiry_over_120_days_fails():
    _, errs = asl.validate([entry(expires=dt.date(2027, 4, 1))], TODAY)
    assert "120 days" in errs[0]


def test_version_mismatch_fails():
    errors, _, _ = asl.evaluate("semgrep", [entry(version="1.28.0")], REPORT)
    assert errors and "1.28.0" in errors[0] and "1.29.0" in errors[0]


def test_stale_ignore_warns_only():
    errors, warnings, _ = asl.evaluate("semgrep", [entry()], {"dependencies": []})
    assert not errors and "no longer reported" in warnings[0]


def test_repo_ignores_file_is_valid_and_main_gates(tmp_path, monkeypatch, capsys):
    entries = asl.load_ignores(ROOT / "docker" / "scanners" / "audit-ignores.toml")
    ok, errs = asl.validate(entries, TODAY)
    assert not errs and len(ok) == len(entries)
    # canned audit: mcp vuln only, lock otherwise clean
    def audit(_bin, lock, _ids):
        return REPORT if lock.name == "semgrep.txt" else {"dependencies": []}
    # repo ignores don't cover CVE-1 -> gate fails; an ignore file that does -> passes
    rc = asl.main(["--ignores", str(ROOT / "docker" / "scanners" / "audit-ignores.toml")], audit=audit, today=TODAY)
    assert rc == 1
    f = tmp_path / "i.toml"
    f.write_text('[[ignore]]\nid="CVE-1"\nlock="semgrep"\npackage="mcp"\nversion="1.29.0"\nreason="r"\n'
                 'evidence="e"\nadded=2026-11-28\nexpires=2027-02-26\ntracking="#1"\n')
    assert asl.main(["--ignores", str(f)], audit=audit, today=TODAY) == 0
    assert asl.main(["--ignores", str(f)], audit=audit, today=dt.date(2027, 3, 1)) == 1
