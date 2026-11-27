"""PR-4: self-test used by Docker build, setup.py --check and run.sh."""
import re
import subprocess
import sys
from pathlib import Path

import pytest

from scanner.pdf import selftest

ROOT = Path(__file__).resolve().parent.parent


def test_selftest_passes_in_process():
    res = selftest.run_all()
    assert res and all(err is None for _, err in res), res


def test_selftest_cli_ok():
    p = subprocess.run([sys.executable, "-m", "scanner.pdf.selftest", "--quiet"],
                       cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stdout + p.stderr
    assert p.stdout.strip().startswith("PDF engine: typst ") and p.stdout.strip().endswith("OK")


def test_selftest_reports_why_when_wheel_missing(monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "typst", None)  # import typst -> ImportError
    assert selftest.main([]) == 1
    cap = capsys.readouterr()
    assert "typst wheel not importable" in cap.out
    assert "FAILED" in cap.err and "requirements.txt" in cap.err


def test_selftest_detects_bad_font():
    from unittest import mock

    pdf = selftest.check_render()
    selftest.check_fonts(pdf)  # baseline ok
    with mock.patch.object(selftest, "ALLOWED_FONT", re.compile(r"^nothing$")):
        with pytest.raises(selftest.SelfTestError, match="unexpected font"):
            selftest.check_fonts(pdf)


def test_dockerfile_runs_selftest_after_source_copy():
    df = (ROOT / "api" / "Dockerfile").read_text()
    i_run = df.index("scanner.pdf.selftest")
    assert i_run > df.index("COPY scanner/ ./scanner/")
    assert "--require-hashes -r requirements.txt" in df
