"""PR-0: renderer PDF Chromium CLI đã gỡ; format=pdf → 503, không fallback in."""
import re
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.main import app
from tests._authutil import bearer, login, make_user

ROOT = Path(__file__).resolve().parent.parent


def test_format_pdf_returns_503_json():
    c = TestClient(app)
    email, _ = make_user()
    h = bearer(login(c, email))
    r = c.get("/api/scans/does-not-matter/report?format=pdf", headers=h)
    assert r.status_code == 503
    assert "text/html" not in r.headers["content-type"]
    assert r.json()["detail"]["code"] == "pdf_export_disabled"


def test_pdf_render_module_gone():
    with pytest.raises(ModuleNotFoundError):
        import scanner.pdf_render  # noqa: F401


def _git_grep(pattern, *pathspecs, cwd=ROOT):
    """rc 1 = no match. Pattern goes after -e so a leading `--` is never parsed as an option."""
    return subprocess.run(["git", "grep", "-nE", "-e", pattern, "--", *pathspecs],
                          cwd=cwd, capture_output=True, text=True)


def _assert_no_match(pattern, *pathspecs, cwd=ROOT):
    out = _git_grep(pattern, *pathspecs, cwd=cwd)
    assert out.returncode == 1, f"rc={out.returncode} stdout={out.stdout!r} stderr={out.stderr!r}"


def test_no_browser_renderer_strings():
    # `file://` legitimately appears as a *blocked* scheme in pentest guards / CWE docs → excluded.
    _assert_no_match(r"--print-to-pdf|file://|CHROMIUM_PATH", "api", "scanner", "mcp_server", "scripts",
                     ":!scanner/pentest", ":!scanner/knowledge")
    _assert_no_match(r"--print-to-pdf|CHROMIUM_PATH", "api", "scanner", "mcp_server", "scripts")


@pytest.mark.parametrize("planted", ["# x --print-to-pdf", "# CHROMIUM_PATH", "# file:///etc/hosts"])
def test_grep_guard_detects_planted_string(tmp_path, planted):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "api").mkdir()
    f = tmp_path / "api" / "x.py"
    f.write_text(planted + "\n")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    out = _git_grep(r"--print-to-pdf|file://|CHROMIUM_PATH", "api", cwd=tmp_path)
    assert out.returncode == 0 and planted.split()[-1] in out.stdout
    with pytest.raises(AssertionError):
        _assert_no_match(r"--print-to-pdf|file://|CHROMIUM_PATH", "api", cwd=tmp_path)


def test_grep_guard_fails_on_git_error(tmp_path):
    with pytest.raises(AssertionError):   # not a repo → rc 128, must not pass silently
        _assert_no_match("x", "api", cwd=tmp_path)


def test_ui_download_report_pdf_has_no_window_open():
    src = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    m = re.search(r"async function downloadReportPdf\(.*?\n}\n", src, re.S)
    assert m, "downloadReportPdf not found"
    assert "window.open(" not in m.group(0)
