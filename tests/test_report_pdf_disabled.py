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


def test_no_browser_renderer_strings():
    # `file://` legitimately appears as a *blocked* scheme in pentest guards / CWE docs → exclude those.
    out = subprocess.run(
        ["git", "grep", "-nE", r"--print-to-pdf|file://|CHROMIUM_PATH", "--", "api", "scanner",
         ":!scanner/pentest", ":!scanner/knowledge"],
        cwd=ROOT, capture_output=True, text=True)
    assert out.stdout == "", out.stdout
    out = subprocess.run(
        ["git", "grep", "-nE", r"--print-to-pdf|CHROMIUM_PATH", "--", "api", "scanner"],
        cwd=ROOT, capture_output=True, text=True)
    assert out.stdout == "", out.stdout


def test_ui_download_report_pdf_has_no_window_open():
    src = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    m = re.search(r"async function downloadReportPdf\(.*?\n}\n", src, re.S)
    assert m, "downloadReportPdf not found"
    assert "window.open(" not in m.group(0)
