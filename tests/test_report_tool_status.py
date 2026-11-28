"""Reports must show per-tool status (failed / skipped / partial) instead of reading as clean."""
import types

import pytest

from scanner import report_pro
from scanner.pdf import adapters, engine
from scanner.report_tools import tool_status
from tests._pdf_fixtures import NOW, make_scan
from tests._pdf_helpers import norm, pdf_text

LOGS = {
    "bandit": {"status": "ok", "count": 3, "label": "Bandit"},
    "trivy": {"status": "skipped", "count": 0, "error": "not installed"},
    "gitleaks": {"status": "error", "count": 0, "error": "boom\x00\x1b[31m"},
    "semgrep": {"status": "partial", "count": 2, "error": "registry pass skipped"},
    "weird": {"status": "???", "count": "x"},
}


def _summary(**kw):
    return {"scanner_logs": LOGS, **kw}


@pytest.mark.parametrize("s", [None, {}, {"scanner_logs": {}}, {"scanner_logs": None}, "x"])
def test_tool_status_empty(s):
    assert tool_status(s) == {"rows": [], "has_gap": False, "warning": ""}


def test_tool_status_all_ok():
    r = tool_status({"scanner_logs": {"a": {"status": "ok", "count": 1}}, "scan_warning": "ignored"})
    assert r["has_gap"] is False and r["warning"] == "" and r["rows"][0]["status"] == "ok"


def test_tool_status_mixed():
    r = tool_status(_summary())
    assert r["has_gap"] and r["warning"]
    st = {x["tool"]: x["status"] for x in r["rows"]}
    assert st == {"bandit": "ok", "trivy": "skipped", "gitleaks": "error", "semgrep": "partial", "weird": "error"}
    assert r["rows"][-1]["tool"] == "bandit"                      # gaps first
    assert all("\x00" not in x["error"] and "\x1b" not in x["error"] for x in r["rows"])
    assert tool_status(_summary(scan_warning="custom"))["warning"] == "custom"
    long = tool_status({"scanner_logs": {"t": {"status": "error", "error": "e" * 5000}}})
    assert len(long["rows"][0]["error"]) <= 160


def _render(summary):
    scan = types.SimpleNamespace(scan_number=1, scan_path="/w", scan_types=["SAST"], started_at=None,
                                 status=types.SimpleNamespace(value="COMPLETED"), summary=summary)
    return report_pro.render(project=types.SimpleNamespace(name="Demo"), scan=scan, grouped={},
                             severity_counts={}, vulns=[])


def test_html_shows_statuses_and_banner():
    html = _render(_summary())
    for t in ("BỎ QUA", "LỖI", "MỘT PHẦN", "Công cụ đã dùng", "tool-gap"):
        assert t in html


def test_html_escapes_error_text():
    html = _render({"scanner_logs": {"t": {"status": "error", "error": "<script>alert(1)</script>"}}})
    assert "<script>alert(1)" not in html and "&lt;script&gt;" in html


@pytest.mark.parametrize("s", [None, {}, {"scanner_logs": {}}])
def test_html_old_scan_has_no_section(s):
    html = _render(s)
    assert "Công cụ đã dùng" not in html and "tool-gap" not in html


def _scan_with(summary):
    p, s, g, c = make_scan(3)
    s.summary = summary
    return p, s, g, c


@pytest.mark.parametrize("lang,words", [("vi", ("BỎ QUA", "LỖI", "MỘT PHẦN")), ("en", ("SKIPPED", "FAILED", "PARTIAL"))])
def test_pdf_shows_statuses(lang, words):
    p, s, g, c = _scan_with(_summary(scan_warning="Gap warning text"))
    doc = adapters.scan_doc(p, s, g, c, now=NOW, lang=lang)
    text = norm(pdf_text(engine.render("scan", doc, generated_at=0)))
    for w in words:
        assert norm(w) in text
    assert norm("Gap warning text") in text
    assert any(k == doc["labels"]["kv_tool_status"] for k, _ in doc["meta"]["kv"])


def test_pdf_without_logs_unchanged():
    p, s, g, c = make_scan(3)
    doc = adapters.scan_doc(p, s, g, c, now=NOW)
    assert doc["summary"]["tool_status"] == [] and doc["summary"]["warning"] == ""
    p, s, g, c = _scan_with({"scanner_logs": {}})
    assert adapters.scan_doc(p, s, g, c, now=NOW) == adapters.scan_doc(*make_scan(3), now=NOW)


def test_pdf_hostile_error_text_is_literal():
    evil = '#import "x"] $ @ ‮ ' + "A" * 10000
    p, s, g, c = _scan_with({"scanner_logs": {"t": {"status": "error", "error": evil, "label": evil}}})
    base = adapters.scan_doc(*make_scan(3), now=NOW)
    doc = adapters.scan_doc(p, s, g, c, now=NOW)
    assert len(doc["summary"]["tool_status"][0]["detail"]) <= 400
    pdf = engine.render("scan", doc, generated_at=0)
    ref = engine.render("scan", base, generated_at=0)
    assert norm('#import"x"]$@') in norm(pdf_text(pdf))
    from pypdf import PdfReader
    import io
    assert len(PdfReader(io.BytesIO(pdf)).pages) <= len(PdfReader(io.BytesIO(ref)).pages) + 1
