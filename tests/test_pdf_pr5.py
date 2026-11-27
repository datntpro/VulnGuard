"""PDF PR-5: mailer uses Typst, fpdf2 gone, prose scrub + caps, per-instance job dirs, filename date, filter docs."""
import os
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch

import pytest

from api.services import pdf_export as px
from scanner.pdf import adapters, engine
from tests._pdf_fixtures import NOW, make_scan
from tests._pdf_helpers import norm, pdf_text

ROOT = Path(__file__).resolve().parent.parent
AWS = "AKIAIOSFODNN7EXAMPLE"
GH = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"


# ── fpdf2 / old fonts removed ──
def _grep(pattern, *paths):
    return subprocess.run(["git", "grep", "-nE", pattern, "--", *paths], cwd=ROOT, capture_output=True, text=True).stdout


def test_fpdf2_fully_removed():
    assert not _grep(r"\bfpdf\b|from fpdf|import fpdf|build_pdf\(|to_pdf\(", "api/*.py", "api/**/*.py", "scanner", "mcp_server", "scripts")
    for f in ("api/requirements.in", "api/requirements.txt", "requirements-dev.in", "requirements-dev.txt"):
        assert "fpdf2" not in (ROOT / f).read_text().lower()
    assert not (ROOT / "scanner" / "assets" / "fonts").exists()
    from scanner import report_builder as rb
    assert not hasattr(rb, "build_pdf")


# ── prose scrub + cap ──
def test_prose_fields_scrubbed_all_adapters():
    p, s, g, c = make_scan(2)
    it = g["SAST"][0]["items"][0]
    it["description"] = f"leak {AWS} and token={GH}"
    g["SAST"][0]["ai_fix_suggestion"] = f"rotate {GH}"
    doc = adapters.scan_doc(p, s, g, c, now=NOW)
    blob = str(doc["findings"])
    assert AWS not in blob and GH not in blob
    ws = adapters.webscan_doc(NS(id="x", started_at=None, status=None, authorized_by="a"),
                              [{"name": "n", "severity": "high", "matched_at": f"https://x.example/?k={GH}&a={AWS}",
                                "description": f"d {AWS}", "remediation": f"use {GH}", "reference": []}])
    blob = str(ws["findings"])
    assert AWS not in blob and GH not in blob
    pdf = engine.render("webscan", ws, generated_at=0)
    assert norm(AWS) not in norm(pdf_text(pdf)) and norm(GH) not in norm(pdf_text(pdf))
    rows = [NS(status=NS(value="NOT_MET"), criteria_id="A-1", criteria_text=f"x {AWS}", category="c", evidence="",
               recommendation=f"fix {GH}")]
    d = adapters.docreview_doc(NS(name="d"), NS(version_number=1), rows, {"total": 1, "not_met": 1})
    assert AWS not in str(d["findings"]) and GH not in str(d["findings"])
    m = __import__("tests._pdf_fixtures", fromlist=["x"]).make_pentest_model()
    m["findings"][0]["description"] = f"d {AWS}"
    m["findings"][0]["remediation"] = f"r {GH}"
    m["findings"][0]["target"] = f"https://x/?t={GH}"
    pd = adapters.pentest_doc(m)
    assert AWS not in str(pd["findings"]) and GH not in str(pd["findings"])


def test_per_field_cap_before_layout():
    big = "A" * 100_000
    p, s, g, c = make_scan(3)
    for grp in g.values():
        for x in grp:
            x["items"][0]["description"] = big
            x["items"][0]["file_path"] = big
            x["ai_fix_suggestion"] = big
    t0 = time.time()
    doc = adapters.scan_doc(p, s, g, c, now=NOW)
    for f in doc["findings"]:
        assert len(f["description"]) <= adapters.MAX_FIELD and len(f["remediation"]) <= adapters.MAX_FIELD
        assert len(f["location"]) <= adapters.MAX_LOCATION + 200   # + "(+N more)" suffix
    pdf = engine.render("scan", doc, generated_at=0)
    assert pdf.startswith(b"%PDF") and time.time() - t0 < 10
    ws = adapters.webscan_doc(NS(id="x", started_at=None, status=None, authorized_by="a"),
                              [{"name": "n", "severity": "high", "matched_at": big, "description": big, "remediation": big, "reference": []}])
    f = ws["findings"][0]
    assert max(len(f["description"]), len(f["remediation"])) <= adapters.MAX_FIELD and len(f["location"]) <= adapters.MAX_LOCATION


# ── filename* keeps the date ──
def test_utf8_stem_long_name_keeps_date():
    stem = px._utf8_stem("VulnGuard_" + "Ngân_hàng_" * 20 + "_20261127")
    assert len(stem) <= 80 and stem.endswith("_20261127") and stem.startswith("VulnGuard_")
    cd = px.content_disposition("a", "VulnGuard_" + "Đ" * 200 + "_20261127")
    assert cd.endswith("_20261127.pdf") or "_20261127.pdf" in cd.replace("%5F", "_")
    assert px._utf8_stem("short_20261127") == "short_20261127"


# ── multi-worker job sweep ──
def test_sweep_never_deletes_other_instance_files(monkeypatch):
    root = px.jobs_root()
    other = root / "w999999-deadbeef"
    other.mkdir(exist_ok=True)
    live = other / ("c" * 32 + ".pdf")
    live.write_bytes(b"%PDF-1.7 other worker")
    stale = other / ("d" * 32 + ".pdf")
    stale.write_bytes(b"%PDF-1.7 stale")
    old = time.time() - 2 * px.JOB_TTL_S - 10
    os.utime(stale, (old, old))
    legacy = root / ("e" * 32 + ".pdf")
    legacy.write_bytes(b"x")
    mine = px.jobs_dir() / ("f" * 32 + ".pdf")
    mine.write_bytes(b"orphan of mine")
    px._sweep()
    assert live.exists(), "other instance's live job file must survive"
    assert legacy.exists(), "recent legacy flat file: owner unknown, keep"
    assert not stale.exists(), "abandoned (>2xTTL) foreign file reclaimed"
    assert not mine.exists(), "own orphan removed"
    # far in the future everything foreign is reclaimable, still never our dir's live (known) jobs
    px._sweep(time.time() + 3 * px.JOB_TTL_S)
    assert not live.exists() and not legacy.exists()
    assert not other.exists()  # emptied foreign dir removed


def test_instance_dir_is_per_process_and_private():
    d = px.jobs_dir()
    assert d.name == px.instance_id() and d.parent == px.jobs_root()
    assert (d.stat().st_mode & 0o077) == 0
    assert px._INSTANCE_DIR.fullmatch(d.name)


# ── mailer ──
def _mail_fixtures():
    from tests.test_pdf_api import _seed_scan
    sid, name = _seed_scan(n=2)
    return sid, name


def test_mailer_attaches_typst_pdf():
    from api.database import SessionLocal
    from api.services import mailer
    sid, name = _mail_fixtures()
    sent = {}
    db = SessionLocal()
    try:
        with patch.object(mailer, "send_email", lambda to, subj, body, att=None: sent.update(to=to, subj=subj, body=body, att=att)):
            mailer.send_scan_report(db, sid, "o@example.com", name)
    finally:
        db.close()
    (a,) = sent["att"]
    assert a["mime"] == "application/pdf" and a["content"][:5] == b"%PDF-" and a["filename"].endswith(".pdf")
    assert "đính kèm" in sent["body"]
    assert b"fpdf" not in a["content"][:2000].lower()          # not produced by the old renderer


def test_mailer_engine_failure_sends_without_attachment():
    from api.database import SessionLocal
    from api.services import mailer
    from scanner.pdf.errors import PdfCompileError
    sid, name = _mail_fixtures()
    sent = {}
    db = SessionLocal()
    try:
        with patch.object(mailer, "send_email", lambda to, subj, body, att=None: sent.update(body=body, att=att)), \
             patch.object(px, "render_pdf", side_effect=PdfCompileError("boom")):
            mailer.send_scan_report(db, sid, "o@example.com", name)
    finally:
        db.close()
    assert sent["att"] == [] and "Không tạo được PDF" in sent["body"]


# ── /export?format=pdf ignores filters (documented + header) ──
def test_export_pdf_ignores_filters_and_says_so():
    from tests.test_pdf_api import _client, _seed_scan
    c, h, _ = _client()
    sid, _ = _seed_scan(n=3)
    r = c.get(f"/api/projects/scans/{sid}/export?format=pdf&severity=LOW&diff=new&scope=active", headers=h)
    assert r.status_code == 200 and r.content[:5] == b"%PDF-"
    assert set(r.headers["x-vg-filters-ignored"].split(",")) == {"severity", "diff", "scope"}
    assert "SQLi" in pdf_text(r.content)                     # the HIGH findings are still there despite severity=LOW
    r2 = c.get(f"/api/projects/scans/{sid}/export?format=pdf", headers=h)
    assert "x-vg-filters-ignored" not in r2.headers
    doc = (ROOT / "docs/wiki/Reports-and-Exports.md").read_text()
    assert "bỏ qua" in doc and "X-VG-Filters-Ignored" in doc
