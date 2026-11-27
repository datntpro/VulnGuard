"""PR-2: golden text extraction, Vietnamese diacritics, page counts, TOC page numbers, ligatures,
all four report kinds, EN labels. Update goldens with ``VG_UPDATE_GOLDEN=1 pytest tests/test_pdf_golden.py``."""
import io
import os
import re
from pathlib import Path
from types import SimpleNamespace as NS

import pytest
from pypdf import PdfReader

from scanner.pdf import adapters, engine
from tests._pdf_fixtures import NOW, make_pentest_model, make_scan
from tests._pdf_helpers import norm

GOLDEN = Path(__file__).parent / "data" / "pdf_golden"
TS = 1795000000


def _scan_pdf(n=8, lang="vi", hostile=False):
    p, s, g, c = make_scan(n, hostile=hostile)
    doc = adapters.scan_doc(p, s, g, c, lang=lang, now=NOW, branding={"org_name": "Công ty ABC"})
    return engine.render("scan", doc, generated_at=TS)


def _pages(pdf):
    return [(pg.extract_text() or "") for pg in PdfReader(io.BytesIO(pdf)).pages]


def _golden_text(pages, upto):
    t = "\n".join(pages[:upto])
    t = t.replace("​", "")
    return "\n".join(re.sub(r"[ \t]+", " ", ln).strip() for ln in t.split("\n") if ln.strip()) + "\n"


def _check_golden(name, text):
    path = GOLDEN / name
    if os.environ.get("VG_UPDATE_GOLDEN"):
        path.write_text(text, encoding="utf-8")
    # whitespace-insensitive: letter-spaced (tracked) text extracts with varying gaps
    assert norm(path.read_text(encoding="utf-8")) == norm(text)


def test_scan_golden_cover_toc_summary_first_card():
    pages = _pages(_scan_pdf())
    # cover, TOC, summary, first detail page
    _check_golden("scan.txt", _golden_text(pages, 4))


def test_pentest_golden():
    doc = adapters.pentest_doc(make_pentest_model(), org="Công ty ABC")
    pages = _pages(engine.render("pentest", doc, generated_at=TS))
    _check_golden("pentest.txt", _golden_text(pages, 4))
    text = "".join(pages)
    n = norm(text)
    assert "ĐÃXÁCMINHBỞIVALIDATOR" in n  # verified badge
    assert "CVSSv4.0" in n and "CVSS:4.0/AV:N/AC:L" in n  # mandatory v4 score + vector
    assert "TRÍCHĐOẠNTRAFFIC" in n and "Authorization:[REDACTED]" in n


def test_vietnamese_diacritics_extract_exactly():
    text = "".join(_pages(_scan_pdf()))
    n = norm(text)
    for word in ("Đốitượngkiểmthử", "Nghiêmtrọng", "KHẮCPHỤC"):
        assert word in n, word
    assert "Đ" in text and "Ð" not in text  # Đ present, Ð (Eth) absent
    p, s, g, c = make_scan(1)
    doc = adapters.scan_doc(p, s, g, c, now=NOW)
    doc["findings"][0]["description"] = "Ư Ơ ỹ ặ ẫ"
    t2 = norm("".join(_pages(engine.render("scan", doc, generated_at=TS))))
    assert "ƯƠỹặẫ" in t2


def test_ligatures_off_in_code():
    p, s, g, c = make_scan(1)
    g["SAST"][0]["items"][0]["code_snippet"] = "a => b != c -> d"
    doc = adapters.scan_doc(p, s, g, c, now=NOW)
    t = "".join(_pages(engine.render("scan", doc, generated_at=TS)))
    assert "=> b != c -> d" in t


def test_page_count_8_findings():
    assert len(PdfReader(io.BytesIO(_scan_pdf(8))).pages) == 7


def test_english_labels_and_lang():
    t = norm("".join(_pages(_scan_pdf(8, "en"))))
    assert "Executivesummary" in t and "Tableofcontents" in t and "REMEDIATION" in t
    assert "Tómtắtđiềuhành" not in t


def test_toc_page_numbers_match_headings():
    pdf = _scan_pdf(8)
    pages = _pages(pdf)
    toc = pages[1]
    ids = re.findall(r"(VG-\d{3}) · ", toc)
    assert ids == [f"VG-{i:03d}" for i in range(1, len(ids) + 1)] and len(ids) >= 5
    for m in re.finditer(r"(VG-\d{3}) · [^\n]*?(\d+)\s*$", toc, re.M):
        vid, page = m.group(1), int(m.group(2))
        assert f"{vid} · " in pages[page - 1], (vid, page)  # page numbers start at 1 on the cover


def test_card_cap_and_low_table():
    pdf = _scan_pdf(30)
    t = "".join(_pages(pdf))
    assert "LOW" in t.upper() or "THẤP" in t.upper()


def test_webscan_and_docreview_render():
    scan = NS(id="abcd1234efgh", started_at=NOW, status=NS(value="COMPLETED"), authorized_by="a@b.c")
    fs = [{"name": "Exposed .git", "severity": "high", "matched_at": "https://x.example/.git/config", "host": "x.example",
           "description": "d", "remediation": "r", "reference": ["x"], "cwe": "CWE-538", "cve": None, "cvss_score": None,
           "template_id": "git-config", "status": "OPEN", "curl_command": "curl https://x.example/.git/config", "extracted": []}]
    pages = _pages(engine.render("webscan", adapters.webscan_doc(scan, fs, now=NOW), generated_at=TS))
    assert "Exposed .git" in "".join(pages)
    st = lambda v: NS(value=v)  # noqa: E731
    rows = [NS(status=st("NOT_MET"), criteria_id="ASVS-2.1.1", criteria_text="Mật khẩu tối thiểu 12 ký tự", category="Xác thực",
               evidence="", recommendation="Bổ sung chính sách mật khẩu"),
            NS(status=st("MET"), criteria_id="ASVS-2.1.2", criteria_text="Khoá tài khoản", category="Xác thực", evidence="Mục 3", recommendation="")]
    summ = {"met": 1, "partial": 0, "not_met": 1, "not_applicable": 0, "total": 2, "score_pct": 50.0}
    doc = adapters.docreview_doc(NS(name="Thiết kế hệ thống"), NS(version_number=2), rows, summ, now=NOW)
    t = norm("".join(_pages(engine.render("docreview", doc, generated_at=TS))))
    assert "ASVS-2.1.1" in t and "Thiếtkếhệthống" in t


@pytest.mark.slow
def test_large_report_page_count_500():
    n = len(PdfReader(io.BytesIO(_scan_pdf(500))).pages)
    assert 60 <= n <= 90, n
