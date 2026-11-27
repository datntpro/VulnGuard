"""PR-2 verify fixes: secrets never reach the PDF (all adapters), worst-case target-controlled bodies
cannot break the export, redaction-error headers, ellipsis/org clamps."""
import io
from types import SimpleNamespace as NS

import pytest
from pypdf import PdfReader

from scanner.pdf import adapters, engine
from tests._pdf_fixtures import NOW, make_pentest_model, make_scan
from tests._pdf_helpers import norm, pdf_text

SECRETS = [
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    "s3cr3tSessionCookieValue99887766",
]
BLOB = "\n".join([
    "Authorization: Bearer " + SECRETS[1],
    "Cookie: session=" + SECRETS[3],
    "aws_access_key_id = " + SECRETS[0],
    'password = "' + SECRETS[3] + '"',
    '{"token": "' + SECRETS[2] + '"}',
])


def _no_secret(pdf):
    t = norm(pdf_text(pdf))
    for s in SECRETS:
        assert norm(s) not in t, s


def test_secrets_never_in_pdf_all_adapters():
    # scan
    p, s, g, c = make_scan(2)
    g["SAST"][0]["items"][0]["code_snippet"] = BLOB
    _no_secret(engine.render("scan", adapters.scan_doc(p, s, g, c, now=NOW), generated_at=0))
    # pentest (model-level redaction defeated on purpose)
    m = make_pentest_model()
    f = m["findings"][0]
    f["evidence"] = BLOB
    f["evidence_traffic"]["request_headers"] = {"Authorization": "Bearer " + SECRETS[1], "Cookie": "session=" + SECRETS[3]}
    f["evidence_traffic"]["request_body"] = BLOB
    f["evidence_traffic"]["response_body"] = BLOB
    f["poc"] = {"curl": "curl -H 'Authorization: Bearer %s' https://x" % SECRETS[1], "steps": [BLOB]}
    _no_secret(engine.render("pentest", adapters.pentest_doc(m), generated_at=0))
    # webscan: extracted + curl_command omitted entirely (parity with the HTML report)
    scan = NS(id="x", started_at=None, status=None, authorized_by="a")
    fs = [{"name": "Exposed token", "severity": "high", "matched_at": "https://x.example/", "description": BLOB,
           "remediation": "r", "reference": [], "extracted": SECRETS, "curl_command": "curl -H 'Authorization: Bearer %s' x" % SECRETS[1]}]
    pdf = engine.render("webscan", adapters.webscan_doc(scan, fs), generated_at=0)
    _no_secret(pdf)
    assert "Exposed token" in pdf_text(pdf)
    # docreview
    rows = [NS(status=NS(value="NOT_MET"), criteria_id="A-1", criteria_text="x", category="c", evidence=BLOB, recommendation="")]
    doc = adapters.docreview_doc(NS(name="d"), NS(version_number=1), rows, {"total": 1, "not_met": 1})
    _no_secret(engine.render("docreview", doc, generated_at=0))


def _heavy_model(n):
    m = make_pentest_model()
    base = m["findings"][0]
    body = "\n".join("x" for _ in range(750))  # 1500 chars, 750 lines
    fs = []
    for i in range(n):
        f = dict(base, id=f"f{i}", evidence=body, evidence_traffic=dict(base["evidence_traffic"], request_body=body, response_body=body))
        f["poc"] = {"curl": body, "steps": [body] * 30}
        fs.append(f)
    m["findings"] = fs
    m["executive_summary"]["total"] = n
    return m


@pytest.mark.parametrize("n", [100, 300])
def test_worst_case_newline_dense_bodies_render(n):
    pdf = engine.render("pentest", adapters.pentest_doc(_heavy_model(n)), generated_at=0)
    pages = len(PdfReader(io.BytesIO(pdf)).pages)
    assert pages < 700, pages
    assert "[truncated]" in pdf_text(pdf)


def test_direct_doc_extra_and_total_budget():
    body = "\n".join("y" for _ in range(750))
    doc = {"title": "t", "findings": [{"severity": "HIGH", "title": "a", "code": body, "evidence": body,
                                       "extra": [{"label": "L", "body": body, "mono": True}] * 20} for _ in range(300)]}
    pdf = engine.render("scan", doc, generated_at=0)
    assert len(PdfReader(io.BytesIO(pdf)).pages) < 700
    assert "[truncated]" in pdf_text(pdf)


def test_traffic_text_survives_redaction_error_headers():
    t = {"method": "GET", "url": "https://x", "status_code": 200, "request_headers": "[redaction error]",
         "response_headers": "[redaction error]", "request_body": None, "response_body": None}
    out = adapters._traffic_text(t)
    assert "[redaction error]" in out and "GET https://x" in out
    m = make_pentest_model()
    m["findings"][0]["evidence_traffic"] = t
    engine.render("pentest", adapters.pentest_doc(m), generated_at=0)


def test_long_title_ellipsis_and_org_clamp():
    p, s, g, c = make_scan(1)
    g["SAST"][0]["title"] = "T" * 400 + " end"
    doc = adapters.scan_doc(p, s, g, c, now=NOW, branding={"org_name": "O" * 200})
    pdf = engine.render("scan", doc, generated_at=0)
    t = pdf_text(pdf)
    assert "…" in t  # cut title + short TOC entry
    pages = PdfReader(io.BytesIO(pdf)).pages
    toc = pages[1].extract_text()
    assert "T" * 100 not in toc.replace("\u200b", "")  # TOC entry clamped (~90 chars + ellipsis)
    footer = pages[2].extract_text().split("\n")[-1]
    assert "O" * 61 not in footer.replace("​", "")
