"""KB: store (schema/lookup/enrich), build (OSV parse), updater (version/verify/import)."""
import gzip
import io
import json
import os
import tempfile
import zipfile

import pytest


# ── store ──
def _seed(path):
    from scanner.knowledge.store import init_db, bulk_insert
    init_db(path)
    bulk_insert(path, [{
        "id": "OSV-1::pypi/django", "source": "osv", "cve": "CVE-2024-1",
        "ghsa": "GHSA-xxxx", "summary": "SQLi in Django", "severity": "HIGH",
        "cvss": None, "cwe": "CWE-89", "ecosystem": "pypi", "package": "django",
        "introduced": "0", "fixed": "4.2.11", "refs": json.dumps(["https://x/1"]),
        "published": "2024-01-01", "modified": "2024-01-02",
    }])


def test_store_lookup_cve_and_package():
    from scanner.knowledge.store import lookup_cve, lookup_package
    d = tempfile.mkdtemp(); p = os.path.join(d, "kb.sqlite"); _seed(p)
    assert lookup_cve("CVE-2024-1", p)[0]["package"] == "django"
    assert lookup_cve("cve-2024-1", p)                       # case-insensitive
    assert lookup_package("pypi", "DJANGO", p)[0]["fixed"] == "4.2.11"
    assert lookup_cve("CVE-9999-0", p) == []


def test_store_enrich_merges():
    from scanner.knowledge.store import enrich
    d = tempfile.mkdtemp(); p = os.path.join(d, "kb.sqlite"); _seed(p)
    e = enrich(cve="CVE-2024-1", path=p)
    assert e["fixed_versions"] == ["4.2.11"]
    assert e["cwe"] == "CWE-89" and e["ghsa"] == "GHSA-xxxx"
    assert "https://x/1" in e["references"]


def test_store_get_meta_absent():
    from scanner.knowledge.store import get_meta
    assert get_meta("/nonexistent/kb.sqlite") == {"available": False}


def test_enrich_findings_fills_only_blanks():
    from scanner.knowledge.store import enrich_findings
    d = tempfile.mkdtemp(); p = os.path.join(d, "kb.sqlite"); _seed(p)
    findings = [
        {"cve": "CVE-2024-1", "package_name": "django", "package_ecosystem": "pip",
         "fixed_version": "", "cwe": ""},                       # trống → điền
        {"cve": "CVE-2024-1", "package_name": "django", "fixed_version": "9.9.9"},  # đã có → giữ
    ]
    n = enrich_findings(findings, path=p)
    assert n == 2
    assert findings[0]["fixed_version"] == "4.2.11" and findings[0]["cwe"] == "CWE-89"
    assert findings[1]["fixed_version"] == "9.9.9"             # không ghi đè
    assert findings[0]["kb"]["source_count"] >= 1


def test_enrich_findings_no_kb_is_safe():
    from scanner.knowledge.store import enrich_findings
    assert enrich_findings([{"cve": "CVE-1"}], path="/nope/kb.sqlite") == 0


# ── build: parse OSV ──
def test_parse_osv_basic():
    from scanner.knowledge.build import parse_osv
    rec = {
        "id": "GHSA-abc", "aliases": ["CVE-2023-5", "GHSA-abc"],
        "summary": "RCE", "database_specific": {"severity": "critical", "cwe_ids": ["CWE-78"]},
        "references": [{"url": "https://ref/1"}],
        "affected": [{"package": {"ecosystem": "PyPI", "name": "Flask"},
                      "ranges": [{"type": "ECOSYSTEM",
                                  "events": [{"introduced": "0"}, {"fixed": "2.3.0"}]}]}],
        "published": "2023-01-01", "modified": "2023-02-01",
    }
    rows = parse_osv(rec)
    assert len(rows) == 1
    r = rows[0]
    assert r["cve"] == "CVE-2023-5" and r["ghsa"] == "GHSA-abc"
    assert r["ecosystem"] == "pypi" and r["package"] == "flask"
    assert r["fixed"] == "2.3.0" and r["severity"] == "CRITICAL" and r["cwe"] == "CWE-78"


def test_parse_osv_no_package_still_row():
    from scanner.knowledge.build import parse_osv
    rows = parse_osv({"id": "OSV-x", "aliases": ["CVE-2020-9"], "affected": []})
    assert len(rows) == 1 and rows[0]["cve"] == "CVE-2020-9" and rows[0]["package"] is None


def test_ingest_osv_zip():
    from scanner.knowledge.build import ingest_osv_zip
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("GHSA-1.json", json.dumps({
            "id": "GHSA-1", "aliases": ["CVE-1"],
            "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                          "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]}))
        z.writestr("bad.json", "{not json")
        z.writestr("skip.txt", "ignore me")
    rows = ingest_osv_zip(buf.getvalue())
    assert len(rows) == 1 and rows[0]["package"] == "lodash" and rows[0]["fixed"] == "4.17.21"


def test_build_with_fake_fetch():
    from scanner.knowledge.build import build
    from scanner.knowledge.store import get_meta
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.json", json.dumps({
            "id": "OSV-a", "aliases": ["CVE-2"],
            "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"},
                          "ranges": [{"events": [{"fixed": "2.31.0"}]}]}]}))
    data = buf.getvalue()
    d = tempfile.mkdtemp(); p = os.path.join(d, "kb.sqlite")
    res = build(p, ecosystems=["PyPI"], _fetch=lambda url: data)
    assert res["total"] == 1
    meta = get_meta(p)
    assert meta["available"] and meta["advisory_count"] == 1


# ── updater ──
def test_needs_update():
    from scanner.knowledge.updater import needs_update
    assert needs_update(None, "2026.01.01") is True
    assert needs_update("2026.01.01", "2026.01.02") is True
    assert needs_update("2026.01.02", "2026.01.01") is False
    assert needs_update("2026.01.01", "2026.01.01") is False
    assert needs_update("2026.01.01", None) is False


def test_validate_manifest():
    from scanner.knowledge.updater import validate_manifest
    validate_manifest({"version": "1", "sha256": "a" * 64, "url": "http://x"})
    for bad in ({}, {"version": "1"}, {"version": "1", "sha256": "short", "url": "u"}):
        with pytest.raises(ValueError):
            validate_manifest(bad)


def test_import_file_gz_and_sha_check():
    from scanner.knowledge.updater import import_file, sha256_file
    # tạo 1 KB hợp lệ rồi gzip
    d = tempfile.mkdtemp(); src = os.path.join(d, "kb.sqlite"); _seed(src)
    gz = src + ".gz"
    with open(src, "rb") as fi, gzip.open(gz, "wb") as fo:
        fo.write(fi.read())
    dest = os.path.join(d, "live", "kb.sqlite")
    sha = sha256_file(gz)
    meta = import_file(gz, dest, expected_sha256=sha)
    assert meta["available"] and meta["advisory_count"] == 1
    # sha sai → raise, dest không đổi
    with pytest.raises(ValueError):
        import_file(gz, dest, expected_sha256="b" * 64)


# ── EPSS ──
_EPSS_CSV = """#model_version:v2025.03.14,score_date:2025-03-20T00:00:00+0000
cve,epss,percentile
CVE-2024-1,0.97123,0.99988
CVE-2020-9,0.00042,0.10111
bad,row
CVE-BADFLOAT,x,y
"""


def test_parse_epss_csv():
    from scanner.knowledge.build import parse_epss_csv
    rows = parse_epss_csv(_EPSS_CSV)
    assert len(rows) == 2                      # bỏ comment/header/dòng hỏng
    r0 = {x["cve"]: x for x in rows}
    assert r0["CVE-2024-1"]["epss"] == pytest.approx(0.97123)
    assert r0["CVE-2024-1"]["percentile"] == pytest.approx(0.99988)
    assert r0["CVE-2024-1"]["score_date"] == "2025-03-20T00:00:00+0000"


def test_enrich_includes_epss():
    from scanner.knowledge.store import set_epss, enrich
    from scanner.knowledge.build import parse_epss_csv
    d = tempfile.mkdtemp(); p = os.path.join(d, "kb.sqlite"); _seed(p)
    set_epss(p, parse_epss_csv(_EPSS_CSV))
    e = enrich(cve="CVE-2024-1", path=p)
    assert e["epss"] == pytest.approx(0.97123)
    assert e["epss_percentile"] == pytest.approx(0.99988)
    # package-only lookup cũng kéo được EPSS qua CVE của advisory (eco đã chuẩn hoá)
    e2 = enrich(ecosystem="pypi", package="django", path=p)
    assert e2["epss"] == pytest.approx(0.97123)


def test_enrich_findings_sets_epss():
    from scanner.knowledge.store import set_epss, enrich_findings
    from scanner.knowledge.build import parse_epss_csv
    d = tempfile.mkdtemp(); p = os.path.join(d, "kb.sqlite"); _seed(p)
    set_epss(p, parse_epss_csv(_EPSS_CSV))
    findings = [{"cve": "CVE-2024-1", "package_name": "django"}]
    enrich_findings(findings, path=p)
    assert findings[0]["epss"] == pytest.approx(0.97123)
    assert findings[0]["kb"]["epss_percentile"] == pytest.approx(0.99988)


def test_lookup_epss_missing_table_safe():
    from scanner.knowledge.store import lookup_epss
    d = tempfile.mkdtemp(); p = os.path.join(d, "kb.sqlite"); _seed(p)
    assert lookup_epss("CVE-NOPE", p) is None


# ── CISA KEV ──
_KEV = {
    "catalogVersion": "2025.03.20",
    "vulnerabilities": [
        {"cveID": "CVE-2024-1", "vendorProject": "Acme", "product": "Web",
         "vulnerabilityName": "Acme RCE", "dateAdded": "2024-05-01",
         "knownRansomwareCampaignUse": "Known", "dueDate": "2024-05-15"},
        {"cveID": "CVE-2020-9", "vendorProject": "X", "product": "Y",
         "vulnerabilityName": "X SQLi", "dateAdded": "2020-02-02",
         "knownRansomwareCampaignUse": "Unknown", "dueDate": "2020-02-20"},
        {"product": "no-cve"},                         # bỏ: thiếu cveID
    ],
}


def test_parse_kev_json():
    from scanner.knowledge.build import parse_kev_json
    rows = parse_kev_json(_KEV)
    assert len(rows) == 2
    m = {r["cve"]: r for r in rows}
    assert m["CVE-2024-1"]["ransomware"] is True
    assert m["CVE-2020-9"]["ransomware"] is False
    assert m["CVE-2024-1"]["due_date"] == "2024-05-15"
    # chấp nhận cả chuỗi JSON
    assert len(parse_kev_json(json.dumps(_KEV))) == 2


def test_enrich_includes_kev():
    from scanner.knowledge.store import set_kev, enrich
    from scanner.knowledge.build import parse_kev_json
    d = tempfile.mkdtemp(); p = os.path.join(d, "kb.sqlite"); _seed(p)
    set_kev(p, parse_kev_json(_KEV))
    e = enrich(cve="CVE-2024-1", path=p)
    assert e["kev"] is True and e["kev_ransomware"] is True
    assert e["kev_date_added"] == "2024-05-01"
    # package-only cũng kéo được KEV qua CVE của advisory
    assert enrich(ecosystem="pypi", package="django", path=p)["kev"] is True
    # CVE không trong KEV
    assert enrich(cve="CVE-0000-0", path=p) == {} or enrich(cve="CVE-0000-0", path=p).get("kev") is False


def test_enrich_findings_sets_kev():
    from scanner.knowledge.store import set_kev, enrich_findings
    from scanner.knowledge.build import parse_kev_json
    d = tempfile.mkdtemp(); p = os.path.join(d, "kb.sqlite"); _seed(p)
    set_kev(p, parse_kev_json(_KEV))
    findings = [{"cve": "CVE-2024-1", "package_name": "django"}]
    enrich_findings(findings, path=p)
    assert findings[0]["kev"] is True and findings[0]["kev_ransomware"] is True
    assert findings[0]["kb"]["kev_due_date"] == "2024-05-15"


def test_lookup_kev_missing_table_safe():
    from scanner.knowledge.store import lookup_kev
    d = tempfile.mkdtemp(); p = os.path.join(d, "kb.sqlite"); _seed(p)
    assert lookup_kev("CVE-NOPE", p) is None


# ── prioritize_findings (nâng ưu tiên theo tri thức khai thác) ──
def test_prioritize_kev_ransomware_to_critical():
    from scanner.knowledge.store import prioritize_findings
    f = [{"severity": "MEDIUM", "kev": True, "kev_ransomware": True}]
    assert prioritize_findings(f) == 1
    assert f[0]["severity"] == "CRITICAL" and f[0]["severity_original"] == "MEDIUM"
    assert "ransomware" in f[0]["priority_reason"].lower()


def test_prioritize_kev_to_high():
    from scanner.knowledge.store import prioritize_findings
    f = [{"severity": "LOW", "kev": True}]
    prioritize_findings(f)
    assert f[0]["severity"] == "HIGH"


def test_prioritize_epss_threshold():
    from scanner.knowledge.store import prioritize_findings
    f = [{"severity": "LOW", "epss": 0.8}, {"severity": "LOW", "epss": 0.1}]
    prioritize_findings(f)
    assert f[0]["severity"] == "HIGH"          # trên ngưỡng
    assert f[1]["severity"] == "LOW"           # dưới ngưỡng → giữ nguyên


def test_prioritize_never_downgrades():
    from scanner.knowledge.store import prioritize_findings
    f = [{"severity": "CRITICAL", "kev": True}]
    prioritize_findings(f)
    assert f[0]["severity"] == "CRITICAL" and "severity_original" not in f[0]
    assert f[0]["priority_reason"]             # vẫn ghi lý do đáng chú ý


def test_import_file_rejects_garbage():
    from scanner.knowledge.updater import import_file
    d = tempfile.mkdtemp()
    junk = os.path.join(d, "x.sqlite")
    with open(junk, "w") as f:
        f.write("not a sqlite db")
    with pytest.raises(ValueError):
        import_file(junk, os.path.join(d, "dest.sqlite"))
