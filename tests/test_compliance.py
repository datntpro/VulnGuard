from types import SimpleNamespace as NS

from scanner import compliance as C
from scanner.report_builder import build_sarif
import json


def _f(sev, cwe=None, cve=None, st="SAST", tool="semgrep", title="t"):
    E = lambda v: NS(value=v)
    return NS(severity=E(sev), scan_type=E(st), cwe=cwe, cve=cve, tool=tool,
              title=title, file_path="a.py", line_start=5, rule_id="r",
              description="d", ai_explanation="e")


def test_cwe_to_owasp():
    assert C.owasp_for(_f("HIGH", cwe="89")) == "A03"      # SQLi → Injection
    assert C.owasp_for(_f("HIGH", cwe="CWE-918")) == "A10"  # SSRF
    assert C.owasp_for(_f("HIGH", cwe="327")) == "A02"      # weak crypto


def test_fallback_without_cwe():
    assert C.owasp_for(_f("HIGH", cve="CVE-2023-1", st="SCA")) == "A06"
    assert C.owasp_for(_f("HIGH", st="SECRETS")) == "A07"


def test_map_finding_all_frameworks():
    m = C.map_finding(_f("CRITICAL", cwe="89"))
    assert m["owasp"][0][0] == "A03"
    assert any(c == "A.8.28" for c, _ in m["iso27001"])
    assert any("AT.UD-MN" == c for c, _ in m["tcvn11930"])
    assert m["pci_dss"]  # có ánh xạ PCI


def test_summary_scores_and_status():
    vulns = [_f("CRITICAL", cwe="89"), _f("LOW", cwe="1004")]
    s = C.compliance_summary(vulns)
    assert set(s.keys()) == set(C.FRAMEWORKS)
    owasp = s["owasp"]
    # 2 nhóm chạm tới (A03 critical → KHÔNG ĐẠT, A05 low → CẢNH BÁO) → score 50
    assert owasp["touched"] == 2 and owasp["failed"] == 1 and owasp["score"] == 50
    a03 = next(c for c in owasp["controls"] if c["control_id"] == "A03")
    assert a03["status"] == "KHÔNG ĐẠT" and a03["worst"] == "CRITICAL"


def test_summary_empty_is_full_score():
    s = C.compliance_summary([])
    assert all(s[fw]["score"] == 100 and s[fw]["touched"] == 0 for fw in C.FRAMEWORKS)


def test_sarif_valid_structure():
    scan = NS(scan_number=1)
    doc = json.loads(build_sarif(scan, [_f("CRITICAL", cwe="89"), _f("MEDIUM", cwe="79")], "app"))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "VulnGuard"
    assert len(run["results"]) == 2
    r = run["results"][0]
    assert r["level"] == "error" and r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "a.py"
    assert r["properties"]["owasp"] == "A03"
    # rule có security-severity cho GitHub Code Scanning
    assert run["tool"]["driver"]["rules"][0]["properties"]["security-severity"]
