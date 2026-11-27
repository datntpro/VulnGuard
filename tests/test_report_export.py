from types import SimpleNamespace as NS
from scanner.report_builder import build_ai_json, build_markdown
import json


def _vulns():
    E = lambda v: NS(value=v)
    return NS(scan_number=1, scan_path="/w/app", scan_types=["SAST"]), [
        NS(severity=E("CRITICAL"), scan_type=E("SAST"), title="SQLi", tool="semgrep",
           file_path="a.py", line_start=5, rule_id="r", cve=None, cwe="89", cvss_score=None,
           status=E("OPEN"), description="mô tả tiếng Việt", ai_false_positive_likelihood="10%",
           ai_explanation="giải thích", ai_fix_suggestion="prepared stmt", ai_provider="claude-api"),
    ]


def test_markdown_structure():
    scan, vulns = _vulns()
    md = build_markdown(scan, vulns, "app")
    assert "# VulnGuard" in md and "CRITICAL" in md and "SQLi" in md and "prepared stmt" in md


def test_ai_json_compact():
    scan, vulns = _vulns()
    d = json.loads(build_ai_json(scan, vulns, "app"))
    assert d["report_type"] == "vulnguard_scan" and d["summary"]["CRITICAL"] == 1
    assert d["findings"][0]["cwe"] == "89" and d["findings"][0]["ai"]["fix_suggestion"]
