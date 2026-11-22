from scanner.scanners.sonarqube import parse_issues


def test_parse_issue_mqr_severity_and_cwe():
    payload = {"total": 1, "issues": [{
        "key": "AX1", "rule": "python:S2076", "component": "proj:app/main.py",
        "line": 42, "message": "OS command injection", "type": "VULNERABILITY",
        "impacts": [{"softwareQuality": "SECURITY", "severity": "HIGH"}],
        "tags": ["cwe-78", "owasp-a1"]}]}
    f = parse_issues(payload, "proj")
    assert len(f) == 1
    assert f[0]["tool"] == "sonarqube" and f[0]["severity"] == "HIGH"
    assert f[0]["file_path"] == "app/main.py" and f[0]["line_start"] == 42
    assert f[0]["cwe"] == "78" and f[0]["rule_id"] == "python:S2076"


def test_parse_issue_legacy_severity():
    payload = {"total": 1, "issues": [{"key": "A", "rule": "r", "component": "p:f.py",
               "severity": "BLOCKER", "message": "m", "type": "BUG"}]}
    assert parse_issues(payload, "p")[0]["severity"] == "CRITICAL"


def test_parse_hotspot():
    payload = {"hotspots": [{"key": "H1", "ruleKey": "python:S4423", "component": "p:tls.py",
               "line": 10, "message": "Weak TLS", "vulnerabilityProbability": "HIGH"}]}
    f = parse_issues(payload, "p", is_hotspot=True)
    assert f[0]["severity"] == "HIGH" and "Hotspot" in f[0]["title"]
