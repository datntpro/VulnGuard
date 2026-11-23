"""P1 quality: security headers, JS/TS ruleset detect, secret FP reduction, feature gate."""
import os
import tempfile


# 1.2 security headers
def test_missing_headers_detected():
    from scanner.crawler.headers_check import analyze_headers
    f = analyze_headers("https://x.test", {"server": "nginx"})
    names = {x["matcher_name"] for x in f}
    assert "strict-transport-security" in names and "content-security-policy" in names
    # có đủ header thì không báo
    full = {"strict-transport-security": "max-age=1", "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer"}
    assert analyze_headers("https://x.test", full) == []


# 1.4 JS/TS ruleset selection
def test_sast_lang_ruleset_jsts():
    from scanner.scanners.sast import SemgrepScanner
    d = tempfile.mkdtemp()
    open(os.path.join(d, "a.ts"), "w").write("const x = 1;")
    open(os.path.join(d, "b.py"), "w").write("x = 1")
    rs = SemgrepScanner(d)._online_rulesets()
    assert any("typescript" in r for r in rs) and "p/python" in rs
    # không file nào → fallback python
    d2 = tempfile.mkdtemp()
    assert "p/python" in SemgrepScanner(d2)._online_rulesets()


# 1.3 secret FP reduction
def test_secret_fp_reduction():
    from scanner.scanners.secrets import _reduce_secret_fp
    out = _reduce_secret_fp([
        {"severity": "CRITICAL", "file_path": "tests/fixtures/x.py", "code_snippet": "key=abc", "description": ""},
        {"severity": "CRITICAL", "file_path": "app/config.py",
         "code_snippet": "123-abc.apps.googleusercontent.com", "description": ""},
        {"severity": "CRITICAL", "file_path": "app/real.py", "code_snippet": "AKIAREAL...", "description": ""},
    ])
    assert out[0]["severity"] == "LOW"         # file test
    assert out[1]["severity"] == "INFO"        # OAuth client id công khai
    assert out[2]["severity"] == "CRITICAL"    # secret thật giữ nguyên
