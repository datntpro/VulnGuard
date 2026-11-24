"""Report chuyên nghiệp (report_pro) — luôn dựng đủ cấu trúc + điểm rủi ro đúng."""
import datetime
import types

from scanner import report_pro


def _scan():
    return types.SimpleNamespace(
        scan_number=1, scan_path="/workspace/app", scan_types=["SAST", "SCA"],
        started_at=datetime.datetime(2026, 11, 19, 10, 20),
        completed_at=datetime.datetime(2026, 11, 19, 10, 35),
        status=types.SimpleNamespace(value="COMPLETED"))


def _grouped():
    g1 = {"severity": "HIGH", "scan_type": "SAST", "title": "SQLi trong Business",
          "tools": ["bandit"], "count": 2, "cve_list": [], "package_name": None,
          "fixed_version": None, "kev": False, "epss": None,
          "items": [{"cwe": "89", "file_path": "app/b.py", "line_start": 42, "cvss_score": ""}],
          "ai_explanation": "", "ai_fix_suggestion": "", "ai_exploitability_public": "", "ai_fp_reason": ""}
    g2 = {"severity": "CRITICAL", "scan_type": "SCA", "title": "requests — CVE-2023-1",
          "tools": ["trivy"], "count": 1, "cve_list": ["CVE-2023-1"], "package_name": "requests",
          "package_version": "2.19", "fixed_version": "2.31.0", "kev": True, "epss": 0.92,
          "items": [{"cwe": "", "file_path": "requirements.txt", "line_start": 5, "cvss_score": "9.8"}],
          "ai_explanation": "", "ai_fix_suggestion": "", "ai_exploitability_public": "", "ai_fp_reason": ""}
    return {"SAST": [g1], "SCA": [g2]}


def test_risk_score_formula():
    assert report_pro._risk_score({"CRITICAL": 1, "HIGH": 1}) == 35   # 25+10
    assert report_pro._risk_score({"LOW": 3}) == 3
    assert report_pro._risk_score({"CRITICAL": 10}) == 100            # cap 100


def test_render_has_all_sections():
    html = report_pro.render(
        project=types.SimpleNamespace(name="Demo"), scan=_scan(),
        grouped=_grouped(), severity_counts={"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        vulns=[1, 2])
    for section in ("KẾT LUẬN ĐÁNH GIÁ", "1. Tóm tắt điều hành",
                    "Danh sách phát hiện", "2. Chi tiết phát hiện", "3. Phụ lục"):
        assert section in html, f"thiếu mục: {section}"
    assert "35/100" in html                       # điểm rủi ro
    assert "VG-01" in html and "VG-02" in html     # mã phát hiện
    assert "Khả năng khai thác / PoC" in html      # luôn có PoC (từ catalog)
    assert "CISA KEV" in html                      # tín hiệu KEV
    assert "CWE-89" in html                        # CWE catalog


def test_render_empty_scan_safe():
    html = report_pro.render(
        project=types.SimpleNamespace(name="Empty"), scan=_scan(),
        grouped={}, severity_counts={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        vulns=[])
    assert "KHÔNG PHÁT HIỆN LỖI" in html
    assert "0/100" in html
