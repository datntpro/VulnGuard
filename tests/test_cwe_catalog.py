"""Catalog tri thức CWE — luôn trả nội dung để báo cáo không rỗng khi AI tắt."""
from scanner.knowledge import cwe_catalog


def test_lookup_known_cwe_full_fields():
    info = cwe_catalog.lookup("CWE-78")
    assert info["cwe"] == "CWE-78"
    for k in ("ten", "mo_ta", "tac_dong", "poc", "khac_phuc"):
        assert info[k] and len(info[k]) > 10


def test_lookup_accepts_many_formats():
    assert cwe_catalog.lookup("78")["cwe"] == "CWE-78"
    assert cwe_catalog.lookup("CWE-89; CWE-20")["cwe"] == "CWE-89"   # mục đầu khớp
    assert cwe_catalog.lookup("cwe_78,cwe_79")["cwe"] == "CWE-78"


def test_fallback_by_scan_type():
    for st in ("SECRETS", "IAC", "SCA", "SAST"):
        info = cwe_catalog.lookup("CWE-999999", st)   # CWE lạ → fallback nhóm
        assert info and info["poc"] and info["khac_phuc"]


def test_no_match_returns_none():
    assert cwe_catalog.lookup(None, None) is None
    assert cwe_catalog.lookup("CWE-999999", "UNKNOWN") is None


def test_poc_mentions_exploitation():
    # PoC của command injection phải gợi ý cách kiểm chứng cụ thể
    assert any(tok in cwe_catalog.lookup("78")["poc"] for tok in ("id", "whoami", ";"))
