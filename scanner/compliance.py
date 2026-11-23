"""
Compliance mapping engine — ánh xạ mỗi finding sang các khung tuân thủ.

Trục xoay: CWE → OWASP Top 10 2021 → {ISO/IEC 27001:2022, TCVN 11930:2017 / NĐ 85,
PCI-DSS v4.0}. Finding không có CWE thì suy theo loại quét (scan_type).

Thiết kế pure-function để test & dùng lại ở: báo cáo PDF, SARIF, dashboard tuân thủ.
Nguồn ánh xạ CWE↔OWASP: danh mục CWE chính thức của OWASP Top 10 2021.
Số hiệu điều khoản TCVN/NĐ dùng tên NHÓM kiểm soát (mô tả), tránh trích dẫn
điều/khoản cụ thể dễ sai — phục vụ định hướng audit, không thay văn bản gốc.
"""
from typing import Any, Dict, List, Optional

# ─────────────────────────────────────────────
# OWASP Top 10 2021 — id → nhãn
# ─────────────────────────────────────────────
OWASP_2021 = {
    "A01": "A01:2021 – Broken Access Control",
    "A02": "A02:2021 – Cryptographic Failures",
    "A03": "A03:2021 – Injection",
    "A04": "A04:2021 – Insecure Design",
    "A05": "A05:2021 – Security Misconfiguration",
    "A06": "A06:2021 – Vulnerable and Outdated Components",
    "A07": "A07:2021 – Identification and Authentication Failures",
    "A08": "A08:2021 – Software and Data Integrity Failures",
    "A09": "A09:2021 – Security Logging and Monitoring Failures",
    "A10": "A10:2021 – Server-Side Request Forgery (SSRF)",
}

# CWE (số) → OWASP category. Dựa trên danh mục CWE chính thức của từng hạng mục.
_CWE_OWASP: Dict[int, str] = {}


def _reg(cat: str, cwes: List[int]):
    for c in cwes:
        _CWE_OWASP[c] = cat


_reg("A01", [22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359,
             377, 402, 425, 441, 497, 538, 540, 548, 552, 566, 601, 639, 651,
             668, 706, 862, 863, 913, 922, 1275])
_reg("A02", [261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329,
             330, 331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759, 760,
             780, 818, 916])
_reg("A03", [20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95,
             96, 97, 98, 99, 100, 113, 116, 138, 184, 470, 471, 564, 610, 643,
             644, 652, 917])
_reg("A04", [73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313,
             316, 419, 430, 434, 444, 451, 472, 501, 522, 525, 539, 579, 598,
             602, 642, 646, 650, 653, 656, 657, 799, 807, 840, 841, 927, 1021, 1173])
_reg("A05", [2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614,
             756, 776, 942, 1004, 1032, 1174])
_reg("A06", [937, 1035, 1104])
_reg("A07", [255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307,
             346, 384, 521, 613, 620, 640, 798, 940, 1216])
_reg("A08", [345, 353, 426, 494, 502, 565, 784, 829, 830, 915])
_reg("A09", [117, 223, 532, 778])
_reg("A10", [918])

# Loại quét → OWASP (fallback khi finding không có CWE)
_SCANTYPE_OWASP = {
    "SCA": "A06", "CONTAINER": "A06", "SECRETS": "A07",
    "IAC": "A05", "DAST": "A05", "SAST": "A03",
}

# ─────────────────────────────────────────────
# OWASP category → điều khoản các khung khác
# ─────────────────────────────────────────────
# ISO/IEC 27001:2022 — Annex A (control id + tên)
_OWASP_ISO = {
    "A01": [("A.8.3", "Information access restriction"), ("A.5.15", "Access control")],
    "A02": [("A.8.24", "Use of cryptography")],
    "A03": [("A.8.28", "Secure coding")],
    "A04": [("A.8.25", "Secure development life cycle"), ("A.8.27", "Secure system architecture & engineering")],
    "A05": [("A.8.9", "Configuration management")],
    "A06": [("A.8.8", "Management of technical vulnerabilities")],
    "A07": [("A.8.5", "Secure authentication"), ("A.5.17", "Authentication information")],
    "A08": [("A.8.28", "Secure coding"), ("A.8.4", "Access to source code")],
    "A09": [("A.8.15", "Logging"), ("A.8.16", "Monitoring activities")],
    "A10": [("A.8.28", "Secure coding"), ("A.8.20", "Networks security")],
}

# TCVN 11930:2017 / Nghị định 85/2016 — nhóm kiểm soát (mô tả, tiếng Việt)
_OWASP_TCVN = {
    "A01": [("AT.UD-KSTC", "An toàn ứng dụng – Kiểm soát truy cập")],
    "A02": [("AT.DL-MH", "An toàn dữ liệu – Mã hóa & bảo mật dữ liệu")],
    "A03": [("AT.UD-MN", "An toàn ứng dụng – An toàn mã nguồn & kiểm tra đầu vào")],
    "A04": [("AT.UD-TK", "An toàn ứng dụng – Thiết kế an toàn (SDLC)")],
    "A05": [("AT.MC-CH", "An toàn máy chủ/ứng dụng – Cấu hình an toàn")],
    "A06": [("QL.LH", "Quản lý điểm yếu & lỗ hổng (NĐ 85/2016)")],
    "A07": [("AT.UD-XT", "An toàn ứng dụng – Xác thực & quản lý phiên")],
    "A08": [("AT.DL-TV", "An toàn dữ liệu – Toàn vẹn & nguồn gốc")],
    "A09": [("AT.UD-NK", "An toàn ứng dụng – Ghi nhật ký & giám sát")],
    "A10": [("AT.MG-KN", "An toàn mạng – Kiểm soát kết nối ra ngoài (SSRF)")],
}

# PCI-DSS v4.0 — yêu cầu
_OWASP_PCI = {
    "A01": [("Req 7", "Restrict access by business need to know")],
    "A02": [("Req 3/4", "Protect stored & transmitted cardholder data")],
    "A03": [("Req 6.2", "Bespoke software developed securely")],
    "A04": [("Req 6.2", "Secure software development")],
    "A05": [("Req 2", "Apply secure configurations")],
    "A06": [("Req 6.3", "Identify & address security vulnerabilities")],
    "A07": [("Req 8", "Identify users & authenticate access")],
    "A08": [("Req 6.5", "Manage changes securely")],
    "A09": [("Req 10", "Log & monitor all access")],
    "A10": [("Req 1", "Network security controls")],
}

FRAMEWORKS = ["owasp", "iso27001", "tcvn11930", "pci_dss"]
FRAMEWORK_LABELS = {
    "owasp": "OWASP Top 10 (2021)",
    "iso27001": "ISO/IEC 27001:2022",
    "tcvn11930": "TCVN 11930:2017 / NĐ 85/2016",
    "pci_dss": "PCI-DSS v4.0",
}
_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _cwe_int(cwe) -> Optional[int]:
    if cwe is None:
        return None
    s = str(cwe).upper().replace("CWE-", "").strip()
    try:
        return int(s)
    except (TypeError, ValueError):
        return None


def _sev(v) -> str:
    s = getattr(v, "severity", None)
    s = s.value if hasattr(s, "value") else str(s or "INFO")
    return s.upper()


def _stype(v) -> str:
    s = getattr(v, "scan_type", None)
    return (s.value if hasattr(s, "value") else str(s or "")).upper()


def owasp_for(finding) -> str:
    """Trả về OWASP category id (A01..A10) cho một finding."""
    cat = _CWE_OWASP.get(_cwe_int(getattr(finding, "cwe", None)))
    if cat:
        return cat
    # có CVE nhưng không CWE → thường là lỗ hổng thành phần
    if getattr(finding, "cve", None):
        return "A06"
    return _SCANTYPE_OWASP.get(_stype(finding), "A05")


def map_finding(finding) -> Dict[str, Any]:
    """Ánh xạ 1 finding sang tất cả khung. Trả dict các control đã gắn."""
    cat = owasp_for(finding)
    return {
        "owasp": [(cat, OWASP_2021[cat])],
        "iso27001": _OWASP_ISO.get(cat, []),
        "tcvn11930": _OWASP_TCVN.get(cat, []),
        "pci_dss": _OWASP_PCI.get(cat, []),
    }


def owasp_tags(finding) -> List[str]:
    """Tag ngắn cho SARIF/PDF: ['OWASP A03', 'ISO A.8.28', 'TCVN AT.UD-MN']."""
    m = map_finding(finding)
    tags = [f"OWASP {m['owasp'][0][0]}"]
    tags += [f"ISO {c}" for c, _ in m["iso27001"]]
    tags += [f"TCVN {c}" for c, _ in m["tcvn11930"]]
    return tags


def compliance_summary(vulns: List[Any]) -> Dict[str, Any]:
    """Tổng hợp theo từng khung: mỗi control + số finding + mức nặng nhất + trạng thái.

    Trạng thái control:
      - KHÔNG ĐẠT  : có finding CRITICAL/HIGH
      - CẢNH BÁO    : có finding MEDIUM/LOW/INFO (chưa Critical/High)
      - (không liệt kê control nếu không có finding nào chạm tới)
    Điểm khung = % control ĐẠT trên tổng control *bị chạm tới*; nếu không có
    finding nào → 100 (không phát hiện vi phạm trong phạm vi quét).
    """
    out: Dict[str, Any] = {}
    for fw in FRAMEWORKS:
        controls: Dict[str, Dict[str, Any]] = {}
        for v in vulns:
            m = map_finding(v)
            sev = _sev(v)
            for cid, cname in m[fw]:
                c = controls.setdefault(cid, {
                    "control_id": cid, "control_name": cname,
                    "findings": 0, "worst": "INFO",
                })
                c["findings"] += 1
                if _SEV_RANK.get(sev, 0) > _SEV_RANK.get(c["worst"], 0):
                    c["worst"] = sev
        rows = []
        failed = 0
        for c in controls.values():
            status = "KHÔNG ĐẠT" if _SEV_RANK[c["worst"]] >= 3 else "CẢNH BÁO"
            if status == "KHÔNG ĐẠT":
                failed += 1
            rows.append({**c, "status": status})
        rows.sort(key=lambda r: (-_SEV_RANK[r["worst"]], -r["findings"]))
        touched = len(rows)
        score = 100 if touched == 0 else round(100 * (touched - failed) / touched)
        out[fw] = {
            "framework": fw,
            "label": FRAMEWORK_LABELS[fw],
            "controls": rows,
            "touched": touched,
            "failed": failed,
            "score": score,
        }
    return out
