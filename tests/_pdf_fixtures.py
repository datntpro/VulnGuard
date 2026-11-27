"""Synthetic inputs for PDF adapter/golden tests (no DB, fixed values, deterministic)."""
import random
from types import SimpleNamespace as NS

_SAMPLES = [
    dict(sev="CRITICAL", scan_type="SAST", title="SQL Injection tại POST /api/transfer (tham số accountNo)", tools=["semgrep"],
         cwe="CWE-89", cvss="9.3", file="src/main/java/vn/abc/bank/repository/TransferRepository.java", line=118,
         code='String sql = "SELECT * FROM accounts WHERE account_no = \'"\n    + req.getAccountNo() + "\' AND status = \'ACTIVE\'";\nreturn jdbc.queryForList(sql);',
         desc="Giá trị accountNo được nối chuỗi trực tiếp vào câu lệnh SQL. Kẻ tấn công không cần đăng nhập có thể đọc toàn bộ bảng customers.",
         fix="Dùng PreparedStatement/named parameters; kiểm tra định dạng số tài khoản; giới hạn quyền tài khoản DB."),
    dict(sev="CRITICAL", scan_type="SECRETS", title="Lộ AWS access key trong mã nguồn", tools=["gitleaks"], cwe="CWE-798", cvss="",
         file="config/application-prod.yml", line=42, code="aws.accessKeyId: AKIA************MNOP   (đã che)",
         desc="Khoá truy cập AWS dạng thật nằm trong file cấu hình production được commit vào Git.",
         fix="Thu hồi khoá trên AWS IAM, xoay vòng, chuyển sang Secrets Manager; xoá khỏi lịch sử Git."),
    dict(sev="HIGH", scan_type="SCA", title="jackson-databind 2.13.1", tools=["trivy", "grype"], cwe="CWE-502", cvss="8.1",
         pkg=("com.fasterxml.jackson.core:jackson-databind", "2.13.1"), fixed="2.15.4", cve="CVE-2026-12345",
         desc="Thư viện có lỗ hổng deserialization cho phép thực thi mã từ xa khi bật default typing.", fix="Nâng cấp lên >= 2.15.4."),
    dict(sev="MEDIUM", scan_type="IAC", title="S3 bucket không bật mã hoá", tools=["checkov"], cwe="CWE-311", cvss="",
         file="infra/main.tf", line=12, code="", desc="Bucket lưu dữ liệu khách hàng nhưng chưa bật mã hoá phía server.", fix="Bật SSE-KMS."),
    dict(sev="LOW", scan_type="SAST", title="Dùng hàm băm MD5", tools=["bandit"], cwe="CWE-327", cvss="",
         file="app/util/hash.py", line=7, code="", desc="MD5 không còn an toàn.", fix="Dùng SHA-256."),
    dict(sev="INFO", scan_type="SAST", title="Cờ debug còn bật", tools=["semgrep"], cwe="", cvss="",
         file="app/settings.py", line=3, code="", desc="", fix=""),
]


def make_scan(n: int = 8, *, hostile: bool = False):
    """Return (project, scan, grouped, severity_counts) shaped like api.routes.report._dedup_and_group."""
    rng = random.Random(7)
    groups = {}
    counts = {s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    for i in range(n):
        s = _SAMPLES[i % len(_SAMPLES)] if i < 24 or n <= 24 else rng.choice(_SAMPLES[2:])
        title = s["title"] if i < len(_SAMPLES) else f"{s['title']} #{i}"
        desc = s["desc"]
        if hostile:
            title = '#import "@preview/tablex:0.0.9": tablex ' + title
            desc = '#read("/etc/hosts") ] #show: x => "PWNED" [ ' + desc
        item = {"title": title, "description": desc, "file_path": s.get("file", ""), "line_start": s.get("line"),
                "code_snippet": s.get("code", ""), "cwe": s["cwe"], "cve": s.get("cve", ""), "cvss_score": s["cvss"],
                "status": "OPEN", "package_name": (s.get("pkg") or ("", ""))[0], "package_version": (s.get("pkg") or ("", ""))[1]}
        g = {"title": title, "severity": s["sev"], "tools": s["tools"], "items": [item], "count": 1, "scan_type": s["scan_type"],
             "ai_explanation": "", "ai_fix_suggestion": s["fix"], "package_name": item["package_name"],
             "package_version": item["package_version"], "fixed_version": s.get("fixed", ""),
             "cve_list": [s["cve"]] if s.get("cve") else [], "kev": i == 2, "epss": 0.87 if i == 2 else None}
        groups.setdefault(s["scan_type"], []).append(g)
        counts[s["sev"]] += 1
    project = NS(name="core-banking-api")
    scan = NS(scan_number=12, scan_path="git: main @ 3f9c2e1", scan_types=sorted(groups), started_at=None,
              status=NS(value="COMPLETED"))
    return project, scan, groups, counts


NOW = __import__("datetime").datetime(2026, 11, 27, 3, 30, tzinfo=__import__("datetime").timezone.utc)


def make_pentest_model():
    """Shaped like scanner.pentest.report.build_report_model output (already scope-filtered/redacted)."""
    f1 = {
        "id": "f1", "title": "SQL Injection tại /api/transfer", "severity": "critical",
        "cvss_v4": {"vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "score": 9.3, "severity": "critical"},
        "wstg_id": "WSTG-INPV-05", "cwe": "CWE-89", "cve": None, "attack_technique": None, "param": "accountNo",
        "target": "https://uat.bank.example/api/transfer",
        "description": "Tham số accountNo bị nối chuỗi vào câu SQL; validator sqli_differential xác nhận.",
        "evidence": "HTTP 200, 4812 bản ghi (bình thường: 1)",
        "evidence_traffic": {"method": "POST", "url": "https://uat.bank.example/api/transfer", "status_code": 200,
                             "request_headers": {"Authorization": "[REDACTED]"}, "request_body": "{\"accountNo\":\"0011' OR '1'='1\"}",
                             "response_headers": {"Content-Type": "application/json"}, "response_body": None},
        "poc": {"curl": "curl -X POST https://uat.bank.example/api/transfer -d '{...}'", "steps": ["Gửi payload", "So sánh số bản ghi"]},
        "verification": {"verified": True, "label": "Confirmed (verified)"}, "status": "OPEN",
        "remediation": "Dùng truy vấn tham số hoá.", "references": ["https://cwe.mitre.org/data/definitions/89.html"],
        "claimed_severity": None, "severity_cap": None,
    }
    f2 = dict(f1, id="f2", title="IDOR tại /api/statements/{id}", severity="medium",
              cvss_v4={"vector": None, "score": 6.9, "severity": "medium"}, cwe="CWE-639",
              verification={"verified": False, "label": "Likely — NOT independently verified"}, evidence_traffic=None, poc={})
    return {
        "generated_at": "2026-11-27T03:30:00+00:00",
        "run": {"engagement": "UAT Internet Banking", "goal": "Kiểm thử OWASP Top 10", "number": 3, "status": "completed",
                "started_at": "2026-11-24T07:00:00+00:00"},
        "executive_summary": {"overall_risk": "critical", "counts": {"critical": 1, "high": 0, "medium": 1, "low": 0, "info": 0}, "total": 2,
                              "top_issues": [{"id": "f1", "title": "SQL Injection tại /api/transfer"}]},
        "scope_and_roe": {"scope_rules": [{"type": "domain", "value": "uat.bank.example", "mode": "allow"}],
                          "exclusions": [], "authorized_by": "ciso@abc.example", "authorization_note": "Cho phép kiểm thử UAT."},
        "findings": [f1, f2],
    }
