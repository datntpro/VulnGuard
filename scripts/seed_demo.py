"""
Seed dữ liệu DEMO cho VulnGuard — tạo dữ liệu thật ở mọi trang để trình diễn ngay.
Chạy: python -m scripts.seed_demo  (DATABASE_URL trỏ tới DB demo)

Tạo: tài khoản admin, projects + scan + vuln (code), domain + crawl + webscan + finding,
assets (từ 3 connector giả) + CVE + alert EDR + EPSS/KEV, pentest engagement + run + steps
+ findings + 1 approval đang chờ + traffic bằng chứng, 3 connector config.
Idempotent: xoá sạch rồi tạo lại.
"""
import os
from datetime import datetime, timedelta

os.environ.setdefault("AUTH_ENABLED", "true")

import api.main  # tạo bảng + migration
from api.database import SessionLocal
from api.security import hash_password
from api.auth_models import User, UserRole
from api.models import Project, Scan, Vulnerability, ScanStatus, ScanType, Severity, VulnStatus
from api.domain_models import Domain, DomainCrawl, CrawlEndpoint, CrawlStatus
from api.webscan_models import WebScan, WebFinding, WebScanStatus, WebFindingStatus
from api.connector_models import ConnectorConfig, ConnectorKind
from api.pentest_models import (Engagement, PentestRun, AgentStep, PentestFinding, ApprovalRequest,
                                AutonomyMode, RunStatus, RiskTier, ApprovalStatus, TrafficEntry)
from scanner.intel import feeds
from scanner.assets.service import upsert_asset, upsert_vuln, upsert_alert, replace_software, recompute_asset_risk

DEMO_EMAIL = "demo@vulnguard.local"
DEMO_PASS = "VulnGuardDemo!"


def wipe(db):
    for M in (TrafficEntry, ApprovalRequest, AgentStep, PentestFinding, PentestRun, Engagement,
              WebFinding, WebScan, CrawlEndpoint, DomainCrawl, Domain,
              Vulnerability, Scan, Project, ConnectorConfig):
        db.query(M).delete()
    from api.asset_models import Asset, AssetSoftware, AssetVuln, AssetAlert
    for M in (AssetAlert, AssetVuln, AssetSoftware, Asset):
        db.query(M).delete()
    db.commit()


def seed():
    feeds.seed_for_test({
        "CVE-2021-44228": 0.975, "CVE-2019-0708": 0.94, "CVE-2023-34362": 0.88,
        "CVE-2022-22965": 0.72, "CVE-2021-3129": 0.55, "CVE-2020-1472": 0.91,
        "CVE-2018-13379": 0.80, "CVE-2024-3400": 0.70,
    }, ["CVE-2021-44228", "CVE-2019-0708", "CVE-2023-34362", "CVE-2020-1472", "CVE-2018-13379", "CVE-2024-3400"])

    db = SessionLocal()
    wipe(db)

    # ── User ──
    if not db.query(User).filter(User.email == DEMO_EMAIL).first():
        db.add(User(email=DEMO_EMAIL, name="Demo Admin", password_hash=hash_password(DEMO_PASS),
                    role=UserRole.ADMIN, last_login_at=datetime.utcnow()))
    db.commit()

    # ── Projects + code scans + vulns ──
    specs = [
        ("payment-gateway", "Spring Boot + PostgreSQL",
         [("CRITICAL", "SQL Injection trong OrderRepository", "SAST", "semgrep", "CWE-89", None),
          ("HIGH", "Spring4Shell RCE", "SCA", "trivy", "CWE-94", "CVE-2022-22965"),
          ("HIGH", "Hardcoded DB password", "SECRETS", "gitleaks", "CWE-798", None),
          ("MEDIUM", "Thiếu rate limit endpoint /login", "SAST", "semgrep", "CWE-307", None),
          ("LOW", "Dockerfile chạy root", "IAC", "checkov", "CWE-250", None)]),
        ("customer-portal", "Next.js + Node",
         [("CRITICAL", "Log4Shell trong logging lib", "SCA", "trivy", "CWE-502", "CVE-2021-44228"),
          ("MEDIUM", "XSS phản chiếu ở search", "SAST", "semgrep", "CWE-79", None),
          ("LOW", "Dependency lỗi thời", "SCA", "trivy", None, None)]),
        ("infra-k8s", "Helm charts & Terraform",
         [("HIGH", "S3 bucket public", "IAC", "checkov", "CWE-732", None),
          ("MEDIUM", "K8s container privileged", "IAC", "trivy", "CWE-250", None)]),
    ]
    for pi, (name, stack, vulns) in enumerate(specs):
        p = Project(name=name, description=stack, language_stacks=stack.split())
        db.add(p); db.commit()
        for sn in range(1, 3):  # 2 scan mỗi project
            sc = Scan(project_id=p.id, scan_number=sn, scan_path=f"/workspace/{name}",
                      scan_types=["SAST", "SCA", "IAC", "SECRETS"], status=ScanStatus.COMPLETED,
                      started_at=datetime.utcnow() - timedelta(days=(3 - pi), hours=sn * 5),
                      completed_at=datetime.utcnow() - timedelta(days=(3 - pi)))
            db.add(sc); db.commit()
            if sn == 2:  # vuln ở scan mới nhất
                summ = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
                for sev, title, st, tool, cwe, cve in vulns:
                    summ[sev] += 1
                    db.add(Vulnerability(scan_id=sc.id, tool=tool, scan_type=ScanType[st], title=title,
                           severity=Severity[sev], cwe=cwe, cve=cve, status=VulnStatus.OPEN,
                           file_path=f"src/{name}/main.py", line_start=42,
                           ai_false_positive_likelihood="10%",
                           ai_explanation="Lỗ hổng có thật, cần ưu tiên xử lý.",
                           ai_provider="claude-api:claude-opus-5-5"))
                sc.summary = summ; db.commit()

    # ── Domain + crawl + webscan ──
    dom = Domain(name="Website chính", url="https://demo-shop.example.com", description="App demo")
    db.add(dom); db.commit()
    crawl = DomainCrawl(domain_id=dom.id, crawl_number=1, status=CrawlStatus.COMPLETED,
                        completed_at=datetime.utcnow(), summary={"total_urls": 3})
    db.add(crawl); db.commit()
    for u in ["/", "/login", "/api/products?id=1"]:
        db.add(CrawlEndpoint(crawl_id=crawl.id, url="https://demo-shop.example.com" + u, path=u.split("?")[0],
               method="GET", query_params=["id"] if "?" in u else []))
    db.commit()
    ws = WebScan(domain_id=dom.id, crawl_id=crawl.id, severities=["critical", "high", "medium"],
                 status=WebScanStatus.COMPLETED, target_count=3, completed_at=datetime.utcnow(),
                 authorized_by=DEMO_EMAIL, summary={"critical": 1, "high": 1, "medium": 1, "total": 3})
    db.add(ws); db.commit()
    for sev, name_, tid, cve in [("critical", "SQLi trên /api/products", "sqli-detect", None),
                                 ("high", "CVE-2024-3400 PAN-OS", "CVE-2024-3400", "CVE-2024-3400"),
                                 ("medium", "Thiếu header bảo mật", "http-missing-security-headers", None)]:
        db.add(WebFinding(scan_id=ws.id, template_id=tid, name=name_, severity=sev,
               matched_at="https://demo-shop.example.com/api/products?id=1", host="demo-shop.example.com",
               cve=cve, status=WebFindingStatus.OPEN,
               curl_command="curl 'https://demo-shop.example.com/api/products?id=1'"))
    db.commit()

    # ── Connectors (config giả) ──
    db.add(ConnectorConfig(name="Trellix XDR Production", kind=ConnectorKind.TRELLIX_XDR,
           base_url="https://api.manage.trellix.com", enabled=True, secrets_enc={},
           last_sync_status="ok", last_sync_at=datetime.utcnow(),
           last_sync_message="Đồng bộ 4 asset, 2 alert", last_sync_stats={"assets": 4, "alerts": 2, "software": 12}))
    db.add(ConnectorConfig(name="FortiNAC Campus", kind=ConnectorKind.FORTINAC,
           base_url="https://fortinac.corp.local", enabled=True, secrets_enc={},
           last_sync_status="ok", last_sync_at=datetime.utcnow(),
           last_sync_message="Đồng bộ 5 host", last_sync_stats={"assets": 5, "alerts": 0}))
    db.add(ConnectorConfig(name="Trend Vision One", kind=ConnectorKind.TRENDMICRO_VISION_ONE,
           base_url="https://api.xdr.trendmicro.com", enabled=False, secrets_enc={}))
    db.commit()

    # ── Assets (như vừa sync từ connector) ──
    assets = [
        dict(norm=dict(hostname="web-prod-01", ip="10.20.1.11", mac="AA:BB:CC:00:00:11",
                       criticality="CRITICAL", exposure="INTERNET", os="Ubuntu 22.04",
                       edr_agent_present=True, edr_health="healthy", vlan="dmz", nac_status="connected"),
             src="trellix", cves=[("CVE-2021-44228", 10.0, "Log4Shell"), ("CVE-2022-22965", 9.8, "Spring4Shell")],
             alert=("Cobalt Strike beacon", "high", "T1071"),
             sw=[("Apache Log4j", "2.14.1"), ("OpenSSH", "8.9"), ("nginx", "1.18")]),
        dict(norm=dict(hostname="dc-01", ip="10.10.0.5", mac="AA:BB:CC:00:00:05",
                       criticality="CRITICAL", exposure="INTERNAL", os="Windows Server 2019",
                       edr_agent_present=True, edr_health="healthy"),
             src="trellix", cves=[("CVE-2020-1472", 10.0, "Zerologon")],
             alert=("Pass-the-hash nghi vấn", "high", "T1550"),
             sw=[("Active Directory", "2019")]),
        dict(norm=dict(hostname="vpn-gw", ip="10.0.0.254", mac="AA:BB:CC:00:00:fe",
                       criticality="HIGH", exposure="INTERNET", os="FortiOS",
                       asset_type="NETWORK_DEVICE", vlan="edge", nac_status="connected"),
             src="fortinac", cves=[("CVE-2018-13379", 9.8, "FortiOS path traversal"), ("CVE-2024-3400", 9.3, "PAN-OS")],
             alert=None, sw=[]),
        dict(norm=dict(hostname="finance-ws-07", ip="10.30.4.77", mac="AA:BB:CC:00:04:77",
                       criticality="MEDIUM", exposure="INTERNAL", os="Windows 10",
                       edr_agent_present=True, edr_health="healthy", vlan="user"),
             src="fortinac", cves=[("CVE-2023-34362", 7.5, "MOVEit")], alert=None,
             sw=[("MOVEit Transfer", "15.0")]),
        dict(norm=dict(hostname="printer-hr-02", ip="10.40.2.22", mac="AA:BB:CC:00:02:22",
                       criticality="LOW", exposure="ISOLATED", os="embedded", asset_type="NETWORK_DEVICE",
                       vlan="iot", nac_status="connected"),
             src="fortinac", cves=[], alert=None, sw=[]),
        dict(norm=dict(hostname="guest-laptop-11", ip="10.50.9.11", mac="AA:BB:CC:00:09:11",
                       criticality="LOW", exposure="INTERNAL", os="macOS 14", edr_agent_present=False),
             src="fortinac", cves=[], alert=None, sw=[]),
    ]
    for a in assets:
        asset = upsert_asset(db, a["norm"], a["src"]); db.commit()
        if a["sw"]:
            replace_software(db, asset, [{"name": n, "version": v} for n, v in a["sw"]], a["src"])
        for cve, cvss, title in a["cves"]:
            upsert_vuln(db, asset, cve, cvss, title, "edr", "critical" if cvss >= 9 else "high")
        if a["alert"]:
            t, sev, tech = a["alert"]
            upsert_alert(db, asset, {"external_id": f"AL-{asset.hostname}", "title": t, "severity": sev,
                         "status": "open", "technique": tech, "detected_at": datetime.utcnow()}, a["src"])
        recompute_asset_risk(db, asset); db.commit()

    # ── Pentest engagement + run + finding + approval + traffic ──
    eng = Engagement(name="Pentest web-prod Q4", description="Theo hợp đồng HD-2025-07",
                     scope_rules=[{"type": "domain", "value": "demo-shop.example.com", "include_subdomains": True, "mode": "allow"},
                                  {"type": "cidr", "value": "10.20.1.0/24", "mode": "allow"}],
                     authorized=True, authorized_by=DEMO_EMAIL, authorization_note="Phê duyệt bởi CISO",
                     default_mode=AutonomyMode.AUTONOMOUS_IN_SCOPE, max_steps=40, max_parallel=3)
    db.add(eng); db.commit()
    run = PentestRun(engagement_id=eng.id, run_number=1, goal="Tìm lỗ hổng xác thực và injection trên web-prod",
                     mode=AutonomyMode.AUTONOMOUS_IN_SCOPE, targets=["https://demo-shop.example.com"],
                     status=RunStatus.WAITING_APPROVAL, started_by=DEMO_EMAIL,
                     steps_used=4, tokens_used=83250,
                     todolist=[{"id": "t1", "step": "Recon web", "status": "done"},
                               {"id": "t2", "step": "Tìm SQLi", "status": "in_progress", "depends_on": ["t1"]},
                               {"id": "t3", "step": "Khai thác lấy dữ liệu", "status": "pending", "depends_on": ["t2"]}],
                     progress={"phase": "waiting_approval", "message": "Chờ duyệt: sqlmap (DESTRUCTIVE)", "current_tool": "sqlmap"},
                     summary={"conclusion": "Phát hiện XSS + endpoint nghi SQLi; đang xin duyệt bước khai thác."})
    db.add(run); db.commit()
    steps = [(1, "http_probe", RiskTier.RECON, "model", "executed", "Recon trang chủ"),
             (2, "web_vuln_scan", RiskTier.ACTIVE_SAFE, "model", "executed", "Quét nuclei"),
             (3, "active_http", RiskTier.INTRUSIVE, "human", "executed", "Thử payload XSS (đã duyệt)"),
             (4, "sqlmap", RiskTier.DESTRUCTIVE, "human", "awaiting_approval", "Chờ duyệt khai thác SQLi")]
    for n, tool, risk, by, outcome, th in steps:
        db.add(AgentStep(run_id=run.id, step_number=n, tool_name=tool, risk_tier=risk, decided_by=by,
                         outcome=outcome, thought=th, tool_input={"url": "https://demo-shop.example.com/api/products?id=1"}))
    db.commit()
    tr = TrafficEntry(run_id=run.id, source="active_http", method="GET", host="demo-shop.example.com",
                      url="https://demo-shop.example.com/api/products?id=1'", status_code=500, scheme="https",
                      response_body="SQL syntax error near ''1''' at line 1")
    db.add(tr); db.commit()
    db.add(PentestFinding(run_id=run.id, title="SQL Injection trên /api/products", severity="high",
           target="https://demo-shop.example.com/api/products", verified=True, status="OPEN",
           evidence="Response 500: SQL syntax error near ''1'''", evidence_traffic_id=tr.id,
           reproduction="GET /api/products?id=1'", description="Tham số id không được tham số hoá.",
           remediation="Dùng prepared statement.", cwe="CWE-89"))
    db.add(PentestFinding(run_id=run.id, title="XSS phản chiếu ở tham số q", severity="medium",
           target="https://demo-shop.example.com/search", verified=True, status="OPEN",
           evidence="Payload <script> phản chiếu trong response", cwe="CWE-79"))
    db.add(ApprovalRequest(run_id=run.id, step_number=4, tool_name="sqlmap", risk_tier=RiskTier.DESTRUCTIVE,
           tool_input={"url": "https://demo-shop.example.com/api/products?id=1", "level": 1, "risk": 1},
           rationale="Xác nhận và khai thác SQLi — có thể đọc/ghi DB, cần người duyệt.",
           status=ApprovalStatus.PENDING))
    db.commit()
    db.close()
    print("✅ Seed demo xong.")
    print(f"   Đăng nhập: {DEMO_EMAIL} / {DEMO_PASS}")


if __name__ == "__main__":
    seed()
