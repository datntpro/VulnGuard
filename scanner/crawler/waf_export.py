"""
Export kết quả crawl sang các định dạng phục vụ xây dựng baseline WAF
(positive security model) và sitemap chuẩn.

Output:
- sitemap.xml          : chuẩn sitemaps.org, để tham khảo/SEO
- endpoints JSON        : toàn bộ dữ liệu thô (url, method, params, forms)
- WAF baseline JSON     : gom theo path -> {methods, allowed query/body params}
                          dùng làm input cấu hình allowlist cho WAF
- ModSecurity rule snippet : ví dụ rule mẫu dựa trên baseline

LƯU Ý QUAN TRỌNG: ModSecurity snippet sinh ra chỉ là điểm khởi đầu (baseline
"deny-by-default, allow known-good"). Đây không phải ruleset có thể deploy
production ngay — cần security team review kỹ (đặc biệt false-positive trên
các path chưa crawl tới, params động, hoặc app có thay đổi sau khi crawl).
"""
import xml.sax.saxutils as saxutils
from datetime import datetime
from typing import List, Dict, Any
from urllib.parse import urlparse


def build_sitemap_xml(base_url: str, endpoints: List[Dict[str, Any]]) -> str:
    """Sinh sitemap.xml chuẩn từ các URL GET 2xx/3xx phát hiện được."""
    urls = sorted({
        e["url"] for e in endpoints
        if e.get("method") == "GET" and (e.get("status_code") or 200) < 400
    })

    lines = ['<?xml version="1.0" encoding="UTF-8"?>']
    lines.append('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">')
    today = datetime.utcnow().strftime("%Y-%m-%d")
    for u in urls:
        lines.append(
            f"  <url><loc>{saxutils.escape(u)}</loc><lastmod>{today}</lastmod></url>"
        )
    lines.append("</urlset>")
    return "\n".join(lines)


def build_endpoints_export(domain_url: str, crawl_meta: dict, endpoints: List[Dict[str, Any]]) -> dict:
    return {
        "export_info": {
            "tool": "VulnGuard",
            "feature": "domain-sitemap-crawler",
            "exported_at": datetime.utcnow().isoformat() + "Z",
        },
        "domain": domain_url,
        "crawl": crawl_meta,
        "total_endpoints": len(endpoints),
        "endpoints": endpoints,
    }


def build_waf_baseline(domain_url: str, endpoints: List[Dict[str, Any]]) -> dict:
    """Gom endpoints theo path -> baseline cho positive security model.

    Mỗi path: methods cho phép, query params hợp lệ đã thấy, body params
    (từ form) hợp lệ đã thấy, content-type phản hồi.
    """
    grouped: Dict[str, Dict[str, Any]] = {}

    for e in endpoints:
        path = e.get("path") or "/"
        node = grouped.setdefault(path, {
            "methods": set(),
            "allowed_query_params": set(),
            "allowed_body_params": set(),
            "content_types": set(),
            "sample_url": e.get("url"),
        })
        node["methods"].add(e.get("method", "GET"))
        node["allowed_query_params"].update(e.get("query_params") or [])
        node["allowed_body_params"].update(e.get("body_params") or [])
        if e.get("content_type"):
            node["content_types"].add(e["content_type"].split(";")[0].strip())
        for form in e.get("forms") or []:
            node["methods"].add(form.get("method", "GET"))
            node["allowed_body_params"].update(form.get("fields") or [])

    baseline_paths = []
    for path, node in sorted(grouped.items()):
        baseline_paths.append({
            "path": path,
            "methods": sorted(node["methods"]),
            "allowed_query_params": sorted(node["allowed_query_params"]),
            "allowed_body_params": sorted(node["allowed_body_params"]),
            "content_types": sorted(node["content_types"]),
            "sample_url": node["sample_url"],
        })

    return {
        "export_info": {
            "tool": "VulnGuard",
            "feature": "waf-baseline (positive security model)",
            "exported_at": datetime.utcnow().isoformat() + "Z",
            "disclaimer": (
                "Baseline được sinh tự động từ 1 lần crawl — chỉ phản ánh các "
                "path/param đã phát hiện được tại thời điểm crawl. Security team "
                "cần review trước khi áp dụng làm rule chặn (deny) thật, tránh "
                "false positive cho path/tham số hợp lệ chưa được crawl tới."
            ),
        },
        "domain": domain_url,
        "total_paths": len(baseline_paths),
        "paths": baseline_paths,
    }


def build_modsecurity_rules(domain_url: str, baseline: dict, rule_id_start: int = 1000000) -> str:
    """Sinh ModSecurity rule snippet mẫu — positive security baseline.

    Chiến lược:
    1. Rule liệt kê tất cả path đã biết (allowlist path) — log + flag nếu
       request tới path lạ (không có trong baseline). Mặc định chỉ LOG
       (khuyến nghị) — chuyển sang "deny" sau khi đã review kỹ ở môi trường
       staging, tránh block nhầm người dùng thật.
    2. Với mỗi path có params đã biết, rule cảnh báo khi xuất hiện param lạ
       (không nằm trong allowed_query_params) — gợi ý cho injection/param
       tampering ngoài baseline.
    """
    paths = baseline.get("paths", [])
    domain_host = urlparse(domain_url).netloc or domain_url

    lines = []
    lines.append(f"# ─────────────────────────────────────────────────────────")
    lines.append(f"# ModSecurity Baseline Rules — domain: {domain_host}")
    lines.append(f"# Sinh tự động bởi VulnGuard từ kết quả crawl (katana).")
    lines.append(f"# CẢNH BÁO: Đây là baseline khởi điểm (default action = log).")
    lines.append(f"# Hãy theo dõi log ở môi trường staging trước khi đổi 'log' -> 'deny'.")
    lines.append(f"# ─────────────────────────────────────────────────────────")
    lines.append("")

    known_paths = sorted({p["path"] for p in paths})
    if known_paths:
        path_list = "|".join(
            p.replace("\\", "\\\\").replace('"', '\\"') for p in known_paths
        )
        rid = rule_id_start
        lines.append(f"# Rule {rid}: flag request tới path KHÔNG nằm trong baseline đã crawl")
        lines.append(
            f'SecRule REQUEST_URI "!@rx ^({path_list})/?$" '
            f'"id:{rid},phase:1,log,pass,msg:\'Request tới path ngoài baseline crawl: %{{REQUEST_URI}}\',tag:\'vulnguard-waf-baseline\'"'
        )
        lines.append("")

    rid = rule_id_start + 1
    for p in paths:
        allowed = sorted(set(p.get("allowed_query_params", [])) | set(p.get("allowed_body_params", [])))
        if not allowed:
            continue
        path_escaped = p["path"].replace('"', '\\"')
        allowed_list = "|".join(a.replace('"', '\\"') for a in allowed)
        lines.append(f"# Rule {rid}: flag param lạ trên path {p['path']}")
        lines.append(
            f'SecRule REQUEST_URI "@streq {path_escaped}" '
            f'"id:{rid},phase:2,log,pass,chain,msg:\'Param ngoài baseline trên {path_escaped}\',tag:\'vulnguard-waf-baseline\'"'
        )
        lines.append(f'  SecRule ARGS_NAMES "!@rx ^({allowed_list})$" ""')
        lines.append("")
        rid += 1

    if not known_paths:
        lines.append("# Không có path nào trong baseline — hãy chạy crawl trước.")

    return "\n".join(lines)
