"""
Trình xuất báo cáo scan: Markdown, AI-JSON (cho LLM đọc), SARIF + branding báo cáo.

- PDF: KHÔNG còn ở đây — dùng engine Typst (scanner/pdf, api/services/pdf_export).
- Markdown: gọn, token-efficient, lý tưởng để dán cho AI hoặc commit vào repo.
- AI-JSON: cấu trúc tối giản, chỉ field cần thiết, để agent/LLM nạp tự động.
"""
import json
import os
from datetime import datetime
from typing import Any, Dict, List

from scanner import compliance

_LOGO = os.path.join(os.path.dirname(__file__), "assets", "logo.png")
_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# ── Branding báo cáo (logo + header/footer) — chỉnh trong Settings → Báo cáo ──
# Lưu cùng chỗ với scanner_config.json; ghi đè bằng env REPORT_BRANDING_FILE.
_BRANDING_FILE = os.environ.get(
    "REPORT_BRANDING_FILE",
    os.path.join(os.path.dirname(os.environ.get(
        "SCANNER_CONFIG_FILE", "/app/storage/scanner_config.json")), "report_branding.json"),
)
_BRANDING_DEFAULT = {
    "org_name": "VulnGuard",
    "org_tagline": "DevSecOps Security Platform",
    "report_title": "BÁO CÁO QUÉT BẢO MẬT\nMÃ NGUỒN & THÀNH PHẦN",
    "footer_text": "VulnGuard · Báo cáo quét bảo mật",
    "confidential_label": "BẢO MẬT / CONFIDENTIAL",
    "logo_path": "",  # rỗng → dùng logo bundled scanner/assets/logo.png
}


def _c1(x) -> str:
    """CVSS to one decimal (7.3, not 7.300000000000001)."""
    try:
        return f"{float(x):.1f}"
    except (TypeError, ValueError):
        return str(x)


def load_branding() -> Dict[str, str]:
    """Đọc branding từ file (nếu có), trộn với mặc định."""
    b = dict(_BRANDING_DEFAULT)
    try:
        with open(_BRANDING_FILE) as f:
            data = json.load(f) or {}
        for k in _BRANDING_DEFAULT:
            if isinstance(data.get(k), str) and data[k].strip():
                b[k] = data[k]
    except Exception:
        pass
    return b


def save_branding(data: Dict[str, str]) -> Dict[str, str]:
    """Lưu branding (chỉ các field hợp lệ), trả về bản đã lưu."""
    cur = load_branding()
    for k in _BRANDING_DEFAULT:
        if k in data and isinstance(data[k], str):
            cur[k] = data[k]
    os.makedirs(os.path.dirname(_BRANDING_FILE), exist_ok=True)
    with open(_BRANDING_FILE, "w") as f:
        json.dump(cur, f, ensure_ascii=False, indent=2)
    return cur


def branding_dir() -> str:
    d = os.path.dirname(_BRANDING_FILE)
    os.makedirs(d, exist_ok=True)
    return d


def _logo_path(branding) -> str:
    """Logo tùy chỉnh nếu có & tồn tại, ngược lại dùng logo bundled."""
    p = (branding or {}).get("logo_path") or ""
    if p and os.path.exists(p):
        return p
    return _LOGO
_SEV_RGB = {
    "CRITICAL": (244, 63, 94), "HIGH": (251, 138, 60), "MEDIUM": (245, 196, 67),
    "LOW": (52, 211, 153), "INFO": (96, 165, 250),
}


def _sev(v) -> str:
    s = (v.severity.value if hasattr(v.severity, "value") else str(v.severity)).upper()
    return s if s in _SEV_ORDER else "INFO"


def _stype(v) -> str:
    return v.scan_type.value if hasattr(v.scan_type, "value") else str(v.scan_type or "")


def _counts(vulns) -> Dict[str, int]:
    c = {s: 0 for s in _SEV_ORDER}
    for v in vulns:
        c[_sev(v)] += 1
    return c


def _clip(s, n=600) -> str:
    s = (s or "").strip()
    return s if len(s) <= n else s[:n] + "…"


# ─────────────────────────────────────────────
# Markdown — cho AI/người đọc
# ─────────────────────────────────────────────
def build_markdown(scan, vulns: List[Any], project_name: str) -> str:
    c = _counts(vulns)
    out = [
        f"# VulnGuard — Báo cáo quét bảo mật / Security Scan Report",
        "",
        f"- **Project:** {project_name}",
        f"- **Scan #:** {scan.scan_number}  ·  **Path:** `{scan.scan_path}`",
        f"- **Loại quét / Scan types:** {', '.join(scan.scan_types or [])}",
        f"- **Thời điểm / Generated:** {datetime.utcnow().isoformat()}Z",
        f"- **Tổng số phát hiện / Total findings:** {len(vulns)}",
        "",
        "## Tổng hợp theo mức độ / Severity summary",
        "",
        "| Mức | Số lượng |", "|---|---|",
    ]
    out += [f"| {s} | {c[s]} |" for s in _SEV_ORDER]
    out += ["", "## Chi tiết phát hiện / Findings", ""]
    for s in _SEV_ORDER:
        group = [v for v in vulns if _sev(v) == s]
        if not group:
            continue
        out.append(f"### {s} ({len(group)})")
        out.append("")
        for v in group:
            loc = f"`{v.file_path}`" + (f":{v.line_start}" if v.line_start else "") if v.file_path else "—"
            ids = " · ".join(filter(None, [
                f"CVE {v.cve}" if v.cve else "", f"CWE {v.cwe}" if v.cwe else "",
                f"CVSS {_c1(v.cvss_score)}" if v.cvss_score else "", f"rule {v.rule_id}" if v.rule_id else ""]))
            out.append(f"#### [{s}] {v.title}")
            out.append(f"- **Tool:** {v.tool} ({_stype(v)})  ·  **Vị trí:** {loc}")
            if ids:
                out.append(f"- **ID:** {ids}")
            if v.status and str(getattr(v.status, 'value', v.status)) != "OPEN":
                out.append(f"- **Trạng thái:** {getattr(v.status,'value',v.status)}")
            if v.description:
                out.append(f"- **Mô tả:** {_clip(v.description, 500)}")
            if getattr(v, "ai_false_positive_likelihood", None):
                out.append(f"- **AI — khả năng false positive:** {v.ai_false_positive_likelihood}"
                           + (f" ({v.ai_provider})" if getattr(v, 'ai_provider', None) else ""))
            if getattr(v, "ai_explanation", None):
                out.append(f"- **AI — giải thích:** {_clip(v.ai_explanation, 500)}")
            if getattr(v, "ai_fix_suggestion", None):
                out.append(f"- **AI — hướng dẫn fix:** {_clip(v.ai_fix_suggestion, 600)}")
            out.append("")
    return "\n".join(out)


# ─────────────────────────────────────────────
# AI-JSON — tối giản cho LLM/agent nạp
# ─────────────────────────────────────────────
def build_ai_json(scan, vulns: List[Any], project_name: str) -> str:
    data = {
        "report_type": "vulnguard_scan",
        "project": project_name,
        "scan_number": scan.scan_number,
        "scan_path": scan.scan_path,
        "scan_types": scan.scan_types or [],
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": _counts(vulns),
        "total": len(vulns),
        "findings": [{
            "severity": _sev(v), "title": v.title, "tool": v.tool, "type": _stype(v),
            "file": v.file_path, "line": v.line_start, "rule_id": v.rule_id,
            "cve": v.cve, "cwe": v.cwe, "cvss": v.cvss_score,
            "status": getattr(v.status, "value", str(v.status)) if v.status else "OPEN",
            "description": _clip(v.description, 800),
            "ai": {
                "false_positive_likelihood": getattr(v, "ai_false_positive_likelihood", None),
                "explanation": _clip(getattr(v, "ai_explanation", None), 800),
                "fix_suggestion": _clip(getattr(v, "ai_fix_suggestion", None), 800),
                "provider": getattr(v, "ai_provider", None),
            },
        } for v in vulns],
    }
    return json.dumps(data, ensure_ascii=False, indent=2)


# ─────────────────────────────────────────────
# SARIF 2.1.0 — cho GitHub Code Scanning / GitLab / Azure DevOps
# ─────────────────────────────────────────────
_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                "LOW": "note", "INFO": "note"}
_SARIF_SECSEV = {"CRITICAL": "9.5", "HIGH": "7.5", "MEDIUM": "5.0", "LOW": "3.0", "INFO": "1.0"}


def build_sarif(scan, vulns: List[Any], project_name: str) -> str:
    """Xuất SARIF 2.1.0 — cắm thẳng vào GitHub Code Scanning / GitLab / Azure DevOps."""
    rules: Dict[str, Dict[str, Any]] = {}
    results = []
    for v in vulns:
        sev = _sev(v)
        rid = (getattr(v, "rule_id", None) or f"{v.tool}:{getattr(v, 'cwe', '') or v.title[:40]}")
        tags = ["security"] + compliance.owasp_tags(v)
        if getattr(v, "cwe", None):
            tags.append(f"external/cwe/cwe-{compliance._cwe_int(v.cwe)}")
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": (v.tool or "VulnGuard").title().replace(" ", ""),
                "shortDescription": {"text": _clip(v.title, 120)},
                "fullDescription": {"text": _clip(getattr(v, "description", "") or v.title, 1000)},
                "helpUri": "https://owasp.org/Top10/",
                "properties": {"tags": tags, "security-severity": _SARIF_SECSEV.get(sev, "1.0")},
            }
        loc = (v.file_path or "").lstrip("/") or "UNKNOWN"
        line = int(getattr(v, "line_start", 0) or 1) or 1
        msg = _clip(getattr(v, "ai_explanation", None) or getattr(v, "description", "") or v.title, 800)
        results.append({
            "ruleId": rid,
            "level": _SARIF_LEVEL.get(sev, "note"),
            "message": {"text": msg},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": loc},
                "region": {"startLine": line},
            }}],
            "properties": {
                "severity": sev,
                "security-severity": _SARIF_SECSEV.get(sev, "1.0"),
                "cwe": str(getattr(v, "cwe", "") or ""),
                "cve": str(getattr(v, "cve", "") or ""),
                "owasp": compliance.owasp_for(v),
                "tool": v.tool,
            },
        })
    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "VulnGuard",
                "informationUri": "https://github.com/datntpro/VulnGuard",
                "version": "1.0",
                "rules": list(rules.values()),
            }},
            "automationDetails": {"id": f"{project_name}/scan-{scan.scan_number}"},
            "results": results,
        }],
    }
    return json.dumps(doc, ensure_ascii=False, indent=2)
