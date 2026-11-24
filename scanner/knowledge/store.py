"""
Knowledge Base store — DB tri thức lỗ hổng (CVE/advisory/fix version) tách RIÊNG
khỏi DB ứng dụng, để cập nhật/hoán đổi nguyên khối (giống Trivy DB).

File: <storage>/knowledge/kb.sqlite  (updater tải bản mới về rồi swap atomically).
Đọc-nhiều, ghi khi build/import. Dùng để làm giàu finding: fix version, CVSS, CWE,
exploit/KEV, tham chiếu.
"""
import json
import os
import sqlite3
from contextlib import closing
from typing import Any, Dict, List, Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS advisory (
  id TEXT PRIMARY KEY,
  source TEXT, cve TEXT, ghsa TEXT, summary TEXT,
  severity TEXT, cvss REAL, cwe TEXT,
  ecosystem TEXT, package TEXT,
  introduced TEXT, fixed TEXT,
  refs TEXT, published TEXT, modified TEXT
);
CREATE INDEX IF NOT EXISTS ix_adv_cve ON advisory(cve);
CREATE INDEX IF NOT EXISTS ix_adv_pkg ON advisory(ecosystem, package);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""


def kb_path() -> str:
    from api.config import settings
    d = os.path.join(settings.storage_dir, "knowledge")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "kb.sqlite")


def _connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(path: str) -> None:
    with closing(_connect(path)) as c:
        c.executescript(_SCHEMA)
        c.commit()


def set_meta(path: str, **kv) -> None:
    with closing(_connect(path)) as c:
        for k, v in kv.items():
            c.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", (k, json.dumps(v)))
        c.commit()


def get_meta(path: Optional[str] = None) -> Dict[str, Any]:
    path = path or kb_path()
    if not os.path.exists(path):
        return {"available": False}
    try:
        with closing(_connect(path)) as c:
            rows = c.execute("SELECT key,value FROM meta").fetchall()
            n = c.execute("SELECT COUNT(*) FROM advisory").fetchone()[0]
        out = {r["key"]: json.loads(r["value"]) for r in rows}
        out.update({"available": True, "advisory_count": n})
        return out
    except Exception:
        return {"available": False}


def bulk_insert(path: str, rows: List[Dict[str, Any]]) -> int:
    cols = ["id", "source", "cve", "ghsa", "summary", "severity", "cvss", "cwe",
            "ecosystem", "package", "introduced", "fixed", "refs", "published", "modified"]
    with closing(_connect(path)) as c:
        c.executemany(
            f"INSERT OR REPLACE INTO advisory({','.join(cols)}) VALUES({','.join('?' * len(cols))})",
            [[r.get(k) for k in cols] for r in rows])
        c.commit()
    return len(rows)


def lookup_cve(cve: str, path: Optional[str] = None) -> List[Dict[str, Any]]:
    path = path or kb_path()
    if not cve or not os.path.exists(path):
        return []
    with closing(_connect(path)) as c:
        rows = c.execute("SELECT * FROM advisory WHERE cve=? LIMIT 50", (cve.upper(),)).fetchall()
    return [dict(r) for r in rows]


def lookup_package(ecosystem: str, package: str, path: Optional[str] = None) -> List[Dict[str, Any]]:
    path = path or kb_path()
    if not package or not os.path.exists(path):
        return []
    with closing(_connect(path)) as c:
        rows = c.execute("SELECT * FROM advisory WHERE ecosystem=? AND package=? LIMIT 100",
                         ((ecosystem or "").lower(), package.lower())).fetchall()
    return [dict(r) for r in rows]


def enrich(cve: Optional[str] = None, ecosystem: Optional[str] = None,
           package: Optional[str] = None, path: Optional[str] = None) -> Dict[str, Any]:
    """Trả về làm giàu: fixed_versions, cvss, severity, cwe, ghsa, refs, summary."""
    path = path or kb_path()
    advs: List[Dict[str, Any]] = []
    if cve:
        advs += lookup_cve(cve, path)
    if package:
        advs += lookup_package(ecosystem, package, path)
    if not advs:
        return {}
    fixed = sorted({a["fixed"] for a in advs if a.get("fixed")})
    cvss = max((a["cvss"] for a in advs if a.get("cvss") is not None), default=None)
    refs = []
    for a in advs:
        try:
            refs += json.loads(a.get("refs") or "[]")
        except Exception:
            pass
    return {
        "fixed_versions": fixed,
        "cvss": cvss,
        "severity": next((a["severity"] for a in advs if a.get("severity")), None),
        "cwe": next((a["cwe"] for a in advs if a.get("cwe")), None),
        "ghsa": next((a["ghsa"] for a in advs if a.get("ghsa")), None),
        "summary": next((a["summary"] for a in advs if a.get("summary")), None),
        "references": sorted(set(refs))[:10],
        "source_count": len(advs),
    }


# map ecosystem Trivy/scanner → tên ecosystem trong KB (OSV)
_ECO_MAP = {
    "pip": "pypi", "python-pkg": "pypi", "python": "pypi",
    "node-pkg": "npm", "npm": "npm", "yarn": "npm",
    "gomod": "go", "go": "go",
    "maven": "maven", "jar": "maven", "gradle": "maven",
    "gem": "rubygems", "rubygems": "rubygems", "bundler": "rubygems",
    "cargo": "crates.io", "composer": "packagist", "nuget": "nuget",
}


def enrich_findings(findings: List[Dict[str, Any]], path: Optional[str] = None) -> int:
    """
    Làm giàu các finding SCA tại chỗ (chỉ điền chỗ TRỐNG — không ghi đè dữ liệu
    scanner đã có). Thêm key 'kb' chứa refs/summary. Trả số finding được làm giàu.
    An toàn khi KB chưa có: trả 0, không lỗi.
    """
    path = path or kb_path()
    if not os.path.exists(path):
        return 0
    n = 0
    for f in findings:
        cve = f.get("cve")
        pkg = f.get("package_name")
        eco = _ECO_MAP.get((f.get("package_ecosystem") or f.get("pkg_type") or "").lower())
        if not cve and not pkg:
            continue
        data = enrich(cve=cve, ecosystem=eco, package=pkg, path=path)
        if not data:
            continue
        if not f.get("fixed_version") and data.get("fixed_versions"):
            f["fixed_version"] = ", ".join(data["fixed_versions"])
        if not f.get("cwe") and data.get("cwe"):
            f["cwe"] = data["cwe"]
        if not f.get("cvss_score") and data.get("cvss") is not None:
            f["cvss_score"] = str(data["cvss"])
        f["kb"] = {"references": data.get("references", []),
                   "summary": data.get("summary"), "source_count": data.get("source_count", 0)}
        n += 1
    return n
