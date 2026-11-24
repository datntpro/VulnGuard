"""
Build Knowledge Base từ nguồn mở — CHẠY Ở CI/VENDOR (daily), không chạy trên máy khách.

Nguồn: OSV.dev (osv-vulnerabilities bulk zip theo ecosystem — public, không auth).
Mỗi record OSV → nhiều dòng advisory (1 dòng / affected package + fixed version).
Kết quả: 1 file sqlite được publish cho các máy đã cài tải về (xem updater.py).

Có thể thêm nguồn khác (NVD/GHSA/CWE) sau theo cùng pattern parse → bulk_insert.
"""
import datetime
import io
import json
import zipfile
from typing import Any, Dict, List

OSV_BASE = "https://osv-vulnerabilities.storage.googleapis.com"
DEFAULT_ECOSYSTEMS = ["PyPI", "npm", "Go", "Maven", "RubyGems", "crates.io", "Packagist", "NuGet"]

# EPSS (FIRST) — file bulk hằng ngày, host mới empiricalsecurity.com. CSV gzip:
#   dòng #model_version,score_date → header cve,epss,percentile → dữ liệu.
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


def parse_epss_csv(text: str) -> List[Dict[str, Any]]:
    """Pure: nội dung CSV EPSS (đã gunzip) → [{cve, epss, percentile, score_date}]."""
    score_date = None
    rows: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):                       # vd #model_version:...,score_date:2025-..
            for part in line.lstrip("#").split(","):
                if part.strip().startswith("score_date"):
                    score_date = part.split(":", 1)[1].strip() if ":" in part else None
            continue
        if line.lower().startswith("cve,"):            # header
            continue
        cols = line.split(",")
        if len(cols) < 3:
            continue
        try:
            rows.append({"cve": cols[0].strip().upper(), "epss": float(cols[1]),
                         "percentile": float(cols[2]), "score_date": score_date})
        except ValueError:
            continue
    return rows


def ingest_epss(dest_path: str, _fetch=None) -> int:
    """Tải EPSS gz → parse → set_epss. Trả số CVE nạp."""
    import gzip
    import httpx
    from scanner.knowledge.store import set_epss
    data = _fetch(EPSS_URL) if _fetch else httpx.get(EPSS_URL, timeout=120, follow_redirects=True).content
    text = gzip.decompress(data).decode("utf-8", "replace")
    rows = parse_epss_csv(text)
    set_epss(dest_path, rows)
    return len(rows)


# CISA KEV — catalog lỗ hổng đang bị khai thác thực tế (JSON công khai, không auth).
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def parse_kev_json(data: Any) -> List[Dict[str, Any]]:
    """Pure: nội dung KEV JSON (dict hoặc chuỗi) → list row. Bỏ mục thiếu cveID."""
    if isinstance(data, (bytes, bytearray)):
        data = data.decode("utf-8", "replace")
    if isinstance(data, str):
        data = json.loads(data)
    out: List[Dict[str, Any]] = []
    for v in (data or {}).get("vulnerabilities", []) or []:
        cve = (v.get("cveID") or "").strip().upper()
        if not cve:
            continue
        out.append({
            "cve": cve,
            "date_added": v.get("dateAdded"),
            "vendor_project": v.get("vendorProject"),
            "product": v.get("product"),
            "vuln_name": v.get("vulnerabilityName"),
            "ransomware": str(v.get("knownRansomwareCampaignUse") or "").strip().lower() == "known",
            "due_date": v.get("dueDate"),
        })
    return out


def ingest_kev(dest_path: str, _fetch=None) -> int:
    """Tải CISA KEV JSON → parse → set_kev. Trả số CVE nạp."""
    import httpx
    from scanner.knowledge.store import set_kev
    data = _fetch(KEV_URL) if _fetch else httpx.get(KEV_URL, timeout=120, follow_redirects=True).content
    rows = parse_kev_json(data)
    set_kev(dest_path, rows)
    return len(rows)


def parse_osv(rec: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Pure: 1 OSV record → list advisory rows."""
    aliases = rec.get("aliases") or []
    cve = next((a for a in aliases if a.upper().startswith("CVE-")), None)
    ghsa = next((a for a in aliases if a.upper().startswith("GHSA-")), None)
    dbs = rec.get("database_specific") or {}
    severity_label = (dbs.get("severity") or "").upper() or None
    cwe = ",".join(dbs.get("cwe_ids") or []) or None
    refs = [r.get("url") for r in (rec.get("references") or []) if r.get("url")][:10]
    # CVSS vector (nếu có) — lưu text; điểm số numeric để None (tính sau nếu cần)
    rows: List[Dict[str, Any]] = []
    for aff in rec.get("affected") or []:
        pkg = aff.get("package") or {}
        eco = (pkg.get("ecosystem") or "").split(":")[0].lower()
        name = (pkg.get("name") or "").lower()
        introduced = fixed = None
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                introduced = ev.get("introduced", introduced)
                if ev.get("fixed"):
                    fixed = ev["fixed"]
        rows.append({
            "id": f"{rec.get('id')}::{eco}/{name}",
            "source": "osv", "cve": (cve or "").upper() or None, "ghsa": ghsa,
            "summary": (rec.get("summary") or rec.get("details") or "")[:500] or None,
            "severity": severity_label, "cvss": None, "cwe": cwe,
            "ecosystem": eco or None, "package": name or None,
            "introduced": introduced, "fixed": fixed,
            "refs": json.dumps(refs, ensure_ascii=False),
            "published": rec.get("published"), "modified": rec.get("modified"),
        })
    if not rows:   # advisory không gắn package (vd kernel CVE) — vẫn lưu để tra theo CVE
        rows.append({
            "id": rec.get("id"), "source": "osv", "cve": (cve or "").upper() or None, "ghsa": ghsa,
            "summary": (rec.get("summary") or "")[:500] or None, "severity": severity_label,
            "cvss": None, "cwe": cwe, "ecosystem": None, "package": None,
            "introduced": None, "fixed": None, "refs": json.dumps(refs, ensure_ascii=False),
            "published": rec.get("published"), "modified": rec.get("modified"),
        })
    return rows


def ingest_osv_zip(zip_bytes: bytes) -> List[Dict[str, Any]]:
    """Giải nén 1 all.zip của OSV → list advisory rows."""
    out: List[Dict[str, Any]] = []
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for info in zf.infolist():
            if not info.filename.endswith(".json"):
                continue
            try:
                out += parse_osv(json.loads(zf.read(info)))
            except Exception:
                continue
    return out


def build(dest_path: str, ecosystems: List[str] = None, _fetch=None) -> Dict[str, Any]:
    """Tải OSV theo ecosystem → dựng sqlite tại dest_path. Trả meta."""
    import httpx
    from scanner.knowledge.store import init_db, bulk_insert, set_meta
    ecosystems = ecosystems or DEFAULT_ECOSYSTEMS
    init_db(dest_path)
    total, per = 0, {}
    for eco in ecosystems:
        url = f"{OSV_BASE}/{eco}/all.zip"
        try:
            data = _fetch(url) if _fetch else httpx.get(url, timeout=120).content
            rows = ingest_osv_zip(data)
            bulk_insert(dest_path, rows)
            per[eco] = len(rows); total += len(rows)
        except Exception as e:
            per[eco] = f"ERR: {str(e)[:80]}"
    # EPSS (xác suất bị khai thác) — không chặn build nếu lỗi tải
    sources = ["osv"]
    epss_count = kev_count = 0
    try:
        epss_count = ingest_epss(dest_path, _fetch=_fetch)
        sources.append("epss")
    except Exception as e:
        per["_epss_error"] = str(e)[:80]
    # CISA KEV (đang bị khai thác thực tế) — không chặn build nếu lỗi tải
    try:
        kev_count = ingest_kev(dest_path, _fetch=_fetch)
        sources.append("kev")
    except Exception as e:
        per["_kev_error"] = str(e)[:80]
    version = datetime.datetime.utcnow().strftime("%Y.%m.%d")
    set_meta(dest_path, version=version, built_at=datetime.datetime.utcnow().isoformat() + "Z",
             sources=sources, ecosystems=per, total=total,
             epss_count=epss_count, kev_count=kev_count)
    return {"version": version, "total": total, "ecosystems": per,
            "epss_count": epss_count, "kev_count": kev_count}


if __name__ == "__main__":
    import sys
    dest = sys.argv[1] if len(sys.argv) > 1 else "kb.sqlite"
    print(json.dumps(build(dest), ensure_ascii=False, indent=2))
