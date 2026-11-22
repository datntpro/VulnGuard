"""
Threat intel feeds — EPSS (xác suất bị khai thác) + CISA KEV (đang bị khai thác thật).

- EPSS: FIRST.org, CSV gzip (cve, epss, percentile). ~250k dòng.
- KEV: CISA known_exploited_vulnerabilities.json (list CVE).

Cache tại <storage>/intel/ (JSON gọn). Offline-capable: fetch best-effort, lỗi mạng
thì dùng cache cũ; không có cache thì trả rỗng (scoring vẫn chạy, chỉ thiếu enrich).
"""
import csv
import gzip
import io
import json
import logging
import os
import time
from typing import Dict, Optional, Tuple

import httpx

from api.config import settings

logger = logging.getLogger(__name__)

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_cache: Dict[str, dict] = {"epss": None, "kev": None}


def _dir() -> str:
    d = os.path.join(settings.storage_dir, "intel")
    os.makedirs(d, exist_ok=True)
    return d


def _epss_path() -> str:
    return os.path.join(_dir(), "epss.json")


def _kev_path() -> str:
    return os.path.join(_dir(), "kev.json")


def _load_json(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


# ── EPSS ──
def _parse_epss_csv(data: bytes) -> Dict[str, float]:
    text = gzip.decompress(data).decode("utf-8", errors="replace")
    out: Dict[str, float] = {}
    for row in csv.reader(io.StringIO(text)):
        if len(row) >= 2 and row[0].startswith("CVE-"):
            try:
                out[row[0].upper()] = float(row[1])
            except ValueError:
                pass
    return out


def refresh_epss(timeout: int = 60) -> Tuple[bool, str]:
    try:
        with httpx.Client(timeout=timeout, trust_env=False, follow_redirects=True) as c:
            r = c.get(EPSS_URL)
            r.raise_for_status()
            scores = _parse_epss_csv(r.content)
        if not scores:
            return False, "EPSS feed rỗng/không parse được"
        payload = {"updated_at": int(time.time()), "scores": scores}
        with open(_epss_path(), "w", encoding="utf-8") as f:
            json.dump(payload, f)
        _cache["epss"] = payload
        return True, f"Đã cập nhật EPSS: {len(scores)} CVE"
    except Exception as e:
        return False, f"Lỗi cập nhật EPSS: {e}"


def _epss_data() -> dict:
    if _cache["epss"] is None:
        _cache["epss"] = _load_json(_epss_path()) or {"scores": {}, "updated_at": None}
    return _cache["epss"]


def epss_for(cve: str) -> Optional[float]:
    return _epss_data().get("scores", {}).get((cve or "").upper())


# ── KEV ──
def refresh_kev(timeout: int = 60) -> Tuple[bool, str]:
    try:
        with httpx.Client(timeout=timeout, trust_env=False, follow_redirects=True) as c:
            r = c.get(KEV_URL)
            r.raise_for_status()
            data = r.json()
        cves = sorted({v.get("cveID", "").upper() for v in data.get("vulnerabilities", []) if v.get("cveID")})
        payload = {"updated_at": int(time.time()), "cves": cves}
        with open(_kev_path(), "w", encoding="utf-8") as f:
            json.dump(payload, f)
        _cache["kev"] = payload
        return True, f"Đã cập nhật KEV: {len(cves)} CVE"
    except Exception as e:
        return False, f"Lỗi cập nhật KEV: {e}"


def _kev_data() -> dict:
    if _cache["kev"] is None:
        _cache["kev"] = _load_json(_kev_path()) or {"cves": [], "updated_at": None}
    return _cache["kev"]


def _kev_set() -> set:
    return set(_kev_data().get("cves", []))


def is_kev(cve: str) -> bool:
    return (cve or "").upper() in _kev_set()


def enrich(cve: str) -> Dict:
    return {"cve": (cve or "").upper(), "epss": epss_for(cve), "kev": is_kev(cve)}


def feed_status() -> Dict:
    e, k = _epss_data(), _kev_data()
    return {
        "epss": {"count": len(e.get("scores", {})), "updated_at": e.get("updated_at")},
        "kev": {"count": len(k.get("cves", [])), "updated_at": k.get("updated_at")},
    }


def seed_for_test(epss: Dict[str, float], kev: list):
    """Dùng trong test/offline — nạp cache trực tiếp + ghi file."""
    _cache["epss"] = {"updated_at": int(time.time()), "scores": {k.upper(): v for k, v in epss.items()}}
    _cache["kev"] = {"updated_at": int(time.time()), "cves": [c.upper() for c in kev]}
    with open(_epss_path(), "w") as f:
        json.dump(_cache["epss"], f)
    with open(_kev_path(), "w") as f:
        json.dump(_cache["kev"], f)
