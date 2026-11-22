"""
Risk scoring kiểu VM (Tenable VPR / Nexpose Real Risk) — có GIẢI THÍCH được.

Điểm 1 vuln trên 1 asset (0..100):
  score = 100 · cvss_norm · threat_mult · context_mult
    cvss_norm   = cvss/10
    threat_mult = 0.2 + 0.8·threat   (threat = EPSS; KEV ⇒ threat = 1.0)  ∈ [0.2, 1.0]
    context_mult= (criticality_w + exposure_w)/2                           ∈ [0.4, 1.0]

Điểm asset = max(điểm các vuln) có cộng thêm khi có cảnh báo EDR đang hoạt động
(đang bị tấn công thật) và khi có nhiều vuln rủi ro cao.
"""
from typing import Dict, List, Optional

from scanner.intel.feeds import epss_for, is_kev

CRIT_W = {"CRITICAL": 1.0, "HIGH": 0.85, "MEDIUM": 0.6, "LOW": 0.4}
EXPO_W = {"INTERNET": 1.0, "INTERNAL": 0.7, "ISOLATED": 0.4, "UNKNOWN": 0.7}


def _enum(v) -> str:
    return v.value if hasattr(v, "value") else str(v or "")


def vuln_risk(cvss: Optional[float], epss: Optional[float], kev: bool,
              criticality: str, exposure: str) -> Dict:
    cvss = float(cvss) if cvss is not None else 5.0
    cvss_norm = max(0.0, min(cvss, 10.0)) / 10.0
    threat = 1.0 if kev else (float(epss) if epss is not None else 0.05)
    threat = max(0.0, min(threat, 1.0))
    threat_mult = 0.2 + 0.8 * threat
    context_mult = (CRIT_W.get(criticality, 0.6) + EXPO_W.get(exposure, 0.7)) / 2.0
    score = round(100.0 * cvss_norm * threat_mult * context_mult, 1)
    return {
        "score": score,
        "factors": {"cvss": cvss, "epss": epss, "kev": kev,
                    "criticality": criticality, "exposure": exposure,
                    "threat_mult": round(threat_mult, 3), "context_mult": round(context_mult, 3)},
    }


def score_vuln_row(av, asset) -> Dict:
    """av: AssetVuln; asset: Asset. Tự enrich EPSS/KEV nếu chưa có."""
    cve = getattr(av, "cve", None)
    epss = av.epss if getattr(av, "epss", None) is not None else epss_for(cve)
    kev = bool(av.kev) if getattr(av, "kev", None) else is_kev(cve)
    return vuln_risk(av.cvss_score, epss, kev, _enum(asset.criticality), _enum(asset.exposure))


def asset_risk(vuln_scores: List[float], active_alert_count: int = 0) -> Dict:
    """Tổng hợp điểm asset từ các điểm vuln + cảnh báo EDR đang hoạt động."""
    base = max(vuln_scores) if vuln_scores else 0.0
    # Nhiều vuln rủi ro cao → cộng nhẹ (diminishing)
    high = [s for s in vuln_scores if s >= 50]
    volume_bump = min(10.0, 2.5 * max(0, len(high) - 1))
    # Đang bị tấn công thật (EDR alert) → đẩy mạnh, tối thiểu 70
    alert_bump = 0.0
    score = base + volume_bump
    if active_alert_count > 0:
        score = max(score, 70.0) + min(20.0, 5.0 * active_alert_count)
        alert_bump = round(score - (base + volume_bump), 1)
    score = round(min(score, 100.0), 1)
    return {"score": score, "factors": {"base_max_vuln": base, "volume_bump": volume_bump,
            "active_alert_count": active_alert_count, "alert_bump": alert_bump}}


def band(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFO"
