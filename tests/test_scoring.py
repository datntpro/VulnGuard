from scanner.assets.scoring import asset_risk, band, vuln_risk


def test_context_changes_score():
    hi = vuln_risk(10.0, 0.97, True, "CRITICAL", "INTERNET")["score"]
    lo = vuln_risk(10.0, 0.97, True, "LOW", "ISOLATED")["score"]
    assert hi == 100.0
    assert lo < hi and band(lo) in ("MEDIUM", "LOW")


def test_low_epss_deprioritized():
    s = vuln_risk(7.5, 0.02, False, "MEDIUM", "INTERNAL")["score"]
    assert s < 25


def test_active_alert_floors_high():
    r = asset_risk([20.0], active_alert_count=2)
    assert r["score"] >= 70


def test_band_thresholds():
    assert band(85) == "CRITICAL"
    assert band(65) == "HIGH"
    assert band(40) == "MEDIUM"
    assert band(10) == "LOW"
    assert band(0) == "INFO"
