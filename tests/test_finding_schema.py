"""P2-12: CVSS v4 (golden), WSTG mapping/coverage, fingerprint + dedup. Không chạm mạng."""
import random

import pytest

from api.database import Base, SessionLocal, engine
from api.pentest_models import PentestFinding, PentestRun
from scanner.pentest import agent as agent_mod
from scanner.pentest import finding_schema as fs
from scanner.pentest import wstg
from scanner.pentest.scoring import CvssError, score_cvss4, severity_from_cvss, try_score_cvss4
from tests.pentest_fakes import ScriptedDriver, make_engagement, make_run
from tests.test_agent_loop import SCOPE, _drive, _finding_turn, _get

B = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N"


@pytest.fixture(autouse=True)
def _db(monkeypatch):
    Base.metadata.create_all(bind=engine)
    import api.services.ai_config as ai
    monkeypatch.setattr(ai, "load_config", lambda: {})


# ── CVSS v4 golden (giá trị theo calculator tham chiếu FIRST) ──
@pytest.mark.parametrize("vec,score,sev", [
    (B + "/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3, "critical"),
    (B + "/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0, "critical"),
    (B + "/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", 6.9, "medium"),
    ("CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", 1.0, "low"),
    (B + "/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0, "info"),
    (B + "/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A", 9.3, "critical"),
    (B + "/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U", 8.1, "high"),
])
def test_cvss4_golden(vec, score, sev):
    assert score_cvss4(vec) == (score, sev)


@pytest.mark.parametrize("bad", [
    "", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:4.0/AV:N", B + "/VC:Z/VI:H/VA:H/SC:N/SI:N/SA:N",
    B + "/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/ZZ:A", B + "/VC:H/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",     # sai thứ tự
])
def test_cvss4_invalid_raises(bad):
    with pytest.raises(CvssError):
        score_cvss4(bad)
    assert try_score_cvss4(bad) is None


def test_severity_bands():
    assert [severity_from_cvss(x) for x in (0, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 10)] == \
        ["info", "low", "medium", "medium", "high", "high", "critical", "critical"]


def test_cvss4_matches_reference_lib_on_random_vectors():
    cvss = pytest.importorskip("cvss")     # chỉ để đối chiếu, không phải dependency chạy
    from scanner.pentest.scoring import BASE_METRICS, OPTIONAL_METRICS
    rnd = random.Random(7)
    opt = ("E", "CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA")
    for i in range(300):
        parts = [f"{k}:{rnd.choice(v)}" for k, v in BASE_METRICS.items()]
        if i % 2:
            parts += [f"{k}:{rnd.choice(OPTIONAL_METRICS[k])}" for k in opt if rnd.random() < .5]
        vec = "CVSS:4.0/" + "/".join(parts)
        assert score_cvss4(vec)[0] == cvss.CVSS4(vec).base_score, vec


# ── WSTG ──
def test_wstg_mapping():
    assert wstg.map_from("sqli") == "WSTG-INPV-05"
    assert wstg.map_from("xss_reflected") == "WSTG-INPV-01"
    assert wstg.map_from("ssrf") == "WSTG-INPV-19"
    assert wstg.map_from("idor") == "WSTG-ATHZ-04"
    assert wstg.map_from("open_redirect") == "WSTG-CLNT-04"
    assert wstg.map_from(None, "CWE-89") == "WSTG-INPV-05" and wstg.map_from(None, "89") == "WSTG-INPV-05"
    assert wstg.map_from("totally_unknown") is None
    assert all(wstg.valid_id(v) for v in list(wstg._BY_CLASS.values()) + list(wstg._BY_CWE.values()))
    assert {"INFO", "CONF", "IDNT", "ATHN", "ATHZ", "SESS", "INPV", "ERRH", "CRYP", "BUSL", "CLNT", "APIT"} <= set(wstg.categories())


# ── fingerprint / dedup ──
def test_canonical_endpoint_ignores_query_values_case_scheme_port():
    a = fs.canonical_endpoint("HTTP://Example.com:80/Search/?q=1&b=2#x")
    b = fs.canonical_endpoint("https://example.com/search?B=9&q=zzz")
    assert a == b == "example.com/search?b&q"
    assert fs.canonical_endpoint("http://h:8080/x") == "h:8080/x"


def test_fingerprint_stable_and_discriminating():
    kw = dict(vuln_class="sqli", target="http://a/x?id=1", param="id", cwe="CWE-89")
    assert fs.fingerprint("e1", **kw) == fs.fingerprint("e1", **{**kw, "target": "http://A/X/?id=999", "cwe": "89"})
    assert fs.fingerprint("e1", **kw) != fs.fingerprint("e2", **kw)
    assert fs.fingerprint("e1", **kw) != fs.fingerprint("e1", **{**kw, "param": "name"})


def _mk_finding(db, run, i, rnd):
    q = rnd.choice(["id=1", "id=77", "ID=abc", "id=%27"])
    host = rnd.choice(["Shop.lab", "shop.lab", "SHOP.LAB"])
    sch = rnd.choice(["http", "https", "HTTP"])
    path = rnd.choice(["/item", "/Item", "/item/"])
    inp = {"title": f"SQLi {i}", "target": f"{sch}://{host}{path}?{q}", "cwe": rnd.choice(["CWE-89", "89"]),
           "vuln_class": "sqli", "param": rnd.choice(["id", "ID"])}
    return inp


def test_dedup_rate_on_40_near_duplicates_across_two_runs():
    db = SessionLocal()
    try:
        eng = make_engagement(db, SCOPE)
        r1, r2 = make_run(db, eng), make_run(db, eng, run_number=2)
        ag = agent_mod.PentestAgent(r1.id, driver_factory=lambda c: ScriptedDriver([]))
        rnd = random.Random(3)
        ids = []
        for i in range(40):
            run = r1 if i < 20 else r2
            inp = {**_mk_finding(db, run, i, rnd), "severity": "high", "description": "d", "evidence": "e"}
            ids.append(ag._save_finding(db, run, inp, None))
        rows = db.query(PentestFinding).filter(PentestFinding.run_id.in_([r1.id, r2.id])).all()
        dups = [f for f in rows if f.duplicate_of]
        assert len(dups) / 40 >= 0.95 or len(dups) >= 38, len(dups)       # 39/40 là bản sao của gốc đầu tiên
        orig = [f for f in rows if not f.duplicate_of]
        assert len(orig) == 1 and orig[0].last_seen_run_id == r2.id and orig[0].first_seen_run_id == r1.id
        assert all(f.status == "DUPLICATE" for f in dups)
    finally:
        db.close()


def test_dedup_does_not_cross_engagements_and_flag_off(monkeypatch):
    db = SessionLocal()
    try:
        e1, e2 = make_engagement(db, SCOPE), make_engagement(db, SCOPE)
        r1, r2 = make_run(db, e1), make_run(db, e2)
        inp = {"title": "t", "severity": "low", "target": "http://a/x?i=1", "description": "d", "evidence": "e",
               "vuln_class": "sqli", "param": "i"}
        a1 = agent_mod.PentestAgent(r1.id, driver_factory=lambda c: ScriptedDriver([]))
        a2 = agent_mod.PentestAgent(r2.id, driver_factory=lambda c: ScriptedDriver([]))
        a1._save_finding(db, r1, inp, None)
        f2 = db.query(PentestFinding).filter(PentestFinding.id == a2._save_finding(db, r2, inp, None)).first()
        assert f2.duplicate_of is None                     # khác engagement → không gộp
        monkeypatch.setattr(agent_mod.pentest_settings, "finding_dedup", False)
        f3 = db.query(PentestFinding).filter(PentestFinding.id == a1._save_finding(db, r1, inp, None)).first()
        assert f3.duplicate_of is None and f3.status == "OPEN"
    finally:
        db.close()


# ── report_finding end-to-end ──
def test_report_finding_cvss_wstg_attack_and_invalid_vector():
    db = SessionLocal()
    try:
        eng = make_engagement(db, SCOPE)
        rid = make_run(db, eng).id
    finally:
        db.close()
    good = B + "/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    _drive(rid, [_finding_turn(severity="low", cvss_v4_vector=good, vuln_class="sqli", param="id"),
                 _finding_turn(title="bad", target="10.0.0.5/other", severity="medium", cvss_v4_vector="CVSS:4.0/garbage"), []])
    fs_ = {f.title: f for f in _get(PentestFinding, run_id=rid)}
    g, b = fs_["t"], fs_["bad"]
    assert (g.cvss_v4_score, g.cvss_v4_severity, g.severity) == (9.3, "critical", "critical")   # severity = CVSS khi có
    assert g.wstg_id == "WSTG-INPV-05" and g.attack_technique == "T1190" and g.fingerprint and g.needs_review is False
    assert b.cvss_v4_vector is None and b.cvss_v4_score is None and b.needs_review is True and b.severity == "medium"


def test_report_finding_schema_is_strict_and_has_new_fields():
    props = agent_mod.REPORT_FINDING_DEF["input_schema"]["properties"]
    assert {"cvss_v4_vector", "wstg_id", "vuln_class", "param", "traffic_id"} <= set(props)
    assert agent_mod.REPORT_FINDING_DEF["input_schema"]["additionalProperties"] is False
    assert set(agent_mod.REPORT_FINDING_DEF["input_schema"]["required"]) == {"title", "severity", "target", "description", "evidence"}


def test_wstg_coverage_tested_found_not_tested():
    from api.pentest_models import AgentStep, RiskTier
    db = SessionLocal()
    try:
        eng = make_engagement(db, SCOPE)
        run = make_run(db, eng)
        db.add(AgentStep(run_id=run.id, step_number=1, tool_name="sqlmap", tool_input={}, risk_tier=RiskTier.DESTRUCTIVE,
                         decided_by="model", outcome="executed", output=""))
        db.add(PentestFinding(run_id=run.id, title="x", severity="high", wstg_id="WSTG-INPV-05"))
        db.commit()
        cov = wstg.coverage(run.id, db)
        assert cov["WSTG-INPV-05"] == "found" and cov["WSTG-INFO-01"] == "not_tested"
        db.add(AgentStep(run_id=run.id, step_number=2, tool_name="content_discovery", tool_input={},
                         risk_tier=RiskTier.ACTIVE_SAFE, decided_by="model", outcome="executed", output=""))
        db.commit()
        assert wstg.coverage(run.id, db)["WSTG-INFO-03"] == "tested"
    finally:
        db.close()


# ── PR #66 verify follow-ups (D1–D4, non-string) ──
def _two_runs():
    db = SessionLocal()
    eng = make_engagement(db, SCOPE)
    r1, r2 = make_run(db, eng), make_run(db, eng, run_number=2)
    mk = lambda r: agent_mod.PentestAgent(r.id, driver_factory=lambda c: ScriptedDriver([]))
    return db, r1, r2, mk(r1), mk(r2)


_BASE = {"title": "SQLi", "severity": "low", "target": "http://a/x?i=1", "description": "d", "evidence": "e",
         "vuln_class": "sqli", "param": "i"}


@pytest.mark.parametrize("status", ["FIXED"])
def test_d1_regression_after_fixed_is_a_new_visible_finding(status):
    db, r1, r2, a1, a2 = _two_runs()
    try:
        o = db.query(PentestFinding).filter(PentestFinding.id == a1._save_finding(db, r1, _BASE, None)).first()
        o.status = status
        db.commit()
        n = db.query(PentestFinding).filter(PentestFinding.id == a2._save_finding(db, r2, _BASE, None)).first()
        assert n.duplicate_of is None and n.status == "OPEN" and o.status == "FIXED"
        # lần re-find tiếp theo gộp vào bản OPEN mới, không vào bản FIXED
        n2 = db.query(PentestFinding).filter(PentestFinding.id == a2._save_finding(db, r2, _BASE, None)).first()
        assert n2.duplicate_of == n.id
    finally:
        db.close()


def test_d1_false_positive_only_absorbs_equal_or_lower_severity():
    db, r1, r2, a1, a2 = _two_runs()
    try:
        o = db.query(PentestFinding).filter(PentestFinding.id == a1._save_finding(db, r1, _BASE, None)).first()
        o.status = "FALSE_POSITIVE"
        db.commit()
        same = db.query(PentestFinding).filter(PentestFinding.id == a2._save_finding(db, r2, _BASE, None)).first()
        assert same.duplicate_of == o.id
        worse = db.query(PentestFinding).filter(PentestFinding.id == a2._save_finding(
            db, r2, {**_BASE, "severity": "critical"}, None)).first()
        assert worse.duplicate_of is None and worse.status == "OPEN"
    finally:
        db.close()


def test_d2_higher_severity_refind_escalates_original_decoy_cannot_suppress():
    db, r1, r2, a1, a2 = _two_runs()
    try:
        o = db.query(PentestFinding).filter(PentestFinding.id == a1._save_finding(db, r1, _BASE, None)).first()
        assert o.severity == "low"
        real = {**_BASE, "severity": "low", "cvss_v4_vector": B + "/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "evidence": "real"}
        d = db.query(PentestFinding).filter(PentestFinding.id == a2._save_finding(db, r2, real, None)).first()
        db.refresh(o)
        assert d.duplicate_of == o.id
        assert (o.severity, o.cvss_v4_score, o.cvss_v4_severity) == ("critical", 9.3, "critical")
        assert o.status == "OPEN" and o.last_seen_run_id == r2.id
        # re-find nhẹ hơn không hạ mức
        a2._save_finding(db, r2, {**_BASE, "severity": "info"}, None)
        db.refresh(o)
        assert o.severity == "critical"
    finally:
        db.close()


def test_d3_generic_class_does_not_merge_distinct_issues():
    kw = dict(vuln_class="misconfiguration", target="http://a/", param=None, cwe=None)
    assert fs.fingerprint("e", title="Missing HSTS", **kw) != fs.fingerprint("e", title="Directory listing", **kw)
    assert fs.fingerprint("e", title="Missing HSTS", **kw) == fs.fingerprint("e", title="missing  hsts", **kw)
    # lớp cụ thể vẫn gộp dù tiêu đề khác
    k2 = dict(vuln_class="sqli", target="http://a/x", param="i", cwe="89")
    assert fs.fingerprint("e", title="A", **k2) == fs.fingerprint("e", title="B", **k2)


def test_d4_coverage_counts_refound_duplicates_in_this_run():
    from api.pentest_models import PentestFinding as PF
    db, r1, r2, a1, a2 = _two_runs()
    try:
        a1._save_finding(db, r1, _BASE, None)
        a2._save_finding(db, r2, {**_BASE, "wstg_id": "WSTG-INPV-05"}, None)
        assert wstg.coverage(r2.id, db)["WSTG-INPV-05"] == "found"
    finally:
        db.close()


def test_non_string_values_do_not_crash():
    assert try_score_cvss4(123) is None
    out = fs.enrich({"cvss_v4_vector": 5, "vuln_class": 7, "wstg_id": 3, "param": 9, "cwe": 89})
    assert out["needs_review"] is True and out["vuln_class"] is None and out["param"] is None
    assert fs.fingerprint("e", vuln_class=5, target=3, param=1, cwe=89, title=None)


# ── W3-1: severity enum enforced server-side ──
@pytest.mark.parametrize("raw,exp,review", [
    ("CRITICAL", "critical", False), (" High ", "high", False), ("informational", "info", False),
    ("crit", "critical", False), ("<img src=x>", "info", True), (None, "info", True), (42, "info", True),
    ("x" * 50, "info", True), ("", "info", True),
])
def test_enrich_normalises_severity(raw, exp, review):
    out = fs.enrich({"severity": raw})
    assert out["severity"] == exp and out["needs_review"] is review


def test_valid_cvss_overrides_bogus_severity():
    good = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    out = fs.enrich({"severity": "<script>", "cvss_v4_vector": good})
    assert out["severity"] in fs.SEVERITIES and out["severity"] != "info"
    assert out["needs_review"] is False


def test_save_finding_stores_enum_severity_only():
    db, r1, _r2, a1, _a2 = _two_runs()
    try:
        fid = a1._save_finding(db, r1, {**_BASE, "severity": "<script>"}, None)
        f = db.query(PentestFinding).filter(PentestFinding.id == fid).first()
        assert f.severity == "info" and f.needs_review is True
    finally:
        db.close()
