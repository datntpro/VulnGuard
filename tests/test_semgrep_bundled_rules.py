"""PR-A #101: mỗi bundled semgrep rule phải có fixture chú thích (`# ruleid:` / `# ok:`) và
khớp CHÍNH XÁC (không thiếu, không thừa). Chạy với cờ giống SemgrepScanner.

Fixture nằm dưới tests/ nên phải copy ra tmp (semgrep mặc định bỏ qua thư mục `tests/`).
CI đặt VG_REQUIRE_SEMGREP=1 để không thể skip âm thầm.
"""
import json
import os
import re
import shutil
import subprocess

import pytest
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = os.path.join(ROOT, "scanner", "rules", "python-security.yaml")
FIXDIR = os.path.join(ROOT, "tests", "fixtures", "semgrep_rules")
_ANN = re.compile(r"#\s*(ruleid|ok):\s*([\w.-]+)")


def _rule_ids():
    with open(RULES, encoding="utf-8") as f:
        return [r["id"] for r in yaml.safe_load(f)["rules"]]


def _semgrep():
    exe = shutil.which("semgrep")
    if exe:
        return exe
    if os.environ.get("VG_REQUIRE_SEMGREP") == "1":
        pytest.fail("VG_REQUIRE_SEMGREP=1 nhưng không tìm thấy semgrep")
    pytest.skip("semgrep chưa cài")


def _annotations(path):
    """Trả (expected, forbidden) = set[(basename, line, rule_id)]."""
    exp, forb = set(), set()
    base = os.path.basename(path)
    with open(path, encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            m = _ANN.search(line)
            if m:
                (exp if m.group(1) == "ruleid" else forb).add((base, i + 1, m.group(2)))
    return exp, forb


def test_every_bundled_rule_has_fixture():
    ids = set(_rule_ids())
    files = {n[:-3] for n in os.listdir(FIXDIR) if n.endswith(".py")}
    assert not ids - files, f"rule thiếu fixture: {sorted(ids - files)}"
    assert not files - ids, f"fixture mồ côi: {sorted(files - ids)}"
    for rid in ids:
        text = open(os.path.join(FIXDIR, rid + ".py"), encoding="utf-8").read()
        assert f"# ruleid: {rid}" in text, f"{rid}: cần ≥1 `# ruleid:`"
        assert f"# ok: {rid}" in text, f"{rid}: cần ≥1 `# ok:`"


def test_rules_validate():
    exe = _semgrep()
    r = subprocess.run([exe, "--validate", "--metrics=off", "--config", RULES],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr


def test_bundled_rules_against_fixtures(tmp_path):
    exe = _semgrep()
    fx = tmp_path / "fx"  # không có thành phần `tests/` trong đường dẫn
    shutil.copytree(FIXDIR, fx)
    expected, forbidden = set(), set()
    for n in sorted(os.listdir(fx)):
        e, f = _annotations(str(fx / n))
        expected |= e
        forbidden |= f
    r = subprocess.run(
        [exe, "--config", RULES, "--json", "--metrics=off", "--no-git-ignore", "--quiet",
         "--timeout", "30", "--dataflow-traces", str(fx)],
        capture_output=True, text=True, timeout=300)
    out = json.loads(r.stdout)
    assert out["errors"] == [], out["errors"]
    got = {(os.path.basename(x["path"]), x["start"]["line"], x["check_id"].split(".")[-1])
           for x in out["results"]}
    tp = {rid: sum(1 for (_, _, i) in got & expected if i == rid) for rid in _rule_ids()}
    table = "\n".join(f"  {k}: TP={v}" for k, v in tp.items())
    assert not expected - got, f"bỏ sót: {sorted(expected - got)}\n{table}"
    assert not got & forbidden, f"báo nhầm (ok:): {sorted(got & forbidden)}\n{table}"
    assert not got - expected, f"hit không chú thích: {sorted(got - expected)}\n{table}"
    for rid, n in tp.items():
        assert n >= 1, f"rule {rid} has zero true positives\n{table}"
