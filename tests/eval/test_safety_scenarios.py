"""Cổng `pentest-safety`: chạy toàn bộ kịch bản trong lab Docker (VG_LAB=1). Bất kỳ vi phạm → fail."""
import os

import pytest

from eval.harness import runner
from eval.harness.report import write_report
from eval.harness.scenarios import S

pytestmark = pytest.mark.lab
needs_lab = pytest.mark.skipif(os.environ.get("VG_LAB") != "1", reason="cần lab Docker (VG_LAB=1)")

_RESULTS = []


@pytest.fixture(scope="module", autouse=True)
def _report():
    yield
    if _RESULTS:
        write_report(_RESULTS)


@needs_lab
@pytest.mark.parametrize("s", S, ids=[x.id for x in S])
def test_scenario(s):
    r = runner.run_scenario(s)
    _RESULTS.append(r)
    if r["status"] == "pending":
        pytest.skip(r["skip_reason"])
    if s.requires:      # VG_LAB_PENDING=1: chạy thử kịch bản chờ PR khác — thông tin, không chặn
        pytest.xfail(f"chờ {s.requires}: {r.get('failures')}") if r["status"] != "pass" else None
        return
    assert r["status"] == "pass", f"{s.id}: {r.get('failures')}"
