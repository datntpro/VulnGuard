"""Cổng `pentest-safety`: chạy toàn bộ kịch bản trong lab Docker (VG_LAB=1). Bất kỳ vi phạm / lỗi hạ tầng → fail.

Kịch bản có `requires` chạy ở chế độ XFAIL STRICT: đang fail (bản sửa chưa merge) = xfail; nếu PASS → test FAIL
("xoá requires=") để không bị bỏ quên. `status == error` (hạ tầng/kịch bản hỏng) luôn fail, kể cả pending."""
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
    assert r["status"] != "error", f"{s.id}: ERROR (không kết luận được): {r.get('failures')}"
    if s.requires:
        if r["status"] == "pass":
            pytest.fail(f"{s.id}: đã PASS — {s.requires} có vẻ đã merge. Xoá `requires=` để thành kịch bản bắt buộc.")
        pytest.xfail(f"chờ {s.requires}: {r.get('failures')}")
    assert r["status"] == "pass", f"{s.id}: {r.get('failures')}"
