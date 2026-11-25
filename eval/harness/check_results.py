"""Bước cuối của CI: đối chiếu results.json với catalogue — chống "exit 0 nhưng không chạy gì" (conftest/marker bị sửa,
kịch bản bị skip hàng loạt, đổi nhãn pending...).  python -m eval.harness.check_results [eval/out]"""
import glob
import json
import os
import sys
from typing import Dict, List

from eval.harness.scenarios import PENDING_IDS, S


def verify(results: List[Dict]) -> List[str]:
    errs = []
    by_id = {r["id"]: r for r in results}
    if len(by_id) != len(results):
        errs.append("results.json có id trùng")
    if set(by_id) != {s.id for s in S}:
        errs.append(f"tập scenario không khớp catalogue: thiếu {sorted({s.id for s in S} - set(by_id))}, "
                    f"thừa {sorted(set(by_id) - {s.id for s in S})}")
    pending = {r["id"] for r in results if r.get("requires")}
    if pending != set(PENDING_IDS):
        errs.append(f"pending {sorted(pending)} != PENDING_IDS {sorted(PENDING_IDS)}")
    for r in results:
        if r["id"] in PENDING_IDS:
            if r["status"] != "fail":      # strict-xfail: phải ĐANG fail (pass → phải xoá requires; error → hạ tầng)
                errs.append(f"{r['id']}: pending nhưng status={r['status']} (kỳ vọng fail)")
        elif r["status"] != "pass":
            errs.append(f"{r['id']}: status={r['status']} (kỳ vọng pass)")
    n_pass = sum(1 for r in results if r["status"] == "pass")
    if n_pass != len(S) - len(PENDING_IDS):
        errs.append(f"số pass = {n_pass}, kỳ vọng {len(S) - len(PENDING_IDS)}")
    return errs


def main(root: str = "eval/out") -> int:
    files = sorted(glob.glob(os.path.join(root, "*", "results.json")))
    if not files:
        print("KHÔNG có results.json — job không chạy kịch bản nào")
        return 1
    errs = verify(json.load(open(files[-1])))
    for e in errs:
        print("FAIL:", e)
    print("results OK" if not errs else f"{len(errs)} vấn đề")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
