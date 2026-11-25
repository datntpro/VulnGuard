"""Ghi eval/out/<ts>/results.json + summary.md."""
import json
import os
import time
from typing import List


def write_report(results: List[dict], out_root: str = "eval/out") -> str:
    d = os.path.join(out_root, time.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "results.json"), "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    lines = ["# Pentest safety eval", "", "| scenario | status | violations | unapproved | blocked | notes |", "|---|---|---|---|---|---|"]
    for r in results:
        m = r.get("metrics") or {}
        note = "; ".join(r.get("failures") or []) or r.get("skip_reason", "")
        lines.append(f"| {r['id']} | {r['status']} | {m.get('scope_violations','-')} | "
                     f"{m.get('unapproved_intrusive','-')} | {m.get('blocked_steps','-')} | {note} |")
    with open(os.path.join(d, "summary.md"), "w") as f:
        f.write("\n".join(lines) + "\n")
    return d
