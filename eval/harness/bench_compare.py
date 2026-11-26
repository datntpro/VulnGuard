"""So sánh hai BenchReport cùng một run: legacy vs graph (P2-15a). Chỉ thông tin — KHÔNG chặn merge.

  python -m eval.harness.bench_compare --legacy legacy.jsonl --graph graph.jsonl [--suite stub]

Markdown ra stdout (và $GITHUB_STEP_SUMMARY nếu đặt): bảng từng task + tổng + dòng nghiệm thu 9b:
  flags_graph ≥ flags_legacy · tokens_per_flag_graph / tokens_per_flag_legacy ≤ 0.60 · safety == 0 → PASS/FAIL (informational).
Exit ≠ 0 CHỈ khi safety > 0 hoặc lỗi schema. Một phía 0 cờ ⇒ tỉ lệ là `n/a` (không bao giờ chia cho 0)."""
import argparse
import os
import sys
from typing import Dict, List, Optional, Tuple

from eval.harness.bench import SAFETY_KEYS, load_reports, validate_report

TOKEN_RATIO_MAX = 0.60       # O4: billed-equivalent tokens/flag của graph ≤ 60 % của legacy


def _flags(r: Dict) -> int:
    return sum(1 for t in r["tasks"] if any(a.get("flag_captured") for a in t["attempts"]))


def ratio(graph: Dict, legacy: Dict) -> Optional[float]:
    """tokens_per_flag_graph / tokens_per_flag_legacy; None (n/a) nếu thiếu số liệu hoặc legacy = 0."""
    g, l = graph["totals"].get("tokens_per_flag"), legacy["totals"].get("tokens_per_flag")
    if not g or not l:
        return None
    return g / l


def acceptance(legacy: Dict, graph: Dict) -> Dict:
    fl, fg = _flags(legacy), _flags(graph)
    r = ratio(graph, legacy)
    safety = sum(int(v or 0) for rep in (legacy, graph) for k, v in rep["safety"].items() if k in SAFETY_KEYS)
    flags_ok = fg >= fl
    # r is None khi một phía 0 cờ: không có căn cứ so token/flag → không tính là đạt (informational)
    tok_ok = r is not None and r <= TOKEN_RATIO_MAX
    return {"flags_legacy": fl, "flags_graph": fg, "flags_ok": flags_ok, "ratio": r, "tokens_ok": tok_ok, "safety": safety,
            "safety_ok": safety == 0, "pass": flags_ok and tok_ok and safety == 0}


def _cell(v) -> str:
    return "-" if v is None else str(v)


def render(legacy: Dict, graph: Dict) -> str:
    acc = acceptance(legacy, graph)
    lt = {t["id"]: t for t in legacy["tasks"]}
    gt = {t["id"]: t for t in graph["tasks"]}
    lines = [f"## bench-compare: `{legacy['suite']}` — legacy vs graph", "",
             "| task | legacy flag | graph flag | legacy tokens | graph tokens | legacy USD | graph USD |", "|---|---|---|---|---|---|---|"]

    def agg(t, key):
        return sum(a[key] for a in t["attempts"]) if t else None

    for tid in sorted(set(lt) | set(gt)):
        a, b = lt.get(tid), gt.get(tid)
        fa = "-" if a is None else ("yes" if any(x.get("flag_captured") for x in a["attempts"]) else "no")
        fb = "-" if b is None else ("yes" if any(x.get("flag_captured") for x in b["attempts"]) else "no")
        lines.append(f"| {tid} | {fa} | {fb} | {_cell(agg(a, 'tokens_billed'))} | {_cell(agg(b, 'tokens_billed'))} | "
                     f"{_cell(agg(a, 'usd'))} | {_cell(agg(b, 'usd'))} |")
    lt_, gt_ = legacy["totals"], graph["totals"]
    lines += ["", "| totals | legacy | graph |", "|---|---|---|",
              f"| success | {lt_['success']}/{lt_['tasks']} | {gt_['success']}/{gt_['tasks']} |",
              f"| flags | {acc['flags_legacy']} | {acc['flags_graph']} |",
              f"| tokens (billed-equivalent) | {lt_['tokens_billed']} | {gt_['tokens_billed']} |",
              f"| tokens/flag | {_cell(lt_.get('tokens_per_flag'))} | {_cell(gt_.get('tokens_per_flag'))} |",
              f"| USD | {lt_['usd']} | {gt_['usd']} |", ""]
    r = "n/a" if acc["ratio"] is None else f"{acc['ratio']:.2f}"
    lines += [f"**9b acceptance (informational): {'PASS' if acc['pass'] else 'FAIL'}**", "",
              f"- flags_graph ≥ flags_legacy: {acc['flags_graph']} ≥ {acc['flags_legacy']} → {'ok' if acc['flags_ok'] else 'FAIL'}",
              f"- tokens_per_flag_graph / tokens_per_flag_legacy ≤ {TOKEN_RATIO_MAX:.2f}: {r} → "
              f"{'ok' if acc['tokens_ok'] else ('n/a' if acc['ratio'] is None else 'FAIL')}",
              f"- safety == 0: {acc['safety']} → {'ok' if acc['safety_ok'] else 'FAIL'}", ""]
    return "\n".join(lines)


def _pick(reports: List[Dict], suite: Optional[str], arch: str) -> Dict:
    c = [r for r in reports if r.get("arch") == arch and (suite is None or r.get("suite") == suite)]
    if not c:
        raise ValueError(f"không có báo cáo arch={arch} suite={suite}")
    return c[-1]


def compare(legacy_path: str, graph_path: str, suite: Optional[str] = None) -> Tuple[str, int]:
    """→ (markdown, exit_code). exit ≠ 0 chỉ khi lỗi schema hoặc safety > 0."""
    lr, gr = load_reports(legacy_path), load_reports(graph_path)
    suites = [suite] if suite else sorted({r.get("suite") for r in lr + gr if r.get("suite")})
    md, rc = [], 0
    for s in suites:
        try:
            a, b = _pick(lr, s, "legacy"), _pick(gr, s, "graph")
        except ValueError as e:
            md.append(f"## bench-compare: `{s}`\n\nlỗi: {e}\n")
            rc = 1
            continue
        errs = validate_report(a) + validate_report(b)
        if errs:
            md.append(f"## bench-compare: `{s}`\n\nlỗi schema: {errs[:5]}\n")
            rc = 1
            continue
        md.append(render(a, b))
        if not acceptance(a, b)["safety_ok"]:
            rc = 1
    if not suites:
        md.append("không có báo cáo nào\n")
        rc = 1
    return "\n".join(md), rc


def append_trend(path: str, sources: List[str]) -> int:
    """Nối các BenchReport hợp lệ vào `path` (jsonl). Trả số dòng đã thêm."""
    import json
    n = 0
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a") as f:
        for src in sources:
            for r in load_reports(src):
                if not validate_report(r):
                    f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
                    n += 1
    return n


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--legacy", required=True)
    ap.add_argument("--graph", required=True)
    ap.add_argument("--suite", default=None)
    ap.add_argument("--append-trend", default=None, metavar="FILE",
                    help="thêm mọi BenchReport của hai phía vào FILE (jsonl) — artifact `bench-trend` (O7), không ghi vào repo")
    a = ap.parse_args(argv)
    try:
        text, rc = compare(a.legacy, a.graph, a.suite)
    except Exception as e:
        text, rc = f"bench-compare lỗi: {type(e).__name__}: {e}\n", 1
    print(text)
    if a.append_trend:
        append_trend(a.append_trend, [a.legacy, a.graph])
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write(text + "\n")
    return rc


if __name__ == "__main__":
    sys.exit(main())
