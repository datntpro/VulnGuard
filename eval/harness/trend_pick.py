"""Chọn artifact `bench-trend` của run TRƯỚC để bench-compare nối tiếp (P2-15b, fix M1).
Đọc JSON của `gh api repos/:o/:r/actions/artifacts?name=bench-trend` và in `workflow_run.id` của artifact mới nhất thoả:
tên == bench-trend, chưa hết hạn, run sinh ra nó thuộc nhánh `main` (chống nhiễm trend từ nhánh khác), không phải run hiện tại.
Không liên quan tới loại sự kiện (cron scripted ban đêm không tạo bench-trend nên tự bị bỏ qua khi lọc theo tên).
In rỗng nếu không có ứng viên. Exit luôn 0."""
import json
import sys
from typing import Optional


def pick(listing: dict, branch: str = "main", exclude_run: Optional[str] = None) -> Optional[str]:
    best = None
    for a in (listing or {}).get("artifacts") or []:
        wr = a.get("workflow_run") or {}
        if a.get("name") != "bench-trend" or a.get("expired") or wr.get("head_branch") != branch:
            continue
        if exclude_run and str(wr.get("id")) == str(exclude_run):
            continue
        key = a.get("created_at") or ""
        if wr.get("id") is not None and (best is None or key > best[0]):
            best = (key, str(wr["id"]))
    return best[1] if best else None


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    try:
        listing = json.load(open(argv[0])) if argv else json.load(sys.stdin)
    except (OSError, ValueError):
        return 0
    rid = pick(listing, exclude_run=argv[1] if len(argv) > 1 else None)
    if rid:
        print(rid)
    return 0


if __name__ == "__main__":
    sys.exit(main())
