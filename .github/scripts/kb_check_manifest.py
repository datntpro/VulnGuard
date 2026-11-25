"""Sanity-check của job `sign` trước khi ký (chạy bằng `python -I`, KHÔNG có secret).

Dùng: kb_check_manifest.py <bundle_dir> <expected_url> [<previous_manifest.json>]
Thoát != 0 nếu bundle không đúng kỳ vọng. Chỉ dùng stdlib.
"""
import datetime
import hashlib
import json
import os
import re
import sys

MAX_MANIFEST = 64 << 10
MAX_SNAPSHOT = 1 << 30
KEYS = {"version", "built_at", "sha256", "url", "advisory_count", "format"}


def _ver(v):
    return tuple(int(x) for x in v.split("."))


def check(bundle, expected_url, previous=None, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    names = sorted(os.listdir(bundle))
    if names != ["kb-manifest.json", "kb.sqlite.gz"]:
        raise ValueError(f"bundle phải có đúng 2 file, thấy: {names}")
    for n in names:
        p = os.path.join(bundle, n)
        if os.path.islink(p) or not os.path.isfile(p):
            raise ValueError(f"{n} phải là file thường")
    mp, sp = (os.path.join(bundle, n) for n in ("kb-manifest.json", "kb.sqlite.gz"))
    if os.path.getsize(mp) > MAX_MANIFEST or os.path.getsize(sp) > MAX_SNAPSHOT or os.path.getsize(sp) == 0:
        raise ValueError("kích thước file ngoài giới hạn")
    m = json.load(open(mp, "rb"))
    if not isinstance(m, dict) or set(m) != KEYS:
        raise ValueError(f"manifest phải có đúng các key {sorted(KEYS)}")
    h = hashlib.sha256()
    with open(sp, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    if m["sha256"] != h.hexdigest():
        raise ValueError("sha256 không khớp snapshot")
    if m["url"] != expected_url:
        raise ValueError("url không đúng")
    if m["format"] != "sqlite+gzip" or not isinstance(m["advisory_count"], int) or m["advisory_count"] < 0:
        raise ValueError("format/advisory_count không hợp lệ")
    if not re.fullmatch(r"\d{4}\.\d{2}\.\d{2}", str(m["version"])):
        raise ValueError("version sai định dạng")
    vdate = datetime.date(*_ver(m["version"]))
    if abs((vdate - now.date()).days) > 1:
        raise ValueError("version lệch quá 1 ngày so với hôm nay (UTC)")
    built = datetime.datetime.strptime(m["built_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    if abs((now - built).total_seconds()) > 3600:
        raise ValueError("built_at lệch quá 1 giờ so với hiện tại")
    if previous is not None:
        if _ver(m["version"]) < _ver(previous["version"]):
            raise ValueError("version thấp hơn bản đang publish (rollback)")
        if m["version"] == previous["version"] and m["built_at"] < previous.get("built_at", ""):
            raise ValueError("built_at cũ hơn bản đang publish cùng version")
    return m


if __name__ == "__main__":
    prev = None
    if len(sys.argv) > 3 and os.path.exists(sys.argv[3]):
        try:
            prev = json.load(open(sys.argv[3]))
        except Exception:
            prev = None   # release trước hỏng/không có → bỏ qua kiểm monotonic
    try:
        check(sys.argv[1], sys.argv[2], prev)
    except Exception as e:
        sys.exit(f"KB bundle KHÔNG hợp lệ: {e}")
    print("KB bundle OK")
