"""XBOW validation benchmarks (D11) → lab (P1-7). Nguồn: KeygraphHQ/xbow-validation-benchmarks (Apache-2.0, đã gỡ hint),
GHIM commit. Mỗi benchmark được dựng với flag NGẪU NHIÊN (model không thể nhớ sẵn) và nối vào lab_net theo IP cố định.

`transform_compose` / `assert_xbow_compose_safe` là hàm thuần (test offline). Chỉ `prepare()` chạm mạng (tải tarball ở SHA ghim,
build image) — chạy tay/nightly, KHÔNG nằm trong test hay trong pentest-safety."""
import json
import os
import re
import secrets
import shutil
import subprocess  # nosec B404 — chỉ gọi `docker` với argv cố định
import tarfile
import urllib.request
from typing import Dict, List, Optional

from eval.bench import isolation

REPO = "KeygraphHQ/xbow-validation-benchmarks"
PINNED_SHA = "07721361bc2464a7625a27dd1f0b5570f75f3db5"
LAB_NETWORK = isolation.LAB_NETWORK  # project `vglab` + network `lab_net` của docker-compose.lab.yml
OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "lab", "xbow", "out")

SELECTION_FILE = os.path.join(os.path.dirname(__file__), "..", "bench", "xbow", "xbow_selection.yaml")


def load_selection(path: str = SELECTION_FILE) -> Dict[str, Dict]:
    """P2-15a: 20 challenge ở eval/bench/xbow/xbow_selection.yaml → {id: {ip, name, category, core, capability}}. `ip` khớp ZONE của DNS lab."""
    import yaml
    with open(path) as f:
        rows = yaml.safe_load(f)["challenges"]
    out = {r["id"]: {k: v for k, v in r.items() if k != "id"} for r in rows}
    if len(out) != len(rows):
        raise ValueError("xbow_selection.yaml: id trùng")
    return out


SELECTION: Dict[str, Dict] = load_selection()
# 3 task năng lực cũ (P1-7, eval.harness.capability.TASKS) = các mục `capability: true`; phần còn lại thuộc bench (eval.harness.bench).
BENCHMARKS: Dict[str, Dict] = {k: {"ip": v["ip"], "name": v["name"]} for k, v in SELECTION.items() if v.get("capability")}
FLAG_RE = re.compile(r"flag\{vg-[0-9a-f]{32}\}")


def new_flag() -> str:
    return "flag{vg-%s}" % secrets.token_hex(16)


def _with_flag_env(svc: Dict) -> None:
    """Cờ ngẫu nhiên PHẢI tới được ứng dụng: biến môi trường runtime (một số benchmark, vd XBEN-007, chỉ đọc os.getenv('FLAG')
    lúc chạy và Dockerfile đặt ENV trước ARG nên build-arg không đủ) + build arg FLAG nếu chưa có."""
    env = svc.get("environment")
    if isinstance(env, list):
        env = [e for e in env if not str(e).startswith("FLAG=") and str(e) != "FLAG"] + ["FLAG=${FLAG}"]
    else:
        env = dict(env or {})
        env["FLAG"] = "${FLAG}"
    svc["environment"] = env
    b = svc.get("build")
    if b is not None:
        b = {"context": b} if isinstance(b, str) else dict(b)
        args = b.get("args")
        if isinstance(args, list):
            args = [a for a in args if str(a).split("=")[0] != "FLAG"] + ["FLAG=${FLAG}"]
        else:
            args = dict(args or {})
            args["FLAG"] = "${FLAG}"
        b["args"] = args
        svc["build"] = b


def flag_is_injected(rendered: Dict, flag: str) -> bool:
    """`docker compose config` đã thế biến: mọi service có build phải nhận cờ qua env HOẶC build arg, và service lộ cổng phải có env."""
    ok = False
    for svc in (rendered.get("services") or {}).values():
        env = svc.get("environment") or {}
        env = env if isinstance(env, dict) else dict(str(e).split("=", 1) for e in env if "=" in str(e))
        ba = (svc.get("build") or {}).get("args") if isinstance(svc.get("build"), dict) else None
        ba = ba if isinstance(ba, dict) else dict(str(e).split("=", 1) for e in (ba or []) if "=" in str(e))
        if env.get("FLAG") == flag or (ba or {}).get("FLAG") == flag:
            ok = True
    return ok


def transform_compose(cfg: Dict, ip: str) -> Dict:
    """Viết lại cô lập (eval.bench.isolation) + đưa cờ ngẫu nhiên vào env/build arg của MỌI service. Trả compose mới; cổng web ở `x-vg-entry-port`."""
    out = isolation.transform_compose(cfg, ip, LAB_NETWORK)
    for svc in out["services"].values():
        _with_flag_env(svc)
    return out


def assert_xbow_compose_safe(cfg: Dict, ip: str) -> None:
    """Kiểm compose ĐÃ viết lại (phase post). Giữ tên + ngoại lệ cũ (LabSafetyError) cho harness P1-7."""
    from eval.harness.runner import LabSafetyError, _lab_ip
    import ipaddress
    if not _lab_ip(ipaddress.ip_address(ip)):
        raise LabSafetyError(f"xbow ip ngoài lab: {ip}")
    try:
        isolation.assert_bench_compose_safe(cfg, [ip], "post")
    except isolation.UnsafeCompose as e:
        raise LabSafetyError(f"xbow compose: {e}") from e


def fetch_composes(ids: List[str]) -> Dict[str, Dict]:
    """Stream tarball ở SHA ghim và đọc CHỈ docker-compose.yml của `ids` (dừng sớm — tarball ~1.3 GB, không giải nén ra đĩa)."""
    import yaml
    want = {f"xbow-validation-benchmarks-{PINNED_SHA}/benchmarks/{i}/docker-compose.yml": i for i in ids}
    found: Dict[str, Dict] = {}
    url = f"https://codeload.github.com/{REPO}/tar.gz/{PINNED_SHA}"
    with tarfile.open(fileobj=urllib.request.urlopen(url, timeout=120), mode="r|gz") as t:  # nosec B310 — URL cố định, https
        for m in t:
            if m.name in want and m.isfile():
                found[want[m.name]] = yaml.safe_load(t.extractfile(m).read())
                if len(found) == len(want):
                    break
    return found


def lint(ids: Optional[List[str]] = None) -> List[str]:
    """Chạy cô lập pre→transform→post trên compose upstream của selection. Trả danh sách lỗi (rỗng = sạch). Không build, không Docker."""
    ids = ids or list(SELECTION)
    errs: List[str] = []
    cfgs = fetch_composes(ids)
    for i in ids:
        try:
            if i not in cfgs:
                raise RuntimeError("không có trong tarball ở SHA ghim")
            isolation.rewrite_and_check(cfgs[i], SELECTION[i]["ip"])
        except Exception as e:
            errs.append(f"{i}: {type(e).__name__}: {e}")
    return errs


def prepare(bench_ids: Optional[List[str]] = None, out_dir: str = OUT_DIR) -> Dict[str, Dict]:
    """Tải tarball ở SHA ghim, sinh compose lab, build image với flag ngẫu nhiên. Trả {id: {ip,name,port,dir,flag}}."""
    import tempfile
    import yaml
    ids = bench_ids or list(BENCHMARKS)
    unknown = [i for i in ids if i not in SELECTION]
    if unknown:
        raise ValueError(f"không có trong selection: {unknown}")
    os.makedirs(out_dir, exist_ok=True)
    res: Dict[str, Dict] = {}
    with tempfile.TemporaryDirectory(prefix="xbow_") as tmp:
        tgz = os.path.join(tmp, "src.tgz")
        urllib.request.urlretrieve(f"https://codeload.github.com/{REPO}/tar.gz/{PINNED_SHA}", tgz)  # nosec B310 — URL cố định, https
        with tarfile.open(tgz) as t:
            t.extractall(tmp, filter="data")
        root = os.path.join(tmp, f"xbow-validation-benchmarks-{PINNED_SHA}", "benchmarks")
        for bid in ids:
            meta = {"ip": SELECTION[bid]["ip"], "name": SELECTION[bid]["name"]}
            dst = os.path.join(out_dir, bid)
            shutil.rmtree(dst, ignore_errors=True)
            shutil.copytree(os.path.join(root, bid), dst)
            for dot in (".env", ".env.local"):                       # compose tự đọc .env của project dir ⇒ xoá (upstream không được đưa biến vào)
                if os.path.isfile(os.path.join(dst, dot)):
                    os.unlink(os.path.join(dst, dot))
            with open(os.path.join(dst, "docker-compose.yml")) as f:
                raw = yaml.safe_load(f)
            isolation.assert_bench_compose_safe(raw, [meta["ip"]], "pre")      # từ chối TRƯỚC khi viết lại (fail closed)
            cfg = transform_compose(raw, meta["ip"])
            assert_xbow_compose_safe({k: v for k, v in cfg.items() if k != "x-vg-entry-port"}, meta["ip"])
            with open(os.path.join(dst, "docker-compose.vglab.yml"), "w") as f:
                yaml.safe_dump(cfg, f)
            flag = new_flag()
            with open(os.path.join(dst, "flag.txt"), "w") as f:
                f.write(flag)
            env = isolation.minimal_env(FLAG=flag)
            rendered = json.loads(subprocess.run(["docker", "compose", "-f", "docker-compose.vglab.yml", "config", "--format", "json"],  # nosec B603 B607
                                                 cwd=dst, env=env, check=True, timeout=120, capture_output=True, text=True).stdout)
            if not flag_is_injected(rendered, flag):       # không có đường đưa cờ vào ⇒ benchmark vô nghĩa ⇒ từ chối
                raise RuntimeError(f"{bid}: cờ ngẫu nhiên không được đưa vào service nào (env/build arg) — từ chối benchmark")
            subprocess.run(["docker", "compose", "-p", f"vgx-{bid.lower()}", "-f", "docker-compose.vglab.yml", "build"],  # nosec B603 B607
                           cwd=dst, env=env, check=True, timeout=1800)
            res[bid] = {**meta, "port": cfg["x-vg-entry-port"], "dir": dst, "flag": flag}
    return res


if __name__ == "__main__":
    import sys
    # KHÔNG in cờ/đường dẫn vào log (repo public); harness đọc cờ từ flag.txt trên đĩa
    print(json.dumps({k: {x: v[x] for x in ("ip", "name", "port")} for k, v in prepare(sys.argv[1:] or None).items()}, indent=2))
