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

REPO = "KeygraphHQ/xbow-validation-benchmarks"
PINNED_SHA = "07721361bc2464a7625a27dd1f0b5570f75f3db5"
LAB_NETWORK = "vglab_lab_net"          # project `vglab` + network `lab_net` của docker-compose.lab.yml
OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "lab", "xbow", "out")

# Mặc định: 3 benchmark web đơn giản, mỗi cái 1 service lộ cổng. Danh sách CHỈNH TAY được (level không có trong bản đã gỡ hint —
# chủ repo rà lại sau lần chạy đầu). `ip` phải khớp ZONE trong eval/lab/dns/dns_server.py.
BENCHMARKS: Dict[str, Dict] = {
    "XBEN-004-24": {"ip": "172.31.250.61", "name": "xbow-1.lab"},
    "XBEN-005-24": {"ip": "172.31.250.62", "name": "xbow-2.lab"},
    "XBEN-007-24": {"ip": "172.31.250.63", "name": "xbow-3.lab"},
}
FLAG_RE = re.compile(r"flag\{vg-[0-9a-f]{32}\}")


def new_flag() -> str:
    return "flag{vg-%s}" % secrets.token_hex(16)


def _container_port(ports: List) -> Optional[int]:
    for p in ports or []:
        s = str(p).split("/")[0]
        return int(s.rsplit(":", 1)[-1])
    return None


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


def _strip_health(svc: Dict) -> None:
    """Healthcheck của benchmark hay dùng công cụ image không có (XBEN-007: `curl` trên python:slim) ⇒ `up --wait` lỗi ⇒ cả run chết.
    Bỏ healthcheck; sự sẵn sàng được harness thăm dò bằng HTTP từ vg-under-test (capability.wait_ready)."""
    svc.pop("healthcheck", None)
    dep = svc.get("depends_on")
    if isinstance(dep, dict):
        svc["depends_on"] = {k: {**(v or {}), "condition": "service_started"} for k, v in dep.items()}


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
    """Bỏ mọi `ports` (không publish ra host), đặt service lộ cổng lên lab_net (IP cố định) + mạng nội bộ của benchmark
    (`internal: true`); các service còn lại (DB...) CHỈ ở mạng nội bộ. Trả (compose mới); cổng web ở `x-vg-entry-port`."""
    out = {k: v for k, v in cfg.items() if k not in ("networks", "services", "name")}
    entry = [n for n, s in cfg["services"].items() if s.get("ports")]
    if len(entry) != 1:
        raise ValueError(f"cần đúng 1 service lộ cổng, có {entry}")
    out["networks"] = {"lab_net": {"external": True, "name": LAB_NETWORK}, "bench_internal": {"internal": True}}
    out["services"] = {}
    for name, svc in cfg["services"].items():
        s = {k: v for k, v in svc.items() if k not in ("ports", "networks", "container_name", "network_mode", "privileged")}
        _with_flag_env(s)
        _strip_health(s)
        if name == entry[0]:
            s["expose"] = [str(_container_port(svc["ports"]))]
            s["networks"] = {"lab_net": {"ipv4_address": ip}, "bench_internal": {}}
            out["x-vg-entry-port"] = _container_port(svc["ports"])
        else:
            s["networks"] = {"bench_internal": {}}
        out["services"][name] = s
    return out


def _host_source(v) -> bool:
    """True nếu mục volumes là bind mount từ đường dẫn host (tuyệt đối, ~, .., hoặc long-syntax type=bind)."""
    if isinstance(v, dict):
        return v.get("type") == "bind" or _host_source(str(v.get("source") or ""))
    src = str(v).split(":", 1)[0]
    return src.startswith(("/", "~", "..", "$")) or (":" in str(v) and src.startswith("."))


def assert_xbow_compose_safe(cfg: Dict, ip: str) -> None:
    from eval.harness.runner import LabSafetyError, _lab_ip
    import ipaddress
    if not _lab_ip(ipaddress.ip_address(ip)):
        raise LabSafetyError(f"xbow ip ngoài lab: {ip}")
    nets = cfg.get("networks") or {}
    if set(nets) != {"lab_net", "bench_internal"} or nets["bench_internal"].get("internal") is not True \
            or nets["lab_net"].get("name") != LAB_NETWORK or nets["lab_net"].get("external") is not True:
        raise LabSafetyError("xbow compose: networks phải là lab_net(external) + bench_internal(internal)")
    for name, svc in (cfg.get("services") or {}).items():
        for bad in ("ports", "privileged", "network_mode", "pid", "cap_add", "devices"):
            if svc.get(bad):
                raise LabSafetyError(f"xbow service {name}: `{bad}` bị cấm")
        for v in svc.get("volumes") or []:
            if "docker.sock" in str(v):
                raise LabSafetyError(f"xbow service {name}: mount docker.sock bị cấm")
            if _host_source(v):
                raise LabSafetyError(f"xbow service {name}: bind mount từ host bị cấm: {v}")
        if not set(svc.get("networks") or {}) <= {"lab_net", "bench_internal"}:
            raise LabSafetyError(f"xbow service {name}: network lạ")


def prepare(bench_ids: Optional[List[str]] = None, out_dir: str = OUT_DIR) -> Dict[str, Dict]:
    """Tải tarball ở SHA ghim, sinh compose lab, build image với flag ngẫu nhiên. Trả {id: {ip,name,port,dir,flag}}."""
    import tempfile
    import yaml
    ids = bench_ids or list(BENCHMARKS)
    os.makedirs(out_dir, exist_ok=True)
    res: Dict[str, Dict] = {}
    with tempfile.TemporaryDirectory(prefix="xbow_") as tmp:
        tgz = os.path.join(tmp, "src.tgz")
        urllib.request.urlretrieve(f"https://codeload.github.com/{REPO}/tar.gz/{PINNED_SHA}", tgz)  # nosec B310 — URL cố định, https
        with tarfile.open(tgz) as t:
            t.extractall(tmp, filter="data")
        root = os.path.join(tmp, f"xbow-validation-benchmarks-{PINNED_SHA}", "benchmarks")
        for bid in ids:
            meta = BENCHMARKS[bid]
            dst = os.path.join(out_dir, bid)
            shutil.rmtree(dst, ignore_errors=True)
            shutil.copytree(os.path.join(root, bid), dst)
            with open(os.path.join(dst, "docker-compose.yml")) as f:
                cfg = transform_compose(yaml.safe_load(f), meta["ip"])
            assert_xbow_compose_safe({k: v for k, v in cfg.items() if k != "x-vg-entry-port"}, meta["ip"])
            with open(os.path.join(dst, "docker-compose.vglab.yml"), "w") as f:
                yaml.safe_dump(cfg, f)
            flag = new_flag()
            with open(os.path.join(dst, "flag.txt"), "w") as f:
                f.write(flag)
            env = dict(os.environ, FLAG=flag)
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
