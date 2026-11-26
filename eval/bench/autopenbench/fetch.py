"""AutoPenBench (D9/O9) → lab. Nguồn: lucagioacchini/auto-pen-bench (MIT) ở SHA GHIM; KHÔNG vendor/submodule — tải tarball lúc chạy.

Upstream dùng bind mount `flag.txt` (bị cấm bởi eval.bench.isolation) và cờ tĩnh. Ở đây mỗi task được dựng lại: build context của vm + Dockerfile
sinh ra có `ARG FLAG` ghi cờ NGẪU NHIÊN vào `flag_path` (flag_static=false) ⇒ model không thể nhớ sẵn; compose sinh ra không có volume/cap/ports.

Phần thuần (`load_selection`, `inject_flag_dockerfile`, `build_compose`) test offline. `download`/`prepare`/`lint` chạm mạng (chỉ job bench / lint)."""
import io
import json
import os
import re
import shutil
import tarfile
import urllib.request
from typing import Dict, List, Optional

from eval.bench import isolation

REPO = "lucagioacchini/auto-pen-bench"
PINNED_SHA = "9c4890a7195896a399339f4b1b0e0c498fdd27cb"
SELECTION_FILE = os.path.join(os.path.dirname(__file__), "apb_selection.yaml")
OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "lab", "apb", "out")
MACHINES = "benchmark/machines/in-vitro"
_FROM = re.compile(r"^(FROM\s+\S+.*)$", re.M | re.I)


def load_selection(path: str = SELECTION_FILE) -> List[Dict]:
    import yaml
    with open(path) as f:
        tasks = yaml.safe_load(f)["tasks"]
    ids = [t["id"] for t in tasks]
    if len(set(ids)) != len(ids):
        raise ValueError("apb_selection.yaml: id trùng")
    return tasks


def vm_dir(task: Dict) -> str:
    u = task["upstream"]
    return f"{MACHINES}/{u['category']}/vm{u['vm']}"


def service_name(task: Dict) -> str:
    u = task["upstream"]
    return f"in-vitro_{u['category']}_vm{u['vm']}"


def inject_flag_dockerfile(text: str, flag_path: str) -> str:
    """Chèn `ARG FLAG` + ghi cờ NGAY SAU `FROM` đầu tiên (còn là root, trước mọi `USER`). Thuần."""
    m = _FROM.search(text)
    if not m or not re.fullmatch(r"/[A-Za-z0-9_./-]+", flag_path):
        raise ValueError("Dockerfile không có FROM hoặc flag_path không hợp lệ")
    d = os.path.dirname(flag_path) or "/"
    inject = (f"\nARG FLAG\nRUN mkdir -p {d} && printf '%s\\n' \"$FLAG\" > {flag_path} && chmod 644 {flag_path}\n")
    return text[:m.end()] + inject + text[m.end():]


def build_compose(task: Dict, upstream_service: Dict, ctx: str = "./ctx") -> Dict:
    """Compose THÔ (trước cô lập) của một task: 1 service `web`, build từ context đã chuẩn bị, command của upstream, cổng 80 qua `expose`.
    Không volume/cap/ports ⇒ qua `isolation.rewrite_and_check(cfg, ip, entry="web")`."""
    svc: Dict = {"build": {"context": ctx, "dockerfile": "Dockerfile.vglab", "args": {"FLAG": "${FLAG}"}},
                 "environment": {"FLAG": "${FLAG}"}, "expose": ["80"]}
    if upstream_service.get("command"):
        svc["command"] = upstream_service["command"]
    if upstream_service.get("init"):
        svc["init"] = True
    return {"services": {"web": svc}}


def _tar_stream():
    url = f"https://codeload.github.com/{REPO}/tar.gz/{PINNED_SHA}"
    return tarfile.open(fileobj=urllib.request.urlopen(url, timeout=120), mode="r|gz")  # nosec B310 — URL cố định, https


def download(dest: str, tasks: Optional[List[Dict]] = None) -> str:
    """Giải nén CHỈ docker-compose của category + thư mục vm đã chọn (tarball nhỏ). Trả đường dẫn gốc repo đã giải nén."""
    tasks = tasks or load_selection()
    wanted = tuple(f"{vm_dir(t)}/" for t in tasks) + tuple(f"{MACHINES}/{t['upstream']['category']}/docker-compose.yml" for t in tasks)
    root = os.path.join(dest, f"auto-pen-bench-{PINNED_SHA}")
    with _tar_stream() as t:
        for m in t:
            rel = m.name.split("/", 1)[1] if "/" in m.name else ""
            if rel.startswith(wanted) and (m.isfile() or m.isdir()):
                if ".." in rel.split("/") or os.path.isabs(rel):
                    raise ValueError(f"đường dẫn lạ trong tarball: {m.name}")
                t.extract(m, dest, filter="data")
    return root


def _compose_for(root: str, task: Dict) -> Dict:
    import yaml
    with open(os.path.join(root, MACHINES, task["upstream"]["category"], "docker-compose.yml")) as f:
        up = yaml.safe_load(f)["services"][service_name(task)]
    return build_compose(task, up)


def lint(tasks: Optional[List[Dict]] = None) -> List[str]:
    """Tải tarball ở SHA ghim, dựng compose của MỌI task đã chọn, chạy cô lập pre→transform→post. Trả danh sách lỗi (rỗng = sạch). Không build."""
    import tempfile
    tasks = tasks or load_selection()
    errs: List[str] = []
    with tempfile.TemporaryDirectory(prefix="apb_lint_") as tmp:
        root = download(tmp, tasks)
        for t in tasks:
            try:
                if not os.path.exists(os.path.join(root, vm_dir(t), "Dockerfile")):
                    raise isolation.UnsafeCompose("thiếu Dockerfile ở SHA ghim")
                with open(os.path.join(root, vm_dir(t), "Dockerfile")) as f:
                    inject_flag_dockerfile(f.read(), t["flag_path"])
                isolation.rewrite_and_check(_compose_for(root, t), t["ip"], entry="web")
            except Exception as e:      # mỗi task báo riêng
                errs.append(f"{t['id']}: {type(e).__name__}: {e}")
    return errs


def prepare(task_ids: Optional[List[str]] = None, out_dir: str = OUT_DIR) -> Dict[str, Dict]:
    """Dựng context + compose cô lập + flag ngẫu nhiên + build image. Trả {id: {ip,name,port,dir,flag}}. Chạy tay/nightly, không ở unit test."""
    import secrets
    import subprocess  # nosec B404 — chỉ gọi `docker` với argv cố định
    import tempfile
    import yaml
    tasks = [t for t in load_selection() if not task_ids or t["id"] in task_ids]
    os.makedirs(out_dir, exist_ok=True)
    res: Dict[str, Dict] = {}
    with tempfile.TemporaryDirectory(prefix="apb_") as tmp:
        root = download(tmp, tasks)
        for t in tasks:
            dst = os.path.join(out_dir, t["id"])
            shutil.rmtree(dst, ignore_errors=True)
            ctx = os.path.join(dst, "ctx")
            shutil.copytree(os.path.join(root, vm_dir(t)), ctx)
            for stale in ("flag.txt", "flag"):                      # cờ tĩnh của upstream không được nằm trong context
                p = os.path.join(ctx, stale)
                if os.path.isfile(p):
                    os.unlink(p)
            with open(os.path.join(ctx, "Dockerfile")) as f:
                df = inject_flag_dockerfile(f.read(), t["flag_path"])
            with open(os.path.join(ctx, "Dockerfile.vglab"), "w") as f:
                f.write(df)
            cfg = isolation.rewrite_and_check(_compose_for(root, t), t["ip"], entry="web")
            for svc in cfg["services"].values():
                svc.setdefault("environment", {})
            with open(os.path.join(dst, "docker-compose.vglab.yml"), "w") as f:
                yaml.safe_dump(cfg, f)
            flag = "flag{vg-%s}" % secrets.token_hex(16)
            with open(os.path.join(dst, "flag.txt"), "w") as f:
                f.write(flag)
            env = dict(os.environ, FLAG=flag)
            subprocess.run(["docker", "compose", "-p", f"vgx-{t['id']}", "-f", "docker-compose.vglab.yml", "build"],  # nosec B603 B607
                           cwd=dst, env=env, check=True, timeout=1800)
            res[t["id"]] = {"ip": t["ip"], "name": t["name"], "port": cfg["x-vg-entry-port"], "dir": dst, "flag": flag}
    return res


if __name__ == "__main__":
    import sys
    # KHÔNG in cờ/đường dẫn vào log (repo public); harness đọc cờ từ flag.txt trên đĩa
    print(json.dumps({k: {x: v[x] for x in ("ip", "name", "port")} for k, v in prepare(sys.argv[1:] or None).items()}, indent=2))
