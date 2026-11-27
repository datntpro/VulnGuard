"""Cô lập compose của benchmark bên thứ ba (XBOW, AutoPenBench…) vào lab. Hàm THUẦN, test offline.

Hợp đồng: `assert_bench_compose_safe(cfg, allowed_ips, phase="pre")` chạy trên compose GỐC (từ chối FAIL-CLOSED mọi khoá có thể
thoát khỏi lab), `transform_compose` viết lại (mọi service chỉ nối lab_net(external)+bench_internal(internal), bỏ `ports`),
rồi `assert_bench_compose_safe(out, allowed_ips, phase="post")` kiểm lại KẾT QUẢ. Không nới danh sách từ chối để một challenge chạy
được — bỏ challenge đó khỏi selection.

`ports` ở phase "pre" được chấp nhận vì transform xoá hết (không bao giờ publish ra host) và đó là cách upstream đánh dấu service
lộ cổng; ở phase "post" `ports` bị cấm tuyệt đối."""
import copy
import ipaddress
import logging
import os
import posixpath
import re
from typing import Dict, Iterable, List, Optional

LAB_NETWORK = "vglab_lab_net"          # project `vglab` + network `lab_net` của docker-compose.lab.yml
LAB_NET = ipaddress.ip_network("172.31.250.0/24")
BENCH_NET = "bench_internal"
log = logging.getLogger(__name__)


class UnsafeCompose(RuntimeError):
    """Compose có khoá/giá trị có thể thoát khỏi cô lập của lab."""


# Khoá cấp service bị từ chối khi có BẤT KỲ giá trị truthy nào.
_FORBIDDEN_ANY = ("network_mode", "privileged", "cap_add", "devices", "pid", "ipc", "uts", "userns_mode", "extra_hosts", "dns",
                  "dns_search", "dns_opt", "sysctls", "cgroup", "cgroup_parent", "volumes_from", "runtime", "secrets", "configs",
                  "external_links", "links", "device_cgroup_rules", "group_add")


def _host_source(v) -> bool:
    """True nếu mục volumes là bind mount từ đường dẫn host (tuyệt đối, ~, .., biến, './x:/y' hoặc long-syntax type=bind)."""
    if isinstance(v, dict):
        return v.get("type") == "bind" or _host_source(str(v.get("source") or ""))
    src = str(v).split(":", 1)[0]
    return src.startswith(("/", "~", "..", "$")) or (":" in str(v) and src.startswith("."))


def _as_dict(x) -> Dict:
    return x if isinstance(x, dict) else {}


# ── ALLOWLIST (fail closed): khoá không nằm trong danh sách ⇒ từ chối, ở MỌI cấp ──
_TOP_ALLOWED = ("services", "networks", "volumes", "version", "name")           # + mọi `x-*`
_SERVICE_ALLOWED = frozenset((
    "image", "build", "command", "entrypoint", "environment", "expose", "ports", "depends_on", "healthcheck", "platform", "init",
    "working_dir", "user", "restart", "networks", "volumes", "tmpfs", "read_only", "stop_signal", "stop_grace_period", "labels",
    "hostname", "cap_drop", "shm_size", "ulimits", "security_opt", "container_name"))   # container_name/ports/networks: pre-only, transform xoá
_BUILD_ALLOWED = frozenset(("context", "dockerfile", "args", "target"))
_HEALTH_ALLOWED = frozenset(("test", "interval", "timeout", "retries", "start_period", "start_interval", "disable"))
_DEP_ALLOWED = frozenset(("condition", "required", "restart"))
_NET_TOP_ALLOWED = frozenset(("name", "driver", "internal", "external"))   # external chỉ nhận giá trị false (kiểm riêng bên dưới)
_VOL_SUB_ALLOWED = frozenset(("nocopy",))
_TMPFS_SUB_ALLOWED = frozenset(("size", "mode"))
_DOCKER_ENV_ALLOWED = frozenset(("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH",
                                 "DOCKER_BUILDKIT", "DOCKER_DEFAULT_PLATFORM"))
_VOL_LONG_ALLOWED = frozenset(("type", "source", "target", "read_only", "tmpfs", "volume"))
_NAMED = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_SAFE_DOLLAR = "${FLAG}"


def _walk_strings(x):
    if isinstance(x, dict):
        for k, v in x.items():
            yield str(k)
            yield from _walk_strings(v)
    elif isinstance(x, (list, tuple)):
        for v in x:
            yield from _walk_strings(v)
    elif isinstance(x, str):
        yield x


def _check_interpolation(cfg: Dict) -> None:
    """Mọi `$` trong chuỗi (kể cả khoá) bị từ chối, trừ đúng `${FLAG}` — chặn rò biến môi trường host qua nội suy."""
    for s in _walk_strings(cfg):
        if "$" in s.replace(_SAFE_DOLLAR, ""):
            raise UnsafeCompose(f"nội suy biến `$` bị cấm (chỉ cho phép ${{FLAG}}): {s[:60]!r}")


def _check_env_list_or_map(name: str, where: str, v) -> None:
    """environment/build.args: mục không có `=` (hoặc giá trị null) = chuyển tiếp biến từ host ⇒ cấm, trừ đúng `FLAG`."""
    if v is None:
        return
    if isinstance(v, dict):
        for k, val in v.items():
            if val is None and str(k) != "FLAG":
                raise UnsafeCompose(f"service {name}: {where}.{k} không có giá trị (chuyển tiếp biến host)")
    elif isinstance(v, list):
        for e in v:
            if "=" not in str(e) and str(e) != "FLAG":
                raise UnsafeCompose(f"service {name}: {where} mục `{e}` không có `=` (chuyển tiếp biến host)")
    else:
        raise UnsafeCompose(f"service {name}: {where} kiểu lạ")


def _check_relpath(name: str, what: str, p) -> None:
    p = str(p)
    n = posixpath.normpath(p)
    if (not p or p != p.strip() or "://" in p or p.startswith(("/", "~", "git@", "\\")) or ":" in p or n == ".."
            or n.startswith("../") or "\\" in p):
        raise UnsafeCompose(f"service {name}: build.{what} phải là đường dẫn tương đối nằm TRONG thư mục challenge: {p!r}")
    if what == "context":
        # compose coi `github.com/x/y` (và `x.git`, `...#ref`) là git context TỪ XA (kéo mã không ghim lúc build) dù nó trông như đường dẫn
        # tương đối ⇒ context phải là `.`, `./...`, hoặc thư mục con thuần (đoạn đầu không chứa dấu chấm).
        first = n.split("/", 1)[0]
        if "#" in p or n.endswith(".git") or (p != "." and not p.startswith("./") and "." in first):
            raise UnsafeCompose(f"service {name}: build.context trông như git context từ xa (phải là `.`/`./...` trong thư mục challenge): {p!r}")


def _check_build(name: str, b) -> None:
    if isinstance(b, str):
        _check_relpath(name, "context", b)
        return
    if not isinstance(b, dict):
        raise UnsafeCompose(f"service {name}: build kiểu lạ")
    for k in b:
        if k not in _BUILD_ALLOWED:
            raise UnsafeCompose(f"service {name}: build.{k} không nằm trong allowlist")
    if "context" in b:
        _check_relpath(name, "context", b["context"])
    if "dockerfile" in b:
        _check_relpath(name, "dockerfile", b["dockerfile"])
    _check_env_list_or_map(name, "build.args", b.get("args"))


def _check_volume_entry(name: str, v, declared) -> None:
    if isinstance(v, dict):
        for k in v:
            if k not in _VOL_LONG_ALLOWED:
                raise UnsafeCompose(f"service {name}: volumes.{k} không nằm trong allowlist")
        t = v.get("type")
        if t not in ("volume", "tmpfs"):
            raise UnsafeCompose(f"service {name}: volume phải có type volume|tmpfs, có {t!r}")
        if t == "volume" and str(v.get("source")) not in declared:
            raise UnsafeCompose(f"service {name}: volume nguồn phải là named volume đã khai báo: {v.get('source')!r}")
        for sub, allowed in (("volume", _VOL_SUB_ALLOWED), ("tmpfs", _TMPFS_SUB_ALLOWED)):
            if sub not in v:
                continue
            d = v[sub]
            if not isinstance(d, dict) or set(map(str, d)) - allowed:
                raise UnsafeCompose(f"service {name}: volumes.{sub} chỉ được chứa {sorted(allowed)}")
            if any(isinstance(x, bool) != (sub == "volume") or not isinstance(x, (bool, int, str)) for x in d.values()):
                raise UnsafeCompose(f"service {name}: volumes.{sub} giá trị phải là scalar đơn giản")
        return
    parts = str(v).split(":")
    if len(parts) < 2 or len(parts) > 3 or parts[0] not in declared or not _NAMED.match(parts[0]) or not parts[1].startswith("/") \
            or (len(parts) == 3 and parts[2] not in ("ro", "rw", "nocopy")):
        raise UnsafeCompose(f"service {name}: volume chỉ được là `named_volume_đã_khai_báo:/path[:ro]`: {v!r}")


def _check_allowlist(cfg: Dict, phase: str) -> None:
    for k in cfg:
        if k not in _TOP_ALLOWED and not str(k).startswith("x-"):
            raise UnsafeCompose(f"khoá cấp cao `{k}` không nằm trong allowlist")
    _check_interpolation(cfg)
    tv = cfg.get("volumes")
    if tv is not None and not isinstance(tv, dict):
        raise UnsafeCompose("volumes cấp cao kiểu lạ")
    for vn, spec in (tv or {}).items():
        if spec not in (None, {}) or not _NAMED.match(str(vn)):
            raise UnsafeCompose(f"volume cấp cao `{vn}` chỉ được khai báo rỗng (không driver/driver_opts/external/name)")
    declared = {str(k) for k in (tv or {})}
    for n, spec in _as_dict(cfg.get("networks")).items():
        if not isinstance(spec, (dict, type(None))):
            raise UnsafeCompose(f"network {n}: kiểu lạ")
        if phase == "pre":
            for k in spec or {}:
                if k not in _NET_TOP_ALLOWED:
                    raise UnsafeCompose(f"network {n}: `{k}` không nằm trong allowlist")
    for name, svc in cfg["services"].items():
        if not isinstance(svc, dict):
            raise UnsafeCompose(f"service {name}: không phải mapping")
        for k in svc:
            if k not in _SERVICE_ALLOWED and not str(k).startswith("x-"):
                raise UnsafeCompose(f"service {name}: khoá `{k}` không nằm trong allowlist")
        if "build" in svc:
            _check_build(name, svc["build"])
        _check_env_list_or_map(name, "environment", svc.get("environment"))
        for v in svc.get("volumes") or []:
            _check_volume_entry(name, v, declared)
        for o in svc.get("security_opt") or []:
            if str(o) not in ("no-new-privileges", "no-new-privileges:true", "no-new-privileges=true"):
                raise UnsafeCompose(f"service {name}: security_opt `{o}` không nằm trong allowlist")
        hc = svc.get("healthcheck")
        if hc is not None and (not isinstance(hc, dict) or set(hc) - _HEALTH_ALLOWED):
            raise UnsafeCompose(f"service {name}: healthcheck có khoá ngoài allowlist")
        dep = svc.get("depends_on")
        if isinstance(dep, dict):
            for dn, ds in dep.items():
                if ds is not None and (not isinstance(ds, dict) or set(ds) - _DEP_ALLOWED):
                    raise UnsafeCompose(f"service {name}: depends_on.{dn} có khoá ngoài allowlist")
        elif dep is not None and not isinstance(dep, list):
            raise UnsafeCompose(f"service {name}: depends_on kiểu lạ")
        for key in ("command", "entrypoint"):
            c = svc.get(key)
            if c is not None and not isinstance(c, (str, list)):
                raise UnsafeCompose(f"service {name}: {key} kiểu lạ")


def assert_bench_compose_safe(cfg: Dict, allowed_ips: Iterable[str], phase: str = "pre") -> None:
    """Từ chối (fail closed) với UnsafeCompose. phase="pre": compose gốc; phase="post": compose đã `transform_compose`."""
    if phase not in ("pre", "post"):
        raise ValueError(f"phase không hợp lệ: {phase}")
    allowed = {str(i) for i in allowed_ips}
    for ip in allowed:
        a = ipaddress.ip_address(ip)
        if a not in LAB_NET or str(a) in (str(LAB_NET.network_address), "172.31.250.1", str(LAB_NET.broadcast_address)):
            raise UnsafeCompose(f"ip ngoài lab: {ip}")
    services = cfg.get("services")
    if not isinstance(services, dict) or not services:
        raise UnsafeCompose("compose không có services")
    for name, svc in services.items():            # denylist trước để có thông điệp cụ thể; allowlist (bên dưới) chặn MỌI thứ còn lại
        if not isinstance(svc, dict):
            raise UnsafeCompose(f"service {name}: không phải mapping")
        for bad in _FORBIDDEN_ANY:
            if svc.get(bad):
                raise UnsafeCompose(f"service {name}: `{bad}` bị cấm")
        if phase == "post" and svc.get("ports"):
            raise UnsafeCompose(f"service {name}: `ports` bị cấm (không publish ra host)")
        if any("unconfined" in str(o) for o in (svc.get("security_opt") or [])):
            raise UnsafeCompose(f"service {name}: security_opt unconfined bị cấm")
        for v in svc.get("volumes") or []:
            if "docker.sock" in str(v):
                raise UnsafeCompose(f"service {name}: mount docker.sock bị cấm")
            if _host_source(v):
                raise UnsafeCompose(f"service {name}: bind mount từ host bị cấm: {v}")
        b = svc.get("build")
        if isinstance(b, dict):
            if str(b.get("network") or "").lower() == "host":
                raise UnsafeCompose(f"service {name}: build.network=host bị cấm")
            for bad in ("extra_hosts", "privileged", "cap_add"):
                if b.get(bad):
                    raise UnsafeCompose(f"service {name}: build.{bad} bị cấm")
        if svc.get("image") and "@sha256:" not in str(svc["image"]) and not b:
            log.warning("service %s: image %s không ghim digest (chỉ cho phép khi build cục bộ)", name, svc["image"])
        nets = svc.get("networks")
        if phase == "post":
            names = set(nets) if isinstance(nets, (dict, list)) else set()
            if not names or not names <= {"lab_net", BENCH_NET}:
                raise UnsafeCompose(f"service {name}: network lạ {sorted(names)}")
            for n, spec in _as_dict(nets).items():
                if set(_as_dict(spec)) - {"ipv4_address"}:
                    raise UnsafeCompose(f"service {name}: networks.{n} có khoá ngoài allowlist")
                ip = _as_dict(spec).get("ipv4_address")
                if ip and str(ip) not in allowed:
                    raise UnsafeCompose(f"service {name}: ipv4_address {ip} không nằm trong allowed_ips")
                if n == BENCH_NET and ip:
                    raise UnsafeCompose(f"service {name}: bench_internal không được có IP cố định")
    _check_allowlist(cfg, phase)                  # allowlist cuối: mọi khoá/giá trị còn lại phải nằm trong danh sách cho phép
    top = _as_dict(cfg.get("networks"))
    if phase == "pre":
        for n, spec in top.items():
            spec = _as_dict(spec)
            if spec.get("external") not in (None, False, "false"):
                raise UnsafeCompose(f"network {n}: external bị cấm")
            if str(spec.get("driver") or "bridge") not in ("bridge",):
                raise UnsafeCompose(f"network {n}: driver {spec.get('driver')} bị cấm")
    else:
        if set(top) != {"lab_net", BENCH_NET}:
            raise UnsafeCompose(f"networks phải là lab_net(external) + bench_internal(internal), có {sorted(top)}")
        lab, bench = _as_dict(top["lab_net"]), _as_dict(top[BENCH_NET])
        if lab.get("external") is not True or lab.get("name") != LAB_NETWORK:
            raise UnsafeCompose("lab_net phải là external và trỏ tới mạng của lab")
        if bench.get("internal") is not True:
            raise UnsafeCompose("bench_internal phải `internal: true`")


def _container_port(svc: Dict) -> Optional[int]:
    for key in ("ports", "expose"):
        for p in svc.get(key) or []:
            s = str(p).split("/")[0]
            return int(s.rsplit(":", 1)[-1])
    return None


def _strip_health(svc: Dict) -> None:
    """Healthcheck của benchmark hay dùng công cụ image không có (XBEN-007: `curl`) ⇒ `up --wait` lỗi ⇒ cả run chết.
    Bỏ healthcheck; harness thăm dò sự sẵn sàng bằng HTTP từ vg-under-test."""
    svc.pop("healthcheck", None)
    dep = svc.get("depends_on")
    if isinstance(dep, dict):
        svc["depends_on"] = {k: {**(v or {}), "condition": "service_started"} for k, v in dep.items()}


def transform_compose(cfg: Dict, ip: str, lab_network: str = LAB_NETWORK, entry: Optional[str] = None) -> Dict:
    """THUẦN (không sửa `cfg`). Bỏ mọi `ports` (không publish ra host), đặt service lộ cổng lên lab_net (IP cố định) + mạng nội bộ
    của benchmark (`internal: true`); service còn lại (DB…) CHỈ ở mạng nội bộ. `entry` = tên service lộ cổng (mặc định: service duy nhất có
    `ports`). Cổng web ở `x-vg-entry-port`."""
    names = [entry] if entry else [n for n, s in cfg["services"].items() if s.get("ports")]
    if len(names) != 1 or names[0] not in cfg["services"]:
        raise ValueError(f"cần đúng 1 service lộ cổng, có {names}")
    port = _container_port(cfg["services"][names[0]])
    if port is None:
        raise ValueError(f"service {names[0]} không khai báo cổng (ports/expose)")
    out = {k: v for k, v in cfg.items() if k not in ("networks", "services", "name")}
    out["networks"] = {"lab_net": {"external": True, "name": lab_network}, BENCH_NET: {"internal": True}}
    out["services"] = {}
    for name, svc in cfg["services"].items():
        s = {k: v for k, v in svc.items() if k not in ("ports", "networks", "container_name", "network_mode", "privileged")}
        _strip_health(s)
        if name == names[0]:
            s["expose"] = [str(port)]
            s["networks"] = {"lab_net": {"ipv4_address": ip}, BENCH_NET: {}}
            out["x-vg-entry-port"] = port
        else:
            s["networks"] = {BENCH_NET: {}}
        out["services"][name] = s
    return copy.deepcopy(out)


def rewrite_and_check(cfg: Dict, ip: str, entry: Optional[str] = None) -> Dict:
    """pre-check → transform → post-check. Trả compose đã cô lập (kèm `x-vg-entry-port`)."""
    assert_bench_compose_safe(cfg, [ip], "pre")
    out = transform_compose(cfg, ip, entry=entry)
    assert_bench_compose_safe({k: v for k, v in out.items() if k != "x-vg-entry-port"}, [ip], "post")
    return out


def minimal_env(**extra: str) -> Dict[str, str]:
    """Môi trường TỐI THIỂU cho `docker compose`/build: PATH, HOME (+ allowlist DOCKER_* chính xác để tới daemon/context; KHÔNG DOCKER_PASSWORD/AUTH_CONFIG…) và `extra` (vd FLAG). KHÔNG chuyển
    tiếp phần còn lại của os.environ (khoá API, token CI…) vào compose/build của benchmark bên thứ ba."""
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME") or k in _DOCKER_ENV_ALLOWED}
    env.update(extra)
    return env
